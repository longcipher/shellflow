//! Copy step execution: rsync with scp fallback, path normalization, and
//! per-host fan-out.

use std::sync::Arc;

use eyre::{Context, Result, bail};
use shellflow_core::{CopyStep, ResolvedHost};
use tokio::{process::Command, task::JoinSet};

use super::{
    ArcUi, CopyStepArgs, DiffFilter, HostOutcome, LogFile, StepConfig,
    process::{GroupGuard, isolate},
    remote::{RunError, resolve_remote_env},
    stream,
};

#[derive(Clone, Copy)]
pub(super) struct CopyOpts<'a> {
    pub(super) delete: bool,
    pub(super) excludes: &'a [String],
}

pub(crate) async fn run_copy_step(
    args: &CopyStepArgs,
    copy: &CopyStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    let (src, dst) = {
        let state = args.run_state.lock().await;
        let interpolated = shellflow_core::interpolate(&copy.src, &state)
            .and_then(|src| shellflow_core::interpolate(&copy.dst, &state).map(|dst| (src, dst)));
        drop(state);
        match interpolated {
            Ok(pair) => pair,
            Err(err) => {
                if config.dry_run || config.check {
                    crate::ui::warn(
                        &format!("{err} — copy skipped (no run state in dry-run/check)"),
                        &args.log_file,
                    );
                    return Ok(Vec::new());
                }
                return Err(err).wrap_err("copy path interpolation");
            }
        }
    };

    if config.local {
        return run_copy_step_local(
            &args.ui,
            &src,
            &dst,
            copy.delete,
            &copy.excludes,
            config,
            &args.log_file,
        )
        .await;
    }

    if config.check {
        crate::ui::note("  syntax check: copy step (no execution)", &args.log_file);
        return Ok(Vec::new());
    }

    if config.dry_run || config.verbose >= 2 {
        crate::ui::note(&format!("  rsync {src} -> {dst} ({} hosts)", hosts.len()), &args.log_file);
    }

    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(&args.ui);
        let semaphore = args.semaphore.clone();
        let src = src.clone();
        let dst = dst.clone();
        let delete = copy.delete;
        let excludes = copy.excludes.clone();
        let shell_cache = Arc::clone(&args.shell_cache);
        let log_file = args.log_file.clone();
        tasks.spawn(async move {
            let _permit = match &semaphore {
                Some(semaphore) => Arc::clone(semaphore).acquire_owned().await.ok(),
                None => None,
            };
            let has_rsync = resolve_remote_env(&host, &shell_cache).await.has_rsync;
            let opts = CopyOpts { delete, excludes: &excludes };
            let host_args = RsyncHostArgs {
                ui,
                host: &host,
                src: &src,
                dst: &dst,
                opts,
                config,
                has_rsync,
                log_file: &log_file,
            };
            run_rsync_host(host_args).await
        });
    }

    stream::collect_hosts(tasks).await
}

async fn run_copy_step_local(
    _ui: &ArcUi,
    src: &str,
    dst: &str,
    delete: bool,
    excludes: &[String],
    config: StepConfig,
    log_file: &LogFile,
) -> Result<Vec<(String, HostOutcome)>> {
    if config.check {
        crate::ui::note("  syntax check: copy step (no execution)", log_file);
        return Ok(vec![("localhost".to_string(), HostOutcome::Ok)]);
    }
    if config.dry_run || config.verbose >= 2 {
        crate::ui::note(&format!("  local copy {src} -> {dst}"), log_file);
    }
    if config.dry_run {
        return Ok(vec![("localhost".to_string(), HostOutcome::Ok)]);
    }

    if !excludes.is_empty() {
        crate::ui::warn(
            "`--exclude` ignored in --local copy mode (local copies use `cp -a`; \
             re-run without `--local` for rsync filtering)",
            log_file,
        );
    }

    if delete {
        let _ = std::fs::remove_dir_all(dst);
        let _ = std::fs::remove_file(dst);
    }

    if let Some(parent) = std::path::Path::new(dst).parent() &&
        !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create {} for local copy", parent.display()))?;
    }

    let mut cmd = Command::new("cp");
    cmd.arg("-a").arg(src).arg(dst);
    cmd.kill_on_drop(true);
    let status = run_command_status(cmd, config.timeout, "local copy").await?;
    if !status.success() {
        bail!("local copy exited with status {status}");
    }
    Ok(vec![("localhost".to_string(), HostOutcome::Ok)])
}

async fn run_command_status(
    mut cmd: Command,
    timeout: Option<u64>,
    label: &str,
) -> Result<std::process::ExitStatus> {
    isolate(&mut cmd);
    cmd.kill_on_drop(true);
    let status = match timeout {
        Some(secs) => {
            let mut child = cmd.spawn().wrap_err(format!("failed to run {label}"))?;
            let mut guard = GroupGuard::new(&child);
            match tokio::time::timeout(std::time::Duration::from_secs(secs), child.wait()).await {
                Ok(Ok(status)) => {
                    guard.disarm();
                    status
                }
                Ok(Err(err)) => return Err(err).wrap_err(format!("failed to run {label}")),
                Err(_) => {
                    crate::ui::warn(&format!("{label} timed out — killed"), &None);
                    super::process::terminate(&mut child).await;
                    guard.disarm();
                    bail!("{label} timed out after {secs}s");
                }
            }
        }
        None => cmd.status().await.wrap_err(format!("failed to run {label}"))?,
    };
    Ok(status)
}

struct RsyncHostArgs<'a> {
    ui: ArcUi,
    host: &'a ResolvedHost,
    src: &'a str,
    dst: &'a str,
    opts: CopyOpts<'a>,
    config: StepConfig,
    has_rsync: bool,
    log_file: &'a LogFile,
}

async fn run_rsync_host(args: RsyncHostArgs<'_>) -> (String, HostOutcome) {
    let RsyncHostArgs { ui, host, src, dst, opts, config, has_rsync, log_file } = args;
    let remote_shell = host.spec.rsync_remote_shell().unwrap_or_else(|| "ssh".to_string());

    if config.verbose >= 2 {
        crate::ui::note(
            &format!(
                "  [{}] remote rsync: {}",
                host.alias,
                if has_rsync { "present" } else { "missing — using scp fallback" }
            ),
            log_file,
        );
    }
    if opts.delete && !has_rsync {
        crate::ui::warn(
            &format!(
                "[{}] `--delete` ignored: remote has no rsync, so the scp fallback cannot mirror deletions",
                host.alias
            ),
            log_file,
        );
    }
    if !opts.excludes.is_empty() && !has_rsync {
        crate::ui::warn(
            &format!(
                "[{}] `--exclude` ignored: remote has no rsync, so the scp fallback cannot filter files",
                host.alias
            ),
            log_file,
        );
    }

    let outcome = if has_rsync {
        let transfer = RsyncTransferArgs {
            ui: ui.clone(),
            host,
            src,
            dst,
            opts,
            remote_shell: &remote_shell,
            config,
            log_file,
        };
        run_rsync_transfer(transfer).await
    } else {
        run_scp_transfer(ui.clone(), host, src, dst, config, log_file).await
    };

    match outcome {
        Ok(()) => (host.alias.clone(), HostOutcome::Ok),
        Err(err) => {
            crate::ui::warn(&format!("[{}] {err:#}", host.alias), log_file);
            if err.to_string().contains("timed out") {
                (host.alias.clone(), HostOutcome::TimedOut)
            } else {
                (host.alias.clone(), HostOutcome::Failed(RunError::Transport))
            }
        }
    }
}

fn normalize_copy_paths(src: &str, dst: &str) -> (String, String) {
    if std::fs::metadata(src).is_ok_and(|meta| meta.is_dir()) {
        (format!("{}/", src.trim_end_matches('/')), format!("{}/", dst.trim_end_matches('/')))
    } else {
        (src.to_string(), dst.to_string())
    }
}

struct RsyncTransferArgs<'a> {
    ui: ArcUi,
    host: &'a ResolvedHost,
    src: &'a str,
    dst: &'a str,
    opts: CopyOpts<'a>,
    remote_shell: &'a str,
    config: StepConfig,
    log_file: &'a LogFile,
}

async fn run_rsync_transfer(args: RsyncTransferArgs<'_>) -> Result<()> {
    let mut cmd = Command::new("rsync");
    cmd.args(["-a", "-z"]);
    if args.opts.delete {
        cmd.arg("--delete");
    }
    for glob in args.opts.excludes {
        cmd.arg("--exclude").arg(glob);
    }
    if args.config.dry_run {
        cmd.args(["--dry-run", "-i"]);
    }
    let (src, dst) = normalize_copy_paths(args.src, args.dst);
    let dir = if dst.ends_with('/') {
        dst.as_str()
    } else {
        match dst.rsplit_once('/') {
            Some((dir, file)) if !file.is_empty() && !dir.is_empty() => dir,
            _ => dst.as_str(),
        }
    };
    let quoted = dir.replace('\'', "'\\''");
    let mkdir_rsync = format!("mkdir -p '{quoted}' && rsync");
    cmd.args(["--rsync-path", &mkdir_rsync, "-e", args.remote_shell]);
    let dest = format!("{}:{dst}", args.host.spec.dest());
    cmd.arg(&src).arg(&dest);
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    if args.config.verbose >= 2 {
        crate::ui::note(
            &format!("  [{}] rsync {}", args.host.alias, super::display_args(&cmd)),
            args.log_file,
        );
    }

    let diff_filter: Option<DiffFilter> = args
        .config
        .diff
        .then(|| Arc::new(|line: &str| super::is_rsync_itemize_line(line)) as DiffFilter);
    match stream::run_piped_child(
        args.ui,
        &args.host.alias,
        cmd,
        None,
        args.config.timeout,
        diff_filter,
        args.log_file,
    )
    .await?
    {
        stream::PipedRun::Completed(status) => {
            if !status.success() {
                bail!("rsync exited with status {status}");
            }
            Ok(())
        }
        stream::PipedRun::TimedOut => {
            bail!("copy step timed out");
        }
    }
}

async fn run_scp_transfer(
    ui: ArcUi,
    host: &ResolvedHost,
    src: &str,
    dst: &str,
    config: StepConfig,
    log_file: &LogFile,
) -> Result<()> {
    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] scp fallback: {src} -> {dst}", host.alias), log_file);
    }

    let is_dir_src = std::fs::metadata(src).is_ok_and(|meta| meta.is_dir());
    let (dir, scp_src) = if is_dir_src {
        (dst.trim_end_matches('/').to_string(), format!("{src}/."))
    } else {
        match dst.rsplit_once('/') {
            Some((dir, file)) if !file.is_empty() && !dir.is_empty() => {
                (dir.to_string(), src.to_string())
            }
            _ => (dst.to_string(), src.to_string()),
        }
    };

    let quoted_dir = dir.replace('\'', "'\\''");
    let mut mkdir = Command::new("ssh");
    mkdir.args(host.spec.to_ssh_args()).arg("-T");
    mkdir.arg(format!("mkdir -p '{quoted_dir}'"));
    mkdir
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    mkdir.kill_on_drop(true);
    isolate(&mut mkdir);
    let status = mkdir.status().await.wrap_err("failed to create remote dir")?;
    if !status.success() {
        bail!("remote mkdir for {dir} failed");
    }

    let dest = format!("{}:{dir}/", host.spec.dest());
    let mut scp = Command::new("scp");
    scp.args(["-q", "-o", "BatchMode=yes"]);
    if let Some(port) = host.spec.port {
        scp.args(["-P", &port.to_string()]);
    }
    if is_dir_src {
        scp.arg("-r");
    }
    scp.arg(&scp_src).arg(&dest);
    scp.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    scp.kill_on_drop(true);
    isolate(&mut scp);

    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] scp {}", host.alias, super::display_args(&scp)), log_file);
    }

    match stream::run_piped_child(ui, &host.alias, scp, None, config.timeout, None, log_file)
        .await?
    {
        stream::PipedRun::Completed(status) => {
            if !status.success() {
                bail!("scp exited with status {status}");
            }
            Ok(())
        }
        stream::PipedRun::TimedOut => {
            bail!("copy step timed out");
        }
    }
}
