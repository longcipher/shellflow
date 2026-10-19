//! Copy step execution: rsync with scp fallback, path normalization, and
//! per-host fan-out.

use std::sync::Arc;

use eyre::{Context, Result, bail};
use shellflow_core::{CopyStep, ResolvedHost};
use tokio::{process::Command, task::JoinSet};

use super::{
    ArcUi, CopyStepArgs, DiffFilter, HostOutcome, LogFile, StepConfig, fanout_slot,
    process::{GroupGuard, isolate},
    remote::{RunError, resolve_remote_env},
    stream,
};

#[derive(Clone, Copy)]
pub(super) struct CopyOpts<'a> {
    pub(super) delete: bool,
    pub(super) excludes: &'a [String],
}

/// How a copy failed, kept separate from the message so nothing has to
/// string-match to pick the exit code (design §6 classifies 3 vs 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyFailureKind {
    /// The transfer exceeded its per-step timeout.
    Timeout,
    /// The transport failed (rsync/scp/ssh could not complete).
    Transport,
}

/// A copy failure: a structural classification plus the detail shown in the UI.
#[derive(Clone, Debug)]
struct CopyFailure {
    kind: CopyFailureKind,
    detail: String,
}

impl CopyFailure {
    fn timeout(detail: impl Into<String>) -> Self {
        Self { kind: CopyFailureKind::Timeout, detail: detail.into() }
    }

    fn transport(detail: impl Into<String>) -> Self {
        Self { kind: CopyFailureKind::Transport, detail: detail.into() }
    }
}

/// Map a transfer result onto the per-host outcome.
fn failure_outcome(alias: &str, failure: CopyFailure) -> (String, HostOutcome) {
    match failure.kind {
        CopyFailureKind::Timeout => (alias.to_string(), HostOutcome::TimedOut),
        CopyFailureKind::Transport => (alias.to_string(), HostOutcome::Failed(RunError::Transport)),
    }
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
            // Never run unthrottled when the semaphore is closed.
            let _permit = fanout_slot!(&semaphore, &log_file, host);
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
        // Stage the replacement *beside* the destination and swap it in only
        // after `cp` succeeded. Wiping first (the previous behaviour) meant a
        // failed copy left the destination empty — the worst possible outcome
        // for a `--delete` deploy.
        return run_local_copy_delete(src, dst, config, log_file).await;
    }

    if let Some(parent) = std::path::Path::new(dst).parent() &&
        !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
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

/// Copy `src` to `dst` with `--delete` semantics, atomically.
///
/// The new tree is built in a sibling staging path first. Only once `cp`
/// exits 0 is the old destination removed and the staging path renamed into
/// place, so an interrupted or failing copy always leaves the previous
/// deployment intact.
async fn run_local_copy_delete(
    src: &str,
    dst: &str,
    config: StepConfig,
    log_file: &LogFile,
) -> Result<Vec<(String, HostOutcome)>> {
    let dst_path = std::path::Path::new(dst);
    if let Some(parent) = dst_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("failed to create {} for local copy", parent.display()))?;
    }

    let staging = dst_path.with_file_name(format!(
        "{}.shellflow-new",
        dst_path.file_name().map_or_else(|| "dst".into(), |n| n.to_string_lossy().into_owned())
    ));
    remove_path(&staging).await?;
    if let Some(parent) = staging.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    let mut cmd = Command::new("cp");
    cmd.arg("-a").arg(src).arg(&staging);
    cmd.kill_on_drop(true);
    let status = run_command_status(cmd, config.timeout, "local copy").await?;
    if !status.success() {
        // The old destination is untouched; drop the half-built staging tree.
        remove_path(&staging).await?;
        bail!("local copy exited with status {status} (destination left unchanged)");
    }

    // The replacement is complete: only now is it safe to drop the old tree.
    if let Err(err) = remove_path(dst_path).await {
        remove_path(&staging).await?;
        crate::ui::warn(&format!("could not remove old destination {dst}: {err}"), log_file);
    }
    if let Err(err) = tokio::fs::rename(&staging, dst_path).await {
        remove_path(&staging).await?;
        bail!("failed to move staged copy into {dst}: {err}");
    }
    Ok(vec![("localhost".to_string(), HostOutcome::Ok)])
}

/// Remove `path` whether it is a file, a symlink, or a directory.
async fn remove_path(path: &std::path::Path) -> std::io::Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(path).await,
        Ok(_) => tokio::fs::remove_file(path).await,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

async fn run_command_status(
    mut cmd: Command,
    timeout: Option<u64>,
    label: &str,
) -> Result<std::process::ExitStatus> {
    isolate(&mut cmd);
    cmd.kill_on_drop(true);
    // Both branches spawn explicitly so every path owns a `GroupGuard`; the
    // previous `cmd.status()` fallback had none, which let a `cp` descendant
    // outlive an aborted run.
    let mut child = cmd.spawn().wrap_err(format!("failed to run {label}"))?;
    let mut guard = GroupGuard::new(&child);
    let status = match timeout {
        Some(secs) => {
            match tokio::time::timeout(std::time::Duration::from_secs(secs), child.wait()).await {
                Ok(Ok(status)) => status,
                Ok(Err(err)) => {
                    super::process::terminate(&mut child).await;
                    guard.disarm();
                    return Err(err).wrap_err(format!("failed to run {label}"));
                }
                Err(_) => {
                    crate::ui::warn(&format!("{label} timed out — killed"), &None);
                    super::process::terminate(&mut child).await;
                    guard.disarm();
                    bail!("{label} timed out after {secs}s");
                }
            }
        }
        None => child.wait().await.wrap_err(format!("failed to run {label}"))?,
    };
    guard.disarm();
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
        Err(failure) => {
            crate::ui::warn(&format!("[{}] {}", host.alias, failure.detail), log_file);
            failure_outcome(&host.alias, failure)
        }
    }
}

/// `src` with a trailing slash when it is a directory, so rsync copies the
/// directory *contents* into `dst` rather than nesting it.
async fn normalize_copy_paths(src: &str, dst: &str) -> (String, String) {
    if tokio::fs::metadata(src).await.is_ok_and(|meta| meta.is_dir()) {
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

async fn run_rsync_transfer(args: RsyncTransferArgs<'_>) -> std::result::Result<(), CopyFailure> {
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
    let (src, dst) = normalize_copy_paths(args.src, args.dst).await;
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
    .await
    .map_err(|err| CopyFailure::transport(format!("rsync could not start: {err:#}")))?
    {
        stream::PipedRun::Completed(status) => {
            if !status.success() {
                return Err(CopyFailure::transport(format!("rsync exited with status {status}")));
            }
            Ok(())
        }
        stream::PipedRun::TimedOut => Err(CopyFailure::timeout("copy step timed out")),
        stream::PipedRun::PipeBroken => {
            Err(CopyFailure::transport("rsync closed its input before the transfer finished"))
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
) -> std::result::Result<(), CopyFailure> {
    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] scp fallback: {src} -> {dst}", host.alias), log_file);
    }

    let is_dir_src = tokio::fs::metadata(src).await.is_ok_and(|meta| meta.is_dir());
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
    // Routed through `run_command_status` so the mkdir honours the per-step
    // timeout and owns a `GroupGuard`: an unbounded `ssh` here used to hang a
    // `--timeout`-bounded copy step forever.
    let status = run_command_status(mkdir, config.timeout, "remote mkdir")
        .await
        .map_err(|err| CopyFailure::transport(format!("failed to create remote dir: {err:#}")))?;
    if !status.success() {
        return Err(CopyFailure::transport(format!("remote mkdir for {dir} failed")));
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
        .await
        .map_err(|err| CopyFailure::transport(format!("scp could not start: {err:#}")))?
    {
        stream::PipedRun::Completed(status) => {
            if !status.success() {
                return Err(CopyFailure::transport(format!("scp exited with status {status}")));
            }
            Ok(())
        }
        stream::PipedRun::TimedOut => Err(CopyFailure::timeout("copy step timed out")),
        stream::PipedRun::PipeBroken => {
            Err(CopyFailure::transport("scp closed its input before the transfer finished"))
        }
    }
}
