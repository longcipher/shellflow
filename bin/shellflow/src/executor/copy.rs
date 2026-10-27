//! Copy step execution: rsync with scp fallback, path normalization, and
//! per-host fan-out.

use std::sync::Arc;

use eyre::{Context, Result, bail};
use shellflow_core::{CopyStep, ResolvedHost};
use tokio::{process::Command, task::JoinSet};

use super::{
    ArcUi, CopyStepArgs, DiffFilter, HostOutcome, LogFile, RunError, StepConfig, fanout_slot,
    process::{GroupGuard, isolate},
    remote::resolve_remote_env,
    stream,
};

#[derive(Clone, Copy)]
pub(super) struct CopyOpts<'a> {
    pub(super) delete: bool,
    pub(super) excludes: &'a [String],
}

/// Split a step timeout across the two sequential scp phases (mkdir + scp).
///
/// Each phase runs sequentially, so giving each the full budget doubles the
/// effective step timeout. The budget is split: mkdir gets half (at least 1s
/// when a timeout is set), scp gets the remainder, so the sum never exceeds
/// the step budget.
fn split_timeout(timeout: Option<u64>) -> (Option<u64>, Option<u64>) {
    match timeout {
        None => (None, None),
        Some(secs) => {
            let first = (secs / 2).max(1).min(secs);
            let second = secs.saturating_sub(first).max(1);
            (Some(first), Some(second))
        }
    }
}

/// How a copy failed, kept separate from the message so nothing has to
/// string-match to pick the exit code (design §6 classifies 3 vs 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyFailureKind {
    /// The transfer exceeded its per-step timeout.
    Timeout,
    /// The transport failed (rsync/scp/ssh could not complete).
    Transport,
    /// The run was interrupted before the transfer finished.
    Cancelled,
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

    fn cancelled(detail: impl Into<String>) -> Self {
        Self { kind: CopyFailureKind::Cancelled, detail: detail.into() }
    }
}

/// Map a transfer result onto the per-host outcome.
fn failure_outcome(alias: &str, failure: CopyFailure) -> (String, HostOutcome) {
    match failure.kind {
        CopyFailureKind::Timeout => (alias.to_string(), HostOutcome::TimedOut),
        CopyFailureKind::Transport => (alias.to_string(), HostOutcome::Failed(RunError::Transport)),
        CopyFailureKind::Cancelled => (alias.to_string(), HostOutcome::Cancelled),
    }
}

pub(crate) async fn run_copy_step(
    args: &CopyStepArgs,
    copy: &CopyStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
) -> (Option<super::RunError>, eyre::Result<Vec<(String, HostOutcome)>>) {
    let entries = {
        let state = args.run_state.lock().await;
        let interpolated = copy.entries.iter().map(|entry| {
            shellflow_core::interpolate(&entry.src, &state).and_then(|src| {
                shellflow_core::interpolate(&entry.dst, &state).map(|dst| (src, dst))
            })
        });
        let mut out = Vec::new();
        for pair in interpolated {
            match pair {
                Ok(pair) => out.push(pair),
                Err(err) => {
                    drop(state);
                    if config.dry_run || config.check {
                        crate::ui::warn(
                            &format!("{err} — copy skipped (no run state in dry-run/check)"),
                            &args.log_file,
                        );
                        return (None, Ok(Vec::new()));
                    }
                    // An unresolved `$VAR` in a copy path is a plan error: design
                    // §6 assigns it to exit 1, not to the script-failure exit 4.
                    crate::ui::step_failed(0, &err.to_string(), &args.log_file);
                    return (Some(super::RunError::Plan), Ok(Vec::new()));
                }
            }
        }
        out
    };

    if config.local {
        let mut outcomes = Vec::new();
        for (src, dst) in &entries {
            let outcome = run_copy_step_local(LocalCopyArgs {
                ui: &args.ui,
                src,
                dst,
                delete: copy.delete,
                excludes: &copy.excludes,
                config,
                log_file: &args.log_file,
                cancel: &args.cancel,
            })
            .await;
            if let Err(err) = outcome {
                return (Some(super::RunError::Script), Err(err));
            }
            outcomes.extend(outcome.unwrap_or_default());
        }
        return (None, Ok(outcomes));
    }

    if config.check {
        crate::ui::note("  syntax check: copy step (no execution)", &args.log_file);
        return (None, Ok(Vec::new()));
    }

    // Files that keep their name and land in the same directory travel in
    // one rsync invocation: five templates to one directory cost one round
    // trip, not five.
    let transfers = group_transfers(&entries).await;

    if config.dry_run || config.verbose >= 2 {
        for transfer in &transfers {
            args.ui.lock().await.masked_note(&format!(
                "  rsync {} -> {} ({} hosts)",
                transfer.srcs.join(" "),
                transfer.dst,
                hosts.len()
            ));
        }
    }

    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(&args.ui);
        let semaphore = args.semaphore.clone();
        let transfers = transfers.clone();
        let delete = copy.delete;
        let excludes = copy.excludes.clone();
        let shell_cache = Arc::clone(&args.shell_cache);
        let log_file = args.log_file.clone();
        let cancel = args.cancel.clone();
        let workdir = args.workdir.clone();
        tasks.spawn(async move {
            // Never run unthrottled when the semaphore is closed.
            let _permit = fanout_slot!(&semaphore, &log_file, host);
            let has_rsync = resolve_remote_env(&host, &shell_cache, &cancel).await.has_rsync;
            let opts = CopyOpts { delete, excludes: &excludes };
            for transfer in &transfers {
                let host_args = RsyncHostArgs {
                    ui: Arc::clone(&ui),
                    host: &host,
                    srcs: &transfer.srcs,
                    dst: &transfer.dst,
                    opts,
                    config,
                    has_rsync,
                    log_file: &log_file,
                    cancel: cancel.clone(),
                };
                let (alias, outcome) = run_rsync_host(host_args).await;
                if !matches!(outcome, HostOutcome::Ok) {
                    return (alias, outcome);
                }
            }
            // A copy into the managed staging directory makes this host
            // responsible for removing it when the run ends.
            if let Some(guard) = &workdir &&
                transfers.iter().any(|transfer| guard.workdir.contains(&transfer.dst))
            {
                guard.touch(&host.alias).await;
            }
            (host.alias.clone(), HostOutcome::Ok)
        });
    }

    (None, Ok(stream::collect_hosts(&args.ui, &args.log_file, tasks).await))
}

/// A group of files that travel in one rsync invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Transfer {
    /// The local sources.
    srcs: Vec<String>,
    /// The remote destination: the exact path for a single source, the
    /// directory (with a trailing slash) for several.
    dst: String,
}

/// Group the entries into transfers.
///
/// A file that keeps its name and lands in the same directory as another
/// such file travels with it: rsync copies several sources into one
/// destination directory. A file that is *renamed*, and a directory source
/// (whose contents are copied rather than the directory itself), each need
/// their own invocation.
async fn group_transfers(entries: &[(String, String)]) -> Vec<Transfer> {
    let mut transfers: Vec<Transfer> = Vec::new();
    // The index of the group per destination directory.
    let mut by_dir: Vec<(String, usize)> = Vec::new();
    for (src, dst) in entries {
        let is_dir_src = tokio::fs::metadata(src).await.is_ok_and(|meta| meta.is_dir());
        let dest = Destination::parse(dst);
        let base_src = src.rsplit('/').next().unwrap_or(src);
        // A directory source copies its *contents*, and a file that is
        // renamed lands under a name of its own: neither can share a
        // transfer with another file.
        let keeps_its_name = match &dest {
            Destination::Dir { .. } => !is_dir_src,
            Destination::File { base, .. } => base_src == base,
        };
        if is_dir_src || !keeps_its_name {
            transfers.push(Transfer { srcs: vec![src.clone()], dst: dst.clone() });
            continue;
        }
        let dir = dest.dir().to_string();
        if let Some(pos) = by_dir.iter().position(|(candidate, _)| *candidate == dir) {
            let idx = by_dir[pos].1;
            transfers[idx].srcs.push(src.clone());
            transfers[idx].dst = format!("{dir}/");
        } else {
            by_dir.push((dir, transfers.len()));
            transfers.push(Transfer { srcs: vec![src.clone()], dst: dst.clone() });
        }
    }
    transfers
}

/// A copy destination: either a file path or a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Destination {
    /// A file path: the file is renamed to it.
    File {
        /// The directory that holds it.
        dir: String,
        /// Its last component.
        base: String,
    },
    /// A directory (the path ends with `/`): the file keeps its name.
    Dir {
        /// The directory itself.
        dir: String,
    },
}

impl Destination {
    /// Parse a destination path.
    fn parse(dst: &str) -> Self {
        if dst.ends_with('/') {
            let trimmed = dst.trim_end_matches('/');
            return Self::Dir {
                dir: if trimmed.is_empty() { "/".to_string() } else { trimmed.to_string() },
            };
        }
        match dst.rsplit_once('/') {
            Some((dir, base)) if !base.is_empty() => {
                Self::File { dir: dir.to_string(), base: base.to_string() }
            }
            _ => Self::File { dir: "/".to_string(), base: dst.to_string() },
        }
    }

    /// The directory the destination lives in.
    fn dir(&self) -> &str {
        match self {
            Self::File { dir, .. } | Self::Dir { dir } => dir,
        }
    }
}

/// The parameters of a local (`--local`) copy step.
struct LocalCopyArgs<'a> {
    ui: &'a ArcUi,
    src: &'a str,
    dst: &'a str,
    delete: bool,
    excludes: &'a [String],
    config: StepConfig,
    log_file: &'a LogFile,
    cancel: &'a super::Cancel,
}

async fn run_copy_step_local(args: LocalCopyArgs<'_>) -> Result<Vec<(String, HostOutcome)>> {
    let LocalCopyArgs { ui, src, dst, delete, excludes, config, log_file, cancel } = args;
    if config.check {
        crate::ui::note("  syntax check: copy step (no execution)", log_file);
        return Ok(vec![("localhost".to_string(), HostOutcome::Ok)]);
    }
    if config.dry_run || config.verbose >= 2 {
        ui.lock().await.masked_note(&format!("  local copy {src} -> {dst}"));
    }
    if config.dry_run {
        // `cp` has no dry-run mode either: previewing the copy would mean
        // performing it, and a dry run must not change anything (§8.2).
        crate::ui::note(
            "  dry run: the local copy is not previewed (nothing was copied)",
            log_file,
        );
        return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
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
        return run_local_copy_delete(src, dst, config, cancel, log_file).await;
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
    let status = run_command_status(cmd, config.timeout, "local copy", cancel, log_file).await?;
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
    cancel: &super::Cancel,
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
    let status = run_command_status(cmd, config.timeout, "local copy", cancel, log_file).await?;
    if !status.success() {
        // The old destination is untouched; drop the half-built staging tree.
        remove_path(&staging).await?;
        bail!("local copy exited with status {status} (destination left unchanged)");
    }

    // The replacement is complete: only now is it safe to drop the old tree.
    // A failed removal is *terminal*: continuing to the rename would fail
    // anyway (the destination is still present), destroy the whole staging
    // tree, and report the misleading "failed to move staged copy" instead
    // of the real cause.
    if let Err(err) = remove_path(dst_path).await {
        remove_path(&staging).await?;
        bail!("could not remove old destination {dst}: {err}");
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
    cancel: &super::Cancel,
    log_file: &LogFile,
) -> Result<std::process::ExitStatus> {
    isolate(&mut cmd);
    cmd.kill_on_drop(true);
    // Both branches spawn explicitly so every path owns a `GroupGuard`; the
    // previous `cmd.status()` fallback had none, which let a `cp` descendant
    // outlive an aborted run.
    let mut child = cmd.spawn().wrap_err(format!("failed to run {label}"))?;
    let mut guard = GroupGuard::new(&child);
    let mut cancel = cancel.clone();
    let status = match super::process::wait_child(&mut child, timeout, &mut cancel).await {
        super::process::ChildOutcome::Finished(Ok(status)) => status,
        super::process::ChildOutcome::Finished(Err(err)) => {
            super::process::terminate(&mut child).await;
            guard.disarm();
            return Err(err).wrap_err(format!("failed to run {label}"));
        }
        super::process::ChildOutcome::TimedOut => {
            crate::ui::warn(&format!("{label} timed out — killed"), log_file);
            super::process::terminate(&mut child).await;
            guard.disarm();
            bail!("{label} timed out");
        }
        super::process::ChildOutcome::Cancelled => {
            // The run was interrupted: tear the group down so no descendant
            // survives the abort.
            super::process::terminate(&mut child).await;
            guard.disarm();
            bail!("{label} cancelled");
        }
    };
    guard.disarm();
    Ok(status)
}

struct RsyncHostArgs<'a> {
    ui: ArcUi,
    host: &'a ResolvedHost,
    srcs: &'a [String],
    dst: &'a str,
    opts: CopyOpts<'a>,
    config: StepConfig,
    has_rsync: bool,
    log_file: &'a LogFile,
    cancel: super::Cancel,
}

async fn run_rsync_host(args: RsyncHostArgs<'_>) -> (String, HostOutcome) {
    let RsyncHostArgs { ui, host, srcs, dst, opts, config, has_rsync, log_file, cancel } = args;
    // Never a bare `ssh`: a transport without BatchMode can stop at a
    // password or host-key prompt in the middle of an unattended deploy. The
    // string comes from the one policy builder, so `--no-ssh-reuse` and the
    // connect bound reach the transfer too.
    let remote_shell = super::transport::rsync_transport(
        super::transport::SshPolicy::step(config.ssh_reuse, false),
        &host.spec,
    );

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
    // The scp fallback cannot mirror deletions or filter files. Performing a
    // materially different transfer than the playbook asked for is worse than
    // failing: an excluded secret would land on the target and stale files
    // would survive, while the step still reported success. Fail closed
    // unless the operator explicitly accepted the downgrade.
    if !has_rsync && (opts.delete || !opts.excludes.is_empty()) {
        let what = if opts.delete { "`--delete`" } else { "`--exclude`" };
        if !config.allow_unfiltered_copy {
            crate::ui::warn(
                &format!(
                    "[{}] {what} cannot be honoured: the remote has no rsync, so the scp \
                     fallback cannot filter files or mirror deletions. Re-run with \
                     --allow-unfiltered-copy to accept the downgrade, or install rsync on \
                     the target.",
                    host.alias
                ),
                log_file,
            );
            return (host.alias.clone(), HostOutcome::Failed(super::RunError::Config));
        }
        crate::ui::warn(
            &format!(
                "[{}] {what} ignored: remote has no rsync, so the scp fallback cannot mirror \
                 deletions or filter files (accepted via --allow-unfiltered-copy)",
                host.alias
            ),
            log_file,
        );
    }

    let outcome = if has_rsync {
        let transfer = RsyncTransferArgs {
            ui: ui.clone(),
            host,
            srcs,
            dst,
            opts,
            remote_shell: &remote_shell,
            config,
            log_file,
            cancel: cancel.clone(),
        };
        run_rsync_transfer(transfer).await
    } else if config.dry_run {
        // `scp` has no dry-run mode: previewing this transfer would mean
        // performing it. A dry run must not change anything (design §8.2),
        // so the step is skipped and the gap is reported — a silent write
        // to the target would make `--dry-run` the most dangerous flag in
        // the tool.
        crate::ui::warn(
            &format!(
                "[{}] the remote has no rsync, so the copy cannot be previewed without \
                 writing to it — skipped (nothing was transferred)",
                host.alias
            ),
            log_file,
        );
        return (host.alias.clone(), HostOutcome::Skipped);
    } else {
        run_scp_transfer(ui.clone(), host, srcs, dst, config, log_file, cancel.clone()).await
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
///
/// Several sources travel as they are: the grouping only puts files that
/// keep their name into one transfer, and a directory source always travels
/// alone.
async fn normalize_copy_paths(srcs: &[String], dst: &str) -> (Vec<String>, String) {
    if srcs.len() == 1 {
        let src = &srcs[0];
        if tokio::fs::metadata(src).await.is_ok_and(|meta| meta.is_dir()) {
            return (
                vec![format!("{}/", src.trim_end_matches('/'))],
                format!("{}/", dst.trim_end_matches('/')),
            );
        }
    }
    (srcs.to_vec(), dst.to_string())
}

struct RsyncTransferArgs<'a> {
    ui: ArcUi,
    host: &'a ResolvedHost,
    srcs: &'a [String],
    dst: &'a str,
    opts: CopyOpts<'a>,
    remote_shell: &'a str,
    config: StepConfig,
    log_file: &'a LogFile,
    cancel: super::Cancel,
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
    let (srcs, dst) = normalize_copy_paths(args.srcs, args.dst).await;
    let dir = if dst.ends_with('/') {
        dst.as_str()
    } else {
        match dst.rsplit_once('/') {
            Some((dir, file)) if !file.is_empty() && !dir.is_empty() => dir,
            _ => dst.as_str(),
        }
    };
    // The remote shell parses `--rsync-path` verbatim, so the directory goes
    // through the one quoting helper instead of a hand-rolled `'\''` swap.
    let mkdir_rsync = format!("mkdir -p -- {} && rsync", super::quote(dir));
    cmd.args(["--rsync-path", &mkdir_rsync, "-e", args.remote_shell]);
    let dest = format!("{}:{dst}", args.host.spec.dest());
    // Several sources land in one destination directory; rsync keeps each
    // source's own name there.
    for src in &srcs {
        cmd.arg(src);
    }
    cmd.arg(&dest);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());
    cmd.kill_on_drop(true);

    if args.config.verbose >= 2 {
        args.ui.lock().await.masked_note(&format!(
            "  [{}] rsync {}",
            args.host.alias,
            super::display_args(&cmd)
        ));
    }

    let diff_filter: Option<DiffFilter> = args
        .config
        .diff
        .then(|| Arc::new(|line: &str| super::is_rsync_itemize_line(line)) as DiffFilter);
    let piped = stream::PipedArgs {
        ui: &args.ui,
        host: &args.host.alias,
        payload: None,
        timeout: args.config.timeout,
        diff_filter,
        log_file: args.log_file,
        cancel: args.cancel.clone(),
        quiet: false,
        collector: None,
    };
    match stream::run_piped_child(piped, cmd)
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
        stream::PipedRun::Cancelled => Err(CopyFailure::cancelled("copy step cancelled")),
    }
}

/// Split an scp-fallback destination into the directory to `mkdir -p` and
/// whether the destination itself is a directory.
///
/// A directory source always lands *in* a directory; a file source may name
/// a file, in which case the destination is used verbatim. A bare filename
/// (`app.tar.gz`) has no parent directory — `mkdir -p .` is a no-op — and
/// `mkdir`-ing the filename itself would create a *directory* by that name
/// and nest the file inside it.
fn scp_remote_dir(dst: &str, is_dir_src: bool) -> (String, bool) {
    if is_dir_src || dst.ends_with('/') {
        let trimmed = dst.trim_end_matches('/');
        // `dst = "/"` trims to "": the destination is the filesystem root.
        let dir = if trimmed.is_empty() { "/" } else { trimmed };
        return (dir.to_string(), true);
    }
    match dst.rsplit_once('/') {
        Some((dir, file)) if !file.is_empty() && !dir.is_empty() => (dir.to_string(), false),
        // A leading `/` with an empty parent (e.g. `/app.tar.gz`): the
        // parent is the filesystem root.
        Some((dir, file)) if !file.is_empty() && dir.is_empty() => ("/".to_string(), false),
        // No `/` at all: a bare filename in the remote home directory.
        _ => (".".to_string(), false),
    }
}

async fn run_scp_transfer(
    ui: ArcUi,
    host: &ResolvedHost,
    srcs: &[String],
    dst: &str,
    config: StepConfig,
    log_file: &LogFile,
    cancel: super::Cancel,
) -> std::result::Result<(), CopyFailure> {
    if config.verbose >= 2 {
        ui.lock().await.masked_note(&format!(
            "  [{}] scp fallback: {} -> {dst}",
            host.alias,
            srcs.join(" ")
        ));
    }

    let first = srcs.first().map_or_default(String::as_str);
    let is_dir_src = tokio::fs::metadata(first).await.is_ok_and(|meta| meta.is_dir());
    // A directory source always lands *in* a directory. A file source may
    // name a file: the destination is then used verbatim, so the artifact
    // keeps the name the playbook asked for. Copying into the parent
    // directory instead would silently rename `./out` to `/srv/out` when the
    // playbook said `/srv/app.tar.gz` — a materially different transfer,
    // reported as a success.
    let (dir, dst_is_dir) = scp_remote_dir(dst, is_dir_src);
    // Several sources land in the destination directory; each keeps its own
    // name. A single directory source copies its *contents*.
    let scp_srcs: Vec<String> =
        if srcs.len() == 1 && is_dir_src { vec![format!("{first}/.")] } else { srcs.to_vec() };

    let mut mkdir = Command::from(super::transport::ssh_command(
        super::transport::SshPolicy::step(config.ssh_reuse, false),
        &host.spec,
    ));
    mkdir.arg(format!("mkdir -p -- {}", super::quote(&dir)));
    mkdir
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    mkdir.kill_on_drop(true);
    // The step budget covers both phases: mkdir gets half, scp gets the rest.
    // Running each with the full timeout doubled the effective budget.
    let (mkdir_timeout, scp_timeout) = split_timeout(config.timeout);
    // Routed through `run_command_status` so the mkdir honours the per-step
    // timeout and owns a `GroupGuard`: an unbounded `ssh` here used to hang a
    // `--timeout`-bounded copy step forever.
    let status = run_command_status(mkdir, mkdir_timeout, "remote mkdir", &cancel, log_file)
        .await
        .map_err(|err| CopyFailure::transport(format!("failed to create remote dir: {err:#}")))?;
    if !status.success() {
        return Err(CopyFailure::transport(format!("remote mkdir for {dir} failed")));
    }

    let dest = if dst_is_dir {
        format!("{}:{dir}/", host.spec.dest())
    } else {
        format!("{}:{dst}", host.spec.dest())
    };
    let mut scp = Command::new("scp");
    scp.args(["-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]);
    if let Some(port) = host.spec.port {
        scp.args(["-P", &port.to_string()]);
    }
    if is_dir_src {
        scp.arg("-r");
    }
    for src in &scp_srcs {
        scp.arg(src);
    }
    scp.arg(&dest);
    scp.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());
    scp.kill_on_drop(true);
    isolate(&mut scp);

    if config.verbose >= 2 {
        ui.lock().await.masked_note(&format!(
            "  [{}] scp {}",
            host.alias,
            super::display_args(&scp)
        ));
    }

    let piped = stream::PipedArgs {
        ui: &ui,
        host: &host.alias,
        payload: None,
        timeout: scp_timeout,
        diff_filter: None,
        log_file,
        cancel: cancel.clone(),
        quiet: false,
        collector: None,
    };
    match stream::run_piped_child(piped, scp)
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
        stream::PipedRun::Cancelled => Err(CopyFailure::cancelled("copy step cancelled")),
    }
}

#[cfg(test)]
mod tests {
    use super::{Destination, group_transfers, scp_remote_dir};

    #[test]
    fn file_destinations_keep_their_parent_dir() {
        assert_eq!(scp_remote_dir("/srv/app.tar.gz", false), ("/srv".to_string(), false));
        assert_eq!(scp_remote_dir("/app.tar.gz", false), ("/".to_string(), false));
    }

    #[test]
    fn bare_filenames_have_no_parent_to_create() {
        // `mkdir -p 'app.tar.gz'` would create a *directory* by that name
        // and nest the file inside it; `mkdir -p .` is a no-op and the
        // file is transferred verbatim.
        assert_eq!(scp_remote_dir("app.tar.gz", false), (".".to_string(), false));
    }

    /// Run a future to completion on a throwaway runtime.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    }

    #[test]
    fn files_that_keep_their_name_share_one_transfer() {
        let entries = vec![
            ("a/one.toml".to_string(), "/srv/cfg/one.toml".to_string()),
            ("a/two.toml".to_string(), "/srv/cfg/two.toml".to_string()),
        ];
        let transfers = block_on(group_transfers(&entries));
        assert_eq!(transfers.len(), 1, "{transfers:?}");
        assert_eq!(transfers[0].srcs.len(), 2);
        assert_eq!(transfers[0].dst, "/srv/cfg/");
    }

    #[test]
    fn a_renamed_file_travels_alone() {
        let entries = vec![
            ("a/one.toml".to_string(), "/srv/cfg/one.toml".to_string()),
            ("a/two.toml".to_string(), "/srv/cfg/renamed.toml".to_string()),
        ];
        let transfers = block_on(group_transfers(&entries));
        assert_eq!(transfers.len(), 2, "{transfers:?}");
        assert_eq!(transfers[1].dst, "/srv/cfg/renamed.toml");
    }

    #[test]
    fn files_for_different_directories_do_not_share_a_transfer() {
        let entries = vec![
            ("a/one.toml".to_string(), "/srv/a/one.toml".to_string()),
            ("b/two.toml".to_string(), "/srv/b/two.toml".to_string()),
        ];
        let transfers = block_on(group_transfers(&entries));
        assert_eq!(transfers.len(), 2, "{transfers:?}");
    }

    #[test]
    fn a_destination_is_split_into_its_directory_and_its_name() {
        assert_eq!(
            Destination::parse("/srv/cfg/x.toml"),
            Destination::File { dir: "/srv/cfg".to_string(), base: "x.toml".to_string() }
        );
        assert_eq!(
            Destination::parse("/srv/cfg/"),
            Destination::Dir { dir: "/srv/cfg".to_string() }
        );
        assert_eq!(
            Destination::parse("x.toml"),
            Destination::File { dir: "/".to_string(), base: "x.toml".to_string() }
        );
    }

    #[test]
    fn directory_destinations_land_inside() {
        assert_eq!(scp_remote_dir("/srv/app/", false), ("/srv/app".to_string(), true));
        assert_eq!(scp_remote_dir("/srv/app", true), ("/srv/app".to_string(), true));
        assert_eq!(scp_remote_dir("/", true), ("/".to_string(), true));
        assert_eq!(scp_remote_dir("/", false), ("/".to_string(), true));
    }
}
