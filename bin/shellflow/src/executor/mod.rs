//! The execution engine: runs local blocks, streams remote blocks over SSH,
//! and syncs files with rsync, with fan-out, timeouts, and dry-run/diff
//! semantics.
//!
//! Every child is spawned in its own process group and torn down through
//! [`terminate`], which escalates `SIGTERM` -> `SIGKILL`. Signalling only the
//! direct child would leave whatever tree a block spawned (`cargo` ->
//! `rustc`, `sudo` -> `systemctl`) running after Ctrl-C, so the whole group
//! is signalled; the `SIGKILL` fallback guarantees termination even when a
//! child traps or blocks `SIGTERM`. `kill_on_drop(true)` remains set as a
//! last-resort net for paths that drop a child without awaiting `terminate`.

mod cancel;
mod copy;
mod local;
mod process;
mod remote;
mod stream;

use std::{path::PathBuf, sync::Arc, time::Duration};

pub(crate) use cancel::Cancel;
pub(crate) use process::StepStats;
pub(crate) use remote::{RunError, RunOutcome, execute_plan};
use shellflow_core::ResolvedHost;
use tokio::sync::Mutex;

use crate::{
    cli::RunArgs,
    ui::{HostStatus, Ui},
};

/// Grace period between the polite `SIGTERM` and the final `SIGKILL`
/// (design §7.5).
pub(crate) const KILL_GRACE: Duration = Duration::from_secs(5);

/// Shared, async-safe UI handle.
pub(crate) type ArcUi = Arc<Mutex<Ui>>;

/// Shared, per-run cache of probed remote environments, keyed by ssh
/// destination so a multi-step playbook probes each host exactly once.
pub(crate) type ShellCache = Arc<Mutex<std::collections::HashMap<String, remote::RemoteEnv>>>;

/// Filter closure for diff-mode output (e.g. rsync itemize lines).
pub(crate) type DiffFilter = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Audit-log file handle shared across executor sub-modules.
pub(crate) type LogFile = Option<Arc<std::sync::Mutex<std::fs::File>>>;

/// Arguments for [`run_copy_step`] — groups the parameters that would
/// otherwise exceed clippy's limit.
#[derive(Clone)]
pub(crate) struct CopyStepArgs {
    pub ui: ArcUi,
    pub semaphore: Option<Arc<tokio::sync::Semaphore>>,
    pub run_state: Arc<Mutex<shellflow_core::RunState>>,
    pub shell_cache: ShellCache,
    pub log_file: LogFile,
    /// The cooperative cancellation signal.
    pub cancel: Cancel,
}

/// Arguments for [`run_local_block`] — groups the parameters that would
/// otherwise exceed clippy's limit.
pub(crate) struct LocalBlockArgs<'a> {
    pub ui: &'a ArcUi,
    pub run_state: &'a Arc<Mutex<shellflow_core::RunState>>,
    pub script: &'a str,
    pub env: &'a [shellflow_core::EnvEntry],
    pub config: StepConfig,
    pub capture: &'a [String],
    pub extra: &'a [(String, String)],
    pub log_file: &'a LogFile,
    /// The cooperative cancellation signal.
    pub cancel: Cancel,
}

/// Shared, monotonically-appended step progress (for interrupt summaries).
pub(crate) type Progress = Arc<Mutex<Vec<StepStats>>>;

/// Per-step execution settings threaded into host tasks.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StepConfig {
    /// No writes: syntax-check payloads and use `rsync --dry-run -i`.
    pub(crate) dry_run: bool,
    /// `--diff`: itemized output is filtered to change lines with markers.
    pub(crate) diff: bool,
    /// Syntax-check only.
    pub(crate) check: bool,
    /// Verbosity level (0-3).
    pub(crate) verbose: u8,
    /// Optional timeout in seconds.
    pub(crate) timeout: Option<u64>,
    /// Execute remote blocks/copies on the local machine (`--local`).
    pub(crate) local: bool,
    /// Reuse SSH connections within a run (ControlMaster).
    pub(crate) ssh_reuse: bool,
    /// Accept the scp fallback on a host without rsync, dropping the
    /// `--delete` / `--exclude` contract the copy step asked for.
    pub(crate) allow_unfiltered_copy: bool,
}

impl StepConfig {
    pub(crate) const fn new(run: &RunArgs, timeout: Option<u64>) -> Self {
        Self {
            dry_run: run.flags.dry_run || run.flags.diff,
            diff: run.flags.diff,
            check: run.flags.check,
            verbose: run.flags.verbose,
            timeout,
            local: run.flags.local,
            ssh_reuse: run.flags.ssh_reuse,
            allow_unfiltered_copy: run.flags.allow_unfiltered_copy,
        }
    }
}

/// The outcome of one host within a step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostOutcome {
    /// Completed successfully.
    Ok,
    /// Skipped because `@only_if` failed.
    Skipped,
    /// The command failed; carries the error classification.
    Failed(RunError),
    /// The step exceeded its timeout.
    TimedOut,
    /// The run was interrupted before the host finished.
    Cancelled,
}

/// Cache key for a host: `user@host[:port]`.
#[must_use]
pub(crate) fn shell_cache_key(host: &ResolvedHost) -> String {
    match host.spec.port {
        Some(port) => format!("{}:{port}", host.spec.dest()),
        None => host.spec.dest(),
    }
}

/// Convert a step outcome into per-host statuses for the UI.
pub(crate) fn outcome_to_statuses(
    outcome: &eyre::Result<Vec<(String, HostOutcome)>>,
) -> Vec<HostStatus> {
    match outcome {
        Ok(hosts) => hosts
            .iter()
            .map(|(alias, result)| HostStatus {
                alias: alias.clone(),
                outcome: match result {
                    HostOutcome::Ok => crate::ui::Outcome::Ok,
                    HostOutcome::Skipped => crate::ui::Outcome::Skipped,
                    HostOutcome::Failed(_) => crate::ui::Outcome::Failed,
                    HostOutcome::TimedOut => crate::ui::Outcome::TimedOut,
                    HostOutcome::Cancelled => crate::ui::Outcome::Cancelled,
                },
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Format a command's argv for display without exposing env values.
pub(crate) fn display_args(cmd: &tokio::process::Command) -> String {
    cmd.as_std()
        .get_args()
        .map(|arg| {
            let s = arg.to_string_lossy();
            if s.contains(' ') { format!("{s:?}") } else { s.into_owned() }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether an rsync stdout line is an `-i` itemized change entry (as opposed
/// to status prose like "sending incremental file list" / "sent N bytes").
///
/// rsync's itemize format is a fixed 11-column summary followed by a space and
/// the path (e.g. `>f+++++++++ path`, `*deleting   path`). We require that
/// shape rather than just a leading character, so normal command output that
/// happens to start with `>`, `<`, `*`, `.`, or `c` is never swallowed by
/// `--diff`.
pub(crate) fn is_rsync_itemize_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    if line.starts_with("*deleting") {
        return bytes.len() > "*deleting".len() && bytes["*deleting".len()] == b' ';
    }
    if bytes.len() < 12 {
        return false;
    }
    if bytes[10] != b' ' {
        return false;
    }
    bytes[..10].iter().all(|&b| {
        b.is_ascii_alphanumeric() ||
            b == b'.' ||
            b == b'*' ||
            b == b'<' ||
            b == b'>' ||
            b == b'c' ||
            b == b'+'
    })
}

/// Convert per-host failures into a step-level error, preferring the first
/// classified failure.
#[must_use]
pub(crate) fn step_error_if_failed(hosts: &[(String, HostOutcome)]) -> Option<RunError> {
    hosts.iter().find_map(|(_, outcome)| match outcome {
        HostOutcome::Failed(err) => Some(*err),
        HostOutcome::TimedOut => Some(RunError::Script),
        // A cancelled host is the consequence of the interrupt, not a
        // failure of the step: the run is already aborting.
        HostOutcome::Ok | HostOutcome::Skipped | HostOutcome::Cancelled => None,
    })
}

/// Acquires a fan-out slot, reporting a failure as a transport error for the
/// host (see [`acquire_fanout_slot`]).
macro_rules! fanout_slot {
    ($semaphore:expr, $log_file:expr, $host:expr) => {
        match super::acquire_fanout_slot($semaphore, $log_file).await {
            Ok(permit) => permit,
            Err(_) => {
                return ($host.alias.clone(), HostOutcome::Failed(RunError::Transport));
            }
        }
    };
}
pub(crate) use fanout_slot;

/// An unpredictable capture path per step: PID + nanosecond nonce. Combined
/// with `create_new` in the caller this defeats symlink pre-planting.
pub(crate) fn capture_file_path() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("shellflow-capture-{}-{nonce}.txt", std::process::id()))
}

/// Acquire one fan-out slot, or report why the host must fail.
///
/// A **closed** semaphore must fail the task, never silently run unthrottled:
/// `None` means "no limit", so treating a closed semaphore as `None` would
/// turn it into a full-speed fan-out — the opposite of `--parallel N`.
pub(crate) async fn acquire_fanout_slot(
    semaphore: &Option<Arc<tokio::sync::Semaphore>>,
    log_file: &LogFile,
) -> eyre::Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    let Some(semaphore) = semaphore else {
        return Ok(None);
    };
    let permit = Arc::clone(semaphore).acquire_owned().await;
    let permit = permit.map_err(|_| {
        crate::ui::warn("fan-out semaphore closed; refusing to exceed --parallel", log_file);
        eyre::eyre!("fan-out semaphore closed; refusing to exceed --parallel")
    })?;
    Ok(Some(permit))
}

/// Deletes an `@export` capture file on **every** exit path.
///
/// The file holds plaintext `NAME=VALUE` records for whatever the step
/// exported, so it must not outlive the step: a failed step (non-zero exit,
/// spawn error, or an unparsable capture) returns through `?`/`bail!` long
/// before any explicit cleanup would run. Cleanup is therefore attached to
/// the guard's lifetime rather than to the happy path, mirroring the
/// [`process::GroupGuard`] rationale for process teardown.
pub(crate) struct CaptureFile(PathBuf);

impl CaptureFile {
    /// Take ownership of an already-created capture file at `path`.
    pub(super) const fn new(path: PathBuf) -> Self {
        Self(path)
    }

    /// The path to hand to the child process via `SHELLFLOW_CAPTURE`.
    pub(super) fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for CaptureFile {
    fn drop(&mut self) {
        // Best-effort, but a failure to remove a plaintext file is worth
        // reporting: silently leaving it behind is exactly the leak this
        // guard exists to prevent.
        if let Err(err) = std::fs::remove_file(&self.0) &&
            err.kind() != std::io::ErrorKind::NotFound
        {
            crate::ui::warn(
                &format!("failed to remove export capture file {}: {err}", self.0.display()),
                &None,
            );
        }
    }
}
