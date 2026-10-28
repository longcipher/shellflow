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

mod assert_step;
mod build;
mod cancel;
mod copy;
mod error;
mod helper;
mod host;
mod image;
mod local;
#[cfg(feature = "muxy")]
pub(crate) mod muxy;
pub(crate) mod process;
mod release;
mod remote;
mod stream;
mod toolchain;
pub(crate) mod transport;

use std::{path::PathBuf, sync::Arc, time::Duration};

pub(crate) use cancel::Cancel;
pub(crate) use error::{RunError, RunOutcome};
pub(crate) use process::StepStats;
pub(crate) use remote::execute_plan;
use shellflow_core::ResolvedHost;
use tokio::sync::Mutex;
pub(crate) use transport::{StepClass, TransportPolicy, policy_from_cli};

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
/// Per-destination login environment, probed at most once per run.
///
/// The map holds a [`tokio::sync::OnceCell`] per destination rather than the
/// value itself: the *cell* is created under the map lock and the probe runs
/// outside it, so one slow (or unreachable) host no longer serialises every
/// other host's probe behind a single mutex while still honouring "probe each
/// destination once".
pub(crate) type ShellCache = Arc<
    Mutex<std::collections::HashMap<String, Arc<tokio::sync::OnceCell<Option<remote::RemoteEnv>>>>>,
>;

/// The native (muxy) transport state for one run.
///
/// **The feature fork lives here and nowhere else in the executors.** Every
/// step struct carries a `Native` unconditionally, so the *shape* of a step no
/// longer depends on the build — only whether the native transport exists.
/// That is what keeps `#[cfg(feature = "muxy")]` out of the dispatch: a step
/// that grows a new field does not also grow a cfg attribute (there were 31 of
/// them before this type existed).
///
/// Without the feature the type is empty, `transport::should_use_muxy` still
/// answers (`--transport muxy` fails closed at the CLI), and nothing reads the
/// fields that are not there.
#[cfg(feature = "muxy")]
#[derive(Clone)]
pub(crate) struct Native {
    /// Per-run connection state, one connection per host.
    pub(crate) run: muxy::MuxyRun,
    /// The 1-based plan index, naming the muxy payload file.
    pub(crate) step_no: usize,
}

/// Empty native-transport state for a build without the feature.
#[cfg(not(feature = "muxy"))]
#[derive(Clone, Default)]
pub(crate) struct Native;

impl Native {
    /// State for a new run: no host connected yet.
    #[cfg(feature = "muxy")]
    #[must_use]
    pub(crate) fn new() -> Self {
        Self { run: muxy::MuxyRun::new(), step_no: 0 }
    }

    /// State for a new run in a build without the native transport.
    #[cfg(not(feature = "muxy"))]
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// The same state, carrying the plan index of the step about to run.
    ///
    /// A plan index names the payload file, so it is per step, not per run;
    /// returning a copy keeps the run-wide handle immutable.
    #[must_use]
    pub(crate) fn at_step(&self, step_no: usize) -> Self {
        #[cfg(feature = "muxy")]
        {
            let mut next = self.clone();
            next.step_no = step_no;
            next
        }
        #[cfg(not(feature = "muxy"))]
        {
            let _ = step_no;
            self.clone()
        }
    }
}

/// Shell-quote one value for a command line that a remote shell will parse.
///
/// Single implementation on purpose: the copy path, the helper install, the
/// workdir teardown and the assertion payloads all interpolate paths into a
/// remote command, and a second hand-rolled `replace('\'', "'\\''")` is how a
/// path with an apostrophe turns into two commands.
pub(crate) fn quote(value: &str) -> String {
    shellflow_core::shell_quote_single(value)
}

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
    /// The managed staging directory, when the run declares one.
    pub workdir: Option<remote::WorkdirGuard>,
}

/// Arguments for [`run_local_block`] — groups the parameters that would
/// otherwise exceed clippy's limit.
pub(crate) struct LocalBlockArgs<'a> {
    pub ui: &'a ArcUi,
    pub run_state: &'a Arc<Mutex<shellflow_core::RunState>>,
    pub script: &'a str,
    pub env: &'a [shellflow_core::EnvEntry],
    pub config: StepConfig,
    pub capture: &'a [shellflow_core::ExportVar],
    pub extra: &'a [(String, String)],
    pub log_file: &'a LogFile,
    /// The masking threshold for a captured `@export` value.
    ///
    /// Every captured value joins the mask registry unless the playbook
    /// declared it `--public`; the threshold only decides *how* a value below
    /// it is redacted (see `capture_exports`).
    pub mask_min_len: usize,
    /// The cooperative cancellation signal.
    pub cancel: Cancel,
}

/// Shared, monotonically-appended step progress (for interrupt summaries).
pub(crate) type Progress = Arc<Mutex<Vec<StepStats>>>;

/// Per-step execution settings threaded into host tasks.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    not(feature = "muxy"),
    expect(dead_code, reason = "the ssh-only build ignores the muxy policy and sizing flags")
)]
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
    /// Which transport a command step takes to its host.
    pub(crate) transport: TransportPolicy,
    /// Leave a cancelled muxy session running (`--muxy-keep`).
    pub(crate) muxy_keep: bool,
    /// Muxy session width in columns.
    pub(crate) muxy_cols: u16,
    /// Muxy session height in rows.
    pub(crate) muxy_rows: u16,
}

impl StepConfig {
    pub(crate) fn new(run: &RunArgs, timeout: Option<u64>) -> Self {
        Self {
            dry_run: run.flags.dry_run || run.flags.diff,
            diff: run.flags.diff,
            check: run.flags.check,
            verbose: run.flags.verbose,
            timeout,
            local: run.flags.local,
            ssh_reuse: run.flags.ssh_reuse && !run.flags.no_ssh_reuse,
            allow_unfiltered_copy: run.flags.allow_unfiltered_copy,
            transport: policy_from_cli(run.effective_transport()),
            muxy_keep: run.flags.muxy_keep,
            muxy_cols: run.flags.muxy_cols.unwrap_or(200),
            muxy_rows: run.flags.muxy_rows.unwrap_or(50),
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

/// Classify one target-side helper exit code.
///
/// The helper protocol is a wire contract (`crate::exit::helper`), and the
/// `@service`/`@install`/`@backup` fan-out and the `@wait_active` path each
/// used to build their own ladder — which drifted: a helper timeout was a
/// script failure on one path and a timeout on the other. Design §6 keeps the
/// two apart on purpose (a slow host is a retry, a failed deploy is a
/// rollback), so the mapping is defined here once and both callers use it.
#[must_use]
pub(crate) const fn classify_helper_exit(code: i32) -> HostOutcome {
    match code {
        crate::exit::helper::OK => HostOutcome::Ok,
        // ssh exits 255 when the connection itself failed: a transport
        // failure, not a failed operation.
        255 => HostOutcome::Failed(RunError::Transport),
        crate::exit::helper::TIMEOUT => HostOutcome::TimedOut,
        _ => HostOutcome::Failed(RunError::Script),
    }
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

/// How many columns rsync's `%i` itemize summary occupies: `YXcstpoguax`.
///
/// The unit tests and the mock `rsync` used ten, so the predicate accepted a
/// shape rsync never prints and rejected the one it does — `--diff` filtered
/// out every real change on a live host.
const ITEMIZE_COLUMNS: usize = 11;

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
    if let Some(rest) = line.strip_prefix("*deleting") {
        // `*deleting` is shorter than the summary field; rsync pads it to the
        // same path column, so the line is still "prefix, blanks, path".
        return rest.starts_with(' ') && rest.chars().any(|c| !c.is_whitespace());
    }
    // The summary, one space, and at least one path byte.
    if bytes.len() < ITEMIZE_COLUMNS + 2 || bytes[ITEMIZE_COLUMNS] != b' ' {
        return false;
    }
    bytes[..ITEMIZE_COLUMNS].iter().all(|&b| is_itemize_summary_byte(b))
}

/// The bytes an itemize summary column may hold: the `YXcstpoguax` alphabet.
///
/// A set membership test rather than a chain of `||`: the chain made every
/// column a separate decision point, and `c` was already covered by
/// `is_ascii_alphanumeric`.
const fn is_itemize_summary_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'*' | b'<' | b'>' | b'+')
}

/// Convert per-host failures into a step-level error, preferring the first
/// classified failure.
#[must_use]
pub(crate) fn step_error_if_failed(hosts: &[(String, HostOutcome)]) -> Option<RunError> {
    hosts.iter().find_map(|(_, outcome)| match outcome {
        HostOutcome::Failed(err) => Some(*err),
        // A timeout is not a script failure: the step did not decide anything,
        // the budget ran out. Keeping the two apart is what lets a retry
        // policy distinguish "the box was slow" from "the deploy broke".
        HostOutcome::TimedOut => Some(RunError::Timeout),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_helper_ladder_separates_a_timeout_from_a_failure() {
        // The `@service`/`@install`/`@backup` fan-out and the `@wait_active`
        // path share this mapping. They used to build it separately and
        // disagreed about exit 4: one called it a script failure (exit 4 of
        // the CLI, roll back) and the other a timeout (exit 5, retry).
        assert_eq!(classify_helper_exit(0), HostOutcome::Ok);
        assert_eq!(classify_helper_exit(255), HostOutcome::Failed(RunError::Transport));
        assert_eq!(classify_helper_exit(crate::exit::helper::TIMEOUT), HostOutcome::TimedOut);
        assert_eq!(
            classify_helper_exit(crate::exit::helper::FAILED),
            HostOutcome::Failed(RunError::Script)
        );
        assert_eq!(
            classify_helper_exit(crate::exit::helper::USAGE),
            HostOutcome::Failed(RunError::Script)
        );
    }

    #[test]
    fn a_host_cache_key_is_the_destination_and_its_port() {
        // The key decides connection sharing: two hosts that hash the same
        // would silently share one ssh master, and a host whose port is
        // dropped would connect to the wrong service.
        let with_port = ResolvedHost {
            alias: "web1".to_string(),
            spec: shellflow_core::SshSpec::parse("deploy@10.0.0.1:2222").expect("spec"),
        };
        let without_port = ResolvedHost {
            alias: "web1".to_string(),
            spec: shellflow_core::SshSpec::parse("deploy@10.0.0.1").expect("spec"),
        };
        assert_eq!(shell_cache_key(&with_port), "deploy@10.0.0.1:2222");
        assert_eq!(shell_cache_key(&without_port), "deploy@10.0.0.1");
    }

    #[test]
    fn an_itemized_change_is_told_apart_from_status_prose() {
        // `--diff` filters rsync output down to the itemized entries: a
        // status line swallowed by the filter hides the transfer summary, and
        // an itemized line dropped by it hides the actual change.
        // `%i` is exactly 11 columns: `>f` plus nine `+` for a new file.
        for line in [
            ">f+++++++++ /etc/app/config.toml",
            "*deleting   /tmp/old",
            ".d..t...... app",
            "cd+++++++++ x", // 11 columns, one path byte: the length boundary
            "<f+++++++++ x", // each summary byte the alphabet allows, on its own
            "*f+++++++++ x",
            ".f+++++++++ x",
            ">f.st...... x",
        ] {
            assert!(is_rsync_itemize_line(line), "{line} is itemized");
        }
        for line in [
            "sending incremental file list",
            "sent 1,234 bytes  received 56 bytes",
            ">f+++++++++",       // the summary alone, no path
            ">f+++++++++x/path", // column 11 is not a space
            ">f++++++++:/path",  // a non-alphanumeric column
            "deleting /tmp/old",
            "*deleting",
            "*deleting   ",   // padding with no path is not an entry
            "*deletingx/foo", // the prefix must be followed by a blank
            "!f+++++++++ x",  // a byte outside the alphabet
            "",
        ] {
            assert!(!is_rsync_itemize_line(line), "{line:?} is not itemized");
        }
    }

    #[test]
    fn a_displayed_arg_is_quoted_only_when_it_contains_a_space() {
        // `-v` shows this string; a path with a space must not read as two
        // arguments, and a plain one must not gain quotes the operator did not
        // type.
        let mut cmd = tokio::process::Command::new("ssh");
        cmd.arg("host").arg("/srv/my app/config.toml").arg("-p").arg("22");
        let rendered = display_args(&cmd);
        assert_eq!(rendered, "host \"/srv/my app/config.toml\" -p 22");
    }

    #[test]
    fn a_helper_timeout_reaches_the_timeout_exit_code() {
        // End to end through the classifier the run uses to pick a code: a
        // slow host must be retryable (5), not indistinguishable from a
        // broken deploy (4).
        let outcome = classify_helper_exit(crate::exit::helper::TIMEOUT);
        assert_eq!(step_error_if_failed(&[("web".to_string(), outcome)]), Some(RunError::Timeout));
        assert_eq!(RunError::Timeout.code().code(), 5);
    }
}
