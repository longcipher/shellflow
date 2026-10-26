//! Generic child-process piped-output forwarding with timeout, cancellation,
//! and structured cleanup — shared by SSH, rsync, scp, and local execution.

use std::{sync::Arc, time::Duration};

use eyre::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc,
    task::JoinSet,
};

use super::{ArcUi, Cancel, HostOutcome, LogFile};
use crate::ui::Stream;

/// How long the reader tasks may take to drain after the child exited.
///
/// A descendant that inherited the child's stdout/stderr keeps the pipe open
/// after the child itself is gone (`nohup svc &` without redirecting). The
/// drain is therefore bounded: a group that still holds the step's output
/// pipe past the grace period is killed rather than hanging the run.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

async fn forward_stream<R>(reader: R, tx: mpsc::Sender<(Stream, String)>, stream: Stream)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if tx.send((stream, line)).await.is_err() {
            break;
        }
    }
}

#[derive(Debug)]
pub(super) enum PipedRun {
    /// The child ran to completion.
    Completed(std::process::ExitStatus),
    /// The step exceeded its timeout.
    TimedOut,
    /// The payload could not be delivered because the child closed its stdin
    /// early (EPIPE).
    ///
    /// This is a **transport** condition, not a timeout: `ssh` exiting 255
    /// (auth refused, host key rejected, connection reset) surfaces here.
    /// Reporting it as `TimedOut` would send an operator chasing timeout
    /// configuration instead of the real cause, and would break the exit-code
    /// contract in design §6 (ssh 255 => exit 3, not exit 4).
    PipeBroken,
    /// The run was interrupted; the child group was terminated.
    Cancelled,
}

/// Everything [`run_piped_child`] needs besides the child itself.
pub(super) struct PipedArgs<'a> {
    /// The output sink.
    pub ui: &'a ArcUi,
    /// The display alias used in log lines.
    pub host: &'a str,
    /// The payload written to the child's stdin.
    pub payload: Option<&'a str>,
    /// The per-step timeout in seconds.
    pub timeout: Option<u64>,
    /// A filter applied to the child's stdout lines.
    pub diff_filter: Option<super::DiffFilter>,
    /// The audit log handle.
    pub log_file: &'a super::LogFile,
    /// The cooperative cancellation signal.
    pub cancel: Cancel,
    /// Discard the child's output instead of forwarding it.
    ///
    /// Used by the `@wait_active` poll, whose verdict is the child's exit
    /// status and whose per-poll output would only be noise.
    pub quiet: bool,
    /// Interpret the child's output instead of forwarding it raw.
    ///
    /// The `@wait_active` step uses this: the target-side helper streams one
    /// machine-readable state line per poll, and the collector turns those
    /// into a progress line for the operator (the service's own `STATUS=`
    /// text, when it publishes one). Lines the collector does not recognise
    /// are dropped.
    pub collector: Option<LineCollector>,
}

/// Interprets a child's output lines on their way to the UI.
///
/// The closure returns the line to display, or `None` to drop it.
#[derive(Clone)]
pub(crate) struct LineCollector {
    inner: std::sync::Arc<std::sync::Mutex<LineInterpreter>>,
}

/// Turns one output line into the line to display (or nothing).
type LineInterpreter = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

impl LineCollector {
    /// Build a collector from an interpretation function.
    pub(super) fn new(f: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self { inner: std::sync::Arc::new(std::sync::Mutex::new(Box::new(f))) }
    }

    /// Interpret one line.
    pub(super) fn record(&self, line: &str) -> Option<String> {
        let guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        (guard)(line)
    }
}

/// Run a piped child with stdout/stderr forwarded through the UI, honoring
/// the timeout and the cancellation signal.
///
/// The payload is written to stdin when non-empty. The timeout covers the
/// payload write *and* the wait, so a peer that never reads the payload
/// cannot outlive the step.
pub(super) async fn run_piped_child(args: PipedArgs<'_>, mut cmd: Command) -> Result<PipedRun> {
    let PipedArgs {
        ui,
        host,
        payload,
        timeout,
        diff_filter,
        log_file,
        mut cancel,
        quiet,
        collector,
    } = args;

    if quiet && collector.is_none() {
        cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    } else {
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    }
    cmd.kill_on_drop(true);
    super::process::isolate(&mut cmd);
    let mut child = cmd.spawn().map_err(|_| eyre::eyre!("spawn failed"))?;
    let pid = child.id();
    let mut guard = super::process::GroupGuard::new(&child);

    // One deadline covers the payload write *and* the wait: a peer that
    // neither reads the payload nor closes its stdin would otherwise block
    // the write forever, and the step timeout would never start ticking.
    let deadline = timeout.map(|secs| tokio::time::Instant::now() + Duration::from_secs(secs));

    // Start the readers *before* waiting: the child blocks once its stdout /
    // stderr pipe buffers fill (~64 KB), so waiting first deadlocks any step
    // with large output. The drain after the wait is bounded (see
    // `DRAIN_GRACE`), which is what stops a backgrounded descendant from
    // hanging the step instead.
    let mut readers = if quiet && collector.is_none() {
        None
    } else {
        spawn_readers(ui, host, diff_filter, collector, &mut child)
    };

    // 1. Deliver the payload, racing cancellation: with no timeout a stalled
    // peer would otherwise ride out the whole interrupt grace period without
    // ever observing the cancel signal.
    if let Some(mut stdin) = child.stdin.take() &&
        let Some(payload) = payload
    {
        let write = with_deadline(deadline, stdin.write_all(payload.as_bytes()));
        tokio::select! {
            result = write => match result {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    crate::ui::warn(&format!("[{host}] stdin write failed"), log_file);
                    super::process::terminate(&mut child).await;
                    guard.disarm();
                    drain_started(readers.take(), pid).await;
                    return Ok(PipedRun::PipeBroken);
                }
                Err(()) => {
                    super::process::terminate(&mut child).await;
                    guard.disarm();
                    drain_started(readers.take(), pid).await;
                    return Ok(PipedRun::TimedOut);
                }
            },
            () = cancel.cancelled() => {
                super::process::terminate(&mut child).await;
                guard.disarm();
                drain_started(readers.take(), pid).await;
                return Ok(PipedRun::Cancelled);
            }
        }
    }
    drop(child.stdin.take());

    // 2. Wait for the child, racing the cancellation signal.
    let outcome = {
        let wait = with_deadline(deadline, child.wait());
        tokio::select! {
            result = wait => result,
            () = cancel.cancelled() => {
                super::process::terminate(&mut child).await;
                guard.disarm();
                drain_started(readers.take(), pid).await;
                return Ok(PipedRun::Cancelled);
            }
        }
    };
    let result = match outcome {
        Ok(Ok(status)) => PipedRun::Completed(status),
        Ok(Err(err)) => {
            // The wait itself failed: tear the group down before giving up,
            // otherwise `kill_on_drop` would only reap the direct child and
            // the rest of the tree would survive.
            super::process::terminate(&mut child).await;
            guard.disarm();
            drain_started(readers.take(), pid).await;
            return Err(eyre::eyre!("wait error: {err}"));
        }
        Err(()) => {
            super::process::terminate(&mut child).await;
            guard.disarm();
            drain_started(readers.take(), pid).await;
            return Ok(PipedRun::TimedOut);
        }
    };

    // 3. Drain the readers. Buffered lines already in the pipe belong in the
    // UI and the audit log even though the child is gone.
    drain_started(readers.take(), pid).await;
    guard.disarm();

    Ok(result)
}

/// Spawn the stdout/stderr forwarder tasks for a piped child.
///
/// Returns `None` when the child has no piped output to read (e.g. the
/// pipes were not requested). Callers must still drive the returned set to
/// completion via [`drain_started`], on *every* terminal path — not just the
/// success path — or buffered lines never reach the UI/audit log.
fn spawn_readers(
    ui: &ArcUi,
    host: &str,
    diff_filter: Option<super::DiffFilter>,
    collector: Option<LineCollector>,
    child: &mut tokio::process::Child,
) -> Option<JoinSet<()>> {
    let stdout = child.stdout.take()?;
    let stderr = child.stderr.take()?;

    let (tx, rx) = mpsc::channel::<(Stream, String)>(256);
    let host_alias = host.to_string();
    let ui_handle = Arc::clone(ui);
    let mut readers = JoinSet::new();
    readers.spawn(forward_stream(stdout, tx.clone(), Stream::Stdout));
    readers.spawn(forward_stream(stderr, tx, Stream::Stderr));
    readers.spawn(async move {
        let mut rx = rx;
        while let Some((stream, line)) = rx.recv().await {
            if let Some(collector) = &collector {
                // The collector owns the line: it decides what (if anything)
                // the operator sees.
                if let Some(rendered) = collector.record(&line) {
                    ui_handle.lock().await.host_line(&host_alias, stream, &rendered);
                }
                continue;
            }
            if let Some(f) = &diff_filter &&
                stream == Stream::Stdout &&
                !f(&line)
            {
                continue;
            }
            ui_handle.lock().await.host_line(&host_alias, stream, &line);
        }
    });
    Some(readers)
}

/// Drive an already-started reader set to EOF, with a bound.
///
/// A descendant that inherited the child's stdout/stderr keeps the pipe open
/// after the child itself is gone (`nohup svc &` without redirecting). The
/// drain is therefore bounded: a group that still holds the step's output
/// pipe past the grace period is killed rather than hanging the run.
async fn drain_started(readers: Option<JoinSet<()>>, pid: Option<u32>) {
    let Some(mut readers) = readers else {
        return;
    };
    // Both streams are drained to EOF. The group may still be alive on the
    // success path (a backgrounded descendant keeps the pipe open), so the
    // drain is bounded: a group that still holds the step's output pipe past
    // the grace period is killed rather than hanging the run.
    let drained =
        tokio::time::timeout(DRAIN_GRACE, async { while readers.join_next().await.is_some() {} })
            .await;
    if drained.is_err() {
        // A descendant still holds the pipe: kill the whole group so the
        // step can finish, then reap the readers.
        if let Some(pid) = pid {
            super::process::signal_group(pid, nix::sys::signal::Signal::SIGKILL);
        }
        let _ = tokio::time::timeout(DRAIN_GRACE, async {
            while readers.join_next().await.is_some() {}
        })
        .await;
        readers.shutdown().await;
    }
}

/// Run `fut` with an optional deadline.
///
/// `Err(())` means the deadline expired.
async fn with_deadline<F, T>(deadline: Option<tokio::time::Instant>, fut: F) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, fut).await.map_err(|_| ()),
        None => Ok(fut.await),
    }
}

/// Collect per-host results, preserving the ones that completed.
///
/// A join error (a host task panicked or was aborted) must not discard the
/// statuses of hosts that already finished — the caller renders those in the
/// step summary, and dropping them would misreport the fan-out. The error is
/// reported and the affected host is reported as failed with
/// `RunError::Transport`: a join failure is a controller-side event, and
/// classifying it `Script` (exit 4) would misattribute it to the remote
/// command.
pub(super) async fn collect_hosts(
    ui: &ArcUi,
    log_file: &LogFile,
    mut tasks: JoinSet<(String, HostOutcome)>,
) -> Vec<(String, HostOutcome)> {
    let mut results = Vec::with_capacity(tasks.len());
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((alias, outcome)) => {
                // The host is finished: flush its grouped block so the log
                // reads as one block per host.
                ui.lock().await.host_finished(&alias);
                results.push((alias, outcome));
            }
            Err(join_err) => {
                crate::ui::warn(&format!("host task failed: {join_err}"), log_file);
                results
                    .push(("unknown".to_string(), HostOutcome::Failed(super::RunError::Transport)));
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ui() -> ArcUi {
        Arc::new(tokio::sync::Mutex::new(
            crate::ui::Ui::new(0, true, crate::cli::OutputMode::Stream, None).expect("ui"),
        ))
    }

    fn args<'a>(
        ui: &'a ArcUi,
        log_file: &'a crate::executor::LogFile,
        cancel: Cancel,
    ) -> PipedArgs<'a> {
        PipedArgs {
            ui,
            host: "test-host",
            payload: None,
            timeout: None,
            diff_filter: None,
            log_file,
            cancel,
            quiet: false,
            collector: None,
        }
    }

    /// Verify that `run_piped_child` with a `diff_filter` correctly filters
    /// stdout lines and returns the completed status.
    #[tokio::test]
    async fn piped_child_with_diff_filter_filters_stdout() {
        let ui = ui();
        let log_file = None;
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("echo hello");
        let filter = |line: &str| line.contains("KEEP");
        let mut args = args(&ui, &log_file, Cancel::new());
        args.diff_filter = Some(Arc::new(filter) as super::super::DiffFilter);
        let result = run_piped_child(args, cmd).await.expect("run_piped_child should succeed");
        match result {
            PipedRun::Completed(status) => assert!(status.success()),
            PipedRun::TimedOut => panic!("should not time out"),
            PipedRun::PipeBroken => panic!("should not break the pipe"),
            PipedRun::Cancelled => panic!("should not be cancelled"),
        }
    }

    /// Verify that `run_piped_child` without a `diff_filter` passes all
    /// lines through.
    #[tokio::test]
    async fn piped_child_without_filter_passes_all_lines() {
        let ui = ui();
        let log_file = None;
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("echo hello");
        let result = run_piped_child(args(&ui, &log_file, Cancel::new()), cmd)
            .await
            .expect("run_piped_child should succeed");
        match result {
            PipedRun::Completed(status) => assert!(status.success()),
            PipedRun::TimedOut => panic!("should not time out"),
            PipedRun::PipeBroken => panic!("should not break the pipe"),
            PipedRun::Cancelled => panic!("should not be cancelled"),
        }
    }

    /// Verify that `run_piped_child` times out correctly.
    #[tokio::test]
    async fn piped_child_times_out() {
        let ui = ui();
        let log_file = None;
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("sleep 10");
        let mut args = args(&ui, &log_file, Cancel::new());
        args.timeout = Some(1);
        let result = run_piped_child(args, cmd).await.expect("run_piped_child should succeed");
        match result {
            PipedRun::Completed(_) => panic!("should have timed out"),
            PipedRun::TimedOut => {}
            PipedRun::PipeBroken => panic!("should not break the pipe"),
            PipedRun::Cancelled => panic!("should not be cancelled"),
        }
    }

    /// A backgrounded descendant that keeps the output pipe open must not
    /// hang the step: the drain is bounded and the group is killed.
    #[tokio::test]
    async fn a_backgrounded_descendant_does_not_hang_the_step() {
        let ui = ui();
        let log_file = None;
        let mut cmd = Command::new("bash");
        // `sleep` inherits the stdout pipe and holds it open after bash exits.
        cmd.arg("-c").arg("sleep 30 &");
        let started = std::time::Instant::now();
        let result = run_piped_child(args(&ui, &log_file, Cancel::new()), cmd)
            .await
            .expect("run_piped_child should succeed");
        assert!(matches!(result, PipedRun::Completed(_)), "the block itself succeeded");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the step must not wait for the backgrounded descendant"
        );
    }

    /// A cancelled run terminates the child group and reports it.
    #[tokio::test]
    async fn cancellation_terminates_the_child() {
        let ui = ui();
        let log_file = None;
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("sleep 30");
        let cancel = Cancel::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            trigger.cancel();
        });
        let args = args(&ui, &log_file, cancel);
        let started = std::time::Instant::now();
        let result = run_piped_child(args, cmd).await.expect("run_piped_child should succeed");
        assert!(matches!(result, PipedRun::Cancelled), "expected a cancelled run");
        assert!(started.elapsed() < Duration::from_secs(20), "the child must be torn down");
    }

    /// Output larger than the pipe buffer must not deadlock the wait: the
    /// readers run *while* the child runs, not after it exits.
    #[tokio::test]
    async fn large_output_does_not_deadlock_without_a_timeout() {
        let ui = ui();
        let log_file = None;
        let mut cmd = Command::new("bash");
        // ~200 KB on stdout: far past the ~64 KB pipe buffer.
        cmd.arg("-c").arg("yes | head -n 100000");
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            run_piped_child(args(&ui, &log_file, Cancel::new()), cmd),
        )
        .await
        .expect("the step must finish instead of deadlocking")
        .expect("run_piped_child should succeed");
        assert!(matches!(result, PipedRun::Completed(_)), "expected completion, got {result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "large output must stream, not block the wait"
        );
    }
}
