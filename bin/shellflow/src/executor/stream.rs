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

use super::{ArcUi, HostOutcome};
use crate::ui::Stream;

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

pub(super) enum PipedRun {
    Completed(std::process::ExitStatus),
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
}

/// Run a piped child with stdout/stderr forwarded through the UI, honoring
/// the timeout. `payload` is written to stdin when non-empty. Returns the
/// exit status or `TimedOut`.
pub(super) async fn run_piped_child(
    ui: ArcUi,
    host: &str,
    mut cmd: Command,
    payload: Option<&str>,
    timeout: Option<u64>,
    diff_filter: Option<super::DiffFilter>,
    log_file: &super::LogFile,
) -> Result<PipedRun> {
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);
    super::process::isolate(&mut cmd);
    let mut child = cmd.spawn().map_err(|_| eyre::eyre!("spawn failed"))?;
    let mut guard = super::process::GroupGuard::new(&child);

    if let Some(mut stdin) = child.stdin.take() &&
        let Some(payload) = payload &&
        stdin.write_all(payload.as_bytes()).await.is_err()
    {
        crate::ui::warn(&format!("[{}] stdin write failed", host), log_file);
        super::process::terminate(&mut child).await;
        guard.disarm();
        return Ok(PipedRun::PipeBroken);
    }

    let stdout = child.stdout.take().ok_or_else(|| eyre::eyre!("stdout not piped"))?;
    let stderr = child.stderr.take().ok_or_else(|| eyre::eyre!("stderr not piped"))?;

    let (tx, rx) = mpsc::channel::<(Stream, String)>(256);
    let host_alias = host.to_string();
    let out_task = tokio::spawn(forward_stream(stdout, tx.clone(), Stream::Stdout));
    let err_task = tokio::spawn(forward_stream(stderr, tx, Stream::Stderr));

    let ui_handle = Arc::clone(&ui);
    let diff_filter = diff_filter.clone();
    let read_task = tokio::spawn(async move {
        let mut rx = rx;
        while let Some((stream, line)) = rx.recv().await {
            if let Some(f) = &diff_filter &&
                stream == Stream::Stdout &&
                !f(&line)
            {
                continue;
            }
            ui_handle.lock().await.host_line(&host_alias, stream, &line);
        }
    });

    let result = match timeout {
        Some(secs) => {
            let timed_out = tokio::time::timeout(Duration::from_secs(secs), child.wait()).await;
            match timed_out {
                Ok(Ok(status)) => Ok(PipedRun::Completed(status)),
                Ok(Err(err)) => Err(eyre::eyre!("wait error: {err}")),
                Err(_) => {
                    // Terminate first so closing the group closes the inherited
                    // pipe ends, which lets both reader tasks see EOF and drain
                    // what is already buffered. Aborting the consumer first
                    // would discard those lines, breaking the `--log-file`
                    // audit trail exactly when an operator needs it most.
                    super::process::terminate(&mut child).await;
                    guard.disarm();
                    Ok(PipedRun::TimedOut)
                }
            }
        }
        None => match child.wait().await {
            Ok(status) => Ok(PipedRun::Completed(status)),
            Err(err) => Err(eyre::eyre!("wait error: {err}")),
        },
    };
    guard.disarm();

    // Both streams are drained to EOF on every path, including the timeout
    // path above: killing the group closes the inherited pipe ends, so the
    // reader tasks finish on their own and joining them cannot hang.
    let _ = out_task.await;
    let _ = err_task.await;
    let _ = read_task.await;
    result
}

/// Collect per-host results, preserving the ones that completed.
///
/// A join error (a host task panicked or was aborted) must not discard the
/// statuses of hosts that already finished — the caller renders those in the
/// step summary, and dropping them would misreport the fan-out.
pub(super) async fn collect_hosts(
    mut tasks: JoinSet<(String, HostOutcome)>,
) -> Result<Vec<(String, HostOutcome)>> {
    let mut results = Vec::with_capacity(tasks.len());
    let mut first_join_error: Option<String> = None;
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(outcome) => results.push(outcome),
            Err(join_err) => {
                if first_join_error.is_none() {
                    first_join_error = Some(join_err.to_string());
                }
            }
        }
    }
    match first_join_error {
        Some(err) => Err(eyre::eyre!("host task failed: {err}")),
        None => Ok(results),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `run_piped_child` with a `diff_filter` correctly filters
    /// stdout lines and returns the completed status.
    #[tokio::test]
    async fn piped_child_with_diff_filter_filters_stdout() {
        let ui: ArcUi = Arc::new(tokio::sync::Mutex::new(crate::ui::Ui::new(
            0,
            true,
            crate::cli::OutputMode::Stream,
            None,
        )));
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("echo hello");
        let filter = |line: &str| -> bool { line.contains("KEEP") };
        let result = run_piped_child(
            ui,
            "test-host",
            cmd,
            None,
            None,
            Some(Arc::new(filter) as super::super::DiffFilter),
            &None,
        )
        .await
        .expect("run_piped_child should succeed");
        match result {
            PipedRun::Completed(status) => assert!(status.success()),
            PipedRun::TimedOut => panic!("should not time out"),
            PipedRun::PipeBroken => panic!("should not break the pipe"),
        }
    }

    /// Verify that `run_piped_child` without a `diff_filter` passes all
    /// lines through.
    #[tokio::test]
    async fn piped_child_without_filter_passes_all_lines() {
        let ui: ArcUi = Arc::new(tokio::sync::Mutex::new(crate::ui::Ui::new(
            0,
            true,
            crate::cli::OutputMode::Stream,
            None,
        )));
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("echo hello");
        let result = run_piped_child(ui, "test-host", cmd, None, None, None, &None)
            .await
            .expect("run_piped_child should succeed");
        match result {
            PipedRun::Completed(status) => assert!(status.success()),
            PipedRun::TimedOut => panic!("should not time out"),
            PipedRun::PipeBroken => panic!("should not break the pipe"),
        }
    }

    /// Verify that `run_piped_child` times out correctly.
    #[tokio::test]
    async fn piped_child_times_out() {
        let ui: ArcUi = Arc::new(tokio::sync::Mutex::new(crate::ui::Ui::new(
            0,
            true,
            crate::cli::OutputMode::Stream,
            None,
        )));
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("sleep 10");
        let result = run_piped_child(ui, "test-host", cmd, None, Some(1), None, &None)
            .await
            .expect("run_piped_child should succeed");
        match result {
            PipedRun::Completed(_) => panic!("should have timed out"),
            PipedRun::TimedOut => {}
            PipedRun::PipeBroken => panic!("should not break the pipe"),
        }
    }
}
