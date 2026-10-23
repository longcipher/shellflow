//! Local step execution: `bash -c` with `set -eu` semantics, guard evaluation,
//! and `@export` capture.

use std::{path::Path, process::Stdio, sync::Arc};

use eyre::{Context as _, Result};
use shellflow_core::{EnvEntry, LocalStep, RunState};
use tokio::{fs, process::Command, sync::Mutex};

use super::{
    ArcUi, Cancel, CaptureFile, HostOutcome, LocalBlockArgs, LogFile, RunError, StepConfig,
    process::isolate,
};

/// Why a local block did not complete successfully.
///
/// The distinction matters: a timeout is a `TIMEOUT` status, a broken payload
/// pipe is a transport failure (exit 3), cancellation is a `CANCELLED` status,
/// and anything else is a script failure (exit 4).
pub(crate) enum LocalFailure {
    /// The block exceeded its timeout.
    Timeout,
    /// The block's script could not be delivered to the shell.
    PipeBroken,
    /// The run was interrupted.
    Cancelled,
    /// The block failed for any other reason.
    Failed(eyre::Report),
}

impl From<eyre::Report> for LocalFailure {
    fn from(report: eyre::Report) -> Self {
        Self::Failed(report)
    }
}

/// The outcome of an `@only_if` guard evaluation.
pub(crate) enum GuardOutcome {
    /// The guard succeeded: run the block.
    Pass,
    /// The guard failed: skip the block.
    Fail,
    /// The guard timed out.
    TimedOut,
    /// The guard was interrupted.
    Cancelled,
    /// The guard could not be evaluated.
    Failed(RunError),
}

pub(super) async fn build_env(
    run_state: &Arc<Mutex<RunState>>,
    entries: &[EnvEntry],
) -> Vec<(String, String)> {
    let state = run_state.lock().await;
    let mut env: Vec<(String, String)> =
        state.vars.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for entry in entries {
        match entry {
            EnvEntry::Literal { key, value } => {
                env.retain(|(k, _)| k != key);
                env.push((key.clone(), value.clone()));
            }
            EnvEntry::Passthrough { key } => {
                if !state.vars.contains_key(key) &&
                    let Ok(value) = std::env::var(key)
                {
                    // A repeated `@env KEY` must not inject the key twice: the
                    // child would see one value, but the payload env block
                    // would carry two.
                    env.retain(|(k, _)| k != key);
                    env.push((key.clone(), value));
                }
            }
        }
    }
    env
}

/// Append the `@export` capture statements to a local block.
///
/// Records are NUL-delimited (`NAME=VALUE\0`), matching design §7.6. NUL is
/// the only delimiter a shell value cannot contain, so a value carrying a
/// newline cannot forge a sibling record or be silently truncated; no
/// escaping is needed. A NUL-separated record also matches the `parse_capture_records`
/// pure parser in `shellflow-core`, which is where the reading side is tested.
fn append_capture(script: &str, vars: &[String]) -> String {
    let mut out = String::with_capacity(script.len() + 64 * vars.len());
    out.push_str(script);
    if !script.ends_with('\n') {
        out.push('\n');
    }
    for var in vars {
        // `printf` interprets `\0` as NUL in the format string; the values are
        // passed as arguments, so `%`/backslash in them are never re-scanned.
        // The variable name is validated by the parser
        // (`is_valid_var_name`), so it cannot break out of the quotes.
        out.push_str(&format!(
            "printf '%s=%s\\0' \"{var}\" \"${{{var}}}\" >> \"$SHELLFLOW_CAPTURE\"\n"
        ));
    }
    out
}

/// Read the NUL-delimited capture file into the run state, then let the
/// [`CaptureFile`] guard delete it.
///
/// Deletion is the guard's job (see [`CaptureFile`]), so every early return
/// here — including the "variable was not exported" error — still cleans up.
pub(crate) async fn capture_exports(
    run_state: &Arc<Mutex<RunState>>,
    vars: &[String],
    capture: &super::CaptureFile,
) -> Result<()> {
    let content = fs::read(capture.path())
        .await
        .wrap_err_with(|| format!("failed to read capture file {}", capture.path().display()))?;
    let table = shellflow_core::parse_capture_records_checked(&content, Some(vars))
        .wrap_err("failed to parse `@export` capture records")?;

    let mut state = run_state.lock().await;
    for var in vars {
        let Some(value) = table.get(var.as_str()) else {
            return Err(eyre::eyre!("variable `{var}` was not exported by the local step"));
        };
        state.vars.insert(var.clone(), value.clone());
    }
    Ok(())
}

pub(crate) fn create_capture_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(
            |err| eyre::eyre!("failed to create capture file {}: {err}", path.display()),
        )?;
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|err| {
            eyre::eyre!("failed to create capture file {}: {err}", path.display())
        })?;
    }
    Ok(())
}

pub(super) async fn run_local_block(args: &LocalBlockArgs<'_>) -> Result<(), LocalFailure> {
    if args.config.check || args.config.dry_run {
        run_bash_n(args.script, args.log_file).await?;
        crate::ui::note("  local syntax check (bash -n): OK", args.log_file);
        for finding in crate::lint::lint_block(args.script) {
            crate::ui::warn(
                &format!("  line {}: {}", finding.line, finding.message),
                args.log_file,
            );
        }
        return Ok(());
    }

    let mut resolved = build_env(args.run_state, args.env).await;
    for (k, v) in args.extra {
        resolved.retain(|(ek, _)| ek != k);
        resolved.push((k.clone(), v.clone()));
    }
    let mut cmd = Command::new("bash");
    cmd.arg("-c");
    cmd.envs(resolved);

    let header = if args.config.verbose >= 3 { "set -eux\n" } else { "set -eu\n" };
    let body = if args.capture.is_empty() {
        args.script.to_string()
    } else {
        append_capture(args.script, args.capture)
    };
    cmd.arg(format!("{header}{body}"));

    // The guard owns the capture file's lifetime: whether the step succeeds,
    // fails, or the capture cannot be parsed, the plaintext file is removed.
    let capture = if args.capture.is_empty() {
        None
    } else {
        let path = super::capture_file_path();
        create_capture_file(&path)?;
        cmd.env("SHELLFLOW_CAPTURE", &path);
        Some(CaptureFile::new(path))
    };

    if args.config.verbose >= 2 {
        args.ui.lock().await.masked_note(&format!("  local command: bash -c {body:?}"));
    }

    let status = run_bash_streamed(
        args.ui,
        "localhost",
        cmd,
        args.config.timeout,
        args.log_file,
        &args.cancel,
    )
    .await?;

    if !status.success() {
        return Err(LocalFailure::Failed(eyre::eyre!("local script exited with status {status}")));
    }

    if let Some(capture) = &capture {
        capture_exports(args.run_state, args.capture, capture)
            .await
            .map_err(LocalFailure::Failed)?;
    }
    Ok(())
}

pub(crate) async fn run_local_step(
    ui: &ArcUi,
    run_state: &Arc<Mutex<RunState>>,
    local: &LocalStep,
    config: StepConfig,
    cancel: &Cancel,
) -> Result<Vec<(String, HostOutcome)>> {
    let log_file = ui.lock().await.log_file();

    // The guard must observe the same environment as the block (run-state
    // `@export` variables plus `@env` entries), exactly like the remote path.
    let env = build_env(run_state, &local.env).await;

    if let Some(guard) = &local.guard {
        // A dry run must not change anything, so the guard is reported rather
        // than evaluated — a guard is a command like any other, and it runs
        // with the block's environment (design §8.2).
        if config.dry_run || config.check {
            crate::ui::note(&format!("  guard not evaluated in dry-run/check: {guard}"), &log_file);
        } else {
            match evaluate_guard(ui, guard, &env, config.timeout, cancel, &log_file).await {
                GuardOutcome::Pass => {
                    if config.verbose >= 2 {
                        ui.lock().await.masked_note(&format!("  guard passed: {guard}"));
                    }
                }
                GuardOutcome::Fail => {
                    crate::ui::note("  local guard failed — skipping block", &log_file);
                    return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
                }
                GuardOutcome::TimedOut => {
                    return Ok(vec![("localhost".to_string(), HostOutcome::TimedOut)]);
                }
                GuardOutcome::Cancelled => {
                    return Ok(vec![("localhost".to_string(), HostOutcome::Cancelled)]);
                }
                GuardOutcome::Failed(err) => {
                    crate::ui::warn(&format!("local guard failed: {err}"), &log_file);
                    return Ok(vec![("localhost".to_string(), HostOutcome::Failed(err))]);
                }
            }
        }
    }

    if config.dry_run || config.verbose >= 2 {
        ui.lock().await.payload_preview("Local Payload", &local.script);
    }

    let args = LocalBlockArgs {
        ui,
        run_state,
        script: &local.script,
        env: &local.env,
        config,
        capture: &local.export,
        extra: &[],
        log_file: &log_file,
        cancel: cancel.clone(),
    };
    // Every failure mode is reported as a *status* rather than an error, so
    // the step summary still lists the host (and can say `TIMEOUT`).
    let outcome = match run_local_block(&args).await {
        Ok(()) => HostOutcome::Ok,
        Err(LocalFailure::Timeout) => HostOutcome::TimedOut,
        Err(LocalFailure::PipeBroken) => HostOutcome::Failed(RunError::Transport),
        Err(LocalFailure::Cancelled) => HostOutcome::Cancelled,
        Err(LocalFailure::Failed(err)) => {
            crate::ui::warn(&format!("local step failed: {err:#}"), &log_file);
            HostOutcome::Failed(RunError::Script)
        }
    };
    Ok(vec![("localhost".to_string(), outcome)])
}

/// Evaluate an `@only_if` guard on the controller.
///
/// The guard's output is forwarded through the UI like any other block
/// output: it is masked, prefixed with the host alias, and written to the
/// audit log. A guard runs with the block's environment, so its output can
/// contain a secret.
pub(crate) async fn evaluate_guard(
    ui: &ArcUi,
    guard: &str,
    env: &[(String, String)],
    timeout: Option<u64>,
    cancel: &Cancel,
    log_file: &LogFile,
) -> GuardOutcome {
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(format!("set -e\n{guard}"));
    // Same env layer as the block: run-state/`@env` pairs overlay the process
    // environment `Command` inherits by default.
    cmd.envs(env.iter().cloned());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);

    let args = super::stream::PipedArgs {
        ui,
        host: "localhost",
        payload: None,
        timeout,
        diff_filter: None,
        log_file,
        cancel: cancel.clone(),
        quiet: false,
        collector: None,
    };
    match super::stream::run_piped_child(args, cmd).await {
        Ok(super::stream::PipedRun::Completed(status)) => {
            if status.success() {
                GuardOutcome::Pass
            } else {
                GuardOutcome::Fail
            }
        }
        Ok(super::stream::PipedRun::TimedOut) => GuardOutcome::TimedOut,
        Ok(super::stream::PipedRun::Cancelled) => GuardOutcome::Cancelled,
        Ok(super::stream::PipedRun::PipeBroken) | Err(_) => {
            GuardOutcome::Failed(RunError::Transport)
        }
    }
}

async fn run_bash_streamed(
    ui: &ArcUi,
    host: &str,
    cmd: Command,
    timeout: Option<u64>,
    log_file: &LogFile,
    cancel: &Cancel,
) -> Result<std::process::ExitStatus, LocalFailure> {
    let args = super::stream::PipedArgs {
        ui,
        host,
        payload: None,
        timeout,
        diff_filter: None,
        log_file,
        cancel: cancel.clone(),
        quiet: false,
        collector: None,
    };
    match super::stream::run_piped_child(args, cmd).await.map_err(LocalFailure::Failed)? {
        super::stream::PipedRun::Completed(status) => Ok(status),
        super::stream::PipedRun::TimedOut => Err(LocalFailure::Timeout),
        // The local child died before reading its script: a spawn-level or
        // script-delivery failure, not a timeout.
        super::stream::PipedRun::PipeBroken => Err(LocalFailure::PipeBroken),
        super::stream::PipedRun::Cancelled => Err(LocalFailure::Cancelled),
    }
}

async fn run_bash_n(script: &str, log_file: &LogFile) -> Result<(), LocalFailure> {
    use super::process::{GroupGuard, isolate};
    let mut cmd = Command::new("bash");
    cmd.arg("-n").arg("-c").arg(script);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    let child = cmd
        .spawn()
        .map_err(|err| LocalFailure::Failed(eyre::eyre!("failed to run bash -n: {err}")))?;
    let mut guard = GroupGuard::new(&child);
    // `bash -n` is short-lived, but a `PATH`-shadowed `bash` shim could hang:
    // bound it like every other child so check/dry-run cannot hang.
    let output =
        match tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
            .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(err)) => {
                guard.disarm();
                return Err(LocalFailure::Failed(eyre::eyre!("failed to run bash -n: {err}")));
            }
            Err(_) => {
                drop(guard);
                return Err(LocalFailure::Failed(eyre::eyre!("bash -n timed out — killed")));
            }
        };
    // Guard disarmed: the child was reaped normally.
    guard.disarm();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // `bash -n` echoes the offending source line, which can contain a
        // secret: the warning goes through the masked render path.
        crate::ui::warn(&format!("syntax error: {stderr}"), log_file);
        return Err(LocalFailure::Failed(eyre::eyre!("bash -n failed")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::create_capture_file;

    #[test]
    fn capture_file_is_owner_only_and_create_new() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("capture.txt");
        create_capture_file(&path).expect("create capture file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "capture file may hold secrets and must be owner-only");
        }
        assert!(
            create_capture_file(&path).is_err(),
            "re-creating an existing capture file must fail (no overwrite races)"
        );
    }
}
