//! Local step execution: `bash -c` with `set -eu` semantics, guard evaluation,
//! and `@export` capture.

use std::{path::Path, sync::Arc};

use eyre::{Context as _, Result, bail};
use shellflow_core::{EnvEntry, LocalStep, RunState};
use tokio::{fs, process::Command, sync::Mutex};

use super::{
    ArcUi, CaptureFile, HostOutcome, LocalBlockArgs, LogFile, StepConfig,
    process::{GroupGuard, isolate},
};

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
    let table = shellflow_core::parse_capture_records(&content)
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

pub(super) async fn run_local_block(args: &LocalBlockArgs<'_>) -> Result<()> {
    if args.config.check || args.config.dry_run {
        run_bash_n(args.script, args.log_file).await?;
        crate::ui::note("  local syntax check (bash -n): OK", args.log_file);
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

    let status =
        run_bash_streamed(args.ui, "localhost", cmd, args.config.timeout, args.log_file).await?;

    if !status.success() {
        bail!("local script exited with status {status}");
    }

    if let Some(capture) = &capture {
        capture_exports(args.run_state, args.capture, capture).await?;
    }
    Ok(())
}

pub(crate) async fn run_local_step(
    ui: &ArcUi,
    run_state: &Arc<Mutex<RunState>>,
    local: &LocalStep,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    let log_file = ui.lock().await.log_file();

    // The guard must observe the same environment as the block (run-state
    // `@export` variables plus `@env` entries), exactly like the remote path.
    let env = build_env(run_state, &local.env).await;

    if let Some(guard) = &local.guard {
        if run_local_guard(guard, &env, config.timeout).await {
            if config.verbose >= 2 {
                ui.lock().await.masked_note(&format!("  guard passed: {guard}"));
            }
        } else {
            crate::ui::note("  local guard failed — skipping block", &log_file);
            return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
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
    };
    match run_local_block(&args).await {
        Ok(()) => Ok(vec![("localhost".to_string(), HostOutcome::Ok)]),
        Err(err) => Err(err),
    }
}

pub(super) async fn run_local_guard(
    guard: &str,
    env: &[(String, String)],
    timeout: Option<u64>,
) -> bool {
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(format!("set -e\n{guard}"));
    // Same env layer as the block: run-state/`@env` pairs overlay the process
    // environment `Command` inherits by default.
    cmd.envs(env.iter().cloned());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return false,
    };
    let mut guard = GroupGuard::new(&child);
    let status = match timeout {
        Some(secs) => {
            match tokio::time::timeout(std::time::Duration::from_secs(secs), child.wait()).await {
                Ok(Ok(status)) => status,
                Ok(Err(_)) => return false,
                Err(_) => {
                    super::process::terminate(&mut child).await;
                    guard.disarm();
                    return false;
                }
            }
        }
        None => match child.wait().await {
            Ok(status) => status,
            Err(_) => return false,
        },
    };
    guard.disarm();
    status.success()
}

async fn run_bash_streamed(
    ui: &ArcUi,
    host: &str,
    cmd: Command,
    timeout: Option<u64>,
    log_file: &LogFile,
) -> Result<std::process::ExitStatus> {
    match super::stream::run_piped_child(Arc::clone(ui), host, cmd, None, timeout, None, log_file)
        .await?
    {
        super::stream::PipedRun::Completed(status) => Ok(status),
        super::stream::PipedRun::TimedOut => {
            bail!("local step timed out");
        }
        // The local child died before reading its script: a spawn-level or
        // script-delivery failure, not a timeout.
        super::stream::PipedRun::PipeBroken => {
            bail!("local script could not be delivered to bash");
        }
    }
}

async fn run_bash_n(script: &str, log_file: &LogFile) -> Result<()> {
    let output = Command::new("bash")
        .arg("-n")
        .arg("-c")
        .arg(script)
        .output()
        .await
        .wrap_err("failed to run bash -n")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        crate::ui::warn(&format!("syntax error: {stderr}"), log_file);
        bail!("bash -n failed");
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
