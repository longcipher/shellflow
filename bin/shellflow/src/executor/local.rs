//! Local step execution: `bash -c` with `set -eu` semantics, guard evaluation,
//! and `@export` capture.

use std::{path::Path, sync::Arc};

use eyre::{Context as _, Result, bail};
use shellflow_core::{EnvEntry, LocalStep, RunState};
use tokio::{fs, process::Command, sync::Mutex};

use super::{
    ArcUi, HostOutcome, LocalBlockArgs, LogFile, StepConfig,
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

fn append_capture(script: &str, vars: &[String]) -> String {
    let mut out = String::with_capacity(script.len() + 64 * vars.len());
    out.push_str(script);
    if !script.ends_with('\n') {
        out.push('\n');
    }
    for var in vars {
        out.push_str(&format!(
            "printf '%s=%s\\n' \"{var}\" \"${{{var}}}\" >> \"$SHELLFLOW_CAPTURE\"\n"
        ));
    }
    out
}

pub(crate) async fn capture_exports(
    run_state: &Arc<Mutex<RunState>>,
    vars: &[String],
    path: &Path,
) -> Result<()> {
    let content = fs::read_to_string(path)
        .await
        .wrap_err_with(|| format!("failed to read capture file {}", path.display()))?;
    let _ = fs::remove_file(path).await;
    let mut state = run_state.lock().await;
    for var in vars {
        let value = content
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{var}=")).map(ToOwned::to_owned));
        match value {
            Some(value) => {
                state.vars.insert(var.clone(), value);
            }
            None => return Err(eyre::eyre!("variable `{var}` was not exported by the local step")),
        }
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

    let capture_path = if args.capture.is_empty() {
        None
    } else {
        let path = super::capture_file_path();
        create_capture_file(&path)?;
        cmd.env("SHELLFLOW_CAPTURE", &path);
        Some(path)
    };

    if args.config.verbose >= 2 {
        args.ui.lock().await.masked_note(&format!("  local command: bash -c {body:?}"));
    }

    let status =
        run_bash_streamed(args.ui, "localhost", cmd, args.config.timeout, args.log_file).await?;

    if !status.success() {
        bail!("local script exited with status {status}");
    }

    if let Some(path) = capture_path {
        capture_exports(args.run_state, args.capture, &path).await?;
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

    if let Some(guard) = &local.guard &&
        !run_local_guard(guard, config.timeout).await
    {
        crate::ui::note("  local guard failed — skipping block", &log_file);
        return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
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

pub(super) async fn run_local_guard(guard: &str, timeout: Option<u64>) -> bool {
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(format!("set -e\n{guard}"));
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
