//! The execution engine: runs local blocks, streams remote blocks over SSH,
//! and syncs files with rsync, with fan-out, timeouts, and dry-run/diff
//! semantics.
//!
//! All child processes are spawned with `kill_on_drop(true)`, so aborting the
//! run task (on SIGINT/SIGTERM) terminates every in-flight `ssh`/`rsync`/`bash`
//! process — no orphans survive.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use eyre::{Context, Result, bail};
use shellflow_core::{
    CopyStep, EnvEntry, ExecutionPlan, LocalStep, RemoteStep, ResolvedHost, RunState, Step,
    interpolate, render_env, resolve_hosts,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use crate::{
    cli::Cli,
    ui::{HostStatus, Outcome, Stream, Ui},
};

/// The error classification mapped to the CLI exit code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    /// A transport/setup failure (exit 3).
    Transport,
    /// A script execution failure (exit 4).
    Script,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport/setup failure"),
            Self::Script => write!(f, "script execution failure"),
        }
    }
}

/// The overall run outcome.
#[derive(Debug)]
pub(crate) enum RunOutcome {
    /// Everything succeeded (or was skipped).
    Success,
    /// At least one step failed.
    Failed(RunError),
    /// Interrupted by a signal; `total` is the step count for reporting.
    Interrupted { total: usize },
}

/// Per-step statistics for the final summary.
///
/// `pub(crate)` so `main` can print an interrupt summary from the shared
/// progress list while the plan is cancelled by a signal.
#[derive(Clone, Debug)]
pub(crate) struct StepStats {
    /// 1-based step index.
    pub(crate) index: usize,
    /// Wall-clock duration.
    pub(crate) elapsed: Duration,
    /// Per-host outcomes.
    pub(crate) statuses: Vec<HostStatus>,
}

/// Shared, monotonically-appended step progress (for interrupt summaries).
type Progress = Arc<Mutex<Vec<StepStats>>>;

/// The outcome of one host within a step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostOutcome {
    /// Completed successfully.
    Ok,
    /// Skipped because `@only_if` failed.
    Skipped,
    /// The command failed; carries the error classification.
    Failed(RunError),
    /// The step exceeded its timeout.
    TimedOut,
}

/// A shared, async-safe UI handle.
type ArcUi = Arc<Mutex<Ui>>;

/// Per-step execution settings threaded into host tasks.
#[derive(Clone, Copy, Debug)]
struct StepConfig {
    /// No writes: syntax-check payloads and use `rsync --dry-run -i`.
    dry_run: bool,
    /// `--diff`: itemize output is filtered to change lines with markers.
    diff: bool,
    /// Syntax-check only.
    check: bool,
    /// Verbosity level (0–3).
    verbose: u8,
    /// Optional timeout in seconds.
    timeout: Option<u64>,
}

impl StepConfig {
    const fn new(cli: &Cli, timeout: Option<u64>) -> Self {
        Self {
            dry_run: cli.dry_run || cli.diff,
            diff: cli.diff,
            check: cli.check,
            verbose: cli.verbose,
            timeout,
        }
    }
}

/// Execute the plan and return the overall outcome.
///
/// Completed step statistics are appended to `progress` so that a signal
/// cancelling the run can still report what finished before the interrupt.
pub(crate) async fn execute_plan(cli: &Cli, plan: ExecutionPlan, progress: Progress) -> RunOutcome {
    let ui =
        Arc::new(Mutex::new(Ui::new(cli.verbose, cli.no_color, cli.output, cli.log_file.clone())));

    // Only literal `@env KEY=value` entries are masked: their values are
    // written in the deploy file and may be secrets. Passthrough entries read
    // from shellflow's own environment are already visible to the user and
    // must not be redacted (e.g. `HOME` would otherwise render as `***`).
    let secrets: Vec<String> = plan
        .env
        .iter()
        .filter_map(|entry| match entry {
            EnvEntry::Literal { value, .. } => Some(value.clone()),
            EnvEntry::Passthrough { .. } => None,
        })
        .collect();
    ui.lock().await.set_secrets(secrets);

    if cli.dry_run {
        crate::ui::dry_run_banner();
    }

    let restrict = cli.target_restrict();
    // `--parallel 0` (default) means unbounded, per the documented "all".
    // An `Option` avoids `Semaphore::new(usize::MAX)`, which would exceed
    // tokio's MAX_PERMITS and panic.
    let semaphore: Option<Arc<Semaphore>> =
        (cli.parallel != 0).then(|| Arc::new(Semaphore::new(cli.parallel)));
    let run_state = Arc::new(Mutex::new(RunState::default()));

    // Apply --only / --skip filtering.
    let selected: Vec<(usize, &Step)> =
        plan.steps.iter().enumerate().filter(|(idx, step)| is_selected(cli, *idx, step)).collect();
    let total = selected.len();

    if ui.lock().await.verbosity().info() {
        ui.lock().await.plan_preview(&plan);
    }

    let mut stats: Vec<StepStats> = Vec::new();
    let mut fail_fast_error: Option<RunError> = None;
    // Records the first failure even with `--continue-on-error`, so the run
    // still exits non-zero when something failed.
    let mut first_error: Option<RunError> = None;

    for (pos, (idx, step)) in selected.iter().enumerate() {
        if fail_fast_error.is_some() {
            break;
        }
        let step_no = pos + 1;
        crate::ui::step_header(step_no, total, step);

        let started = std::time::Instant::now();
        let config = StepConfig::new(cli, cli.timeout.or_else(|| step.timeout()));
        let outcome = match step {
            Step::Local(local) => run_local_step(&ui, &run_state, local, config).await,
            Step::Remote(remote) => match resolve_hosts(&plan, &remote.target, &restrict) {
                Ok(hosts) => {
                    run_remote_step(&ui, &semaphore, &run_state, remote, hosts, config).await
                }
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string());
                    fail_fast_error = Some(RunError::Script);
                    continue;
                }
            },
            Step::Copy(copy) => match resolve_hosts(&plan, &copy.target, &restrict) {
                Ok(hosts) => run_copy_step(&ui, &semaphore, &run_state, copy, hosts, config).await,
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string());
                    fail_fast_error = Some(RunError::Script);
                    continue;
                }
            },
        };

        ui.lock().await.flush_grouped();
        let elapsed = started.elapsed();
        let statuses = outcome_to_statuses(&outcome);
        crate::ui::step_outcome(elapsed, &statuses);
        let step_stats = StepStats { index: idx + 1, elapsed, statuses };
        progress.lock().await.push(step_stats.clone());
        stats.push(step_stats);

        let step_err: Option<RunError> = match &outcome {
            Err(join_err) => {
                crate::ui::warn(&format!("step failed: {join_err:#}"));
                Some(RunError::Script)
            }
            Ok(hosts) => step_error_if_failed(hosts),
        };

        if let Some(err) = step_err {
            if first_error.is_none() {
                first_error = Some(err);
            }
            if cli.continue_on_error {
                crate::ui::step_failed(step_no, &err.to_string());
            } else {
                fail_fast_error = Some(err);
            }
        }
    }

    if cli.continue_on_error || fail_fast_error.is_none() {
        let summary: Vec<(usize, Duration, Vec<HostStatus>)> =
            stats.iter().map(|s| (s.index, s.elapsed, s.statuses.clone())).collect();
        crate::ui::final_summary(&summary);
    }

    match fail_fast_error.or(first_error) {
        Some(err) => RunOutcome::Failed(err),
        None => RunOutcome::Success,
    }
}

/// Whether a step matches `--only` / `--skip` selectors (name or 1-based index).
fn is_selected(cli: &Cli, idx: usize, step: &Step) -> bool {
    let matches_selector = |selector: &str| -> bool {
        if selector == step.name().unwrap_or_default() {
            return true;
        }
        matches!(selector.parse::<usize>(), Ok(n) if n == idx + 1)
    };
    if !cli.only.is_empty() && !cli.only.iter().any(|s| matches_selector(s)) {
        return false;
    }
    if cli.skip.iter().any(|s| matches_selector(s)) {
        return false;
    }
    true
}

/// Convert a step outcome into per-host statuses for the UI.
fn outcome_to_statuses(outcome: &Result<Vec<(String, HostOutcome)>>) -> Vec<HostStatus> {
    match outcome {
        Ok(hosts) => hosts
            .iter()
            .map(|(alias, result)| HostStatus {
                alias: alias.clone(),
                outcome: match result {
                    HostOutcome::Ok => Outcome::Ok,
                    HostOutcome::Skipped => Outcome::Skipped,
                    HostOutcome::Failed(_) => Outcome::Failed,
                    HostOutcome::TimedOut => Outcome::TimedOut,
                },
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Local steps
// ---------------------------------------------------------------------------

async fn run_local_step(
    ui: &ArcUi,
    run_state: &Arc<Mutex<RunState>>,
    local: &LocalStep,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    if let Some(guard) = &local.guard &&
        !run_local_guard(guard, config.timeout).await
    {
        crate::ui::note("  ↳ local guard failed — skipping block");
        return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
    }

    if config.dry_run || config.verbose >= 2 {
        ui.lock().await.payload_preview("Local Payload", &local.script);
    }

    if config.check || config.dry_run {
        run_bash_n(&local.script).await?;
        crate::ui::note("  ↳ local syntax check (bash -n): OK");
        return Ok(vec![("localhost".to_string(), HostOutcome::Ok)]);
    }

    let env = build_env(run_state, &local.env).await;
    let mut cmd = Command::new("bash");
    cmd.arg("-c");
    cmd.envs(env);

    // Mirror the remote payload header: `set -eu` by default, `set -x` at
    // -vvv, so local and remote blocks share the same fail-fast semantics.
    let header = if config.verbose >= 3 { "set -eux\n" } else { "set -eu\n" };
    let body = if local.export.is_empty() {
        local.script.clone()
    } else {
        append_capture(&local.script, &local.export)
    };
    cmd.arg(format!("{header}{body}"));
    let capture_path = if local.export.is_empty() {
        None
    } else {
        let path = capture_file_path();
        // `create_new` fails if a file (or planted symlink) already exists at
        // the unpredictable path — no pre-planting or deletion races.
        std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|err| {
            eyre::eyre!("failed to create capture file {}: {err}", path.display())
        })?;
        cmd.env("SHELLFLOW_CAPTURE", &path);
        Some(path)
    };
    cmd.kill_on_drop(true);

    if config.verbose >= 2 {
        crate::ui::note(&format!("  ↳ local command: bash -c {:?}", body));
    }

    let status = match config.timeout {
        Some(secs) => match tokio::time::timeout(Duration::from_secs(secs), cmd.status()).await {
            Ok(Ok(status)) => status,
            Ok(Err(err)) => return Err(err).wrap_err("failed to run local bash"),
            Err(_) => {
                crate::ui::warn("local step timed out — killed");
                bail!("local step timed out after {secs}s");
            }
        },
        None => cmd.status().await.wrap_err("failed to run local bash")?,
    };

    if !status.success() {
        bail!("local script exited with status {status}");
    }

    if let Some(path) = &capture_path {
        capture_exports(run_state, &local.export, path).await?;
    }
    Ok(vec![("localhost".to_string(), HostOutcome::Ok)])
}

async fn run_local_guard(guard: &str, timeout: Option<u64>) -> bool {
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(format!("set -e\n{guard}"));
    cmd.kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return false,
    };
    let status = match timeout {
        Some(secs) => {
            let timed = tokio::time::timeout(Duration::from_secs(secs), child.wait()).await;
            if let Ok(Ok(status)) = timed {
                status
            } else {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return false;
            }
        }
        None => match child.wait().await {
            Ok(status) => status,
            Err(_) => return false,
        },
    };
    status.success()
}

async fn run_bash_n(script: &str) -> Result<()> {
    let output = Command::new("bash")
        .arg("-n")
        .arg("-c")
        .arg(script)
        .output()
        .await
        .wrap_err("failed to run bash -n")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        crate::ui::warn(&format!("syntax error: {stderr}"));
        bail!("bash -n failed");
    }
    Ok(())
}

/// Build the effective env for a block: every `@export`ed variable (design
/// §7.6) plus explicit `@env` entries layered on top (explicit wins).
async fn build_env(
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
                // Captured state already covers the key; only fall back to
                // shellflow's own environment when it is not exported.
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

/// Append `printf` capture lines that write exported variables to
/// `$SHELLFLOW_CAPTURE` after the user's script runs.
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

/// An unpredictable capture path per step: PID + nanosecond nonce. Combined
/// with `create_new` in the caller this defeats symlink pre-planting.
fn capture_file_path() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("shellflow-capture-{}-{nonce}.txt", std::process::id()))
}

async fn capture_exports(
    run_state: &Arc<Mutex<RunState>>,
    vars: &[String],
    path: &Path,
) -> Result<()> {
    let content = tokio::fs::read_to_string(path)
        .await
        .wrap_err_with(|| format!("failed to read capture file {}", path.display()))?;
    let _ = tokio::fs::remove_file(path).await;
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

// ---------------------------------------------------------------------------
// Remote steps
// ---------------------------------------------------------------------------

async fn run_remote_step(
    ui: &ArcUi,
    semaphore: &Option<Arc<Semaphore>>,
    run_state: &Arc<Mutex<RunState>>,
    remote: &RemoteStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    if config.dry_run || config.verbose >= 2 {
        ui.lock()
            .await
            .payload_preview(&format!("Remote Payload ({})", remote.target.text), &remote.script);
    }

    let env = build_env(run_state, &remote.env).await;
    let trace_line = if config.verbose >= 3 { "set -x\n" } else { "" };
    let payload = format!("set -eu\n{}{}{}", render_env(&env), trace_line, remote.script);

    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let semaphore = semaphore.clone();
        let payload = payload.clone();
        let guard = remote.guard.clone();
        let env = env.clone();
        tasks.spawn(async move {
            if let Some(semaphore) = &semaphore {
                let _permit = Arc::clone(semaphore).acquire_owned().await;
            }
            run_remote_host(ui, &host, &payload, guard.as_deref(), &env, config).await
        });
    }

    collect_hosts(tasks).await
}

async fn run_remote_host(
    ui: ArcUi,
    host: &ResolvedHost,
    payload: &str,
    guard: Option<&str>,
    env: &[(String, String)],
    config: StepConfig,
) -> (String, HostOutcome) {
    // Dry-run/check: syntax-check the payload on each host, never execute.
    if config.check || config.dry_run {
        if config.verbose >= 2 {
            let cmd = build_ssh_cmd(host, true, config);
            crate::ui::note(&format!("  [{}] ssh {}", host.alias, display_args(&cmd)));
        }
        return match run_ssh_child(
            ui,
            host,
            build_ssh_cmd(host, true, config),
            payload,
            config.timeout,
        )
        .await
        {
            Ok(()) => {
                crate::ui::note(&format!("[{}] syntax check (bash -n): OK", host.alias));
                (host.alias.clone(), HostOutcome::Ok)
            }
            Err(err) => {
                crate::ui::warn(&format!("[{}] {err:#}", host.alias));
                (host.alias.clone(), classify_ssh_err(&err))
            }
        };
    }

    // Real run: evaluate the guard (with the same env as the block), then
    // stream the payload.
    if let Some(guard) = guard {
        match run_remote_guard(host, guard, env, config.timeout).await {
            GuardResult::Pass => {}
            GuardResult::Fail => {
                crate::ui::note(&format!("[{}] SKIPPED (guard)", host.alias));
                return (host.alias.clone(), HostOutcome::Skipped);
            }
            GuardResult::Transport => {
                return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
            }
        }
    }

    let cmd = build_ssh_cmd(host, false, config);
    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] ssh {}", host.alias, display_args(&cmd)));
    }
    match run_ssh_child(ui, host, cmd, payload, config.timeout).await {
        Ok(()) => (host.alias.clone(), HostOutcome::Ok),
        Err(err) => {
            crate::ui::warn(&format!("[{}] {err:#}", host.alias));
            (host.alias.clone(), classify_ssh_err(&err))
        }
    }
}

/// Build the `ssh` command for a host: `ssh [-p port] [-v] host <bash…>`.
fn build_ssh_cmd(host: &ResolvedHost, syntax_only: bool, config: StepConfig) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    if config.verbose >= 3 {
        cmd.arg("-v");
    }
    cmd.arg(if syntax_only { "bash -n -s" } else { "bash -s" });
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    cmd
}

/// Map an ssh error string to a host outcome.
fn classify_ssh_err(err: &eyre::Report) -> HostOutcome {
    let msg = err.to_string();
    if msg.contains("timed out") {
        HostOutcome::TimedOut
    } else if msg.contains("exit 255") {
        HostOutcome::Failed(RunError::Transport)
    } else {
        HostOutcome::Failed(RunError::Script)
    }
}

/// Outcome of a `@only_if` guard evaluation on a host.
enum GuardResult {
    /// Guard succeeded; run the block.
    Pass,
    /// Guard failed; skip the block.
    Fail,
    /// Could not reach the host; treat as a transport failure.
    Transport,
}

/// Evaluate a guard command on a remote host via `ssh host bash -s`.
///
/// The guard runs with the same env header as the block (so `@export`ed
/// variables and `@env` entries are visible). Subject to the same
/// `--timeout`/`@timeout`; a timed-out or unreachable guard is treated as a
/// transport failure.
async fn run_remote_guard(
    host: &ResolvedHost,
    guard: &str,
    env: &[(String, String)],
    timeout: Option<u64>,
) -> GuardResult {
    let mut cmd = Command::new("ssh");
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    cmd.arg("bash -s");
    cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return GuardResult::Transport,
    };
    if let Some(mut stdin) = child.stdin.take() {
        let script = format!("set -e\n{}{guard}\n", render_env(env));
        let _ = stdin.write_all(script.as_bytes()).await;
    }
    let wait = match timeout {
        Some(secs) => tokio::time::timeout(Duration::from_secs(secs), child.wait()).await,
        None => Ok(child.wait().await),
    };
    match wait {
        Ok(Ok(status)) if status.success() => GuardResult::Pass,
        Ok(Ok(status)) if status.code() == Some(255) => GuardResult::Transport,
        Ok(Ok(_)) => GuardResult::Fail,
        _ => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            GuardResult::Transport
        }
    }
}

async fn run_ssh_child(
    ui: ArcUi,
    host: &ResolvedHost,
    mut cmd: Command,
    payload: &str,
    timeout: Option<u64>,
) -> Result<()> {
    let mut child = cmd.spawn().wrap_err("failed to spawn ssh")?;

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(payload.as_bytes()).await {
            let _ = child.wait().await;
            bail!("failed to write payload: {err}");
        }
        drop(stdin);
    }

    let stdout = child.stdout.take().ok_or_else(|| eyre::eyre!("stdout not piped"))?;
    let stderr = child.stderr.take().ok_or_else(|| eyre::eyre!("stderr not piped"))?;

    // Two reader tasks + one channel: both streams fully drained. The parent
    // holds no sender, so the channel closes when both readers finish.
    let (tx, rx) = tokio::sync::mpsc::channel::<(Stream, String)>(256);
    let host_alias = host.alias.clone();
    let out_task = tokio::spawn(forward_stream(stdout, tx.clone(), Stream::Stdout));
    let err_task = tokio::spawn(forward_stream(stderr, tx, Stream::Stderr));

    let read_task = tokio::spawn(async move {
        let mut rx = rx;
        while let Some((stream, line)) = rx.recv().await {
            ui.lock().await.host_line(&host_alias, stream, &line);
        }
    });

    let status = match timeout {
        Some(secs) => {
            let timed_out = tokio::time::timeout(Duration::from_secs(secs), child.wait()).await;
            match timed_out {
                Ok(Ok(status)) => status,
                Ok(Err(err)) => return Err(eyre::Report::new(err)),
                Err(_) => {
                    read_task.abort();
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    bail!("remote step timed out after {secs}s");
                }
            }
        }
        None => child.wait().await?,
    };

    // Drain remaining buffered output.
    let _ = out_task.await;
    let _ = err_task.await;
    let _ = read_task.await;

    if !status.success() {
        if status.code() == Some(255) {
            bail!("ssh transport error (exit 255)");
        }
        bail!("remote script exited with status {status}");
    }
    Ok(())
}

async fn forward_stream<R>(
    reader: R,
    tx: tokio::sync::mpsc::Sender<(Stream, String)>,
    stream: Stream,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if tx.send((stream, line)).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Copy steps (rsync)
// ---------------------------------------------------------------------------

async fn run_copy_step(
    ui: &ArcUi,
    semaphore: &Option<Arc<Semaphore>>,
    run_state: &Arc<Mutex<RunState>>,
    copy: &CopyStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    // Interpolate `$VAR` from captured state. In dry-run/check the local
    // steps did not execute, so unresolved variables are a warning + skip
    // (never a guessed path); in a real run they are hard errors.
    let (src, dst) = {
        let state = run_state.lock().await;
        let interpolated = interpolate(&copy.src, &state)
            .and_then(|src| interpolate(&copy.dst, &state).map(|dst| (src, dst)));
        drop(state);
        match interpolated {
            Ok(pair) => pair,
            Err(err) => {
                if config.dry_run || config.check {
                    crate::ui::warn(&format!(
                        "{err} — copy skipped (no run state in dry-run/check)"
                    ));
                    return Ok(Vec::new());
                }
                return Err(err).wrap_err("copy path interpolation");
            }
        }
    };

    if config.check {
        crate::ui::note("  ↳ syntax check: copy step (no execution)");
        return Ok(Vec::new());
    }

    if config.dry_run || config.verbose >= 2 {
        crate::ui::note(&format!("  ↳ rsync {src} -> {dst} ({} hosts)", hosts.len()));
    }

    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let semaphore = semaphore.clone();
        let src = src.clone();
        let dst = dst.clone();
        let delete = copy.delete;
        tasks.spawn(async move {
            if let Some(semaphore) = &semaphore {
                let _permit = Arc::clone(semaphore).acquire_owned().await;
            }
            run_rsync_host(ui, &host, &src, &dst, delete, config).await
        });
    }

    collect_hosts(tasks).await
}

async fn run_rsync_host(
    ui: ArcUi,
    host: &ResolvedHost,
    src: &str,
    dst: &str,
    delete: bool,
    config: StepConfig,
) -> (String, HostOutcome) {
    let remote_shell = host.spec.rsync_remote_shell().unwrap_or_else(|| "ssh".to_string());

    // Probe for a remote `rsync`. When it is missing (common on minimal
    // hosts), fall back to `ssh mkdir -p` + `scp` so `@copy` still works and
    // the target only ever needs `bash` (design §9).
    let has_rsync = probe_remote_rsync(host).await;
    if config.verbose >= 2 {
        crate::ui::note(&format!(
            "  [{}] remote rsync: {}",
            host.alias,
            if has_rsync { "present" } else { "missing — using scp fallback" }
        ));
    }

    let outcome = if has_rsync {
        run_rsync_transfer(ui.clone(), host, src, dst, delete, &remote_shell, config).await
    } else {
        run_scp_transfer(ui.clone(), host, src, dst, config).await
    };

    match outcome {
        Ok(()) => (host.alias.clone(), HostOutcome::Ok),
        Err(err) => {
            crate::ui::warn(&format!("[{}] {err:#}", host.alias));
            if err.to_string().contains("timed out") {
                (host.alias.clone(), HostOutcome::TimedOut)
            } else {
                // Transfer failures are I/O or protocol errors.
                (host.alias.clone(), HostOutcome::Failed(RunError::Transport))
            }
        }
    }
}

/// Whether the remote host has `rsync` on its PATH.
async fn probe_remote_rsync(host: &ResolvedHost) -> bool {
    let mut cmd = Command::new("ssh");
    cmd.args(host.spec.to_ssh_args()).arg("-T").arg("command -v rsync");
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.kill_on_drop(true);
    cmd.status().await.is_ok_and(|s| s.success())
}

/// Copy via rsync with a remote `mkdir -p` wrapper.
async fn run_rsync_transfer(
    ui: ArcUi,
    host: &ResolvedHost,
    src: &str,
    dst: &str,
    delete: bool,
    remote_shell: &str,
    config: StepConfig,
) -> Result<()> {
    let mut cmd = Command::new("rsync");
    cmd.args(["-a", "-z"]);
    if delete {
        cmd.arg("--delete");
    }
    if config.dry_run {
        cmd.args(["--dry-run", "-i"]);
    }
    // The remote `rsync` runs under a `mkdir -p` wrapper so the destination
    // directory is created automatically. `dst` may name a file (e.g.
    // `/srv/app.tar.gz`); in that case only its parent needs to exist — rsync
    // itself creates the final component. When `dst` ends with `/` it is a
    // directory and is created in full.
    let dir = if dst.ends_with('/') {
        dst
    } else {
        match dst.rsplit_once('/') {
            Some((dir, file)) if !file.is_empty() && !dir.is_empty() => dir,
            _ => dst,
        }
    };
    let quoted = dir.replace('\'', "'\\''");
    let mkdir_rsync = format!("mkdir -p '{quoted}' && rsync");
    cmd.args(["--rsync-path", &mkdir_rsync, "-e", remote_shell]);
    let dest = format!("{}:{dst}", host.spec.dest());
    cmd.arg(src).arg(&dest);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] rsync {}", host.alias, display_args(&cmd)));
    }

    run_rsync_child(ui, host, cmd, config.timeout, config.diff).await
}

/// Fallback copy via `ssh mkdir -p` + `scp` for hosts without rsync.
///
/// scp's destination semantics differ from rsync: when `dst` does not exist
/// on the remote, scp treats it as a directory and would create
/// `dst/basename(src)`. We therefore always target a directory — `dirname(dst)`
/// — and let scp place the file inside it, matching rsync's behavior.
async fn run_scp_transfer(
    ui: ArcUi,
    host: &ResolvedHost,
    src: &str,
    dst: &str,
    config: StepConfig,
) -> Result<()> {
    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] scp fallback: {src} -> {dst}", host.alias));
    }

    // Split `dst` into its parent directory and final component. For a plain
    // file target like `/tmp/x/app.tar.gz`, `dir` is `/tmp/x` and the file
    // lands at `/tmp/x/app.tar.gz` (matching the rsync semantics).
    let (dir, _file) = match dst.rsplit_once('/') {
        Some((dir, file)) if !file.is_empty() && !dir.is_empty() => (dir, file),
        _ => (dst, ""), // dst is already a directory (trailing `/` or bare dir)
    };

    // 1. Create the destination directory remotely.
    let quoted_dir = dir.replace('\'', "'\\''");
    let mut mkdir = Command::new("ssh");
    mkdir.args(host.spec.to_ssh_args()).arg("-T");
    mkdir.arg(format!("mkdir -p '{quoted_dir}'"));
    mkdir.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    mkdir.kill_on_drop(true);
    let status = mkdir.status().await.wrap_err("failed to create remote dir")?;
    if !status.success() {
        bail!("remote mkdir for {dir} failed");
    }

    // 2. Transfer the source into the (now existing) remote directory. The
    // trailing `/` makes scp copy `src` *into* `dir`, preserving the source
    // basename — identical to what rsync does for `src -> dir/`.
    let dest = format!("{}:{dir}/", host.spec.dest());
    let mut scp = Command::new("scp");
    scp.args(["-q", "-o", "BatchMode=yes"]);
    if let Some(port) = host.spec.port {
        scp.args(["-P", &port.to_string()]);
    }
    scp.arg(src).arg(&dest);
    scp.stdout(Stdio::piped()).stderr(Stdio::piped());
    scp.kill_on_drop(true);

    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] scp {}", host.alias, display_args(&scp)));
    }

    let mut child = scp.spawn().wrap_err("failed to spawn scp")?;
    let stdout = child.stdout.take().ok_or_else(|| eyre::eyre!("stdout not piped"))?;
    let stderr = child.stderr.take().ok_or_else(|| eyre::eyre!("stderr not piped"))?;

    let (tx, rx) = tokio::sync::mpsc::channel::<(Stream, String)>(256);
    let host_alias = host.alias.clone();
    let out_task = tokio::spawn(forward_stream(stdout, tx.clone(), Stream::Stdout));
    let err_task = tokio::spawn(forward_stream(stderr, tx, Stream::Stderr));

    let read_task = tokio::spawn(async move {
        let mut rx = rx;
        while let Some((stream, line)) = rx.recv().await {
            ui.lock().await.host_line(&host_alias, stream, &line);
        }
    });

    let status = match config.timeout {
        Some(secs) => {
            let timed = tokio::time::timeout(Duration::from_secs(secs), child.wait()).await;
            match timed {
                Ok(Ok(status)) => status,
                Ok(Err(err)) => return Err(eyre::Report::new(err)),
                Err(_) => {
                    read_task.abort();
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    bail!("copy step timed out after {secs}s");
                }
            }
        }
        None => child.wait().await?,
    };

    let _ = out_task.await;
    let _ = err_task.await;
    let _ = read_task.await;

    if !status.success() {
        bail!("scp exited with status {status}");
    }
    Ok(())
}

async fn run_rsync_child(
    ui: ArcUi,
    host: &ResolvedHost,
    mut cmd: Command,
    timeout: Option<u64>,
    diff: bool,
) -> Result<()> {
    let mut child = cmd.spawn().wrap_err("failed to spawn rsync")?;
    let stdout = child.stdout.take().ok_or_else(|| eyre::eyre!("stdout not piped"))?;
    let stderr = child.stderr.take().ok_or_else(|| eyre::eyre!("stderr not piped"))?;

    let (tx, rx) = tokio::sync::mpsc::channel::<(Stream, String)>(256);
    let host_alias = host.alias.clone();
    let out_task = tokio::spawn(forward_stream(stdout, tx.clone(), Stream::Stdout));
    let err_task = tokio::spawn(forward_stream(stderr, tx, Stream::Stderr));

    let read_task = tokio::spawn(async move {
        let mut rx = rx;
        while let Some((stream, line)) = rx.recv().await {
            if diff && stream == Stream::Stdout && !is_rsync_itemize_line(&line) {
                // `--diff`: hide rsync status lines, keep only the itemized
                // change list (`>f…`, `*deleting…`, `.d..t…`).
                continue;
            }
            ui.lock().await.host_line(&host_alias, stream, &line);
        }
    });

    let status = match timeout {
        Some(secs) => {
            let timed_out = tokio::time::timeout(Duration::from_secs(secs), child.wait()).await;
            match timed_out {
                Ok(Ok(status)) => status,
                Ok(Err(err)) => return Err(eyre::Report::new(err)),
                Err(_) => {
                    read_task.abort();
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    bail!("copy step timed out after {secs}s");
                }
            }
        }
        None => child.wait().await?,
    };

    let _ = out_task.await;
    let _ = err_task.await;
    let _ = read_task.await;

    if !status.success() {
        bail!("rsync exited with status {status}");
    }
    Ok(())
}

/// Drain a JoinSet of per-host tasks, mapping failures to a step error.
async fn collect_hosts(
    mut tasks: JoinSet<(String, HostOutcome)>,
) -> Result<Vec<(String, HostOutcome)>> {
    let mut results = Vec::with_capacity(tasks.len());
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(outcome) => results.push(outcome),
            Err(join_err) => return Err(eyre::eyre!("host task failed: {join_err}")),
        }
    }
    Ok(results)
}

/// Whether an rsync stdout line is an `-i` itemized change entry (as opposed
/// to status prose like "sending incremental file list" / "sent N bytes").
fn is_rsync_itemize_line(line: &str) -> bool {
    line.starts_with('>') ||
        line.starts_with('<') ||
        line.starts_with('*') ||
        line.starts_with('.') ||
        line.starts_with('c')
}

/// Format a command's argv for display without exposing env values.
fn display_args(cmd: &Command) -> String {
    cmd.as_std()
        .get_args()
        .map(|arg| {
            let s = arg.to_string_lossy();
            if s.contains(' ') { format!("{s:?}") } else { s.into_owned() }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Convert per-host failures into a step-level error, preferring the first
/// classified failure.
#[must_use]
fn step_error_if_failed(hosts: &[(String, HostOutcome)]) -> Option<RunError> {
    hosts.iter().find_map(|(_, outcome)| match outcome {
        HostOutcome::Failed(err) => Some(*err),
        HostOutcome::TimedOut => Some(RunError::Script),
        HostOutcome::Ok | HostOutcome::Skipped => None,
    })
}
