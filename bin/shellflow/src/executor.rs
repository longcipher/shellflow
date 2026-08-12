//! The execution engine: runs local blocks, streams remote blocks over SSH,
//! and syncs files with rsync, with fan-out, timeouts, and dry-run/diff
//! semantics.
//!
//! All child processes are spawned with `kill_on_drop(true)`, so aborting the
//! run task (on SIGINT/SIGTERM) terminates every in-flight `ssh`/`rsync`/`bash`
//! process — no orphans survive.

use std::{
    collections::HashMap,
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
    cli::RunArgs,
    secrets::resolve_secrets,
    ui::{HostStatus, Outcome, Stream, Ui},
};

/// The error classification mapped to the CLI exit code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    /// A configuration/plan-build failure (exit 1), e.g. secrets resolution.
    Config,
    /// A transport/setup failure (exit 3).
    Transport,
    /// A script execution failure (exit 4).
    Script,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config => write!(f, "configuration failure"),
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
    /// Execute remote blocks/copies on the local machine (`--local`).
    local: bool,
}

impl StepConfig {
    const fn new(run: &RunArgs, timeout: Option<u64>) -> Self {
        Self {
            dry_run: run.flags.dry_run || run.flags.diff,
            diff: run.flags.diff,
            check: run.flags.check,
            verbose: run.flags.verbose,
            timeout,
            local: run.flags.local,
        }
    }
}

/// The login shell detected on a remote host.
///
/// Remote payloads stream over `ssh host <shell> -l -s` so a target sees the
/// same login profile files as a manual `ssh host`. When the probe fails or
/// the shell is unsupported, bash is the fallback, preserving the "targets
/// only need bash" contract (§9).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RemoteShell {
    #[default]
    Bash,
    Zsh,
}

impl RemoteShell {
    /// Detect the shell from the basename of a `$SHELL` value; anything that
    /// is not `zsh` (fish, nushell, unknown, empty) falls back to bash.
    /// Surrounding whitespace (e.g. a trailing newline from `printf`) is
    /// trimmed first.
    #[must_use]
    fn detect(shell: &str) -> Self {
        match shell.trim().rsplit('/').next() {
            Some("zsh") => Self::Zsh,
            _ => Self::Bash,
        }
    }

    /// The interpreter argv passed to `ssh host …`, e.g. `bash -l -s`.
    ///
    /// Syntax checks always run under plain `bash -n -s`: they only need a
    /// parser, never a login environment, and bash is guaranteed present.
    #[must_use]
    const fn invoke(self, syntax_only: bool) -> &'static str {
        if syntax_only {
            return "bash -n -s";
        }
        match self {
            Self::Bash => "bash -l -s",
            Self::Zsh => "zsh -l -s",
        }
    }
}

/// The probed login environment of a remote host: which login shell to use
/// for streaming, the PATH that an interactive login would see, and whether
/// `rsync` is available for copy steps.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RemoteEnv {
    /// Login shell (`bash -l -s` / `zsh -l -s`).
    shell: RemoteShell,
    /// PATH from the user's rc file (where toolchain managers export it).
    ///
    /// The rc file is *not* sourced inside payloads — interactive configs
    /// (oh-my-zsh hooks, aliases, prompts) break `set -eu` in scripts — so we
    /// extract only the resulting PATH during the probe and inject it into
    /// the payload's env block instead.
    path: Option<String>,
    /// Whether the remote host has `rsync` on its PATH (drives the scp
    /// fallback for `@copy`).
    has_rsync: bool,
}

/// Shared, per-run cache of probed remote environments, keyed by ssh
/// destination so a multi-step playbook probes each host exactly once.
type ShellCache = Arc<Mutex<HashMap<String, RemoteEnv>>>;

/// Cache key for a host: `user@host[:port]`.
#[must_use]
fn shell_cache_key(host: &ResolvedHost) -> String {
    match host.spec.port {
        Some(port) => format!("{}:{port}", host.spec.dest()),
        None => host.spec.dest(),
    }
}

/// Execute the plan and return the overall outcome.
///
/// Completed step statistics are appended to `progress` so that a signal
/// cancelling the run can still report what finished before the interrupt.
pub(crate) async fn execute_plan(
    run: &RunArgs,
    plan: ExecutionPlan,
    progress: Progress,
) -> RunOutcome {
    let flags = &run.flags;
    let ui = Arc::new(Mutex::new(Ui::new(
        flags.verbose,
        flags.no_color,
        flags.output,
        flags.log_file.clone(),
    )));

    // Only literal `@env KEY=value` entries are masked: their values are
    // written in the deploy file and may be secrets. Passthrough entries read
    // from shellflow's own environment are already visible to the user and
    // must not be redacted (e.g. `HOME` would otherwise render as `***`).
    let mut secrets: Vec<String> = plan
        .env
        .iter()
        .filter_map(|entry| match entry {
            EnvEntry::Literal { value, .. } => Some(value.clone()),
            EnvEntry::Passthrough { .. } => None,
        })
        .collect();

    let run_state = Arc::new(Mutex::new(RunState::default()));
    // Remote login shells are probed once per host and cached for the whole
    // run (see `RemoteShell` / `resolve_remote_shell`).
    let shell_cache: ShellCache = Arc::new(Mutex::new(HashMap::new()));

    // Resolve `@secrets` before the first step: decrypt, inject into run-state
    // env, and register every value for masking.
    if !plan.secrets.is_empty() {
        match resolve_secrets(&plan.secrets, flags.identity.as_deref(), flags.mask_min_len) {
            Ok((env_pairs, masks)) => {
                secrets.extend(masks);
                let mut state = run_state.lock().await;
                for (key, value) in env_pairs {
                    state.vars.insert(key, value);
                }
            }
            Err(err) => {
                eprintln!("error: {err:#}");
                return RunOutcome::Failed(RunError::Config);
            }
        }
    }
    ui.lock().await.set_secrets(secrets);

    if flags.dry_run {
        crate::ui::dry_run_banner();
    }

    let restrict = run.target_restrict();
    // `--parallel 0` (default) means unbounded, per the documented "all".
    // An `Option` avoids `Semaphore::new(usize::MAX)`, which would exceed
    // tokio's MAX_PERMITS and panic.
    let semaphore: Option<Arc<Semaphore>> =
        (flags.parallel != 0).then(|| Arc::new(Semaphore::new(flags.parallel)));

    // Apply --only / --skip filtering.
    let selected: Vec<(usize, &Step)> =
        plan.steps.iter().enumerate().filter(|(idx, step)| is_selected(run, *idx, step)).collect();
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
        let config = StepConfig::new(run, flags.timeout.or_else(|| step.timeout()));
        let outcome = match step {
            Step::Local(local) => run_local_step(&ui, &run_state, local, config).await,
            Step::Remote(remote) => match resolve_hosts(&plan, &remote.target, &restrict) {
                Ok(hosts) => {
                    run_remote_step(
                        &ui,
                        &semaphore,
                        &run_state,
                        remote,
                        hosts,
                        config,
                        &shell_cache,
                    )
                    .await
                }
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string());
                    fail_fast_error = Some(RunError::Script);
                    continue;
                }
            },
            Step::Copy(copy) => match resolve_hosts(&plan, &copy.target, &restrict) {
                Ok(hosts) => {
                    run_copy_step(&ui, &semaphore, &run_state, copy, hosts, config, &shell_cache)
                        .await
                }
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
            if flags.continue_on_error {
                crate::ui::step_failed(step_no, &err.to_string());
            } else {
                fail_fast_error = Some(err);
            }
        }
    }

    if flags.continue_on_error || fail_fast_error.is_none() {
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
fn is_selected(run: &RunArgs, idx: usize, step: &Step) -> bool {
    let matches_selector = |selector: &str| -> bool {
        if selector == step.name().unwrap_or_default() {
            return true;
        }
        matches!(selector.parse::<usize>(), Ok(n) if n == idx + 1)
    };
    if !run.flags.only.is_empty() && !run.flags.only.iter().any(|s| matches_selector(s)) {
        return false;
    }
    if run.flags.skip.iter().any(|s| matches_selector(s)) {
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

/// Execute a Bash block as a local `bash -c` process, sharing the same
/// `set -eu`/`set -x` header and fail-fast semantics as remote blocks.
///
/// This is the single local-execution primitive used by both local steps and
/// `--local` mode (where remote blocks run on the controller). The `capture`
/// argument, when non-empty, appends `@export` capture lines and reads the
/// values back into `run_state` afterwards.
async fn run_local_block(
    ui: &ArcUi,
    run_state: &Arc<Mutex<RunState>>,
    script: &str,
    env: &[EnvEntry],
    config: StepConfig,
    capture: &[String],
) -> Result<()> {
    if config.check || config.dry_run {
        run_bash_n(script).await?;
        crate::ui::note("  ↳ local syntax check (bash -n): OK");
        return Ok(());
    }

    let resolved = build_env(run_state, env).await;
    let mut cmd = Command::new("bash");
    cmd.arg("-c");
    cmd.envs(resolved);

    // `set -eu` by default, `set -eux` at -vvv, so local and remote blocks
    // share the same fail-fast semantics.
    let header = if config.verbose >= 3 { "set -eux\n" } else { "set -eu\n" };
    let body =
        if capture.is_empty() { script.to_string() } else { append_capture(script, capture) };
    cmd.arg(format!("{header}{body}"));

    let capture_path = if capture.is_empty() {
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

    if config.verbose >= 2 {
        crate::ui::note(&format!("  ↳ local command: bash -c {:?}", body));
    }

    // Stream output through the UI so secrets are masked and `--log-file`
    // captures local output too.
    let status = run_bash_streamed(ui, "localhost", cmd, config.timeout).await?;

    if !status.success() {
        bail!("local script exited with status {status}");
    }

    if let Some(path) = capture_path {
        capture_exports(run_state, capture, &path).await?;
    }
    Ok(())
}

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

    match run_local_block(ui, run_state, &local.script, &local.env, config, &local.export).await {
        Ok(()) => Ok(vec![("localhost".to_string(), HostOutcome::Ok)]),
        Err(err) => Err(err),
    }
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

/// Run a child process to completion, honoring the timeout with a friendly
/// kill + message.
async fn run_command_status(
    mut cmd: Command,
    timeout: Option<u64>,
    label: &str,
) -> Result<std::process::ExitStatus> {
    let status = match timeout {
        Some(secs) => match tokio::time::timeout(Duration::from_secs(secs), cmd.status()).await {
            Ok(Ok(status)) => status,
            Ok(Err(err)) => return Err(err).wrap_err(format!("failed to run {label}")),
            Err(_) => {
                crate::ui::warn(&format!("{label} timed out — killed"));
                bail!("{label} timed out after {secs}s");
            }
        },
        None => cmd.status().await.wrap_err(format!("failed to run {label}"))?,
    };
    Ok(status)
}

/// Run a local `bash`/child, streaming stdout/stderr through the UI so secret
/// masking and `--log-file` apply to local output too.
async fn run_bash_streamed(
    ui: &ArcUi,
    host: &str,
    mut cmd: Command,
    timeout: Option<u64>,
) -> Result<std::process::ExitStatus> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().wrap_err("failed to spawn bash")?;

    let stdout = child.stdout.take().ok_or_else(|| eyre::eyre!("stdout not piped"))?;
    let stderr = child.stderr.take().ok_or_else(|| eyre::eyre!("stderr not piped"))?;

    let (tx, rx) = tokio::sync::mpsc::channel::<(Stream, String)>(256);
    let host_alias = host.to_string();
    let out_task = tokio::spawn(forward_stream(stdout, tx.clone(), Stream::Stdout));
    let err_task = tokio::spawn(forward_stream(stderr, tx, Stream::Stderr));

    let ui_handle = Arc::clone(ui);
    let read_task = tokio::spawn(async move {
        let mut rx = rx;
        while let Some((stream, line)) = rx.recv().await {
            ui_handle.lock().await.host_line(&host_alias, stream, &line);
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
                    bail!("local step timed out after {secs}s");
                }
            }
        }
        None => child.wait().await?,
    };

    let _ = out_task.await;
    let _ = err_task.await;
    let _ = read_task.await;
    Ok(status)
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
    shell_cache: &ShellCache,
) -> Result<Vec<(String, HostOutcome)>> {
    if config.local {
        return run_remote_step_local(ui, run_state, remote, config).await;
    }

    if config.dry_run || config.verbose >= 2 {
        ui.lock()
            .await
            .payload_preview(&format!("Remote Payload ({})", remote.target.text), &remote.script);
    }

    let env = build_env(run_state, &remote.env).await;
    let trace_line = if config.verbose >= 3 { "set -x\n" } else { "" };
    // The payload is assembled per host: each host's probed login PATH is
    // injected into its env block, so the rc file never needs sourcing inside
    // the payload (interactive configs break `set -eu` in scripts).
    let parts = PayloadParts {
        script: remote.script.clone(),
        guard: remote.guard.clone(),
        env,
        trace_line,
    };
    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let semaphore = semaphore.clone();
        let parts = parts.clone();
        let shell_cache = Arc::clone(shell_cache);
        tasks.spawn(async move {
            if let Some(semaphore) = &semaphore {
                let _permit = Arc::clone(semaphore).acquire_owned().await;
            }
            run_remote_host(ui, &host, &parts, config, shell_cache).await
        });
    }

    collect_hosts(tasks).await
}

/// `--local` mode: run a remote block's payload through the local `bash`
/// (once, not per host). Guards are evaluated locally; dry-run/check use
/// `bash -n`. This makes playbooks debuggable on a machine with no SSH access
/// to the targets.
async fn run_remote_step_local(
    ui: &ArcUi,
    run_state: &Arc<Mutex<RunState>>,
    remote: &RemoteStep,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    if config.dry_run || config.verbose >= 2 {
        ui.lock().await.payload_preview(
            &format!("Local Payload (remote block @{})", remote.target.text),
            &remote.script,
        );
    }

    if let Some(guard) = &remote.guard &&
        !run_local_guard(guard, config.timeout).await
    {
        crate::ui::note("  ↳ local guard failed — skipping block");
        return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
    }

    // Reuse the local execution primitive; remote blocks have no `@export`.
    match run_local_block(ui, run_state, &remote.script, &remote.env, config, &[]).await {
        Ok(()) => Ok(vec![("localhost".to_string(), HostOutcome::Ok)]),
        Err(err) => Err(err),
    }
}

/// The per-block payload inputs shared across hosts.
///
/// The env is extended per host with that host's probed login PATH before the
/// payload is assembled (see [`with_login_path`]).
#[derive(Clone)]
struct PayloadParts {
    /// The block's Bash lines, verbatim.
    script: String,
    /// Optional `@only_if` guard command.
    guard: Option<String>,
    /// The block env (`@env`/`@export` state).
    env: Vec<(String, String)>,
    /// `set -x\n` at `-vvv`, otherwise empty.
    trace_line: &'static str,
}

async fn run_remote_host(
    ui: ArcUi,
    host: &ResolvedHost,
    parts: &PayloadParts,
    config: StepConfig,
    shell_cache: ShellCache,
) -> (String, HostOutcome) {
    // Dry-run/check: syntax-check the payload on each host, never execute.
    // No env probe: plain `bash -n -s` needs no login environment.
    if config.check || config.dry_run {
        let payload =
            format!("set -eu\n{}{}{}", render_env(&parts.env), parts.trace_line, parts.script);
        if config.verbose >= 2 {
            let cmd = build_ssh_cmd(host, RemoteShell::Bash, true, config);
            crate::ui::note(&format!("  [{}] ssh {}", host.alias, display_args(&cmd)));
        }
        return match run_ssh_child(
            ui,
            host,
            build_ssh_cmd(host, RemoteShell::Bash, true, config),
            &payload,
            config.timeout,
        )
        .await
        {
            Ok(()) => {
                crate::ui::note(&format!("[{}] syntax check (bash -n): OK", host.alias));
                (host.alias.clone(), HostOutcome::Ok)
            }
            Err(outcome) => {
                crate::ui::warn(&format!("[{}] {outcome:?}", host.alias));
                (host.alias.clone(), classify_ssh(outcome))
            }
        };
    }

    // Real run: probe (and cache) the login environment once, evaluate the
    // guard, then stream the payload — all with the probed PATH injected.
    let remote_env = resolve_remote_env(host, &shell_cache).await;
    let payload_env = with_login_path(parts.env.clone(), remote_env.path.as_deref());
    if let Some(guard) = &parts.guard {
        match run_remote_guard(host, remote_env.shell, guard, &payload_env, config.timeout).await {
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

    let payload =
        format!("set -eu\n{}{}{}", render_env(&payload_env), parts.trace_line, parts.script);
    let cmd = build_ssh_cmd(host, remote_env.shell, false, config);
    if config.verbose >= 2 {
        crate::ui::note(&format!("  [{}] ssh {}", host.alias, display_args(&cmd)));
    }
    match run_ssh_child(ui, host, cmd, &payload, config.timeout).await {
        Ok(()) => (host.alias.clone(), HostOutcome::Ok),
        Err(outcome) => {
            crate::ui::warn(&format!("[{}] {outcome:?}", host.alias));
            (host.alias.clone(), classify_ssh(outcome))
        }
    }
}

/// Layer the probed login PATH onto the block env: an explicit `@env
/// PATH=…`/`@export PATH` always wins, otherwise the probe result is used.
#[must_use]
fn with_login_path(mut env: Vec<(String, String)>, path: Option<&str>) -> Vec<(String, String)> {
    if env.iter().any(|(k, _)| k == "PATH") {
        return env;
    }
    if let Some(path) = path {
        env.push(("PATH".to_string(), path.to_string()));
    }
    env
}

/// Build the `ssh` command for a host: `ssh [-p port] [-v] host <interp>`.
///
/// Real runs use the host's login shell (`<shell> -l -s`) so remote blocks
/// see the user's login PATH; syntax checks stay on plain `bash -n -s`.
fn build_ssh_cmd(
    host: &ResolvedHost,
    shell: RemoteShell,
    syntax_only: bool,
    config: StepConfig,
) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    if config.verbose >= 3 {
        cmd.arg("-v");
    }
    cmd.arg(shell.invoke(syntax_only));
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.kill_on_drop(true);
    cmd
}

/// Look up (or probe and cache) the login environment for a host.
///
/// The probe is a single `ssh host …` round trip, run once per host per
/// playbook run (the cache lives for the whole run).
async fn resolve_remote_env(host: &ResolvedHost, cache: &ShellCache) -> RemoteEnv {
    let key = shell_cache_key(host);
    if let Some(env) = cache.lock().await.get(&key) {
        return env.clone();
    }
    let env = probe_remote_env(host).await;
    cache.lock().await.insert(key, env.clone());
    env
}

/// The remote probe script: prints the login shell on line 1 and the PATH
/// that an interactive login would see on line 2.
///
/// The rc file is sourced *inside the probe shell only* (`>/dev/null 2>&1`
/// keeps any greeting or noise off stdout) so the resulting PATH — including
/// toolchain managers' entries — is captured without ever loading the rc's
/// hooks/aliases into a `set -eu` payload. A missing rc, an unknown shell,
/// or a probe failure simply leaves the PATH unset (payloads then run with
/// the plain ssh PATH).
const PROBE_SCRIPT: &str = r#"
{
    printf '%s\n' "$SHELL";
    if [ -n "$ZSH_VERSION" ]; then
        . "$HOME/.zshrc" >/dev/null 2>&1 || true
    elif [ -n "$BASH_VERSION" ]; then
        . "$HOME/.bashrc" >/dev/null 2>&1 || true
    fi
    printf '%s\n' "$PATH";
}
"#;

/// Probe the remote login environment (shell + rc-extended PATH + rsync
/// availability) over ssh. The shell/PATH probe and the rsync probe are run in
/// a single ssh round trip so a host is probed exactly once per run and the
/// result is cached (see [`resolve_remote_env`]).
///
/// A failed, timed-out, or empty probe falls back to a plain bash environment
/// with no rsync (the scp fallback then applies for `@copy`).
async fn probe_remote_env(host: &ResolvedHost) -> RemoteEnv {
    // Combine the login-shell probe and the rsync probe into one script so a
    // single ssh connection yields both facts.
    let script = format!(
        "{}\ncommand -v rsync >/dev/null 2>&1 && echo SHELLFLOW_HAS_RSYNC",
        PROBE_SCRIPT.trim()
    );
    let mut cmd = Command::new("ssh");
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    cmd.arg(script);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.kill_on_drop(true);
    let output = match tokio::time::timeout(Duration::from_secs(15), cmd.output()).await {
        Ok(Ok(output)) if output.status.success() => output,
        _ => return RemoteEnv::default(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let shell = RemoteShell::detect(lines.next().unwrap_or_default());
    let path = lines.next().filter(|p| !p.is_empty()).map(ToOwned::to_owned);
    let has_rsync = lines.any(|l| l == "SHELLFLOW_HAS_RSYNC");
    RemoteEnv { shell, path, has_rsync }
}

/// The classified result of an SSH child process (remote payload or guard).
///
/// This replaces fragile string matching on `eyre` messages: every failure
/// path constructs one of these variants explicitly, so transport vs. script
/// vs. timeout classification is centralized and cannot drift from wording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshOutcome {
    /// Connection/setup failure (e.g. ssh exit 255, unreachable host).
    Transport,
    /// The remote command exited non-zero.
    Script,
    /// The transfer exceeded its timeout and was killed.
    TimedOut,
}

/// Map a classified SSH result to a host outcome.
const fn classify_ssh(outcome: SshOutcome) -> HostOutcome {
    match outcome {
        SshOutcome::Transport => HostOutcome::Failed(RunError::Transport),
        SshOutcome::Script => HostOutcome::Failed(RunError::Script),
        SshOutcome::TimedOut => HostOutcome::TimedOut,
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

/// Evaluate a guard command on a remote host via `ssh host <shell> -l -s`.
///
/// The guard runs under the same login shell and env header (including the
/// probed login PATH) as the block it guards. Subject to the same
/// `--timeout`/`@timeout`; a timed-out or unreachable guard is treated as a
/// transport failure.
async fn run_remote_guard(
    host: &ResolvedHost,
    shell: RemoteShell,
    guard: &str,
    env: &[(String, String)],
    timeout: Option<u64>,
) -> GuardResult {
    let mut cmd = Command::new("ssh");
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    cmd.arg(shell.invoke(false));
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
) -> Result<(), SshOutcome> {
    let mut child = cmd.spawn().map_err(|_| SshOutcome::Transport)?;

    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(payload.as_bytes()).await.is_err() {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(SshOutcome::Transport);
        }
        drop(stdin);
    }

    let stdout = child.stdout.take().ok_or(SshOutcome::Transport)?;
    let stderr = child.stderr.take().ok_or(SshOutcome::Transport)?;

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
                Ok(Err(_)) => {
                    let _ = out_task.await;
                    let _ = err_task.await;
                    let _ = read_task.await;
                    return Err(SshOutcome::Transport);
                }
                Err(_) => {
                    read_task.abort();
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    let _ = out_task.await;
                    let _ = err_task.await;
                    return Err(SshOutcome::TimedOut);
                }
            }
        }
        None => {
            if let Ok(status) = child.wait().await {
                status
            } else {
                let _ = out_task.await;
                let _ = err_task.await;
                let _ = read_task.await;
                return Err(SshOutcome::Transport);
            }
        }
    };

    // Drain remaining buffered output.
    let _ = out_task.await;
    let _ = err_task.await;
    let _ = read_task.await;

    if !status.success() {
        if status.code() == Some(255) {
            return Err(SshOutcome::Transport);
        }
        return Err(SshOutcome::Script);
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
    shell_cache: &ShellCache,
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

    if config.local {
        return run_copy_step_local(ui, &src, &dst, copy.delete, config).await;
    }

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
        let shell_cache = Arc::clone(shell_cache);
        tasks.spawn(async move {
            if let Some(semaphore) = &semaphore {
                let _permit = Arc::clone(semaphore).acquire_owned().await;
            }
            // Reuse the per-run login-env cache, which now also carries the
            // rsync probe — no extra ssh round trip per copy step (design §7.4).
            let has_rsync = resolve_remote_env(&host, &shell_cache).await.has_rsync;
            run_rsync_host(ui, &host, &src, &dst, delete, config, has_rsync).await
        });
    }

    collect_hosts(tasks).await
}

/// `--local` mode: mirror a copy step with a local `cp -a` (once). `--delete`
/// clears the destination first. Debugging only; remote delta semantics do
/// not apply.
async fn run_copy_step_local(
    _ui: &ArcUi,
    src: &str,
    dst: &str,
    delete: bool,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    if config.check {
        crate::ui::note("  ↳ syntax check: copy step (no execution)");
        return Ok(vec![("localhost".to_string(), HostOutcome::Ok)]);
    }
    if config.dry_run || config.verbose >= 2 {
        crate::ui::note(&format!("  ↳ local copy {src} -> {dst}"));
    }
    if config.dry_run {
        return Ok(vec![("localhost".to_string(), HostOutcome::Ok)]);
    }

    if delete {
        let _ = std::fs::remove_dir_all(dst);
        let _ = std::fs::remove_file(dst);
    }

    if let Some(parent) = std::path::Path::new(dst).parent() &&
        !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
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

async fn run_rsync_host(
    ui: ArcUi,
    host: &ResolvedHost,
    src: &str,
    dst: &str,
    delete: bool,
    config: StepConfig,
    has_rsync: bool,
) -> (String, HostOutcome) {
    let remote_shell = host.spec.rsync_remote_shell().unwrap_or_else(|| "ssh".to_string());

    // When the target lacks `rsync` (common on minimal hosts), fall back to
    // `ssh mkdir -p` + `scp` so `@copy` still works and the target only ever
    // needs `bash` (design §9). `has_rsync` comes from the per-run cache, not a
    // fresh probe.
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
///
/// rsync's itemize format is a fixed 11-column summary followed by a space and
/// the path (e.g. `>f+++++++++ path`, `*deleting   path`). We require that
/// shape rather than just a leading character, so normal command output that
/// happens to start with `>`, `<`, `*`, `.`, or `c` is never swallowed by
/// `--diff`.
fn is_rsync_itemize_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    // A normal itemize line is a 10-character summary followed by a space and
    // the path. rsync also emits a shorter "*deleting  <path>" marker for
    // removals, which we accept as well.
    if line.starts_with("*deleting") {
        return bytes.len() > "*deleting".len() && bytes["*deleting".len()] == b' ';
    }
    // Need at least the 10-letter summary, a separator space, and a path.
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

#[cfg(test)]
mod tests {
    use shellflow_core::{ResolvedHost, SshSpec};

    use super::{RemoteEnv, RemoteShell, shell_cache_key, with_login_path};

    #[test]
    fn detects_bash_and_zsh() {
        assert_eq!(RemoteShell::detect("/usr/bin/bash"), RemoteShell::Bash);
        assert_eq!(RemoteShell::detect("/bin/zsh"), RemoteShell::Zsh);
        assert_eq!(RemoteShell::detect("fish"), RemoteShell::Bash);
        assert_eq!(RemoteShell::detect(""), RemoteShell::Bash);
        // Probe output often carries a trailing newline; it must be trimmed.
        assert_eq!(RemoteShell::detect("/bin/zsh\n"), RemoteShell::Zsh);
    }

    #[test]
    fn invokes_login_interpreter() {
        assert_eq!(RemoteShell::Bash.invoke(false), "bash -l -s");
        assert_eq!(RemoteShell::Zsh.invoke(false), "zsh -l -s");
        // Syntax checks never need a login environment.
        assert_eq!(RemoteShell::Bash.invoke(true), "bash -n -s");
        assert_eq!(RemoteShell::Zsh.invoke(true), "bash -n -s");
    }

    #[test]
    fn shell_cache_key_includes_port() {
        let host =
            ResolvedHost { alias: "web".to_string(), spec: SshSpec::parse("deploy@h1").unwrap() };
        assert_eq!(shell_cache_key(&host), "deploy@h1");
        let host = ResolvedHost {
            alias: "web".to_string(),
            spec: SshSpec::parse("deploy@h1:2222").unwrap(),
        };
        assert_eq!(shell_cache_key(&host), "deploy@h1:2222");
    }

    #[test]
    fn login_path_is_appended_to_env() {
        let env = with_login_path(vec![("K".to_string(), "v".to_string())], Some("/opt/bin"));
        assert_eq!(
            env,
            vec![("K".to_string(), "v".to_string()), ("PATH".to_string(), "/opt/bin".to_string())]
        );
    }

    #[test]
    fn missing_path_leaves_env_unchanged() {
        let env = with_login_path(vec![("K".to_string(), "v".to_string())], None);
        assert_eq!(env, vec![("K".to_string(), "v".to_string())]);
    }

    #[test]
    fn explicit_path_wins_over_probe() {
        let env =
            with_login_path(vec![("PATH".to_string(), "/explicit".to_string())], Some("/probed"));
        assert_eq!(env, vec![("PATH".to_string(), "/explicit".to_string())]);
    }

    #[test]
    fn probe_script_sources_rc_only_in_the_probe_shell() {
        // The probe sources the rc inside the probe shell only; the payload
        // env carries the extracted PATH, never the rc itself.
        assert!(super::PROBE_SCRIPT.contains(". \"$HOME/.zshrc\""), "zsh rc branch missing");
        assert!(super::PROBE_SCRIPT.contains(". \"$HOME/.bashrc\""), "bash rc branch missing");
        assert!(super::PROBE_SCRIPT.contains(">/dev/null 2>&1"), "rc output must be silenced");
        assert!(super::PROBE_SCRIPT.contains("printf '%s\\n' \"$PATH\""), "PATH must be printed");
    }

    #[test]
    fn rsync_itemize_detection_is_strict() {
        // A real itemize line: 10-letter summary, space, path.
        assert!(super::is_rsync_itemize_line(">f++++++++ target/release/app"));
        assert!(super::is_rsync_itemize_line("*deleting   old-app"));
        // Status prose is NOT an itemize line.
        assert!(!super::is_rsync_itemize_line("sending incremental file list"));
        assert!(!super::is_rsync_itemize_line("sent 1,234 bytes  received 56 bytes"));
        // A normal command line that happens to start with '>' is NOT swallowed.
        assert!(!super::is_rsync_itemize_line("> important output from my script"));
        // Too short to be an itemize line.
        assert!(!super::is_rsync_itemize_line(">f+ path"));
    }

    #[test]
    fn remote_env_defaults_to_plain_bash() {
        let env = RemoteEnv::default();
        assert_eq!(env.shell, RemoteShell::Bash);
        assert_eq!(env.path, None);
    }
}
