//! Remote step execution: SSH streaming with login-shell parity, per-host
//! fan-out with semaphore, and remote guard evaluation.

use std::{collections::HashMap, sync::Arc, time::Duration};

use eyre::Result;
use shellflow_core::{ResolvedHost, RunState, render_env};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use super::{
    ArcUi, CopyStepArgs, HostOutcome, LogFile, ShellCache, StepConfig,
    local::{build_env, run_local_block, run_local_guard},
    process::{GroupGuard, isolate},
    stream,
};
use crate::{secrets::ResolvedSecrets, ui::HostStatus};

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

/// The login shell detected on a remote host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum RemoteShell {
    #[default]
    Bash,
    Zsh,
}

impl RemoteShell {
    #[must_use]
    fn detect(shell: &str) -> Self {
        match shell.trim().rsplit('/').next() {
            Some("zsh") => Self::Zsh,
            _ => Self::Bash,
        }
    }

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

/// The probed login environment of a remote host.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RemoteEnv {
    pub(crate) shell: RemoteShell,
    pub(crate) path: Option<String>,
    pub(crate) has_rsync: bool,
}

/// Shared handles threaded through a remote step's host fan-out.
pub(crate) struct RemoteStepCtx<'a> {
    pub(crate) ui: &'a ArcUi,
    pub(crate) semaphore: &'a Option<Arc<Semaphore>>,
    pub(crate) run_state: &'a Arc<Mutex<RunState>>,
    pub(crate) shell_cache: &'a ShellCache,
    pub(crate) secrets: &'a Arc<ResolvedSecrets>,
    pub(crate) log_file: &'a LogFile,
}

/// Fully-initialized per-run state, built once by [`setup_run`] so
/// [`execute_plan`] stays a lean schedule loop.
struct RunSetup {
    ui: ArcUi,
    log_file: LogFile,
    run_state: Arc<Mutex<RunState>>,
    shell_cache: ShellCache,
    semaphore: Option<Arc<Semaphore>>,
    resolved: Arc<ResolvedSecrets>,
    restrict: Vec<String>,
    selected: Vec<(usize, shellflow_core::Step)>,
    total: usize,
}

/// Build every per-run handle: UI + masks, run state, host selection, secret
/// resolution, and the fan-out semaphore.
///
/// Returns `None` when setup itself fails (the failure is already reported);
/// every setup failure maps to [`RunError::Config`].
async fn setup_run(
    run: &crate::cli::RunArgs,
    plan: &shellflow_core::ExecutionPlan,
) -> Option<RunSetup> {
    let flags = &run.flags;
    let ui: ArcUi = Arc::new(Mutex::new(crate::ui::Ui::new(
        flags.verbose,
        flags.no_color,
        flags.output,
        flags.log_file.clone(),
    )));

    let log_file = ui.lock().await.log_file();

    let mut secrets: Vec<String> = plan
        .env
        .iter()
        .filter_map(|entry| match entry {
            shellflow_core::EnvEntry::Literal { value, .. } => Some(value.clone()),
            shellflow_core::EnvEntry::Passthrough { .. } => None,
        })
        .collect();

    let run_state = Arc::new(Mutex::new(RunState::default()));
    let shell_cache: ShellCache = Arc::new(Mutex::new(HashMap::new()));

    let restrict = run.target_restrict();
    let selected: Vec<(usize, shellflow_core::Step)> = plan
        .steps
        .iter()
        .enumerate()
        .filter(|(idx, step)| is_selected(run, *idx, step))
        .map(|(idx, step)| (idx, step.clone()))
        .collect();

    let host_aliases = target_host_aliases(plan, &restrict, &selected, &log_file);

    let resolved = if plan.secrets.is_empty() {
        ResolvedSecrets::empty()
    } else {
        match crate::secrets::resolve_secrets(
            &plan.secrets,
            &host_aliases,
            flags.identity.as_deref(),
            run.mask_min_len(),
        ) {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("error: {err:#}");
                return None;
            }
        }
    };

    secrets.extend(resolved.masks().iter().cloned());
    {
        let mut state = run_state.lock().await;
        for (key, value) in resolved.shared_env() {
            state.vars.insert(key.clone(), value.clone());
        }
    }
    ui.lock().await.set_secrets(secrets);

    if flags.local && resolved.has_per_host() && host_aliases.len() > 1 {
        eprintln!(
            "error: `--local` cannot resolve per-host `@secrets` ({{host}}) across {} hosts; \
             re-run with `-t <host>`",
            host_aliases.len()
        );
        return None;
    }

    let resolved = Arc::new(resolved);

    if flags.dry_run {
        crate::ui::dry_run_banner(&log_file);
    }

    let semaphore: Option<Arc<Semaphore>> =
        (flags.parallel != 0).then(|| Arc::new(Semaphore::new(flags.parallel)));

    let total = selected.len();

    if ui.lock().await.verbosity().info() {
        ui.lock().await.plan_preview(plan);
    }

    Some(RunSetup {
        ui,
        log_file,
        run_state,
        shell_cache,
        semaphore,
        resolved,
        restrict,
        selected,
        total,
    })
}

/// Dispatch one selected step to its executor (local / remote / copy).
///
/// Target-resolution failures are reported inline and returned as
/// `Some(RunError::Script)` with an empty outcome, so the caller records a
/// fail-fast error and moves on.
async fn run_single_step(
    setup: &RunSetup,
    plan: &shellflow_core::ExecutionPlan,
    run: &crate::cli::RunArgs,
    step_no: usize,
    step: &shellflow_core::Step,
) -> (Option<RunError>, eyre::Result<Vec<(String, HostOutcome)>>) {
    let config = StepConfig::new(run, run.flags.timeout.or_else(|| step.timeout()));
    match step {
        shellflow_core::Step::Local(local) => {
            let outcome =
                super::local::run_local_step(&setup.ui, &setup.run_state, local, config).await;
            (None, outcome)
        }
        shellflow_core::Step::Remote(remote) => {
            match shellflow_core::resolve_hosts(plan, &remote.target, &setup.restrict) {
                Ok(hosts) => {
                    let ctx = RemoteStepCtx {
                        ui: &setup.ui,
                        semaphore: &setup.semaphore,
                        run_state: &setup.run_state,
                        shell_cache: &setup.shell_cache,
                        secrets: &setup.resolved,
                        log_file: &setup.log_file,
                    };
                    (None, run_remote_step(&ctx, remote, hosts, config).await)
                }
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
                    (Some(RunError::Script), Ok(Vec::new()))
                }
            }
        }
        shellflow_core::Step::Copy(copy) => {
            match shellflow_core::resolve_hosts(plan, &copy.target, &setup.restrict) {
                Ok(hosts) => {
                    let copy_args = CopyStepArgs {
                        ui: Arc::clone(&setup.ui),
                        semaphore: setup.semaphore.clone(),
                        run_state: Arc::clone(&setup.run_state),
                        shell_cache: Arc::clone(&setup.shell_cache),
                        log_file: setup.log_file.clone(),
                    };
                    (None, super::copy::run_copy_step(&copy_args, copy, hosts, config).await)
                }
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
                    (Some(RunError::Script), Ok(Vec::new()))
                }
            }
        }
    }
}

/// Execute the plan and return the overall outcome.
pub(crate) async fn execute_plan(
    run: &crate::cli::RunArgs,
    plan: shellflow_core::ExecutionPlan,
    progress: super::Progress,
) -> RunOutcome {
    let flags = &run.flags;
    let Some(setup) = setup_run(run, &plan).await else {
        return RunOutcome::Failed(RunError::Config);
    };
    let (ui, log_file, total) = (Arc::clone(&setup.ui), setup.log_file.clone(), setup.total);

    let mut stats: Vec<super::StepStats> = Vec::new();
    let mut fail_fast_error: Option<RunError> = None;
    let mut first_error: Option<RunError> = None;

    for (pos, (_idx, step)) in setup.selected.iter().enumerate() {
        if fail_fast_error.is_some() {
            break;
        }
        let step_no = pos + 1;
        crate::ui::step_header(step_no, total, step, &log_file);

        let started = std::time::Instant::now();
        let (resolve_err, outcome) = run_single_step(&setup, &plan, run, step_no, step).await;
        if let Some(err) = resolve_err {
            fail_fast_error = Some(err);
            continue;
        }

        ui.lock().await.flush_grouped();
        let elapsed = started.elapsed();
        let statuses = super::outcome_to_statuses(&outcome);
        crate::ui::step_outcome(elapsed, &statuses, &log_file);
        let step_stats = super::StepStats { index: step_no, elapsed, statuses };
        progress.lock().await.push(step_stats.clone());
        stats.push(step_stats);

        let step_err: Option<RunError> = match &outcome {
            Err(join_err) => {
                crate::ui::warn(&format!("step failed: {join_err:#}"), &log_file);
                Some(RunError::Script)
            }
            Ok(hosts) => super::step_error_if_failed(hosts),
        };

        if let Some(err) = step_err {
            if first_error.is_none() {
                first_error = Some(err);
            }
            if flags.continue_on_error {
                crate::ui::step_failed(step_no, &err.to_string(), &log_file);
            } else {
                fail_fast_error = Some(err);
            }
        }
    }

    if flags.continue_on_error || fail_fast_error.is_none() {
        let summary: Vec<(usize, Duration, Vec<HostStatus>)> =
            stats.iter().map(|s| (s.index, s.elapsed, s.statuses.clone())).collect();
        crate::ui::final_summary(&summary, &log_file);
    }

    match fail_fast_error.or(first_error) {
        Some(err) => RunOutcome::Failed(err),
        None => RunOutcome::Success,
    }
}

fn is_selected(run: &crate::cli::RunArgs, idx: usize, step: &shellflow_core::Step) -> bool {
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

fn target_host_aliases(
    plan: &shellflow_core::ExecutionPlan,
    restrict: &[String],
    selected: &[(usize, shellflow_core::Step)],
    log_file: &LogFile,
) -> Vec<String> {
    let mut aliases = std::collections::BTreeSet::new();
    for (_, step) in selected {
        let target = match step {
            shellflow_core::Step::Remote(remote) => &remote.target,
            shellflow_core::Step::Copy(copy) => &copy.target,
            shellflow_core::Step::Local(_) => continue,
        };
        match shellflow_core::resolve_hosts(plan, target, restrict) {
            Ok(hosts) => {
                aliases.extend(
                    hosts
                        .into_iter()
                        .map(|host| host.alias)
                        .filter(|alias| plan.servers.contains_key(alias)),
                );
            }
            Err(err) => {
                crate::ui::warn(
                    &format!("target `{}` skipped for secrets pre-resolution: {err}", target.text),
                    log_file,
                );
            }
        }
    }
    aliases.into_iter().collect()
}

#[derive(Clone)]
pub(super) struct PayloadParts {
    pub(super) script: String,
    pub(super) guard: Option<String>,
    pub(super) env: Vec<(String, String)>,
    pub(super) trace_line: &'static str,
}

pub(super) async fn run_remote_step(
    ctx: &RemoteStepCtx<'_>,
    remote: &shellflow_core::RemoteStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    if config.local {
        let alias = hosts.first().map(|host| host.alias.clone());
        return run_remote_step_local(
            ctx.ui,
            ctx.run_state,
            remote,
            config,
            ctx.secrets,
            alias.as_deref(),
            ctx.log_file,
        )
        .await;
    }

    if config.dry_run || config.verbose >= 2 {
        ctx.ui
            .lock()
            .await
            .payload_preview(&format!("Remote Payload ({})", remote.target.text), &remote.script);
    }

    let env = build_env(ctx.run_state, &remote.env).await;
    let trace_line = if config.verbose >= 3 { "set -x\n" } else { "" };
    let parts = PayloadParts {
        script: remote.script.clone(),
        guard: remote.guard.clone(),
        env,
        trace_line,
    };
    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ctx.ui);
        let semaphore = ctx.semaphore.clone();
        let parts = parts.clone();
        let shell_cache = Arc::clone(ctx.shell_cache);
        let secrets = Arc::clone(ctx.secrets);
        let log_file = ctx.log_file.clone();
        tasks.spawn(async move {
            let _permit = match &semaphore {
                Some(semaphore) => Arc::clone(semaphore).acquire_owned().await.ok(),
                None => None,
            };
            run_remote_host(ui, &host, &parts, config, shell_cache, &secrets, &log_file).await
        });
    }

    stream::collect_hosts(tasks).await
}

async fn run_remote_step_local(
    ui: &ArcUi,
    run_state: &Arc<Mutex<RunState>>,
    remote: &shellflow_core::RemoteStep,
    config: StepConfig,
    secrets: &Arc<ResolvedSecrets>,
    host_alias: Option<&str>,
    log_file: &LogFile,
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
        crate::ui::note("  local guard failed — skipping block", log_file);
        return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
    }

    let extra: Vec<(String, String)> = host_alias
        .and_then(|alias| secrets.host_pairs(alias))
        .map_or_default(|pairs| pairs.to_vec());
    let args = super::LocalBlockArgs {
        ui,
        run_state,
        script: &remote.script,
        env: &remote.env,
        config,
        capture: &[],
        extra: &extra,
        log_file,
    };
    match run_local_block(&args).await {
        Ok(()) => Ok(vec![("localhost".to_string(), HostOutcome::Ok)]),
        Err(err) => Err(err),
    }
}

async fn run_remote_host(
    ui: ArcUi,
    host: &ResolvedHost,
    parts: &PayloadParts,
    config: StepConfig,
    shell_cache: ShellCache,
    secrets: &Arc<ResolvedSecrets>,
    log_file: &LogFile,
) -> (String, HostOutcome) {
    if config.check || config.dry_run {
        let payload =
            format!("set -eu\n{}{}{}", render_env(&parts.env), parts.trace_line, parts.script);
        if config.verbose >= 2 {
            let cmd = build_ssh_cmd(host, RemoteShell::Bash, true, config);
            crate::ui::note(
                &format!("  [{}] ssh {}", host.alias, super::display_args(&cmd)),
                log_file,
            );
        }
        return match run_ssh_child(
            ui,
            host,
            build_ssh_cmd(host, RemoteShell::Bash, true, config),
            &payload,
            config.timeout,
            log_file,
        )
        .await
        {
            Ok(()) => {
                crate::ui::note(&format!("[{}] syntax check (bash -n): OK", host.alias), log_file);
                (host.alias.clone(), HostOutcome::Ok)
            }
            Err(outcome) => {
                crate::ui::warn(&format!("[{}] {outcome:?}", host.alias), log_file);
                (host.alias.clone(), classify_ssh(outcome))
            }
        };
    }

    let remote_env = resolve_remote_env(host, &shell_cache).await;
    let mut payload_env = with_login_path(parts.env.clone(), remote_env.path.as_deref());
    secrets.overlay(&mut payload_env, &host.alias);
    if let Some(guard) = &parts.guard {
        match run_remote_guard(host, remote_env.shell, guard, &payload_env, config.timeout).await {
            GuardResult::Pass => {
                if config.verbose >= 2 {
                    crate::ui::note(&format!("  [{}] guard passed: {guard}", host.alias), log_file);
                }
            }
            GuardResult::Fail => {
                crate::ui::note(&format!("[{}] SKIPPED (guard)", host.alias), log_file);
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
        crate::ui::note(&format!("  [{}] ssh {}", host.alias, super::display_args(&cmd)), log_file);
    }
    match run_ssh_child(ui, host, cmd, &payload, config.timeout, log_file).await {
        Ok(()) => (host.alias.clone(), HostOutcome::Ok),
        Err(outcome) => {
            crate::ui::warn(&format!("[{}] {outcome:?}", host.alias), log_file);
            (host.alias.clone(), classify_ssh(outcome))
        }
    }
}

fn with_login_path(mut env: Vec<(String, String)>, path: Option<&str>) -> Vec<(String, String)> {
    if env.iter().any(|(k, _)| k == "PATH") {
        return env;
    }
    if let Some(path) = path {
        env.push(("PATH".to_string(), path.to_string()));
    }
    env
}

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
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    cmd
}

pub(crate) async fn resolve_remote_env(host: &ResolvedHost, cache: &ShellCache) -> RemoteEnv {
    let key = super::shell_cache_key(host);
    if let Some(env) = cache.lock().await.get(&key) {
        return env.clone();
    }
    let env = probe_remote_env(host).await;
    cache.lock().await.insert(key, env.clone());
    env
}

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

async fn probe_remote_env(host: &ResolvedHost) -> RemoteEnv {
    let script = format!(
        "{}\ncommand -v rsync >/dev/null 2>&1 && echo SHELLFLOW_HAS_RSYNC",
        PROBE_SCRIPT.trim()
    );
    let mut cmd = Command::new("ssh");
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    cmd.arg(script);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshOutcome {
    Transport,
    Script,
    TimedOut,
}

const fn classify_ssh(outcome: SshOutcome) -> HostOutcome {
    match outcome {
        SshOutcome::Transport => HostOutcome::Failed(RunError::Transport),
        SshOutcome::Script => HostOutcome::Failed(RunError::Script),
        SshOutcome::TimedOut => HostOutcome::TimedOut,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardResult {
    Pass,
    Fail,
    Transport,
}

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
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return GuardResult::Transport,
    };
    let mut group = GroupGuard::new(&child);
    if let Some(mut stdin) = child.stdin.take() {
        let script = format!("set -e\n{}{guard}\n", render_env(env));
        let _ = stdin.write_all(script.as_bytes()).await;
    }
    let wait = match timeout {
        Some(secs) => tokio::time::timeout(Duration::from_secs(secs), child.wait()).await,
        None => Ok(child.wait().await),
    };
    let result = match wait {
        Ok(Ok(status)) if status.success() => GuardResult::Pass,
        Ok(Ok(status)) if status.code() == Some(255) => GuardResult::Transport,
        Ok(Ok(_)) => GuardResult::Fail,
        _ => {
            super::process::terminate(&mut child).await;
            GuardResult::Transport
        }
    };
    match result {
        GuardResult::Pass | GuardResult::Fail => group.disarm(),
        GuardResult::Transport => {}
    }
    result
}

async fn run_ssh_child(
    ui: ArcUi,
    host: &ResolvedHost,
    cmd: Command,
    payload: &str,
    timeout: Option<u64>,
    log_file: &LogFile,
) -> Result<(), SshOutcome> {
    match stream::run_piped_child(ui, &host.alias, cmd, Some(payload), timeout, None, log_file)
        .await
        .map_err(|_| SshOutcome::Transport)?
    {
        stream::PipedRun::Completed(status) => {
            if !status.success() {
                if status.code() == Some(255) {
                    return Err(SshOutcome::Transport);
                }
                return Err(SshOutcome::Script);
            }
            Ok(())
        }
        stream::PipedRun::TimedOut => Err(SshOutcome::TimedOut),
    }
}
