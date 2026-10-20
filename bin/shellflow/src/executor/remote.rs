//! Remote step execution: SSH streaming with login-shell parity, per-host
//! fan-out with semaphore, and remote guard evaluation.

use std::{collections::HashMap, sync::Arc, time::Duration};

use eyre::Result;
use shellflow_core::{ResolvedHost, RunState, render_env};
use tokio::{
    process::Command,
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use super::{
    ArcUi, Cancel, CopyStepArgs, HostOutcome, LogFile, ShellCache, StepConfig, fanout_slot,
    local::{GuardOutcome, build_env, run_local_block},
    process::isolate,
    stream,
};
use crate::{secrets::ResolvedSecrets, ui::HostStatus};

/// The error classification mapped to the CLI exit code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    /// A configuration/plan-build failure (exit 1), e.g. secrets resolution.
    Config,
    /// A plan error (exit 1): a bad script, an unresolved `@export` variable,
    /// an unresolvable target, or a syntax error found by a dry-run check.
    ///
    /// Design §6 assigns these to exit 1, distinct from a script that ran
    /// and failed (exit 4): CI can tell "the playbook is wrong" from "the
    /// deployment failed".
    Plan,
    /// A transport/setup failure (exit 3).
    Transport,
    /// A script execution failure (exit 4).
    Script,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config => write!(f, "configuration failure"),
            Self::Plan => write!(f, "plan error"),
            Self::Transport => write!(f, "transport/setup failure"),
            Self::Script => write!(f, "script execution failure"),
        }
    }
}

impl RunError {
    /// The process exit code for this failure (design §6).
    ///
    /// The mapping lives with the classification so it cannot drift from it:
    /// 1 = configuration/plan error, 3 = transport/setup failure,
    /// 4 = script execution failure.
    #[must_use]
    pub(crate) const fn into_exit_code(self) -> i32 {
        match self {
            Self::Config | Self::Plan => 1,
            Self::Transport => 3,
            Self::Script => 4,
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
    ///
    /// The audit-log handle is *not* carried here: the caller owns the UI
    /// (and therefore the file), so the interrupt summary is recorded in the
    /// same trail as every other line of the run — including when the
    /// teardown did not finish inside the grace period.
    ///
    /// `torn_down` reports whether every in-flight process group was reaped
    /// before returning. When the grace period expires the executor is
    /// aborted and the run must not claim the groups are gone.
    Interrupted { total: usize, torn_down: bool },
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
    pub(crate) cancel: &'a Cancel,
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
    cancel: Cancel,
}

/// Build every per-run handle: run state, host selection, secret resolution,
/// and the fan-out semaphore.
///
/// The UI is *not* built here: the caller owns it, because the audit-log
/// handle must exist before the run starts (an audit trail that cannot be
/// opened has to fail the run) and because the interrupt summary must be
/// able to reach the same file.
///
/// Returns `None` when setup itself fails (the failure is already reported);
/// every setup failure maps to [`RunError::Config`].
async fn setup_run(
    run: &crate::cli::RunArgs,
    plan: &shellflow_core::ExecutionPlan,
    cancel: &Cancel,
    ui: ArcUi,
) -> Option<RunSetup> {
    let flags = &run.flags;
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
    // Surface the exemption instead of staying silent: name the affected KEYS
    // only, never the values.
    if !resolved.shorts().is_empty() {
        let keys: Vec<&str> = resolved.shorts().iter().map(|(key, _)| key.as_str()).collect();
        crate::ui::warn(
            &format!(
                "@secrets value(s) shorter than the masking threshold are masked only where they \
                 appear as a standalone token or under their own key: {}. Lower --mask-min-len / \
                 $SHELLFLOW_MASK_MIN_LEN to mask them everywhere. Values are never printed.",
                keys.join(", ")
            ),
            &log_file,
        );
    }
    ui.lock().await.set_secret_values(secrets, resolved.shorts().to_vec());

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
        ui.lock().await.plan_preview(plan, &selected);
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
        cancel: cancel.clone(),
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
            let outcome = super::local::run_local_step(
                &setup.ui,
                &setup.run_state,
                local,
                config,
                &setup.cancel,
            )
            .await;
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
                        cancel: &setup.cancel,
                    };
                    (None, run_remote_step(&ctx, remote, hosts, config).await)
                }
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
                    (Some(RunError::Plan), Ok(Vec::new()))
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
                        cancel: setup.cancel.clone(),
                    };
                    super::copy::run_copy_step(&copy_args, copy, hosts, config).await
                }
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
                    (Some(RunError::Plan), Ok(Vec::new()))
                }
            }
        }
        shellflow_core::Step::Wait(wait) => {
            match shellflow_core::resolve_hosts(plan, &wait.target, &setup.restrict) {
                Ok(hosts) => (
                    None,
                    run_wait_step(
                        &setup.ui,
                        wait,
                        hosts,
                        config,
                        &setup.semaphore,
                        &setup.log_file,
                        &setup.cancel,
                    )
                    .await,
                ),
                Err(err) => {
                    crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
                    (Some(RunError::Plan), Ok(Vec::new()))
                }
            }
        }
    }
}

/// Execute the plan and return the overall outcome.
///
/// The caller owns the UI (and therefore the audit-log handle) so that the
/// run's audit trail is opened before anything is attempted and so that the
/// interrupt summary can be written to it.
pub(crate) async fn execute_plan(
    run: &crate::cli::RunArgs,
    plan: shellflow_core::ExecutionPlan,
    progress: super::Progress,
    cancel: Cancel,
    ui: ArcUi,
) -> RunOutcome {
    let flags = &run.flags;
    let Some(setup) = setup_run(run, &plan, &cancel, ui).await else {
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
        // A cancelled run stops scheduling new steps; the in-flight host
        // tasks observe the same signal and tear their children down.
        if cancel.is_cancelled() {
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

    if cancel.is_cancelled() {
        return RunOutcome::Interrupted { total, torn_down: true };
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
            shellflow_core::Step::Wait(wait) => &wait.target,
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

/// Default wait budget in seconds when neither `@timeout` nor `--timeout`
/// bounds a `@wait_active` step (slow starters: substrate nodes, JVMs,
/// container image pulls).
const DEFAULT_WAIT_SECS: u64 = 300;

/// Poll `systemctl is-active <unit>` on every target host until it reports
/// active or the budget expires. One slow host never blocks others (fan-out
/// with the run semaphore); a host that never reports active is `FAILED`
/// (script class: the unit is broken, not the transport).
///
/// The unit name is validated at parse time (`[A-Za-z0-9._-]` plus `@`/`:`,
/// no leading dots, no `..`), so interpolating it into the poll command is
/// safe.
///
/// The poll runs through the shared child supervisor, so the `ssh` is spawned
/// in its own process group, is killed when the run is interrupted, and
/// cannot outlive the budget: a blackholed connection used to block the poll
/// loop indefinitely.
/// The remote command that waits for a unit to become ready.
///
/// The helper does the waiting **on the target**: it polls systemd there and
/// streams one state line per poll, so the whole wait costs a single SSH
/// round-trip instead of one per poll.
///
/// When the helper is not installed yet (a host that has never seen this
/// shellflow), a self-contained fallback polls `systemctl is-active` so the
/// step still works — it just cannot show the service's own `STATUS=` text.
///
/// The unit name is validated at parse time (`[A-Za-z0-9._-]` plus `@`/`:`,
/// no leading dots, no `..`), so interpolating it into the script cannot
/// smuggle a quote or a shell metacharacter.
fn wait_command(unit: &str, budget_secs: u64) -> String {
    format!(
        "if [ -x /usr/local/bin/shellflow ]; then exec /usr/local/bin/shellflow systemd wait '{unit}' --timeout {budget_secs} --for ready; fi; \
         u='{unit}'; d=$(( $(date +%s) + {budget_secs} )); \
         while :; do \
           if systemctl is-active --quiet \"$u\"; then echo 'SFW active'; exit 0; fi; \
           if systemctl is-failed --quiet \"$u\"; then echo 'SFW failed'; exit 3; fi; \
           echo 'SFW pending'; \
           if [ \"$(date +%s)\" -ge \"$d\" ]; then exit 4; fi; \
           sleep 5; \
         done"
    )
}

/// Interpret the state lines the target-side helper streams.
///
/// The helper emits `SFW<TAB>type<TAB>active<TAB>sub<TAB>result<TAB>status`;
/// the fallback emits a single word. The operator sees the service's own
/// `STATUS=` text when it publishes one (that is the whole point of the notify
/// protocol) and the raw systemd state otherwise.
fn wait_collector(unit: &str) -> stream::LineCollector {
    let unit = unit.to_string();
    stream::LineCollector::new(move |line| {
        if let Some(state) = crate::systemd::parse_state_line(line) {
            let mut bits = Vec::new();
            if !state.unit_type.is_empty() {
                bits.push(format!("type={}", state.unit_type));
            }
            if !state.active.is_empty() {
                bits.push(format!("active={}", state.active));
            }
            if !state.sub.is_empty() {
                bits.push(format!("sub={}", state.sub));
            }
            if !state.result.is_empty() {
                bits.push(format!("result={}", state.result));
            }
            let bits = bits.join(" ");
            return Some(if state.status.is_empty() {
                format!("waiting {unit}: {bits}")
            } else {
                format!("waiting {unit}: {}", state.status)
            });
        }
        let rest = line.strip_prefix("SFW")?;
        let word = rest.trim();
        if word.is_empty() {
            return None;
        }
        Some(format!("waiting {unit}: {word}"))
    })
}

pub(super) async fn run_wait_step(
    ui: &ArcUi,
    wait: &shellflow_core::WaitStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
    semaphore: &Option<Arc<Semaphore>>,
    log_file: &LogFile,
    cancel: &Cancel,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    use tokio::time::Duration;
    if config.check || config.dry_run {
        crate::ui::note(
            &format!(
                "  wait_active {} ({}s budget): no-op in check/dry-run",
                wait.unit,
                config.timeout.unwrap_or(DEFAULT_WAIT_SECS),
            ),
            log_file,
        );
        return Ok(hosts.into_iter().map(|host| (host.alias, HostOutcome::Ok)).collect());
    }
    let budget = Duration::from_secs(config.timeout.unwrap_or(DEFAULT_WAIT_SECS));
    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let unit = wait.unit.clone();
        let semaphore = semaphore.clone();
        let log_file = log_file.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let _permit = match semaphore.as_ref() {
                Some(sem) => match sem.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                    }
                },
                None => None,
            };
            if cancel.is_cancelled() {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
            // The wait runs *on the target*: the helper polls systemd there and
            // streams one state line per poll. The whole wait therefore costs
            // a single SSH round-trip instead of one per poll, and the
            // operator sees the service's own `STATUS=` text while it starts.
            let mut cmd = Command::new("ssh");
            // Fail closed on an unknown host key or a missing key: never prompt.
            cmd.args(["-o", "BatchMode=yes"]);
            cmd.args(host.spec.to_ssh_args())
                .arg("-T")
                .arg(wait_command(&unit, budget.as_secs()));
            let args = stream::PipedArgs {
                ui: &ui,
                host: &host.alias,
                payload: None,
                // The helper enforces its own budget; the transport gets a
                // little more so the helper's own verdict wins.
                timeout: Some(budget.as_secs() + 30),
                diff_filter: None,
                log_file: &log_file,
                cancel: cancel.clone(),
                quiet: false,
                collector: Some(wait_collector(&unit)),
            };
            let outcome = match stream::run_piped_child(args, cmd).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                }
            };
            match outcome {
                stream::PipedRun::Completed(status) => {
                    let code = status.code().unwrap_or(-1);
                    match code {
                        0 => {
                            ui.lock().await.masked_note(&format!(
                                "[{}] {unit} active",
                                host.alias
                            ));
                            (host.alias.clone(), HostOutcome::Ok)
                        }
                        // ssh exits 255 when the connection itself failed:
                        // that is a transport failure, not an inactive unit.
                        255 => (host.alias.clone(), HostOutcome::Failed(RunError::Transport)),
                        3 => {
                            ui.lock().await.masked_note(&format!(
                                "[{}] {unit} failed",
                                host.alias
                            ));
                            (host.alias.clone(), HostOutcome::Failed(RunError::Script))
                        }
                        4 => {
                            ui.lock().await.masked_note(&format!(
                                "[{}] {unit} not ready after {}s",
                                host.alias,
                                budget.as_secs()
                            ));
                            (host.alias.clone(), HostOutcome::Failed(RunError::Script))
                        }
                        5 => {
                            ui.lock().await.masked_note(&format!(
                                "[{}] {unit} does not exist",
                                host.alias
                            ));
                            (host.alias.clone(), HostOutcome::Failed(RunError::Script))
                        }
                        other => {
                            ui.lock().await.masked_note(&format!(
                                "[{}] {unit} wait failed (exit {other})",
                                host.alias
                            ));
                            (host.alias.clone(), HostOutcome::Failed(RunError::Script))
                        }
                    }
                }
                stream::PipedRun::TimedOut | stream::PipedRun::PipeBroken => {
                    (host.alias.clone(), HostOutcome::Failed(RunError::Transport))
                }
                stream::PipedRun::Cancelled => {
                    (host.alias.clone(), HostOutcome::Cancelled)
                }
            }
        });
    }
    let mut out = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(pair) => {
                ui.lock().await.host_finished(&pair.0);
                out.push(pair);
            }
            Err(_) => out.push(("unknown".to_string(), HostOutcome::Failed(RunError::Transport))),
        }
    }
    Ok(out)
}

pub(super) async fn run_remote_step(
    ctx: &RemoteStepCtx<'_>,
    remote: &shellflow_core::RemoteStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
) -> Result<Vec<(String, HostOutcome)>> {
    if config.local {
        let alias = hosts.first().map(|host| host.alias.clone());
        return run_remote_step_local(RemoteLocalArgs {
            ui: ctx.ui,
            run_state: ctx.run_state,
            remote,
            config,
            secrets: ctx.secrets,
            host_alias: alias.as_deref(),
            log_file: ctx.log_file,
            cancel: ctx.cancel,
        })
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
        let cancel = ctx.cancel.clone();
        tasks.spawn(async move {
            // Never run unthrottled when the semaphore is closed.
            let _permit = fanout_slot!(&semaphore, &log_file, host);
            run_remote_host(RemoteHostArgs {
                ui,
                host: &host,
                parts: &parts,
                config,
                shell_cache,
                secrets: &secrets,
                log_file: &log_file,
                cancel,
            })
            .await
        });
    }

    Ok(stream::collect_hosts(ctx.ui, tasks).await)
}

/// The parameters of a remote block that runs on the controller (`--local`).
struct RemoteLocalArgs<'a> {
    ui: &'a ArcUi,
    run_state: &'a Arc<Mutex<RunState>>,
    remote: &'a shellflow_core::RemoteStep,
    config: StepConfig,
    secrets: &'a Arc<ResolvedSecrets>,
    host_alias: Option<&'a str>,
    log_file: &'a LogFile,
    cancel: &'a Cancel,
}

async fn run_remote_step_local(args: RemoteLocalArgs<'_>) -> Result<Vec<(String, HostOutcome)>> {
    let RemoteLocalArgs { ui, run_state, remote, config, secrets, host_alias, log_file, cancel } =
        args;
    if config.dry_run || config.verbose >= 2 {
        ui.lock().await.payload_preview(
            &format!("Local Payload (remote block @{})", remote.target.text),
            &remote.script,
        );
    }

    // The block's environment: the run-state `@export` variables and the
    // `@env` entries, plus this host's `{host}` secrets. `overlay` also
    // extends `LT_SECRET_KEYS` with the host's key names, so a per-host
    // playbook can iterate them — exactly what the remote path does.
    let mut extra = build_env(run_state, &remote.env).await;
    if let Some(alias) = host_alias {
        secrets.overlay(&mut extra, alias);
    }

    // The guard must observe the same environment as the block: run-state
    // `@export` variables, `@env` entries, and this host's `{host}` secrets —
    // exactly what the remote path renders into the guard script.
    if let Some(guard) = &remote.guard {
        let mut guard_env = build_env(run_state, &remote.env).await;
        if let Some(alias) = host_alias {
            secrets.overlay(&mut guard_env, alias);
        }
        // A dry run must not change anything, so the guard is reported rather
        // than evaluated — the same rule the remote path follows.
        if config.dry_run || config.check {
            crate::ui::note(&format!("  guard not evaluated in dry-run/check: {guard}"), log_file);
        } else {
            match super::local::evaluate_guard(
                ui,
                guard,
                &guard_env,
                config.timeout,
                cancel,
                log_file,
            )
            .await
            {
                GuardOutcome::Pass => {
                    if config.verbose >= 2 {
                        ui.lock().await.masked_note(&format!("  guard passed: {guard}"));
                    }
                }
                GuardOutcome::Fail => {
                    crate::ui::note("  local guard failed — skipping block", log_file);
                    return Ok(vec![("localhost".to_string(), HostOutcome::Skipped)]);
                }
                GuardOutcome::Failed(err) => {
                    crate::ui::warn(&format!("local guard failed: {err}"), log_file);
                    return Ok(vec![("localhost".to_string(), HostOutcome::Failed(err))]);
                }
            }
        }
    }
    let args = super::LocalBlockArgs {
        ui,
        run_state,
        script: &remote.script,
        env: &remote.env,
        config,
        capture: &[],
        extra: &extra,
        log_file,
        cancel: cancel.clone(),
    };
    match run_local_block(&args).await {
        Ok(()) => Ok(vec![("localhost".to_string(), HostOutcome::Ok)]),
        Err(super::local::LocalFailure::Timeout) => {
            Ok(vec![("localhost".to_string(), HostOutcome::TimedOut)])
        }
        Err(super::local::LocalFailure::PipeBroken) => {
            Ok(vec![("localhost".to_string(), HostOutcome::Failed(RunError::Transport))])
        }
        Err(super::local::LocalFailure::Failed(err)) => {
            crate::ui::warn(&format!("local step failed: {err:#}"), log_file);
            Ok(vec![("localhost".to_string(), HostOutcome::Failed(RunError::Script))])
        }
    }
}

/// The parameters of one host's remote step.
struct RemoteHostArgs<'a> {
    ui: ArcUi,
    host: &'a ResolvedHost,
    parts: &'a PayloadParts,
    config: StepConfig,
    shell_cache: ShellCache,
    secrets: &'a Arc<ResolvedSecrets>,
    log_file: &'a LogFile,
    cancel: Cancel,
}

async fn run_remote_host(args: RemoteHostArgs<'_>) -> (String, HostOutcome) {
    let RemoteHostArgs { ui, host, parts, config, shell_cache, secrets, log_file, cancel } = args;
    if config.check || config.dry_run {
        let env_header = match render_env(&parts.env) {
            Ok(header) => header,
            Err(err) => {
                crate::ui::warn(&format!("[{}] {err}", host.alias), log_file);
                return (host.alias.clone(), HostOutcome::Failed(RunError::Plan));
            }
        };
        let payload = format!("set -eu\n{}{}{}", env_header, parts.trace_line, parts.script);
        if config.verbose >= 2 {
            let cmd = build_ssh_cmd(host, RemoteShell::Bash, true, config);
            ui.lock().await.masked_note(&format!(
                "  [{}] ssh {}",
                host.alias,
                super::display_args(&cmd)
            ));
        }
        return match run_ssh_child(
            ui,
            host,
            build_ssh_cmd(host, RemoteShell::Bash, true, config),
            &payload,
            config.timeout,
            log_file,
            cancel,
        )
        .await
        {
            Ok(()) => {
                crate::ui::note(&format!("[{}] syntax check (bash -n): OK", host.alias), log_file);
                for finding in crate::lint::lint_block(&parts.script) {
                    crate::ui::warn(
                        &format!("[{}] line {}: {}", host.alias, finding.line, finding.message),
                        log_file,
                    );
                }
                (host.alias.clone(), HostOutcome::Ok)
            }
            Err(outcome) => {
                crate::ui::warn(&format!("[{}] {outcome:?}", host.alias), log_file);
                (host.alias.clone(), classify_ssh(outcome))
            }
        };
    }

    let remote_env = resolve_remote_env(host, &shell_cache, &cancel).await;
    let mut payload_env = with_login_path(parts.env.clone(), remote_env.path.as_deref());
    secrets.overlay(&mut payload_env, &host.alias);
    if let Some(guard) = &parts.guard {
        match run_remote_guard(RemoteGuardArgs {
            ui: &ui,
            host,
            shell: remote_env.shell,
            guard,
            env: &payload_env,
            timeout: config.timeout,
            cancel: &cancel,
            log_file,
        })
        .await
        {
            GuardResult::Pass => {
                if config.verbose >= 2 {
                    // The guard text is user content and can embed a secret.
                    ui.lock()
                        .await
                        .masked_note(&format!("  [{}] guard passed: {guard}", host.alias));
                }
            }
            GuardResult::Fail => {
                crate::ui::note(&format!("[{}] SKIPPED (guard)", host.alias), log_file);
                return (host.alias.clone(), HostOutcome::Skipped);
            }
            GuardResult::Transport => {
                return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
            }
            GuardResult::Cancelled => {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
        }
    }

    let env_header = match render_env(&payload_env) {
        Ok(header) => header,
        Err(err) => {
            crate::ui::warn(&format!("[{}] {err}", host.alias), log_file);
            return (host.alias.clone(), HostOutcome::Failed(RunError::Plan));
        }
    };
    let payload = format!("set -eu\n{}{}{}", env_header, parts.trace_line, parts.script);
    let cmd = build_ssh_cmd(host, remote_env.shell, false, config);
    if config.verbose >= 2 {
        ui.lock().await.masked_note(&format!(
            "  [{}] ssh {}",
            host.alias,
            super::display_args(&cmd)
        ));
    }
    match run_ssh_child(ui, host, cmd, &payload, config.timeout, log_file, cancel).await {
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
    // Fail closed on an unknown host key or a missing key: never prompt.
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    if config.ssh_reuse {
        // Opt-in connection reuse: later steps in the same run share the
        // first step's authenticated connection instead of re-handshaking.
        // Off by default so a stale master socket can never break a deploy
        // silently; rsync/scp copies always go direct.
        cmd.args([
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPath=~/.ssh/shellflow-%r@%h-%p",
            "-o",
            "ControlPersist=60",
        ]);
    }
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

pub(crate) async fn resolve_remote_env(
    host: &ResolvedHost,
    cache: &ShellCache,
    cancel: &Cancel,
) -> RemoteEnv {
    let key = super::shell_cache_key(host);
    if let Some(env) = cache.lock().await.get(&key) {
        return env.clone();
    }
    let env = probe_remote_env(host, cancel).await;
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
    # A shell rc can pollute $PATH with noise (an npm shim's error message
    # lands in the value), which splits it into entries that are not
    # directories and breaks the PATH injected into the payload. Only real
    # directories are reported, one per line, between sentinels.
    printf '%s\n' 'SHELLFLOW_PATH_BEGIN';
    printf '%s\n' "$PATH" | tr ':' '\n' | while IFS= read -r d; do
        if [ -n "$d" ] && [ -d "$d" ]; then printf '%s\n' "$d"; fi
    done;
    printf '%s\n' 'SHELLFLOW_PATH_END';
}
"#;

/// The end marker of a successful probe.
///
/// The probe's *exit status* must not depend on anything it reports: a
/// trailing `&&` list would make the status fail on a host without `rsync`,
/// and the whole probe result — the login shell and the rc-extended PATH —
/// would be discarded with it. The marker is therefore the only success
/// criterion, and every field degrades independently.
const PROBE_END_MARKER: &str = "SHELLFLOW_PROBE_END";

async fn probe_remote_env(host: &ResolvedHost, cancel: &Cancel) -> RemoteEnv {
    use tokio::io::AsyncReadExt as _;
    // The rsync check is separated from the report by a `;` and its result is
    // carried in the marker line, so a host without `rsync` still returns a
    // successful probe.
    let script = format!(
        "{}\ncommand -v rsync >/dev/null 2>&1 && echo SHELLFLOW_HAS_RSYNC\nprintf '%s\\n' {marker}",
        PROBE_SCRIPT.trim(),
        marker = PROBE_END_MARKER,
    );
    let mut cmd = Command::new("ssh");
    // Fail closed on an unknown host key or a missing key: never prompt.
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    cmd.arg(script);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return RemoteEnv::default(),
    };
    let mut group = super::process::GroupGuard::new(&child);
    // Collect stdout concurrently: waiting before reading deadlocks once the
    // pipe buffer fills.
    let stdout = child.stdout.take();
    let reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut out) = stdout {
            let _ = out.read_to_end(&mut buf).await;
        }
        buf
    });
    // The probe races the timeout *and* cancellation: a hung probe must not
    // eat the whole interrupt grace period, and its group must not survive
    // the run.
    let mut cancel_probe = cancel.clone();
    let status = super::process::wait_child(&mut child, Some(15), &mut cancel_probe).await;
    let output = match status {
        super::process::ChildOutcome::Finished(Ok(status)) if status.success() => {
            group.disarm();
            match tokio::time::timeout(Duration::from_secs(2), reader).await {
                Ok(Ok(buf)) => buf,
                _ => return RemoteEnv::default(),
            }
        }
        super::process::ChildOutcome::Finished(Ok(_)) => {
            // Non-zero exit still carries a usable probe when the marker is
            // present (e.g. a host without rsync): fall through to parsing
            // rather than discarding the login shell and PATH with it.
            group.disarm();
            match tokio::time::timeout(Duration::from_secs(2), reader).await {
                Ok(Ok(buf)) => buf,
                _ => return RemoteEnv::default(),
            }
        }
        _ => {
            super::process::terminate(&mut child).await;
            group.disarm();
            reader.abort();
            return RemoteEnv::default();
        }
    };
    let text = String::from_utf8_lossy(&output);
    let mut lines = text.lines();
    let shell = RemoteShell::detect(lines.next().unwrap_or_default());
    // The PATH is reported between sentinels, one directory per line, so a
    // polluted $PATH cannot split the value.
    let mut dirs: Vec<&str> = Vec::new();
    let mut in_path = false;
    let mut has_rsync = false;
    let mut completed = false;
    for line in lines {
        match line.trim() {
            "SHELLFLOW_PATH_BEGIN" => in_path = true,
            "SHELLFLOW_PATH_END" => in_path = false,
            "SHELLFLOW_HAS_RSYNC" => has_rsync = true,
            other if other == PROBE_END_MARKER => completed = true,
            other if in_path && !other.is_empty() => dirs.push(other),
            _ => {}
        }
    }
    if !completed {
        // The probe did not run to completion (a truncated connection, an
        // unreachable host): fall back rather than act on a partial result.
        return RemoteEnv::default();
    }
    let path = if dirs.is_empty() { None } else { Some(dirs.join(":")) };
    RemoteEnv { shell, path, has_rsync }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshOutcome {
    Transport,
    Script,
    TimedOut,
    Cancelled,
}

const fn classify_ssh(outcome: SshOutcome) -> HostOutcome {
    match outcome {
        SshOutcome::Transport => HostOutcome::Failed(RunError::Transport),
        SshOutcome::Script => HostOutcome::Failed(RunError::Script),
        SshOutcome::TimedOut => HostOutcome::TimedOut,
        SshOutcome::Cancelled => HostOutcome::Cancelled,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardResult {
    Pass,
    Fail,
    Transport,
    Cancelled,
}

/// The parameters of one host's `@only_if` guard evaluation.
struct RemoteGuardArgs<'a> {
    ui: &'a ArcUi,
    host: &'a ResolvedHost,
    shell: RemoteShell,
    guard: &'a str,
    env: &'a [(String, String)],
    timeout: Option<u64>,
    cancel: &'a Cancel,
    log_file: &'a LogFile,
}

async fn run_remote_guard(args: RemoteGuardArgs<'_>) -> GuardResult {
    let RemoteGuardArgs { ui, host, shell, guard, env, timeout, cancel, log_file } = args;
    let env_header = match render_env(env) {
        Ok(header) => header,
        Err(_) => return GuardResult::Transport,
    };
    let mut cmd = Command::new("ssh");
    // Fail closed on an unknown host key or a missing key: never prompt.
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    cmd.arg(shell.invoke(false));
    cmd.stdin(std::process::Stdio::piped());
    // Stdout/stderr are set by `run_piped_child` (`quiet` discards the
    // guard's own output); stdin must already be piped so the payload can
    // be delivered.
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    // Fail closed: a guard that could not be delivered must never be reported
    // as `Pass`. If the write fails, stdin drops, the remote shell reads an
    // empty script and exits 0 — which would otherwise mark an *unevaluated*
    // precondition as satisfied and release the block. Routing through the
    // shared supervisor also bounds the stdin write by the step deadline,
    // races it against cancellation, and isolates the child in its own
    // process group.
    let script = format!("set -e\n{env_header}{guard}\n");
    let args = stream::PipedArgs {
        ui,
        host: &host.alias,
        payload: Some(&script),
        timeout,
        diff_filter: None,
        log_file,
        cancel: cancel.clone(),
        quiet: true,
        collector: None,
    };
    match stream::run_piped_child(args, cmd).await {
        Ok(stream::PipedRun::Completed(status)) if status.success() => GuardResult::Pass,
        Ok(stream::PipedRun::Completed(status)) if status.code() == Some(255) => {
            GuardResult::Transport
        }
        Ok(stream::PipedRun::Completed(_)) => GuardResult::Fail,
        Ok(stream::PipedRun::Cancelled) => GuardResult::Cancelled,
        // Timed out, broken pipe, or spawn failure: the guard was never
        // evaluated, so it must not pass. Timeouts surface as transport
        // here to match the historical classification.
        Ok(stream::PipedRun::TimedOut | stream::PipedRun::PipeBroken) | Err(_) => {
            if cancel.is_cancelled() { GuardResult::Cancelled } else { GuardResult::Transport }
        }
    }
}

async fn run_ssh_child(
    ui: ArcUi,
    host: &ResolvedHost,
    cmd: Command,
    payload: &str,
    timeout: Option<u64>,
    log_file: &LogFile,
    cancel: Cancel,
) -> Result<(), SshOutcome> {
    let args = stream::PipedArgs {
        ui: &ui,
        host: &host.alias,
        payload: Some(payload),
        timeout,
        diff_filter: None,
        log_file,
        cancel,
        quiet: false,
        collector: None,
    };
    match stream::run_piped_child(args, cmd).await.map_err(|_| SshOutcome::Transport)? {
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
        // A broken stdin pipe means the transport died (auth refused, host
        // key rejected, reset), not that the step ran out of time: exit 3.
        stream::PipedRun::PipeBroken => Err(SshOutcome::Transport),
        stream::PipedRun::Cancelled => Err(SshOutcome::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use super::{wait_command, wait_collector};

    #[test]
    fn the_wait_command_prefers_the_target_side_helper() {
        let cmd = wait_command("foo.service", 300);
        assert!(
            cmd.contains("/usr/local/bin/shellflow systemd wait 'foo.service'"),
            "the helper is the primary path: {cmd}"
        );
        assert!(cmd.contains("--timeout 300"), "{cmd}");
        assert!(cmd.contains("--for ready"), "{cmd}");
    }

    #[test]
    fn the_wait_command_has_a_self_contained_fallback() {
        let cmd = wait_command("foo.service", 30);
        // A host that has never seen this shellflow has no helper: the step
        // must still work, so the script falls back to polling systemctl.
        assert!(cmd.contains("systemctl is-active"), "{cmd}");
        assert!(cmd.contains("systemctl is-failed"), "{cmd}");
    }

    #[test]
    fn the_wait_command_carries_the_budget_into_the_fallback() {
        let cmd = wait_command("foo.service", 42);
        assert!(cmd.contains("+ 42"), "{cmd}");
    }

    #[test]
    fn the_collector_renders_the_services_own_status() {
        let collector = wait_collector("foo.service");
        let line = "SFW\tnotify\tactivating\tstart\tsuccess\tsyncing chain 42%";
        let rendered = collector.record(line).expect("renders");
        assert_eq!(rendered, "waiting foo.service: syncing chain 42%");
    }

    #[test]
    fn the_collector_falls_back_to_the_raw_state() {
        let collector = wait_collector("foo.service");
        let line = "SFW\tnotify\tactivating\tstart\tsuccess\t";
        let rendered = collector.record(line).expect("renders");
        assert_eq!(rendered, "waiting foo.service: type=notify active=activating sub=start result=success");
    }

    #[test]
    fn the_collector_handles_the_fallback_line() {
        let collector = wait_collector("foo.service");
        let rendered = collector.record("SFW pending").expect("renders");
        assert_eq!(rendered, "waiting foo.service: pending");
    }

    #[test]
    fn the_collector_drops_unrelated_output() {
        let collector = wait_collector("foo.service");
        assert!(collector.record("some unrelated output").is_none());
        assert!(collector.record("").is_none());
    }
}
