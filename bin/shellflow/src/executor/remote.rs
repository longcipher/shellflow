//! Remote step execution: SSH streaming with login-shell parity, per-host
//! fan-out with semaphore, and remote guard evaluation.

use std::{collections::HashMap, sync::Arc, time::Duration};

use eyre::Result;
use shellflow_core::{ResolvedHost, RunState};
use tokio::{
    process::Command,
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use super::{
    ArcUi, Cancel, CopyStepArgs, HostOutcome, LogFile, RunError, RunOutcome, ShellCache,
    StepConfig, fanout_slot, helper,
    local::{GuardOutcome, build_env, run_local_block},
    process::isolate,
    stream,
};
use crate::{secrets::ResolvedSecrets, ui::HostStatus};

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
    pub(super) const fn invoke(self, syntax_only: bool) -> &'static str {
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
    /// The probe saw a `muxy` binary (`SHELLFLOW_MUXY=1`).
    pub(crate) has_muxy: bool,
}

/// Shared handles threaded through a remote step's host fan-out.
#[cfg_attr(
    not(feature = "muxy"),
    expect(dead_code, reason = "the ssh-only build ignores the step index")
)]
pub(crate) struct RemoteStepCtx<'a> {
    pub(crate) ui: &'a ArcUi,
    pub(crate) semaphore: &'a Option<Arc<Semaphore>>,
    pub(crate) run_state: &'a Arc<Mutex<RunState>>,
    pub(crate) shell_cache: &'a ShellCache,
    pub(crate) secrets: &'a Arc<ResolvedSecrets>,
    pub(crate) log_file: &'a LogFile,
    pub(crate) cancel: &'a Cancel,
    /// The 1-based plan index (names the muxy payload file).
    pub(crate) step_no: usize,
    /// Per-run muxy state (connections cached per host).
    #[cfg(feature = "muxy")]
    pub(crate) muxy: &'a super::muxy::MuxyRun,
}

/// The transport half of a reload/wait step, cloned into its host fan-out.
#[derive(Clone)]
pub(super) struct StepTransport {
    /// The probed remote environments (the muxy sentinel, the login `PATH`).
    #[cfg(feature = "muxy")]
    pub(super) shell_cache: ShellCache,
    /// Per-run muxy state (connections cached per host).
    #[cfg(feature = "muxy")]
    pub(super) muxy: super::muxy::MuxyRun,
    /// The 1-based plan index (names the muxy payload file).
    #[cfg(feature = "muxy")]
    pub(super) step_no: usize,
}

/// Fully-initialized per-run state, built once by [`setup_run`] so
/// [`execute_plan`] stays a lean schedule loop.
struct RunSetup {
    ui: ArcUi,
    log_file: LogFile,
    run_state: Arc<Mutex<RunState>>,
    shell_cache: ShellCache,
    /// The `@secrets` masking threshold, applied to runtime-`@export`ed
    /// values as well.
    mask_min_len: usize,
    semaphore: Option<Arc<Semaphore>>,
    resolved: Arc<ResolvedSecrets>,
    restrict: Vec<String>,
    selected: Vec<(usize, shellflow_core::Step)>,
    total: usize,
    cancel: Cancel,
    /// Per-run muxy state (connections cached per host, payloads named per
    /// run).
    #[cfg(feature = "muxy")]
    muxy: super::muxy::MuxyRun,
    /// The managed work directory, removed when the run ends.
    ///
    /// The field exists for its `Drop`: the directory must disappear on
    /// every exit path — success, failure, and `SIGINT` — and a field's
    /// lifetime is the only hook that covers all three.
    workdir: Option<WorkdirGuard>,
}

/// The managed staging directory of one run.
///
/// The directory lives on the **target**: the playbook ships the service
/// files there and installs them from there. The controller never creates
/// it, so a run leaves nothing behind on the machine that drives the
/// deployment — the leak the hand-written `mkdir -p /tmp/<svc>-<epoch>`
/// caused on every single deploy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Workdir {
    /// The absolute path on the target.
    path: String,
}

impl Workdir {
    /// Whether a destination path lives inside the staging directory.
    pub(crate) fn contains(&self, path: &str) -> bool {
        path == self.path || path.starts_with(&format!("{}/", self.path))
    }
}

/// Removes the staging directory from the targets that received a copy.
#[derive(Clone)]
pub(crate) struct WorkdirGuard {
    /// The staging directory.
    pub(crate) workdir: Workdir,
    /// The hosts that received a copy into the staging directory.
    pub(crate) hosts: Arc<Mutex<std::collections::BTreeSet<String>>>,
}

impl WorkdirGuard {
    /// Record that a host received a copy into the staging directory.
    pub(crate) async fn touch(&self, alias: &str) {
        self.hosts.lock().await.insert(alias.to_string());
    }

    /// Remove the staging directory from every host that received a copy.
    ///
    /// The removal is best effort: a host that is already gone must not
    /// fail the run that just succeeded. Each removal is bounded (10s) and
    /// the removals run **concurrently, under the same `--parallel` bound as
    /// every other fan-out**: sequential cleanups with an unreachable host
    /// each eat their full 10s budget, so two dead hosts alone would outrun
    /// the interrupt grace period — and an unbounded fan-out over a large
    /// fleet would open one `ssh` per host at once, which is exactly what the
    /// semaphore exists to prevent.
    pub(crate) async fn cleanup(
        &self,
        plan: &shellflow_core::ExecutionPlan,
        semaphore: &Option<Arc<Semaphore>>,
        log_file: &LogFile,
    ) {
        let aliases: Vec<String> = self.hosts.lock().await.iter().cloned().collect();
        let workdir = self.workdir.clone();
        let mut tasks = tokio::task::JoinSet::new();
        for alias in aliases {
            let Ok(hosts) =
                shellflow_core::resolve_hosts(plan, &shellflow_core::Target::new(&alias), &[])
            else {
                continue;
            };
            let Some(host) = hosts.first().cloned() else {
                continue;
            };
            let workdir = workdir.clone();
            let semaphore = semaphore.clone();
            let log_file = log_file.clone();
            tasks.spawn(async move {
                let Ok(_permit) = super::acquire_fanout_slot(&semaphore, &log_file).await else {
                    crate::ui::warn(
                        &format!(
                            "workdir cleanup for `{alias}` skipped: the fan-out semaphore is closed"
                        ),
                        &log_file,
                    );
                    return;
                };
                let mut cmd = Command::from(super::transport::ssh_command(
                    super::transport::SshPolicy::batch(),
                    &host.spec,
                ));
                cmd
                    // Quoted through the one helper: the staging path is
                    // generated, but a single quote in it (a `$TMPDIR` an
                    // operator set, a host alias) would otherwise end the
                    // remote command early.
                    .arg(format!("rm -rf -- {}", super::quote(&workdir.path)));
                cmd.stdin(std::process::Stdio::null());
                cmd.stdout(std::process::Stdio::null());
                cmd.stderr(std::process::Stdio::null());
                cmd.kill_on_drop(true);
                crate::executor::process::isolate(&mut cmd);
                let Ok(mut child) = cmd.spawn() else {
                    crate::ui::warn(
                        &format!("workdir cleanup on `{alias}`: ssh could not start"),
                        &log_file,
                    );
                    return;
                };
                let _guard = crate::executor::process::GroupGuard::new(&child);
                match tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await {
                    Ok(Ok(status)) if status.success() => {}
                    Ok(Ok(status)) => crate::ui::warn(
                        &format!("workdir cleanup on `{alias}` failed (exit {status})"),
                        &log_file,
                    ),
                    Ok(Err(err)) => crate::ui::warn(
                        &format!("workdir cleanup on `{alias}` failed: {err}"),
                        &log_file,
                    ),
                    Err(_) => crate::ui::warn(
                        &format!("workdir cleanup on `{alias}` timed out after 10s"),
                        &log_file,
                    ),
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            // Best effort by contract; a panicking cleanup task is logged so
            // the operator knows the staging directory may remain.
            if let Err(err) = result {
                crate::ui::warn(&format!("workdir cleanup task failed: {err}"), log_file);
            }
        }
    }
}

/// Create the managed work directory for this run and publish it to the run
/// state as `WORKDIR`.
///
/// The directory is **not** created here: it lives on the target, and the
/// copy step creates it where the files land. Publishing the path is all
/// the controller has to do.
async fn create_workdir(
    workdir: &shellflow_core::Workdir,
    run_state: &Arc<Mutex<RunState>>,
) -> Result<Workdir, String> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = format!("/tmp/{prefix}-{nonce}", prefix = workdir.prefix);
    // The lock is awaited, never taken blocking: this runs inside the
    // runtime, and a blocking lock there panics the worker thread.
    run_state.lock().await.vars.insert("WORKDIR".to_string(), path.clone());
    Ok(Workdir { path })
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
/// every setup failure maps to [`RunError::Config`]. A run-configuration
/// failure goes through [`crate::ui::fatal`] — stderr, masked, and in the audit
/// trail — so this module never prints directly.
async fn setup_run(
    run: &crate::cli::RunArgs,
    plan: &shellflow_core::ExecutionPlan,
    cancel: &Cancel,
    ui: ArcUi,
) -> Option<RunSetup> {
    let flags = &run.flags;
    let log_file = ui.lock().await.log_file();

    let mut secrets: Vec<String> = plan
        .env()
        .iter()
        .filter_map(|entry| match entry {
            shellflow_core::EnvEntry::Literal { value, .. } => Some(value.clone()),
            // A passthrough value comes from shellflow's own environment and is
            // not a `@secrets` mask; an unknown variant (`EnvEntry` is
            // `#[non_exhaustive]`) cannot be one either, and registering a
            // non-value would only shred output.
            _ => None,
        })
        .collect();

    let run_state = Arc::new(Mutex::new(RunState::default()));
    let shell_cache: ShellCache = Arc::new(Mutex::new(HashMap::new()));

    let restrict = run.target_restrict();
    let selected: Vec<(usize, shellflow_core::Step)> = plan
        .steps()
        .iter()
        .enumerate()
        .filter(|(idx, step)| is_selected(run, *idx, step))
        .map(|(idx, step)| (idx, step.clone()))
        .collect();

    let host_targets = target_host_aliases(plan, &restrict, &selected, &log_file);
    let host_aliases = host_targets.aliases;
    let uses_per_host = plan.secrets().iter().any(|entry| entry.file.contains("{host}"));
    if !flags.check && uses_per_host && !host_targets.raw.is_empty() {
        // A hard run-configuration failure, not a streamed warning: the run
        // is aborting, and the operator greps stderr for it. `ui::fatal` is
        // that path — stderr *and* the masker *and* the audit log, so a raw
        // SSH spec that happens to carry a credential in its userinfo is not
        // printed in the clear.
        crate::ui::fatal(
            &format!(
                "per-host `@secrets` ({{host}}) need a named `@server` alias; these targets are \
                 raw SSH specs and cannot key a secret file: {}",
                host_targets.raw.join(", ")
            ),
            &log_file,
        );
        return None;
    }

    // `--check` is the syntax gate: it does not execute anything, so it must
    // not need an identity or a `{host}` file. Resolving secrets here made a
    // keyless CI runner unable to run the cheapest, safest check.
    let resolved = if flags.check || plan.secrets().is_empty() {
        ResolvedSecrets::empty()
    } else {
        match crate::secrets::resolve_secrets(
            plan.secrets(),
            &host_aliases,
            flags.identity.as_deref(),
            run.mask_min_len(),
        ) {
            Ok(resolved) => resolved,
            Err(err) => {
                crate::ui::warn(&format!("error: {err:#}"), &log_file);
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
        // Hard run-configuration failure, same rationale as above.
        crate::ui::fatal(
            &format!(
                "`--local` cannot resolve per-host `@secrets` ({{host}}) across {} hosts; re-run \
                 with `-t <host>`",
                host_aliases.len()
            ),
            &log_file,
        );
        return None;
    }

    let resolved = Arc::new(resolved);

    if flags.dry_run {
        crate::ui::dry_run_banner(&log_file);
    }

    let semaphore: Option<Arc<Semaphore>> =
        (flags.parallel != 0).then(|| Arc::new(Semaphore::new(flags.parallel)));

    // Numbering is by the step's position in the unfiltered plan, the same
    // index `--only`/`--skip` use. Numbering by the filtered position made
    // `--skip 1 --only 1` select a step the preview had numbered
    // differently.
    let total = plan.steps().len();

    // The managed work directory exists before the first step, so every
    // block and every `@copy` path can name `$WORKDIR`.
    let workdir = match plan.workdir() {
        Some(declared) => match create_workdir(declared, &run_state).await {
            Ok(workdir) => Some(WorkdirGuard {
                workdir,
                hosts: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            }),
            Err(err) => {
                crate::ui::warn(&format!("error: {err}"), &log_file);
                return None;
            }
        },
        None => None,
    };

    if ui.lock().await.verbosity().info() {
        ui.lock().await.plan_preview(plan, &selected);
        ui.lock().await.masked_note(&format!("  transport {}", run.effective_transport()));
    }

    Some(RunSetup {
        ui,
        log_file,
        run_state,
        shell_cache,
        mask_min_len: run.mask_min_len(),
        semaphore,
        resolved,
        restrict,
        selected,
        total,
        cancel: cancel.clone(),
        #[cfg(feature = "muxy")]
        muxy: super::muxy::MuxyRun::new(),
        workdir,
    })
}

/// The `(error, outcome)` pair a step returns when host resolution fails:
/// the caller records a fail-fast plan error and moves on.
const fn plan_failure() -> (Option<RunError>, eyre::Result<Vec<(String, HostOutcome)>>) {
    (Some(RunError::Plan), Ok(Vec::new()))
}

/// Resolve a step's target to concrete hosts, reporting a resolution failure
/// inline via the UI. Returns `None` after reporting; the caller then returns
/// [`plan_failure`].
fn resolve_or_report(
    plan: &shellflow_core::ExecutionPlan,
    setup: &RunSetup,
    step_no: usize,
    target: &shellflow_core::Target,
) -> Option<Vec<shellflow_core::ResolvedHost>> {
    match shellflow_core::resolve_hosts(plan, target, &setup.restrict) {
        Ok(hosts) => Some(hosts),
        Err(err) => {
            crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
            None
        }
    }
}

/// Run one target-command step (`@service`, `@install`, `@backup`, …) on
/// already-resolved hosts.
///
/// The transport choice (ssh/muxy) and the per-host fan-out are owned by
/// [`super::host::run_target_command`]; this wrapper only threads the shared
/// per-run state, so a new verb contributes its `command`, `label`, and
/// [`super::transport::StepClass`] and nothing else.
#[cfg_attr(
    not(feature = "muxy"),
    expect(
        unused_variables,
        reason = "the ssh-only build never classifies steps; the class drives only the muxy policy"
    )
)]
async fn run_target_step(
    setup: &RunSetup,
    step_no: usize,
    config: StepConfig,
    hosts: Vec<shellflow_core::ResolvedHost>,
    command: String,
    label: String,
    class: super::transport::StepClass,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    super::host::run_target_command(super::host::TargetCommand {
        ui: &setup.ui,
        command,
        hosts,
        config,
        semaphore: &setup.semaphore,
        log_file: &setup.log_file,
        cancel: &setup.cancel,
        secrets: &setup.resolved,
        shell_cache: &setup.shell_cache,
        label: &label,
        #[cfg(feature = "muxy")]
        step_class: class,
        #[cfg(feature = "muxy")]
        muxy: &setup.muxy,
        #[cfg(feature = "muxy")]
        step_no,
    })
    .await
}

/// Dispatch one selected step to its executor (local / remote / copy).
async fn run_single_step(
    setup: &RunSetup,
    plan: &shellflow_core::ExecutionPlan,
    run: &crate::cli::RunArgs,
    step_no: usize,
    step: &shellflow_core::Step,
) -> (Option<RunError>, eyre::Result<Vec<(String, HostOutcome)>>) {
    // `@timeout` overrides the run-wide default: a long build or health
    // check must be able to widen the budget the CLI set for ordinary steps.
    let config = StepConfig::new(run, step.timeout().or(run.flags.timeout));
    #[cfg(not(feature = "muxy"))]
    if config.transport == super::transport::TransportPolicy::Muxy {
        crate::ui::step_failed(
            step_no,
            "--transport muxy needs a shellflow built with the `muxy` feature (use --transport ssh)",
            &setup.log_file,
        );
        return (Some(RunError::Plan), Ok(Vec::new()));
    }
    match step {
        shellflow_core::Step::Local(local) => {
            let outcome = super::local::run_local_step(
                &setup.ui,
                &setup.run_state,
                local,
                config,
                setup.mask_min_len,
                &setup.cancel,
            )
            .await;
            (None, outcome)
        }
        shellflow_core::Step::Remote(remote) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &remote.target) else {
                return plan_failure();
            };
            let ctx = RemoteStepCtx {
                ui: &setup.ui,
                semaphore: &setup.semaphore,
                run_state: &setup.run_state,
                shell_cache: &setup.shell_cache,
                secrets: &setup.resolved,
                log_file: &setup.log_file,
                cancel: &setup.cancel,
                step_no,
                #[cfg(feature = "muxy")]
                muxy: &setup.muxy,
            };
            (None, run_remote_step(&ctx, remote, hosts, config).await)
        }
        shellflow_core::Step::Copy(copy) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &copy.target) else {
                return plan_failure();
            };
            let copy_args = CopyStepArgs {
                ui: Arc::clone(&setup.ui),
                semaphore: setup.semaphore.clone(),
                run_state: Arc::clone(&setup.run_state),
                shell_cache: Arc::clone(&setup.shell_cache),
                log_file: setup.log_file.clone(),
                cancel: setup.cancel.clone(),
                workdir: setup.workdir.clone(),
            };
            super::copy::run_copy_step(&copy_args, copy, hosts, config).await
        }
        shellflow_core::Step::Wait(wait) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &wait.target) else {
                return plan_failure();
            };
            (
                None,
                run_wait_step(
                    &setup.ui,
                    wait,
                    hosts,
                    config,
                    &setup.semaphore,
                    &setup.log_file,
                    &setup.cancel,
                    &StepTransport {
                        #[cfg(feature = "muxy")]
                        shell_cache: Arc::clone(&setup.shell_cache),
                        #[cfg(feature = "muxy")]
                        muxy: setup.muxy.clone(),
                        #[cfg(feature = "muxy")]
                        step_no,
                    },
                )
                .await,
            )
        }
        shellflow_core::Step::Assert(assert) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &assert.target) else {
                return plan_failure();
            };
            (
                None,
                super::assert_step::run_assert_step(super::assert_step::AssertStepArgs {
                    ui: &setup.ui,
                    assert,
                    hosts,
                    config,
                    semaphore: &setup.semaphore,
                    log_file: &setup.log_file,
                    cancel: &setup.cancel,
                    run_state: &setup.run_state,
                })
                .await,
            )
        }
        shellflow_core::Step::Helper(helper) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &helper.target) else {
                return plan_failure();
            };
            (
                None,
                super::host::run_helper_step(
                    &setup.ui,
                    helper,
                    hosts,
                    config,
                    &setup.semaphore,
                    &setup.log_file,
                    &setup.cancel,
                )
                .await,
            )
        }
        shellflow_core::Step::Reload(reload) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &reload.target) else {
                return plan_failure();
            };
            (
                None,
                run_reload_step(
                    &setup.ui,
                    reload,
                    hosts,
                    config,
                    &setup.semaphore,
                    &setup.log_file,
                    &setup.cancel,
                    &StepTransport {
                        #[cfg(feature = "muxy")]
                        shell_cache: Arc::clone(&setup.shell_cache),
                        #[cfg(feature = "muxy")]
                        muxy: setup.muxy.clone(),
                        #[cfg(feature = "muxy")]
                        step_no,
                    },
                )
                .await,
            )
        }
        shellflow_core::Step::Service(service) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &service.target) else {
                return plan_failure();
            };
            let command = super::host::service_command(
                &service.unit,
                super::host::ServiceActions {
                    enable: service.enable,
                    restart: service.restart,
                    reload: service.reload,
                    wait: service.wait,
                    verify: service.verify,
                    force_start: service.force_start,
                },
                service.timeout.unwrap_or(helper::DEFAULT_WAIT_SECS),
            );
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    command,
                    format!("service {}", service.unit),
                    super::transport::StepClass::Service,
                )
                .await,
            )
        }
        shellflow_core::Step::Install(install) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &install.target) else {
                return plan_failure();
            };
            // The paths may name a captured variable (`$WORKDIR/…`).
            // In check mode the local blocks never ran, so the run
            // state is empty: the paths are left uninterpolated and
            // the step is a no-op, exactly like a copy step.
            let (src, dst) = if config.check || config.dry_run {
                (install.src.clone(), install.dst.clone())
            } else {
                let state = setup.run_state.lock().await;
                let src =
                    shellflow_core::interpolate(&install.src, &state).map_err(eyre::Error::from);
                let dst =
                    shellflow_core::interpolate(&install.dst, &state).map_err(eyre::Error::from);
                match (src, dst) {
                    (Ok(src), Ok(dst)) => (src, dst),
                    (Err(err), _) | (_, Err(err)) => {
                        crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
                        return (Some(RunError::Plan), Ok(Vec::new()));
                    }
                }
            };
            let command = super::host::install_command(
                &src,
                &dst,
                install.mode,
                install.owner.as_deref(),
                install.dir_mode,
            );
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    command,
                    format!("install {dst}"),
                    super::transport::StepClass::ShortHelper,
                )
                .await,
            )
        }
        shellflow_core::Step::Backup(backup) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &backup.target) else {
                return plan_failure();
            };
            let paths = if config.check || config.dry_run {
                backup.paths.clone()
            } else {
                let state = setup.run_state.lock().await;
                let mut resolved = Vec::with_capacity(backup.paths.len());
                for path in &backup.paths {
                    match shellflow_core::interpolate(path, &state) {
                        Ok(path) => resolved.push(path),
                        Err(err) => {
                            crate::ui::step_failed(step_no, &err.to_string(), &setup.log_file);
                            return (Some(RunError::Plan), Ok(Vec::new()));
                        }
                    }
                }
                resolved
            };
            let command = super::host::backup_command(
                &paths,
                backup.service.as_deref(),
                backup.dir.as_deref(),
                backup.keep,
                backup.seal,
            );
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    command,
                    "backup".to_string(),
                    super::transport::StepClass::LongHelper,
                )
                .await,
            )
        }
        shellflow_core::Step::Credstore(credstore) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &credstore.target) else {
                return plan_failure();
            };
            let command = super::host::credstore_command(&credstore.service, &credstore.require);
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    command,
                    format!("credstore {}", credstore.service),
                    super::transport::StepClass::ShortHelper,
                )
                .await,
            )
        }
        shellflow_core::Step::UnitInventory(inventory) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &inventory.target) else {
                return plan_failure();
            };
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    super::host::unit_inventory_command(),
                    "unit inventory".to_string(),
                    super::transport::StepClass::ShortHelper,
                )
                .await,
            )
        }
        shellflow_core::Step::Release(release) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &release.target) else {
                return plan_failure();
            };
            let command = super::release::release_command(
                &release.repo,
                &release.installed_cmd,
                &release.asset,
                &release.to_dir,
                release.base_url.as_deref(),
            );
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    command,
                    format!("release {}", release.repo),
                    super::transport::StepClass::LongHelper,
                )
                .await,
            )
        }
        shellflow_core::Step::Build(build) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &build.target) else {
                return plan_failure();
            };
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    super::build::build_command(build),
                    format!("build {}", build.repo),
                    super::transport::StepClass::LongHelper,
                )
                .await,
            )
        }
        shellflow_core::Step::Toolchain(toolchain) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &toolchain.target) else {
                return plan_failure();
            };
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    super::toolchain::toolchain_command(&toolchain.tools),
                    "toolchain update".to_string(),
                    super::transport::StepClass::LongHelper,
                )
                .await,
            )
        }
        shellflow_core::Step::Image(image) => {
            let Some(hosts) = resolve_or_report(plan, setup, step_no, &image.target) else {
                return plan_failure();
            };
            (
                None,
                run_target_step(
                    setup,
                    step_no,
                    config,
                    hosts,
                    super::image::image_command(&image.images, image.prune),
                    "image update".to_string(),
                    super::transport::StepClass::LongHelper,
                )
                .await,
            )
        }
        // `Step` is `#[non_exhaustive]`. A variant this build does not know
        // cannot be executed, and skipping it silently would report a
        // successful deploy that never ran the step: fail the plan instead.
        _ => {
            crate::ui::step_failed(
                step_no,
                "this build does not recognise the step (upgrade shellflow)",
                &setup.log_file,
            );
            plan_failure()
        }
    }
}

/// Trigger a graceful reload of a unit on the remote hosts.
///
/// The ladder is the one the target-side helper implements: the unit's own
/// `ExecReload=` first, then an explicit `--signal`, and never a silent
/// fallback to a restart — a restart drops the connections the reload exists
/// to preserve, so failing is the honest answer.
#[expect(
    clippy::too_many_arguments,
    reason = "the transport context is an additional parameter to the existing seven"
)]
pub(super) async fn run_reload_step(
    ui: &ArcUi,
    reload: &shellflow_core::ReloadStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
    semaphore: &Option<Arc<Semaphore>>,
    log_file: &LogFile,
    cancel: &Cancel,
    #[cfg_attr(
        not(feature = "muxy"),
        expect(unused_variables, reason = "the ssh-only build ignores the muxy transport")
    )]
    transport: &StepTransport,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    use tokio::time::Duration;
    if config.check || config.dry_run {
        crate::ui::note(&format!("  reload {} (no-op in check/dry-run)", reload.unit), log_file);
        return Ok(hosts.into_iter().map(|host| (host.alias, HostOutcome::Ok)).collect());
    }
    let timeout = Duration::from_secs(reload.timeout.unwrap_or(helper::DEFAULT_RELOAD_SECS));
    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let unit = reload.unit.clone();
        let signal = reload.signal.clone();
        let wait = reload.wait;
        let semaphore = semaphore.clone();
        let log_file = log_file.clone();
        let cancel = cancel.clone();
        #[cfg(feature = "muxy")]
        let transport = transport.clone();
        tasks.spawn(async move {
            let _permit = fanout_slot!(&semaphore, &log_file, host);
            if cancel.is_cancelled() {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
            // Muxy first: the reload helper owns a session like any other
            // long command; a failed connect falls back to ssh under auto.
            #[cfg(feature = "muxy")]
            if super::muxy::class_uses_muxy(config, super::StepClass::Reload) {
                let remote_env = resolve_remote_env(&host, &transport.shell_cache, &cancel).await;
                let attempt = super::muxy::exec_command(super::muxy::CommandStep {
                    ui: &ui,
                    host: &host,
                    class: super::StepClass::Reload,
                    command: helper::reload_command(
                        &unit,
                        signal.as_deref(),
                        wait,
                        timeout.as_secs(),
                    ),
                    env: with_login_path(Vec::new(), remote_env.path.as_deref()),
                    has_secrets: false,
                    probe_muxy: remote_env.has_muxy,
                    timeout: Some(timeout.as_secs() + 30),
                    config,
                    log_file: &log_file,
                    cancel: &cancel,
                    muxy: &transport.muxy,
                    step_no: transport.step_no,
                    transform: None,
                    explain_exit: Some(helper::reload_explain(&unit, timeout.as_secs())),
                })
                .await;
                if let super::muxy::CommandAttempt::Done((alias, outcome)) = attempt {
                    if outcome == HostOutcome::Ok {
                        ui.lock().await.masked_note(&format!("[{alias}] {unit} reloaded"));
                    }
                    return (alias, outcome);
                }
            }
            // One SSH round-trip: the helper performs the reload and, with
            // `--wait`, waits for the notify handshake on the target.
            let cmd = super::transport::ssh_argv_command(
                &host,
                &helper::reload_command(&unit, signal.as_deref(), wait, timeout.as_secs()),
                super::transport::SshPolicy::step(config.ssh_reuse, config.verbose >= 3),
            );
            let args = stream::PipedArgs {
                ui: &ui,
                host: &host.alias,
                payload: None,
                timeout: Some(timeout.as_secs() + 30),
                diff_filter: None,
                log_file: &log_file,
                cancel: cancel.clone(),
                quiet: false,
                collector: Some(helper::wait_collector(&unit)),
            };
            let outcome = match stream::run_piped_child(args, cmd).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                }
            };
            match outcome {
                stream::PipedRun::Completed(status) => {
                    // One ladder for both helpers (see `classify_helper_exit`):
                    // the reload and wait paths used to spell the same
                    // `0/255/3/4/other` vocabulary out twice, in different
                    // words.
                    let (outcome, note) = helper::classify_helper_exit(
                        status.code().unwrap_or(-1),
                        &unit,
                        helper::HelperVerb::Reload,
                        timeout.as_secs(),
                        &host.alias,
                    );
                    if !note.is_empty() {
                        ui.lock().await.masked_note(&note);
                    }
                    (host.alias.clone(), outcome)
                }
                // The transport's own budget expiring is a timeout, not a
                // transport failure: the ssh connection was fine.
                stream::PipedRun::TimedOut => (host.alias.clone(), HostOutcome::TimedOut),
                stream::PipedRun::PipeBroken => {
                    (host.alias.clone(), HostOutcome::Failed(RunError::Transport))
                }
                stream::PipedRun::Cancelled => (host.alias.clone(), HostOutcome::Cancelled),
            }
        });
    }
    Ok(stream::collect_hosts(ui, log_file, tasks).await)
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

    for (idx, step) in &setup.selected {
        if fail_fast_error.is_some() {
            break;
        }
        // A cancelled run stops scheduling new steps; the in-flight host
        // tasks observe the same signal and tear their children down.
        if cancel.is_cancelled() {
            break;
        }
        let step_no = idx + 1;
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
        // The staging directory is removed even on an interrupt: the run
        // must not leave its scratch space behind on the target.
        if let Some(guard) = &setup.workdir {
            guard.cleanup(&plan, &setup.semaphore, &setup.log_file).await;
        }
        return RunOutcome::Interrupted { total, torn_down: true };
    }

    // The staging directory is removed when the run ends, on every path.
    if let Some(guard) = &setup.workdir {
        guard.cleanup(&plan, &setup.semaphore, &setup.log_file).await;
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

/// The named hosts a run targets, plus the raw SSH specs that cannot key a
/// per-host secret file.
struct HostTargets {
    aliases: Vec<String>,
    raw: Vec<String>,
}

fn target_host_aliases(
    plan: &shellflow_core::ExecutionPlan,
    restrict: &[String],
    selected: &[(usize, shellflow_core::Step)],
    log_file: &LogFile,
) -> HostTargets {
    let mut aliases = std::collections::BTreeSet::new();
    let mut raw = std::collections::BTreeSet::new();
    for (_, step) in selected {
        // One accessor instead of a sixteen-arm match: a new step variant
        // must not have to be added here as well.
        let Some(target) = step.target() else {
            continue;
        };
        match shellflow_core::resolve_hosts(plan, target, restrict) {
            Ok(hosts) => {
                for host in hosts {
                    if plan.servers().contains_key(&host.alias) {
                        aliases.insert(host.alias);
                    } else {
                        raw.insert(host.alias);
                    }
                }
            }
            Err(err) => {
                crate::ui::warn(
                    &format!("target `{}` skipped for secrets pre-resolution: {err}", target.text),
                    log_file,
                );
            }
        }
    }
    HostTargets { aliases: aliases.into_iter().collect(), raw: raw.into_iter().collect() }
}

#[derive(Clone)]
pub(super) struct PayloadParts {
    pub(super) script: String,
    pub(super) guard: Option<String>,
    pub(super) env: Vec<(String, String)>,
    pub(super) trace: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the transport context is an additional parameter to the existing seven"
)]
pub(super) async fn run_wait_step(
    ui: &ArcUi,
    wait: &shellflow_core::WaitStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
    semaphore: &Option<Arc<Semaphore>>,
    log_file: &LogFile,
    cancel: &Cancel,
    #[cfg_attr(
        not(feature = "muxy"),
        expect(unused_variables, reason = "the ssh-only build ignores the muxy transport")
    )]
    transport: &StepTransport,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    use tokio::time::Duration;
    if config.check || config.dry_run {
        crate::ui::note(
            &format!(
                "  wait_active {} ({}s budget): no-op in check/dry-run",
                wait.unit,
                config.timeout.unwrap_or(helper::DEFAULT_WAIT_SECS),
            ),
            log_file,
        );
        return Ok(hosts.into_iter().map(|host| (host.alias, HostOutcome::Ok)).collect());
    }
    let budget = Duration::from_secs(config.timeout.unwrap_or(helper::DEFAULT_WAIT_SECS));
    let mut tasks = JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let unit = wait.unit.clone();
        let semaphore = semaphore.clone();
        let log_file = log_file.clone();
        let cancel = cancel.clone();
        #[cfg(feature = "muxy")]
        let transport = transport.clone();
        tasks.spawn(async move {
            let _permit = fanout_slot!(&semaphore, &log_file, host);
            if cancel.is_cancelled() {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
            // Muxy first: a readiness wait is exactly the long command the
            // transport exists for; the collector still turns its `SFW` state
            // lines into progress.
            #[cfg(feature = "muxy")]
            if super::muxy::class_uses_muxy(config, super::StepClass::Wait) {
                let remote_env = resolve_remote_env(&host, &transport.shell_cache, &cancel).await;
                let attempt = super::muxy::exec_command(super::muxy::CommandStep {
                    ui: &ui,
                    host: &host,
                    class: super::StepClass::Wait,
                    command: helper::wait_command(&unit, budget.as_secs()),
                    env: with_login_path(Vec::new(), remote_env.path.as_deref()),
                    has_secrets: false,
                    probe_muxy: remote_env.has_muxy,
                    timeout: Some(budget.as_secs() + 30),
                    config,
                    log_file: &log_file,
                    cancel: &cancel,
                    muxy: &transport.muxy,
                    step_no: transport.step_no,
                    transform: Some(helper::wait_collector(&unit)),
                    explain_exit: Some(helper::wait_explain(&unit, budget.as_secs())),
                })
                .await;
                if let super::muxy::CommandAttempt::Done((alias, outcome)) = attempt {
                    if outcome == HostOutcome::Ok {
                        ui.lock().await.masked_note(&format!("[{alias}] {unit} active"));
                    }
                    return (alias, outcome);
                }
            }
            // The wait runs *on the target*: the helper polls systemd there and
            // streams one state line per poll. The whole wait therefore costs
            // a single SSH round-trip instead of one per poll, and the
            // operator sees the service's own `STATUS=` text while it starts.
            let cmd = super::transport::ssh_argv_command(
                &host,
                &helper::wait_command(&unit, budget.as_secs()),
                super::transport::SshPolicy::step(config.ssh_reuse, config.verbose >= 3),
            );
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
                collector: Some(helper::wait_collector(&unit)),
            };
            let outcome = match stream::run_piped_child(args, cmd).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                }
            };
            match outcome {
                stream::PipedRun::Completed(status) => {
                    let (outcome, note) = helper::classify_helper_exit(
                        status.code().unwrap_or(-1),
                        &unit,
                        helper::HelperVerb::Wait,
                        budget.as_secs(),
                        &host.alias,
                    );
                    if !note.is_empty() {
                        ui.lock().await.masked_note(&note);
                    }
                    (host.alias.clone(), outcome)
                }
                stream::PipedRun::TimedOut => (host.alias.clone(), HostOutcome::TimedOut),
                stream::PipedRun::PipeBroken => {
                    (host.alias.clone(), HostOutcome::Failed(RunError::Transport))
                }
                stream::PipedRun::Cancelled => (host.alias.clone(), HostOutcome::Cancelled),
            }
        });
    }
    Ok(stream::collect_hosts(ui, log_file, tasks).await)
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
    let parts = PayloadParts {
        script: remote.script.clone(),
        guard: remote.guard.clone(),
        env,
        trace: config.verbose >= 3,
    };
    let mut tasks = JoinSet::new();
    #[cfg(feature = "muxy")]
    let step_no = ctx.step_no;
    #[cfg(feature = "muxy")]
    let muxy = ctx.muxy.clone();
    for host in hosts {
        let ui = Arc::clone(ctx.ui);
        let semaphore = ctx.semaphore.clone();
        let parts = parts.clone();
        let shell_cache = Arc::clone(ctx.shell_cache);
        let secrets = Arc::clone(ctx.secrets);
        let log_file = ctx.log_file.clone();
        let cancel = ctx.cancel.clone();
        #[cfg(feature = "muxy")]
        let muxy = muxy.clone();
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
                #[cfg(feature = "muxy")]
                step_no,
                #[cfg(feature = "muxy")]
                muxy: &muxy,
            })
            .await
        });
    }

    Ok(stream::collect_hosts(ctx.ui, ctx.log_file, tasks).await)
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
                GuardOutcome::TimedOut => {
                    return Ok(vec![("localhost".to_string(), HostOutcome::TimedOut)]);
                }
                GuardOutcome::Cancelled => {
                    return Ok(vec![("localhost".to_string(), HostOutcome::Cancelled)]);
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
        // A `--local` remote block never captures (`@export` requires a
        // local block), so the threshold is irrelevant here; `0` would mask
        // everything, which is the safe direction if a capture is ever
        // added.
        capture: &[],
        extra: &extra,
        log_file,
        mask_min_len: 0,
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
        Err(super::local::LocalFailure::Cancelled) => {
            Ok(vec![("localhost".to_string(), HostOutcome::Cancelled)])
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
    /// The 1-based plan index (names the muxy payload file).
    #[cfg(feature = "muxy")]
    step_no: usize,
    /// Per-run muxy state.
    #[cfg(feature = "muxy")]
    muxy: &'a super::muxy::MuxyRun,
}

async fn run_remote_host(args: RemoteHostArgs<'_>) -> (String, HostOutcome) {
    let RemoteHostArgs {
        ui,
        host,
        parts,
        config,
        shell_cache,
        secrets,
        log_file,
        cancel,
        #[cfg(feature = "muxy")]
        step_no,
        #[cfg(feature = "muxy")]
        muxy,
    } = args;
    if config.dry_run {
        return run_syntax_check(SyntaxCheckArgs { ui, host, parts, config, log_file, cancel })
            .await;
    }
    if config.check {
        // `--check` is `bash -n -s`: byte-exact stdin, no PTY, no session.
        // On a muxy host that is the `exec` channel; anything else is ssh.
        #[cfg(feature = "muxy")]
        if super::muxy::class_uses_muxy(config, super::StepClass::Check) {
            let remote_env = resolve_remote_env(host, &shell_cache, &cancel).await;
            // The check payload is the session payload minus the guard and
            // the environment header: `bash -n` needs neither, and leaving
            // them out keeps secret material off the wire entirely.
            let check_payload = super::transport::Payload {
                script: &parts.script,
                guard: None,
                trace: parts.trace,
                env: Vec::new(),
                timeout: config.timeout,
            }
            .render_check();
            match super::muxy::ensure_host(muxy, host, remote_env.has_muxy, false, config, log_file)
                .await
            {
                super::muxy::EnsureOutcome::Muxy(conn) => {
                    match super::muxy::check_via_muxy(&conn, &check_payload, config.timeout).await {
                        Ok(()) => {
                            report_syntax_ok(host, &parts.script, log_file);
                            return (host.alias.clone(), HostOutcome::Ok);
                        }
                        Err(err) => {
                            crate::ui::warn(&format!("[{}] {err}", host.alias), log_file);
                            // A check changes nothing, so under `auto` the
                            // ssh syntax check is still a valid fallback.
                            if config.transport == super::transport::TransportPolicy::Muxy {
                                return (
                                    host.alias.clone(),
                                    HostOutcome::Failed(RunError::Transport),
                                );
                            }
                        }
                    }
                }
                super::muxy::EnsureOutcome::Ssh => {}
                super::muxy::EnsureOutcome::Fail(message) => {
                    crate::ui::warn(&message, log_file);
                    return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                }
            }
        }
        return run_syntax_check(SyntaxCheckArgs { ui, host, parts, config, log_file, cancel })
            .await;
    }

    let remote_env = resolve_remote_env(host, &shell_cache, &cancel).await;
    let mut payload_env = with_login_path(parts.env.clone(), remote_env.path.as_deref());
    secrets.overlay(&mut payload_env, &host.alias);

    // The guard is folded into the payload: evaluating it used to cost a
    // second SSH round trip, so a guarded step paid double for one
    // precondition.
    let has_guard = parts.guard.is_some();
    let payload = super::transport::Payload {
        script: &parts.script,
        guard: parts.guard.as_deref(),
        trace: parts.trace,
        env: payload_env,
        timeout: config.timeout,
    };

    // Muxy first: one session for the block, environment applied by the
    // server (never written to disk), lines streamed through the same Ui.
    #[cfg(feature = "muxy")]
    if super::muxy::class_uses_muxy(config, super::StepClass::Remote) {
        let has_secrets = secrets.has_for_host(&host.alias);
        match super::muxy::ensure_host(
            muxy,
            host,
            remote_env.has_muxy,
            has_secrets,
            config,
            log_file,
        )
        .await
        {
            super::muxy::EnsureOutcome::Muxy(conn) => {
                let attempt = super::muxy::attempt_step(super::muxy::MuxyStep {
                    ui: &ui,
                    host: host.clone(),
                    conn,
                    script: payload.script.to_string(),
                    guard: payload.guard.map(str::to_string),
                    env: payload.env.clone(),
                    has_secrets,
                    has_guard,
                    timeout: payload.timeout,
                    config,
                    transform: None,
                    explain_exit: None,
                    log_file: log_file.clone(),
                    cancel: cancel.clone(),
                    run_id: muxy.run_id.clone(),
                    step_id: format!("step-{step_no}"),
                })
                .await;
                match attempt {
                    super::muxy::MuxyAttempt::Done(pair) => return pair,
                    // Nothing was created on the target: the ssh path below
                    // runs the block exactly once.
                    super::muxy::MuxyAttempt::Fallback => {}
                }
            }
            super::muxy::EnsureOutcome::Ssh => {}
            super::muxy::EnsureOutcome::Fail(message) => {
                crate::ui::warn(&message, log_file);
                return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
            }
        }
    }

    let payload = match payload.render_ssh() {
        Ok(payload) => payload,
        Err(err) => {
            crate::ui::warn(&format!("[{}] {err}", host.alias), log_file);
            return (host.alias.clone(), HostOutcome::Failed(RunError::Plan));
        }
    };
    let cmd = super::transport::ssh_stdin_command(
        host,
        remote_env.shell.invoke(false),
        config.ssh_reuse,
        config.verbose >= 3,
    );
    if config.verbose >= 2 {
        ui.lock().await.masked_note(&format!(
            "  [{}] ssh {}",
            host.alias,
            super::display_args(&cmd)
        ));
    }
    match run_ssh_child(SshChildArgs {
        ui: ui.clone(),
        host,
        cmd,
        payload: &payload,
        timeout: config.timeout,
        has_guard,
        log_file,
        cancel,
    })
    .await
    {
        Ok(()) => {
            if let Some(guard) = &parts.guard &&
                config.verbose >= 2
            {
                // The guard text is user content and can embed a secret.
                ui.lock().await.masked_note(&format!("  [{}] guard passed: {guard}", host.alias));
            }
            (host.alias.clone(), HostOutcome::Ok)
        }
        Err(SshOutcome::Skipped) => {
            crate::ui::note(&format!("[{}] SKIPPED (guard)", host.alias), log_file);
            (host.alias.clone(), HostOutcome::Skipped)
        }
        Err(outcome) => {
            crate::ui::warn(&format!("[{}] {outcome:?}", host.alias), log_file);
            (host.alias.clone(), classify_ssh(outcome))
        }
    }
}

/// The parameters of a `bash -n` syntax check on one host.
struct SyntaxCheckArgs<'a> {
    ui: ArcUi,
    host: &'a ResolvedHost,
    parts: &'a PayloadParts,
    config: StepConfig,
    log_file: &'a LogFile,
    cancel: Cancel,
}

/// `bash -n` over ssh: the `--check`/`--dry-run` path, and the `auto`
/// fallback when the muxy `exec` channel is unavailable.
async fn run_syntax_check(args: SyntaxCheckArgs<'_>) -> (String, HostOutcome) {
    let SyntaxCheckArgs { ui, host, parts, config, log_file, cancel } = args;
    let payload = match (super::transport::Payload {
        script: &parts.script,
        guard: None,
        trace: parts.trace,
        env: parts.env.clone(),
        timeout: config.timeout,
    })
    .render_ssh()
    {
        Ok(payload) => payload,
        Err(err) => {
            crate::ui::warn(&format!("[{}] {err}", host.alias), log_file);
            return (host.alias.clone(), HostOutcome::Failed(RunError::Plan));
        }
    };
    let cmd = || {
        super::transport::ssh_stdin_command(
            host,
            RemoteShell::Bash.invoke(true),
            config.ssh_reuse,
            config.verbose >= 3,
        )
    };
    if config.verbose >= 2 {
        let cmd = cmd();
        ui.lock().await.masked_note(&format!(
            "  [{}] ssh {}",
            host.alias,
            super::display_args(&cmd)
        ));
    }
    match run_ssh_child(SshChildArgs {
        ui,
        host,
        cmd: cmd(),
        payload: &payload,
        timeout: config.timeout,
        // A syntax check has no guard: exit 42 in user code is an
        // ordinary failure, never a skip.
        has_guard: false,
        log_file,
        cancel,
    })
    .await
    {
        Ok(()) => {
            report_syntax_ok(host, &parts.script, log_file);
            (host.alias.clone(), HostOutcome::Ok)
        }
        Err(outcome) => {
            crate::ui::warn(&format!("[{}] {outcome:?}", host.alias), log_file);
            (host.alias.clone(), classify_ssh(outcome))
        }
    }
}

/// The verdict of a successful syntax check, plus the local lint findings.
fn report_syntax_ok(host: &ResolvedHost, script: &str, log_file: &LogFile) {
    crate::ui::note(&format!("[{}] syntax check (bash -n): OK", host.alias), log_file);
    for finding in crate::lint::lint_block(script) {
        crate::ui::warn(
            &format!("[{}] line {}: {}", host.alias, finding.line, finding.message),
            log_file,
        );
    }
}

pub(super) fn with_login_path(
    mut env: Vec<(String, String)>,
    path: Option<&str>,
) -> Vec<(String, String)> {
    if env.iter().any(|(k, _)| k == "PATH") {
        return env;
    }
    if let Some(path) = path {
        env.push(("PATH".to_string(), path.to_string()));
    }
    env
}

pub(crate) async fn resolve_remote_env(
    host: &ResolvedHost,
    cache: &ShellCache,
    cancel: &Cancel,
) -> RemoteEnv {
    let key = super::shell_cache_key(host);
    // The map lock guards the map only. The probe used to run while the lock
    // was held, which made "probe each destination once" mean "probe the whole
    // fleet one host at a time": a single unreachable host costs its full
    // retry budget (2 x 6s + 0.5s) and every other host task waited on the
    // same mutex, so `--parallel N` degraded to a serial sweep. A per-key
    // `OnceCell` keeps the de-duplication and moves the wait off the lock.
    let cell = {
        let mut map = cache.lock().await;
        Arc::clone(map.entry(key.clone()).or_default())
    };
    if let Some(env) = cell.get_or_init(|| probe_remote_env(host, cancel)).await {
        return env.clone();
    }
    // Only a *completed* probe is cached: a failed one yields the default
    // environment and is retried by the next caller instead of being pinned on
    // the host for the rest of the run.
    cache.lock().await.remove(&key);
    RemoteEnv::default()
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
    if command -v muxy >/dev/null 2>&1; then
        printf '%s\n' 'SHELLFLOW_MUXY=1'
    else
        printf '%s\n' 'SHELLFLOW_MUXY=0'
    fi;
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

/// The wall-clock budget of one probe attempt.
///
/// The budget must exceed
/// [`super::transport::PROBE_CONNECT_TIMEOUT_SECS`]: with the two
/// equal, a slow TCP connect has `ssh` give up at the same moment the probe
/// does, and the probe is cut off mid-flight — the host looks like it has no
/// rsync, and a perfectly good deploy fails with a misleading message.
/// Kept small so two attempts plus backoff stay within the interrupt grace.
const PROBE_ATTEMPT_BUDGET_SECS: u64 = 6;

/// How many times a failed probe is retried.
///
/// A dropped SYN, a proxy hiccup or a half-open connection is transient;
/// writing the host off on the first failure turns a network blip into a
/// failed deploy.
const PROBE_ATTEMPTS: usize = 2;

/// Probe the remote host, retrying a transient failure once.
///
/// # Errors
///
/// Returns `None` when the probe did not complete (an unreachable host): the
/// caller must **not** cache that outcome, or one transient failure would pin
/// `has_rsync = false` and no login `PATH` on the host for the rest of the run.
async fn probe_remote_env(host: &ResolvedHost, cancel: &Cancel) -> Option<RemoteEnv> {
    for attempt in 1..=PROBE_ATTEMPTS {
        if let Some(env) = probe_once(host, cancel).await {
            return Some(env);
        }
        if cancel.is_cancelled() {
            break;
        }
        if attempt < PROBE_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    None
}

/// One probe attempt.
///
/// Returns `None` when the probe did not run to completion (a truncated
/// connection, an unreachable host): the caller retries rather than acting
/// on a partial result.
async fn probe_once(host: &ResolvedHost, cancel: &Cancel) -> Option<RemoteEnv> {
    use tokio::io::AsyncReadExt as _;
    // The rsync check is separated from the report by a `;` and its result is
    // carried in the marker line, so a host without `rsync` still returns a
    // successful probe.
    let script = format!(
        "{}\ncommand -v rsync >/dev/null 2>&1 && echo SHELLFLOW_HAS_RSYNC\nprintf '%s\\n' {marker}",
        PROBE_SCRIPT.trim(),
        marker = PROBE_END_MARKER,
    );
    // The probe uses its own policy: it bounds the connect phase tighter than
    // a step does, and it never joins a multiplexed connection — a probe is a
    // cheap question that must answer (or fail) on its own.
    let mut cmd = Command::from(super::transport::ssh_command(
        super::transport::SshPolicy::probe(),
        &host.spec,
    ));
    cmd.arg(script);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return None,
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
    let status =
        super::process::wait_child(&mut child, Some(PROBE_ATTEMPT_BUDGET_SECS), &mut cancel_probe)
            .await;
    // A completed ssh — zero or not — still carries a usable probe when the
    // marker is present (e.g. a host without rsync): fall through to parsing
    // rather than discarding the login shell and PATH with it. Anything else
    // (timeout, cancellation, spawn failure) kills the probe.
    let output = if let super::process::ChildOutcome::Finished(Ok(_)) = status {
        group.disarm();
        match tokio::time::timeout(Duration::from_secs(2), reader).await {
            Ok(Ok(buf)) => buf,
            _ => return None,
        }
    } else {
        super::process::terminate(&mut child).await;
        group.disarm();
        reader.abort();
        return None;
    };
    let text = String::from_utf8_lossy(&output);
    let mut lines = text.lines();
    let shell = RemoteShell::detect(lines.next().unwrap_or_default());
    // The PATH is reported between sentinels, one directory per line, so a
    // polluted $PATH cannot split the value.
    let mut dirs: Vec<&str> = Vec::new();
    let mut in_path = false;
    let mut has_rsync = false;
    let mut has_muxy = false;
    let mut completed = false;
    for line in lines {
        match line.trim() {
            "SHELLFLOW_PATH_BEGIN" => in_path = true,
            "SHELLFLOW_PATH_END" => in_path = false,
            "SHELLFLOW_HAS_RSYNC" => has_rsync = true,
            "SHELLFLOW_MUXY=1" => has_muxy = true,
            "SHELLFLOW_MUXY=0" => has_muxy = false,
            other if other == PROBE_END_MARKER => completed = true,
            other if in_path && !other.is_empty() => dirs.push(other),
            _ => {}
        }
    }
    if !completed {
        // The probe did not run to completion (a truncated connection, an
        // unreachable host): fall back rather than act on a partial result.
        return None;
    }
    let path = if dirs.is_empty() { None } else { Some(dirs.join(":")) };
    Some(RemoteEnv { shell, path, has_rsync, has_muxy })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshOutcome {
    Transport,
    Script,
    TimedOut,
    Cancelled,
    /// The block's `@only_if` guard said no: the block was skipped.
    Skipped,
}

const fn classify_ssh(outcome: SshOutcome) -> HostOutcome {
    match outcome {
        SshOutcome::Transport => HostOutcome::Failed(RunError::Transport),
        SshOutcome::Script => HostOutcome::Failed(RunError::Script),
        SshOutcome::TimedOut => HostOutcome::TimedOut,
        SshOutcome::Cancelled => HostOutcome::Cancelled,
        SshOutcome::Skipped => HostOutcome::Skipped,
    }
}

/// The exit code a folded guard uses to say "skip this block".
///
/// The guard runs *inside* the payload, so it cannot report "skip" through a
/// separate channel; the exit code is the channel. It is deliberately
/// unusual: `ssh` uses 255 for a transport failure and a shell uses 1..125
/// for ordinary failures.
const GUARD_SKIP_EXIT: i32 = 42;

/// The guard folded into the payload of a remote block.
///
/// The guard used to be a **separate** SSH invocation: one round trip to
/// evaluate it and another to run the block. Folding it into the payload
/// halves the round trips of a guarded step, with the same observable
/// behaviour — a failing guard still skips the block, and the block's own
/// output is still discarded.
///
/// The `EXIT` trap remaps the *block's* exit code 42 to 1: 42 is the skip
/// channel, and a script that exits 42 for its own reason must not be
/// reported as a skipped block. The guard's own `exit 42` disables the trap
/// first, so only the guard can use the channel.
///
/// The guard keeps its own relaxed shell options (`set +u`), so a guard that
/// reads an unset variable behaves as it did before, and its output stays
/// hidden.
pub(crate) fn folded_guard(guard: &str) -> String {
    format!(
        "trap 'rc=$?; if [ \"$rc\" = {GUARD_SKIP_EXIT} ]; then exit 1; fi' EXIT\n\
         if ! ( set +u; {guard} ) >/dev/null 2>&1; then trap - EXIT; exit {GUARD_SKIP_EXIT}; fi\n"
    )
}

/// One SSH child invocation.
struct SshChildArgs<'a> {
    ui: ArcUi,
    host: &'a ResolvedHost,
    cmd: Command,
    payload: &'a str,
    timeout: Option<u64>,
    /// Only a payload that folded a guard may use the skip exit code. Without
    /// this flag, any block that exits 42 would be classified as SKIPPED and
    /// the step would count as a success.
    has_guard: bool,
    log_file: &'a LogFile,
    cancel: Cancel,
}

async fn run_ssh_child(args: SshChildArgs<'_>) -> Result<(), SshOutcome> {
    let SshChildArgs { ui, host, cmd, payload, timeout, has_guard, log_file, cancel } = args;
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
                if has_guard && status.code() == Some(GUARD_SKIP_EXIT) {
                    return Err(SshOutcome::Skipped);
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
    use super::{
        GUARD_SKIP_EXIT, folded_guard,
        helper::{wait_collector, wait_command},
    };

    /// Run a folded guard plus a body exactly as the remote payload does.
    fn run_payload(guard: &str, body: &str) -> i32 {
        let script = format!("set -eu\n{}{body}", folded_guard(guard));
        let status =
            std::process::Command::new("bash").args(["-c", &script]).status().expect("bash");
        status.code().expect("the child was not signalled")
    }

    #[test]
    fn a_failed_guard_uses_the_reserved_skip_exit() {
        assert_eq!(run_payload("false", "echo ran"), GUARD_SKIP_EXIT);
    }

    #[test]
    fn a_block_exiting_42_is_not_mistaken_for_a_skip() {
        // 42 is the skip channel; a block that exits 42 for its own reason is
        // an ordinary failure, so the trap must remap it.
        assert_eq!(run_payload("true", "exit 42"), 1);
    }

    #[test]
    fn a_guarded_block_keeps_its_own_failure_code() {
        assert_eq!(run_payload("true", "exit 7"), 7);
        assert_eq!(run_payload("true", "false"), 1);
    }

    #[test]
    fn a_passing_guard_runs_the_block() {
        assert_eq!(run_payload("true", "exit 0"), 0);
    }

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
        assert_eq!(
            rendered,
            "waiting foo.service: type=notify active=activating sub=start result=success"
        );
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
