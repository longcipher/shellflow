//! The muxy adapter: one connection per host, one session per step.
//!
//! The executor calls [`ensure_host`] the first time a host needs the
//! transport (connect + handshake + Home project, cached for the run), then
//! [`attempt_step`] per eligible step. Anything that fails before a session
//! exists reports [`MuxyAttempt::Fallback`] under `auto` so the step runs
//! over ssh instead; a failure after the session started is a real outcome
//! (the step may still be running — re-running it is never automatic).

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use shellflow_core::ResolvedHost;
use shellflow_muxy::{
    MuxyError, SessionId,
    conn::HostConnection,
    outcome::MuxyOutcome,
    session::{StepParams, StepResult, exec_check, run_step, sweep_stale},
};

use super::{
    ArcUi, HostOutcome, LogFile, RunError, StepConfig,
    cancel::Cancel,
    transport::{StepClass, TransportPolicy},
};
use crate::ui::Stream;

/// Per-run muxy state: the connection cache and the stable run id that names
/// the payload directories (and lets the stale sweep age them).
#[derive(Clone)]
pub(crate) struct MuxyRun {
    /// Connections by [`super::shell_cache_key`].
    pub(crate) cache: MuxyCache,
    /// Nanoseconds since the epoch, as decimal text.
    pub(crate) run_id: String,
}

impl MuxyRun {
    /// Fresh per-run state.
    #[must_use]
    pub(crate) fn new() -> Self {
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
            .to_string();
        Self { cache: Arc::new(std::sync::Mutex::new(HashMap::new())), run_id }
    }
}

impl Default for MuxyRun {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MuxyRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("MuxyRun").field("run_id", &self.run_id).finish_non_exhaustive()
    }
}

/// Connections by host key: one connection per host per run.
pub(crate) type MuxyCache = Arc<std::sync::Mutex<HashMap<String, MuxySlot>>>;

/// What the cache knows about a host.
pub(crate) enum MuxySlot {
    /// A live connection, shared by every step on this host.
    Available(Arc<std::sync::Mutex<HostConnection>>),
    /// No compatible server: use ssh, with this one-line reason at `-v`.
    Unavailable(String),
}

/// What `ensure_host` decided for one host.
pub(crate) enum EnsureOutcome {
    /// Run the step through this connection.
    Muxy(Arc<std::sync::Mutex<HostConnection>>),
    /// Run the step over ssh.
    Ssh,
    /// `--transport muxy` cannot be satisfied: fail the step (exit 3).
    Fail(String),
}

/// Ensure the transport for one host: reuse the cached connection (pinged),
/// connect once, or fall back to ssh.
///
/// `probe_muxy` is the `SHELLFLOW_MUXY` bit from the probe; `has_secrets`
/// marks a secret-bearing step, which needs `SESSION_ENVIRONMENT`.
pub(crate) async fn ensure_host(
    shared: &MuxyRun,
    host: &ResolvedHost,
    probe_muxy: bool,
    has_secrets: bool,
    config: StepConfig,
    log_file: &LogFile,
) -> EnsureOutcome {
    if config.transport == TransportPolicy::Ssh {
        return EnsureOutcome::Ssh;
    }
    let key = super::shell_cache_key(host);
    let cached = shared.cache.lock().map(|cache| cache.get(&key).map(slot_clone)).ok().flatten();
    match cached {
        Some(MuxySlot::Available(conn)) => {
            if ping(Arc::clone(&conn)).await {
                return EnsureOutcome::Muxy(conn);
            }
            shared.cache.lock().map(|mut cache| cache.remove(&key)).ok();
        }
        Some(MuxySlot::Unavailable(reason)) => {
            return fallback_or_fail(config.transport, &reason, host);
        }
        None => {}
    }
    if !probe_muxy {
        let reason = "muxy not installed".to_string();
        shared
            .cache
            .lock()
            .map(|mut cache| cache.insert(key, MuxySlot::Unavailable(reason.clone())))
            .ok();
        return fallback_or_fail(config.transport, &reason, host);
    }
    connect_host(shared, host, &key, has_secrets, config, log_file).await
}

fn slot_clone(slot: &MuxySlot) -> MuxySlot {
    match slot {
        MuxySlot::Available(conn) => MuxySlot::Available(Arc::clone(conn)),
        MuxySlot::Unavailable(reason) => MuxySlot::Unavailable(reason.clone()),
    }
}

async fn ping(conn: Arc<std::sync::Mutex<HostConnection>>) -> bool {
    tokio::task::spawn_blocking(move || conn.lock().is_ok_and(|conn| conn.ping().is_ok()))
        .await
        .unwrap_or(false)
}

/// Connect in a blocking thread (ssh + handshake must not stall the
/// runtime), sweep stale payloads, and cache the result.
async fn connect_host(
    shared: &MuxyRun,
    host: &ResolvedHost,
    key: &str,
    has_secrets: bool,
    config: StepConfig,
    log_file: &LogFile,
) -> EnsureOutcome {
    let alias = host.alias.clone();
    let spec = host.spec.to_ssh_args();
    let key = key.to_string();
    let cache = Arc::clone(&shared.cache);
    let run_id = shared.run_id.clone();
    let verbose = config.verbose;
    let connected = tokio::task::spawn_blocking(move || {
        HostConnection::connect(&alias, &spec).inspect(|conn| {
            sweep_stale(conn, &run_id);
        })
    })
    .await;
    let conn = match connected {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            let reason = short_reason(&err);
            cache
                .lock()
                .map(|mut cache| cache.insert(key, MuxySlot::Unavailable(reason.clone())))
                .ok();
            return fallback_or_fail(config.transport, &reason, host);
        }
        Err(_) => {
            let reason = "the muxy connect task stopped unexpectedly".to_string();
            return fallback_or_fail(config.transport, &reason, host);
        }
    };
    // (no debug note)
    if has_secrets && !conn.supports_env() {
        let reason = "the server does not support session environments".to_string();
        if config.transport == TransportPolicy::Muxy {
            return EnsureOutcome::Fail(format!(
                "[{}] {reason}; secret-bearing steps need it (use --transport ssh)",
                host.alias
            ));
        }
        if verbose >= 1 {
            crate::ui::note(&format!("[{}] {reason} — using ssh", host.alias), log_file);
        }
        return EnsureOutcome::Ssh;
    }
    if verbose >= 1 {
        crate::ui::note(
            &format!("[{}] transport muxy {}", host.alias, conn.server_version()),
            log_file,
        );
    }
    let conn = Arc::new(std::sync::Mutex::new(conn));
    cache.lock().map(|mut cache| cache.insert(key, MuxySlot::Available(Arc::clone(&conn)))).ok();
    EnsureOutcome::Muxy(conn)
}

fn short_reason(err: &MuxyError) -> String {
    match err {
        MuxyError::NotInstalled { .. } => "muxy not installed".to_string(),
        MuxyError::Unreachable { detail, .. } => format!("unreachable ({detail})"),
        MuxyError::Incompatible { detail, .. } => format!("incompatible ({detail})"),
        MuxyError::Timeout { .. } => "connection timed out".to_string(),
        other => other.to_string(),
    }
}

fn fallback_or_fail(policy: TransportPolicy, reason: &str, host: &ResolvedHost) -> EnsureOutcome {
    if policy == TransportPolicy::Muxy {
        return EnsureOutcome::Fail(format!(
            "[{}] transport muxy unavailable: {reason}",
            host.alias
        ));
    }
    EnsureOutcome::Ssh
}

/// What one muxy attempt produced.
pub(crate) enum MuxyAttempt {
    /// The step ran through muxy (or failed to in a way ssh must not retry).
    Done((String, HostOutcome)),
    /// Nothing was created on the target: run the ssh path instead.
    Fallback,
}

/// Parameters of one muxy step, shared by remote blocks and target commands.
pub(crate) struct MuxyStep<'a> {
    /// The shared UI handle.
    pub(crate) ui: &'a ArcUi,
    /// The host the step runs on.
    pub(crate) host: ResolvedHost,
    /// Its cached connection.
    pub(crate) conn: Arc<std::sync::Mutex<HostConnection>>,
    /// The shell block.
    pub(crate) script: String,
    /// The folded `@only_if` guard, if any.
    pub(crate) guard: Option<String>,
    /// The step environment (literals, secrets overlay, login `PATH`).
    pub(crate) env: Vec<(String, String)>,
    /// Whether any of `env` came from `@secrets`.
    pub(crate) has_secrets: bool,
    /// Whether the payload folded a guard (honours the 42 channel).
    pub(crate) has_guard: bool,
    /// Per-step deadline in seconds (the ssh path uses the same budget).
    pub(crate) timeout: Option<u64>,
    /// Per-step settings.
    pub(crate) config: StepConfig,
    /// Interprets output lines before they reach the UI (wait/reload state
    /// lines); `None` streams every line verbatim.
    pub(crate) transform: Option<super::stream::LineCollector>,
    /// Names a non-zero exit code for step classes with their own codes
    /// (a wait knows what `3`, `4`, and `5` mean).
    pub(crate) explain_exit: Option<ExplainExit>,
    /// The audit-log handle.
    pub(crate) log_file: LogFile,
    /// The cooperative cancellation signal.
    pub(crate) cancel: Cancel,
    /// Stable per-run id (names the payload directory).
    pub(crate) run_id: String,
    /// Stable per-step id (names the payload file).
    pub(crate) step_id: String,
}

/// Run one step through muxy, streaming lines through `Ui::host_line`.
pub(crate) async fn attempt_step(args: MuxyStep<'_>) -> MuxyAttempt {
    let MuxyStep {
        ui,
        host,
        conn,
        script,
        guard,
        env,
        has_secrets,
        has_guard,
        timeout,
        config,
        transform,
        explain_exit,
        log_file,
        cancel,
        run_id,
        step_id,
    } = args;
    let alias = host.alias.clone();
    let params = StepParams {
        run_id,
        step_id,
        script,
        guard,
        trace: config.verbose >= 3,
        env,
        has_secrets,
        has_guard,
        cols: config.muxy_cols,
        rows: config.muxy_rows,
        timeout: timeout.map(Duration::from_secs),
        keep_on_cancel: config.muxy_keep,
    };
    let policy = config.transport;
    let (lines_tx, mut lines_rx) = tokio::sync::mpsc::channel::<String>(256);
    let cancelled = Arc::new(AtomicBool::new(cancel.is_cancelled()));
    let watcher = {
        let cancelled = Arc::clone(&cancelled);
        let mut cancel = cancel.clone();
        tokio::spawn(async move {
            cancel.cancelled().await;
            cancelled.store(true, Ordering::SeqCst);
        })
    };
    let mut work = tokio::task::spawn_blocking(move || {
        let mut guard = conn.lock().map_err(|_| {
            (
                shellflow_muxy::MuxyFailure {
                    error: MuxyError::Request {
                        detail: "the muxy connection lock was poisoned".to_string(),
                    },
                    session: None,
                    still_running: false,
                },
                alias.clone(),
            )
        })?;
        run_step(
            &mut guard,
            &params,
            &|line| {
                let _ = lines_tx.blocking_send(line);
            },
            &cancelled,
        )
        .map(|result| (result, alias.clone()))
        .map_err(|failure| (failure, alias.clone()))
    });
    /// The join result of a muxy step's blocking task.
    type StepJoin = Result<
        Result<(StepResult, String), (shellflow_muxy::MuxyFailure, String)>,
        tokio::task::JoinError,
    >;
    let mut finished: Option<StepJoin> = None;
    loop {
        tokio::select! {
            line = lines_rx.recv() => {
                match line {
                    Some(line) => emit_line(ui, &host.alias, transform.as_ref(), line).await,
                    None => break,
                }
            }
            result = &mut work => {
                finished = Some(result);
                break;
            }
        }
    }
    // The sender is gone with the blocking task: drain what is left.
    lines_rx.close();
    while let Some(line) = lines_rx.recv().await {
        emit_line(ui, &host.alias, transform.as_ref(), line).await;
    }
    ui.lock().await.host_finished(&host.alias);
    watcher.abort();
    if finished.is_none() {
        finished = Some(work.await);
    }
    match finished {
        Some(Ok(Ok((result, alias)))) => {
            let outcome =
                map_muxy_outcome(&result.outcome, &alias, result.session, explain_exit, &log_file);
            if result.still_running {
                print_session_hints(&alias, result.session, &log_file);
            }
            MuxyAttempt::Done((alias, outcome))
        }
        Some(Ok(Err((failure, alias)))) => {
            if failure.session.is_none() && policy == TransportPolicy::Auto {
                MuxyAttempt::Fallback
            } else {
                if failure.still_running &&
                    let Some(session) = failure.session
                {
                    print_session_hints(&alias, session, &log_file);
                }
                crate::ui::warn(&format!("[{}] {}", alias, failure.error), &log_file);
                MuxyAttempt::Done((alias, HostOutcome::Failed(RunError::Transport)))
            }
        }
        Some(Err(err)) => {
            crate::ui::warn(
                &format!("[{}] the muxy step task stopped unexpectedly: {err}", host.alias),
                &log_file,
            );
            MuxyAttempt::Done((host.alias.clone(), HostOutcome::Failed(RunError::Transport)))
        }
        None => {
            crate::ui::warn(
                &format!("[{}] the muxy step task stopped unexpectedly", host.alias),
                &log_file,
            );
            MuxyAttempt::Done((host.alias.clone(), HostOutcome::Failed(RunError::Transport)))
        }
    }
}

/// One output line on its way to the UI: the collector owns it when a step
/// class interprets its own state lines (a wait), otherwise it passes through.
async fn emit_line(
    ui: &ArcUi,
    alias: &str,
    transform: Option<&super::stream::LineCollector>,
    line: String,
) {
    let Some(collector) = transform else {
        ui.lock().await.host_line(alias, Stream::Stdout, &line);
        return;
    };
    if let Some(rendered) = collector.record(&line) {
        ui.lock().await.host_line(alias, Stream::Stdout, &rendered);
    }
}

/// Map a muxy step outcome to a host outcome.
fn map_muxy_outcome(
    outcome: &MuxyOutcome,
    alias: &str,
    session: SessionId,
    explain_exit: Option<ExplainExit>,
    log_file: &LogFile,
) -> HostOutcome {
    let _ = session;
    match outcome {
        MuxyOutcome::Ok => HostOutcome::Ok,
        MuxyOutcome::Skipped => {
            crate::ui::note(&format!("[{alias}] SKIPPED (guard)"), log_file);
            HostOutcome::Skipped
        }
        MuxyOutcome::FailedScript { message, exit } => {
            let message = exit
                .and_then(|code| explain_exit.as_ref().and_then(|explain| explain(code)))
                .unwrap_or_else(|| message.clone());
            crate::ui::warn(&format!("[{alias}] {message}"), log_file);
            HostOutcome::Failed(RunError::Script)
        }
        MuxyOutcome::FailedTransport { message } => {
            crate::ui::warn(&format!("[{alias}] {message}"), log_file);
            HostOutcome::Failed(RunError::Transport)
        }
        MuxyOutcome::TimedOut => HostOutcome::TimedOut,
        MuxyOutcome::Cancelled => HostOutcome::Cancelled,
    }
}

/// The `--check` path over muxy: `bash -n -s` through `exec` (byte-exact
/// stdin, no PTY, no session).
pub(crate) async fn check_via_muxy(
    conn: &Arc<std::sync::Mutex<HostConnection>>,
    payload: &str,
    timeout_secs: Option<u64>,
) -> Result<(), MuxyError> {
    let payload = payload.to_string();
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(60));
    let conn = Arc::clone(conn);
    tokio::task::spawn_blocking(move || {
        let conn = conn.lock().map_err(|_| MuxyError::Request {
            detail: "the muxy connection lock was poisoned".to_string(),
        })?;
        exec_check(&conn, &payload, timeout)
    })
    .await
    .unwrap_or_else(|_| {
        Err(MuxyError::Request { detail: "the check task stopped unexpectedly".to_string() })
    })
}

/// Print the session id and the follow-up commands when a session outlives
/// its step (cancel + `--muxy-keep`, or a dropped connection).
pub(crate) fn print_session_hints(alias: &str, session: SessionId, log_file: &LogFile) {
    let id = session.get();
    crate::ui::note(&format!("[{alias}] step is still running as muxy session {id}"), log_file);
    crate::ui::note(&format!("[{alias}]   muxy --host {alias} session read-screen {id}"), log_file);
    crate::ui::note(&format!("[{alias}]   muxy --host {alias} session end {id} --yes"), log_file);
}

/// Whether this step class goes through muxy under the step's policy.
#[must_use]
pub(crate) const fn class_uses_muxy(config: StepConfig, class: StepClass) -> bool {
    super::transport::should_use_muxy(config.transport, class)
}

/// The closure that names a non-zero exit code for a step class.
pub(crate) type ExplainExit = Arc<dyn Fn(i32) -> Option<String> + Send + Sync>;

/// One command-shaped step (a target command, a reload, a wait) through muxy.
///
/// The ssh path for these steps is an argv (`ssh host 'cmd'`); the muxy path
/// is a one-session script with the same command text, so the two transports
/// run the same bytes.
pub(crate) struct CommandStep<'a> {
    /// The shared UI handle.
    pub(crate) ui: &'a ArcUi,
    /// The host the command runs on.
    pub(crate) host: &'a ResolvedHost,
    /// Which step class this command is (drives the muxy policy).
    pub(crate) class: StepClass,
    /// The command text (already the transport-independent form).
    pub(crate) command: String,
    /// The session environment (already including the probed login `PATH`).
    pub(crate) env: Vec<(String, String)>,
    /// Whether any of `env` came from `@secrets`.
    pub(crate) has_secrets: bool,
    /// The probe saw a `muxy` binary on this host.
    pub(crate) probe_muxy: bool,
    /// Per-step deadline in seconds (the ssh path adds its own grace).
    pub(crate) timeout: Option<u64>,
    /// Per-step settings.
    pub(crate) config: StepConfig,
    /// The audit-log handle.
    pub(crate) log_file: &'a LogFile,
    /// The cooperative cancellation signal.
    pub(crate) cancel: &'a Cancel,
    /// Per-run muxy state.
    pub(crate) muxy: &'a MuxyRun,
    /// The 1-based plan index (names the payload file).
    pub(crate) step_no: usize,
    /// Interprets output lines before they reach the UI.
    pub(crate) transform: Option<super::stream::LineCollector>,
    /// Names a non-zero exit code for step classes with their own codes.
    pub(crate) explain_exit: Option<ExplainExit>,
}

/// What [`exec_command`] decided.
pub(crate) enum CommandAttempt {
    /// The command ran through muxy (or failed in a way ssh must not retry).
    Done((String, HostOutcome)),
    /// Nothing was created on the target: run the ssh path instead.
    Fallback,
}

/// Run one command step through muxy when its class allows it.
///
/// Under `--transport muxy` an unavailable transport is a hard failure; under
/// `auto` it falls back to ssh as long as no session was created (a step that
/// may have partially run is never retried automatically).
pub(crate) async fn exec_command(args: CommandStep<'_>) -> CommandAttempt {
    if !class_uses_muxy(args.config, args.class) {
        return CommandAttempt::Fallback;
    }
    let conn = match ensure_host(
        args.muxy,
        args.host,
        args.probe_muxy,
        args.has_secrets,
        args.config,
        args.log_file,
    )
    .await
    {
        EnsureOutcome::Muxy(conn) => conn,
        EnsureOutcome::Ssh => return CommandAttempt::Fallback,
        EnsureOutcome::Fail(message) => {
            crate::ui::warn(&message, args.log_file);
            return CommandAttempt::Done((
                args.host.alias.clone(),
                HostOutcome::Failed(RunError::Transport),
            ));
        }
    };
    match attempt_step(MuxyStep {
        ui: args.ui,
        host: args.host.clone(),
        conn,
        script: args.command,
        guard: None,
        env: args.env,
        has_secrets: args.has_secrets,
        has_guard: false,
        timeout: args.timeout,
        config: args.config,
        transform: args.transform,
        explain_exit: args.explain_exit,
        log_file: args.log_file.clone(),
        cancel: args.cancel.clone(),
        run_id: args.muxy.run_id.clone(),
        step_id: format!("step-{}", args.step_no),
    })
    .await
    {
        MuxyAttempt::Done(pair) => CommandAttempt::Done(pair),
        MuxyAttempt::Fallback => CommandAttempt::Fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::{StepClass, TransportPolicy, class_uses_muxy};
    use crate::executor::StepConfig;

    fn config(transport: TransportPolicy) -> StepConfig {
        StepConfig {
            dry_run: false,
            diff: false,
            check: false,
            verbose: 0,
            timeout: None,
            local: false,
            ssh_reuse: true,
            allow_unfiltered_copy: false,
            transport,
            muxy_keep: false,
            muxy_cols: 200,
            muxy_rows: 50,
        }
    }

    #[test]
    fn short_helpers_stay_on_ssh_under_auto() {
        let config = config(TransportPolicy::Auto);
        assert!(class_uses_muxy(config, StepClass::Remote));
        assert!(!class_uses_muxy(config, StepClass::ShortHelper));
        assert!(class_uses_muxy(config, StepClass::Check));
    }
}
