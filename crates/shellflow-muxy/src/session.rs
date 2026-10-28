//! One session per step: payload file, environment, bootstrap, stream,
//! outcome, cleanup.
//!
//! The step thread owns the session lifecycle; the pump ([`crate::conn`])
//! owns the grid and the assembler. The two meet at a channel registration:
//! the pump forwards finished lines and the end reason, and the step thread
//! issues file/session requests, handles timeouts and cancellation, gap-fills
//! across a reconnect, and tears everything down.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use muxy_client::Client;
use muxy_protocol::{Feature, OperationId, ServerPath, SessionId, Size};

use crate::{
    conn::{DEFAULT_COLS, DEFAULT_ROWS, HostConnection, PumpMsg},
    error::MuxyError,
    outcome::{MuxyOutcome, map_exit_reason},
    payload::{begin_marker, bootstrap_line, build_payload, payload_rel_path, run_dir_rel_path},
};

/// How long the step waits for the last rows after asking the server to end
/// the session (timeout or cancel).
const END_GRACE: Duration = Duration::from_secs(5);

/// Cap of one payload file: the server rejects larger files.
const MAX_PAYLOAD_BYTES: usize = 5 * 1024 * 1024;

/// Parameters of one step's session.
#[derive(Clone)]
pub struct StepParams {
    /// Stable per-run id (names the payload directory).
    pub run_id: String,
    /// Stable per-step id (names the payload file).
    pub step_id: String,
    /// The shell block.
    pub script: String,
    /// The folded `@only_if` guard, if any.
    pub guard: Option<String>,
    /// `set -x` tracing at `-vvv`.
    pub trace: bool,
    /// `@env` values, `@secrets` overlays, and the probed login `PATH`.
    pub env: Vec<(String, String)>,
    /// Whether any of `env` came from `@secrets`.
    pub has_secrets: bool,
    /// Whether the payload folded a guard (honours the 42 channel).
    pub has_guard: bool,
    /// Session size.
    pub cols: u16,
    /// Session size.
    pub rows: u16,
    /// Step deadline (the `@timeout`/`--timeout` budget).
    pub timeout: Option<Duration>,
    /// Leave a cancelled session running (`--muxy-keep`).
    pub keep_on_cancel: bool,
}

impl StepParams {
    /// Session size, defaulting to 200x50.
    #[must_use]
    pub const fn size(&self) -> Size {
        Size { cols: self.cols, rows: self.rows }
    }
}

impl std::fmt::Debug for StepParams {
    /// Hand-written on purpose: `env` carries `@secrets` values, so a derived
    /// `Debug` would put plaintext credentials into any `{:?}` of a step.
    /// Keys are kept (they are the diagnostics) and values are counted only.
    /// `guard` is rendered the same way: it can interpolate a secret-bearing
    /// capture, so only its length/presence is shown.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<&str> = self.env.iter().map(|(key, _)| key.as_str()).collect();
        formatter
            .debug_struct("StepParams")
            .field("run_id", &self.run_id)
            .field("step_id", &self.step_id)
            .field("script_bytes", &self.script.len())
            .field("guard_bytes", &self.guard.as_ref().map(String::len))
            .field("trace", &self.trace)
            .field("env_keys", &keys)
            .field("has_secrets", &self.has_secrets)
            .field("has_guard", &self.has_guard)
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .field("timeout", &self.timeout)
            .field("keep_on_cancel", &self.keep_on_cancel)
            .finish_non_exhaustive()
    }
}

/// What a finished step leaves behind.
#[derive(Clone, Debug)]
pub struct StepResult {
    /// The mapped outcome.
    pub outcome: MuxyOutcome,
    /// The session id (for post-mortem hints and `--muxy-keep`).
    pub session: SessionId,
    /// True when the session is still running (cancel + `--muxy-keep`, or a
    /// connection loss that kept the step alive).
    pub still_running: bool,
}

/// Run one step to completion on `host`.
///
/// `on_line` receives every finished line, oldest first; it must not block
/// (masking and the audit log happen downstream). `cancelled` is polled
/// between frames.
///
/// # Errors
///
/// Returns a classified [`MuxyError`]; auto mode falls back to ssh on these.
/// A failed step: the error plus what it left behind.
///
/// `session` is `Some` only when a session was created on the target (and,
/// unless `still_running` is set, was ended again). Auto mode falls back to
/// ssh only when nothing was created — re-running a step that may have
/// partially executed is never automatic.
#[derive(Debug)]
pub struct MuxyFailure {
    /// The classified error.
    pub error: MuxyError,
    /// The session id, when a session was created.
    pub session: Option<SessionId>,
    /// True when the session may still be running (cancel + `--muxy-keep`,
    /// or a connection loss after the session started).
    pub still_running: bool,
}

/// Run one step to completion, streaming its lines to `on_line`.
///
/// # Errors
///
/// Returns a [`MuxyFailure`] carrying the classified error, the session id
/// (when one was created), and whether the step may still be running.
pub fn run_step(
    host: &mut HostConnection,
    params: &StepParams,
    on_line: &dyn Fn(String),
    cancelled: &AtomicBool,
) -> Result<StepResult, MuxyFailure> {
    let client = host.client().clone();
    let destination = host.destination().to_string();
    let cols = if params.cols == 0 { DEFAULT_COLS } else { params.cols };
    let rows = if params.rows == 0 { DEFAULT_ROWS } else { params.rows };
    let size = Size { cols, rows };

    if let Err(error) = check_env(host, params) {
        return Err(MuxyFailure { error, session: None, still_running: false });
    }

    let payload = build_payload(
        &params.script,
        params.guard.as_deref(),
        params.trace,
        &params.run_id,
        &params.step_id,
    );
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(MuxyFailure {
            error: MuxyError::Plan {
                detail: format!(
                    "the payload is {} bytes; the file API accepts at most {MAX_PAYLOAD_BYTES}",
                    payload.len()
                ),
            },
            session: None,
            still_running: false,
        });
    }
    if let Err(err) =
        write_payload(&client, host.home(), &params.run_id, &params.step_id, payload.as_bytes())
    {
        return Err(MuxyFailure {
            error: crate::error::classify_client_error(&destination, &err),
            session: None,
            still_running: false,
        });
    }

    let mut env_map = BTreeMap::new();
    for (key, value) in &params.env {
        env_map.insert(key.clone(), value.clone());
    }
    let home_dir = path_to_std(host.home_dir());
    let info = match client.create_project_session_with_environment(
        host.home(),
        OperationId::new(),
        &home_dir,
        size,
        env_map,
    ) {
        Ok(info) => info,
        Err(err) => {
            cleanup(&client, host.home(), params, None);
            return Err(MuxyFailure {
                error: crate::error::classify_client_error(&destination, &err),
                session: None,
                still_running: false,
            });
        }
    };
    let session = info.id;

    let outcome: Result<StepResult, MuxyFailure> =
        run_attached(host, &client, session, size, params, on_line, cancelled);

    match &outcome {
        Ok(result) if result.still_running => {}
        Err(failure) if failure.still_running => {}
        _ => cleanup(&client, host.home(), params, Some(session)),
    }

    outcome
}

/// The attach/stream/wait half of [`run_step`].
fn run_attached(
    host: &mut HostConnection,
    client: &Client,
    session: SessionId,
    size: Size,
    params: &StepParams,
    on_line: &dyn Fn(String),
    cancelled: &AtomicBool,
) -> Result<StepResult, MuxyFailure> {
    let destination = host.destination().to_string();
    let marker = begin_marker(&params.run_id, &params.step_id);
    let (tx, rx) = mpsc::sync_channel::<PumpMsg>(super::conn::PUMP_QUEUE);

    let attachment = match client.attach(session, size) {
        Ok(attachment) => attachment,
        Err(err) => {
            // The session exists but was never attached to: end it so no
            // half-created terminal is left behind, then report with no
            // session left — auto mode may fall back to ssh.
            let _ = client.end_session(session);
            return Err(MuxyFailure {
                error: crate::error::classify_client_error(&destination, &err),
                session: None,
                still_running: false,
            });
        }
    };
    let channel = attachment.channel;
    let history = attachment.grid.history_total;
    let grid = attachment.grid;
    host.register(session, channel, grid, history, &marker, tx.clone());

    let bootstrap = bootstrap_line(&params.run_id, &params.step_id);
    if let Err(err) = client.write_input(channel, bootstrap.into_bytes()) {
        // The bootstrap never reached the shell: end the session so nothing
        // runs, then report with no session left.
        host.unregister(&channel);
        let _ = client.end_session(session);
        return Err(MuxyFailure {
            error: crate::error::classify_client_error(&destination, &err),
            session: None,
            still_running: false,
        });
    }

    let mut state = LoopState {
        deadline: params.timeout.map(|budget| Instant::now() + budget),
        reconnected: false,
        budget_warned: false,
    };
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Ok(cancel_outcome(host, client, session, channel, params, &rx, on_line));
        }
        if state.expired() {
            return Ok(timeout_outcome(host, client, session, channel, &rx, on_line));
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(msg) => {
                let mut ctx = StepCtx {
                    host: &mut *host,
                    client,
                    session,
                    channel,
                    params,
                    on_line,
                    rx: &rx,
                    tx: &tx,
                };
                if let Some(result) = handle_msg(&mut ctx, msg, &mut state) {
                    return result;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                host.unregister(&channel);
                return Err(MuxyFailure {
                    error: MuxyError::Disconnected { destination },
                    session: Some(session),
                    still_running: true,
                });
            }
        }
    }
}

/// Mutable per-loop state: the deadline, whether the one reconnect was spent,
/// and whether the budget warning already went out.
struct LoopState {
    deadline: Option<Instant>,
    reconnected: bool,
    budget_warned: bool,
}

impl LoopState {
    fn expired(&self) -> bool {
        self.deadline.is_some_and(|end| Instant::now() >= end)
    }
}

/// Everything one pump message needs: the step's session, its channel, and
/// the callbacks that carry lines out.
struct StepCtx<'a> {
    host: &'a mut HostConnection,
    client: &'a Client,
    session: SessionId,
    channel: muxy_protocol::ChannelId,
    params: &'a StepParams,
    on_line: &'a dyn Fn(String),
    rx: &'a mpsc::Receiver<PumpMsg>,
    tx: &'a mpsc::SyncSender<PumpMsg>,
}

/// Handle one pump message; `Some` finishes the step.
fn handle_msg(
    ctx: &mut StepCtx<'_>,
    msg: PumpMsg,
    state: &mut LoopState,
) -> Option<Result<StepResult, MuxyFailure>> {
    let destination = ctx.host.destination().to_string();
    match msg {
        PumpMsg::Lines(lines) => {
            for line in lines {
                (ctx.on_line)(line);
            }
            None
        }
        PumpMsg::BudgetExceeded => {
            if !state.budget_warned {
                state.budget_warned = true;
                (ctx.on_line)(MuxyError::BudgetExceeded { host: destination }.to_string());
            }
            None
        }
        PumpMsg::TuiRedraw => {
            ctx.host.unregister(&ctx.channel);
            let _ = ctx.client.end_session(ctx.session);
            let _ = wait_for_end(ctx.rx, ctx.on_line);
            Some(Ok(StepResult {
                outcome: MuxyOutcome::FailedScript {
                    message: MuxyError::Tui { host: destination }.to_string(),
                    exit: None,
                },
                session: ctx.session,
                still_running: false,
            }))
        }
        PumpMsg::Ended(reason) => {
            ctx.host.unregister(&ctx.channel);
            drain_lines(ctx.rx, ctx.on_line);
            let outcome = map_exit_reason(&reason, ctx.params.has_guard);
            Some(Ok(StepResult { outcome, session: ctx.session, still_running: false }))
        }
        PumpMsg::Disconnected => {
            if state.reconnected {
                ctx.host.unregister(&ctx.channel);
                return Some(Err(MuxyFailure {
                    error: MuxyError::Disconnected { destination },
                    session: Some(ctx.session),
                    still_running: true,
                }));
            }
            state.reconnected = true;
            if let Err(err) = resume_after_reconnect(ctx.host, ctx.session, ctx.params, ctx.tx) {
                ctx.host.unregister(&ctx.channel);
                return Some(Err(MuxyFailure {
                    error: err,
                    session: Some(ctx.session),
                    still_running: true,
                }));
            }
            None
        }
    }
}

/// The deadline fired: end the session, flush, report `TimedOut`.
fn timeout_outcome(
    host: &HostConnection,
    client: &Client,
    session: SessionId,
    channel: muxy_protocol::ChannelId,
    rx: &mpsc::Receiver<PumpMsg>,
    on_line: &dyn Fn(String),
) -> StepResult {
    let _ = client.end_session(session);
    let end = wait_for_end(rx, on_line);
    host.unregister(&channel);
    // A transport drop during the grace leaves the session's fate unknown:
    // keep `still_running` so the payload is not cleaned up from under a
    // step that may still be running on the target.
    let still_running = matches!(end, WaitEnd::Disconnected);
    StepResult { outcome: MuxyOutcome::TimedOut, session, still_running }
}

/// The run was interrupted: end the session unless `--muxy-keep` leaves it.
fn cancel_outcome(
    host: &HostConnection,
    client: &Client,
    session: SessionId,
    channel: muxy_protocol::ChannelId,
    params: &StepParams,
    rx: &mpsc::Receiver<PumpMsg>,
    on_line: &dyn Fn(String),
) -> StepResult {
    if params.keep_on_cancel {
        let _ = client.detach(channel);
        host.unregister(&channel);
        return StepResult { outcome: MuxyOutcome::Cancelled, session, still_running: true };
    }
    let _ = client.end_session(session);
    // The interrupted step still produced output up to the cancel; the end
    // notification carries the assembler's flush, so collect it before the
    // channel goes away. A transport drop during the grace is reported via
    // `still_running`, as in `timeout_outcome`.
    let end = wait_for_end(rx, on_line);
    host.unregister(&channel);
    let still_running = matches!(end, WaitEnd::Disconnected);
    StepResult { outcome: MuxyOutcome::Cancelled, session, still_running }
}

/// Reconnect once and re-attach the same session.
fn resume_after_reconnect(
    host: &mut HostConnection,
    session: SessionId,
    params: &StepParams,
    tx: &mpsc::SyncSender<PumpMsg>,
) -> Result<(), MuxyError> {
    let destination = host.destination().to_string();
    host.reconnect()?;
    let client = host.client().clone();
    let attachment = client
        .attach_without_resize(session)
        .map_err(|err| crate::error::classify_client_error(&destination, &err))?;
    let channel = attachment.channel;
    let history_total = attachment.grid.history_total;
    let grid = attachment.grid;
    let marker = begin_marker(&params.run_id, &params.step_id);
    host.register(session, channel, grid, history_total, &marker, tx.clone());
    Ok(())
}

/// What `wait_for_end` observed during the grace period.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitEnd {
    /// The pump delivered the session's end reason.
    Ended(muxy_protocol::ExitReason),
    /// The transport dropped before the end arrived; the session may still be
    /// running on the target.
    Disconnected,
    /// The grace expired with no end and no drop.
    Expired,
}

/// Wait up to [`END_GRACE`] for the session's end reason, forwarding lines.
fn wait_for_end(rx: &mpsc::Receiver<PumpMsg>, on_line: &dyn Fn(String)) -> WaitEnd {
    let end = Instant::now() + END_GRACE;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return WaitEnd::Expired;
        }
        match rx.recv_timeout(left.min(Duration::from_millis(200))) {
            Ok(PumpMsg::Lines(lines)) => {
                for line in lines {
                    on_line(line);
                }
            }
            Ok(PumpMsg::Ended(reason)) => {
                drain_lines(rx, on_line);
                return WaitEnd::Ended(reason);
            }
            Ok(PumpMsg::Disconnected) => {
                drain_lines(rx, on_line);
                return WaitEnd::Disconnected;
            }
            Ok(PumpMsg::BudgetExceeded | PumpMsg::TuiRedraw) |
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return WaitEnd::Disconnected,
        }
    }
}

/// Drain already-queued lines without blocking.
fn drain_lines(rx: &mpsc::Receiver<PumpMsg>, on_line: &dyn Fn(String)) {
    while let Ok(PumpMsg::Lines(lines)) = rx.try_recv() {
        for line in lines {
            on_line(line);
        }
    }
}

/// The server-side limits on a step's environment: 128 variables and 64 KiB
/// of keys and values in total.
///
/// Kept pure (and tested) because a limit that is only enforced on the wire is
/// a limit nobody can prove: the check is a plan-time rejection, not a
/// remote failure the operator has to guess at.
fn env_limits(env: &[(String, String)]) -> Result<(), String> {
    if env.len() > 128 {
        return Err(format!("the step has {} env vars; the server accepts at most 128", env.len()));
    }
    let total: usize = env.iter().map(|(k, v)| k.len() + v.len()).sum();
    if total > 64 * 1024 {
        return Err("the step environment exceeds 64 KiB".to_string());
    }
    Ok(())
}

/// Check the environment against the server's capabilities and limits.
fn check_env(host: &HostConnection, params: &StepParams) -> Result<(), MuxyError> {
    env_limits(&params.env).map_err(|detail| MuxyError::Plan { detail })?;
    if !params.env.is_empty() && !host.supports(Feature::SESSION_ENVIRONMENT) {
        return Err(MuxyError::Incompatible {
            destination: host.destination().to_string(),
            detail: "the server does not support session environments; use --transport ssh"
                .to_string(),
        });
    }
    Ok(())
}

/// Write the payload through the file API (`Mkdir` + `WriteBytes`).
fn write_payload(
    client: &Client,
    home: muxy_protocol::ProjectId,
    run_id: &str,
    step_id: &str,
    bytes: &[u8],
) -> Result<(), muxy_client::ClientError> {
    use muxy_protocol::{FilesAction, FilesRequest};
    // The server's `Mkdir` creates a directory with the requested name only
    // when its parent already exists (and on a name collision appends a
    // suffix), so every ancestor must be created first, and only when missing.
    fn ensure_dir(client: &Client, home: muxy_protocol::ProjectId, rel: &str) {
        let path = ServerPath(rel.as_bytes().to_vec());
        if client
            .files(FilesRequest { project: home, action: FilesAction::Stat(path.clone()) })
            .is_ok()
        {
            return;
        }
        let _ = client.files(FilesRequest { project: home, action: FilesAction::Mkdir(path) });
    }
    ensure_dir(client, home, ".shellflow");
    ensure_dir(client, home, ".shellflow/steps");
    ensure_dir(client, home, &run_dir_rel_path(run_id));
    let path = ServerPath(payload_rel_path(run_id, step_id).into_bytes());
    client.files(FilesRequest {
        project: home,
        action: FilesAction::WriteBytes { path, bytes: bytes.to_vec() },
    })?;
    Ok(())
}

/// Best-effort teardown: delete the payload, discard secret-bearing screens.
///
/// Runs only when the session is not still running: a live session keeps its
/// payload until it ends (the stale sweep collects it later).
fn cleanup(
    client: &Client,
    home: muxy_protocol::ProjectId,
    params: &StepParams,
    session: Option<SessionId>,
) {
    use muxy_protocol::{FilesAction, FilesRequest};
    let path = ServerPath(payload_rel_path(&params.run_id, &params.step_id).into_bytes());
    let _ = client.files(FilesRequest { project: home, action: FilesAction::Delete(vec![path]) });
    if params.has_secrets &&
        let Some(session) = session
    {
        let _ = client.discard_session(session);
    }
}

/// Whether a run-id directory is old enough to collect: strictly older than
/// 24 h, and never the run that is currently executing.
///
/// Pure (and tested) because the arithmetic is what decides whether a crashed
/// run's payload survives: a directory whose name is not a timestamp — or
/// whose timestamp is in the future — is never collected.
fn is_stale_run_id(name: &str, now_nanos: u128) -> bool {
    name.parse::<u128>()
        .is_ok_and(|nanos| now_nanos.saturating_sub(nanos) > 24 * 60 * 60 * 1_000_000_000)
}

/// Remove `<run-id>` payload directories older than 24 h (a crashed run
/// leaves one behind). Best effort: file ages are not visible through the
/// file API, so run ids carry their creation time.
pub fn sweep_stale(host: &HostConnection, current_run_id: &str) {
    use muxy_protocol::{FilesAction, FilesRequest};
    let now_nanos: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let entries = match host.client().files(FilesRequest {
        project: host.home(),
        action: FilesAction::List(ServerPath(b".shellflow/steps".to_vec())),
    }) {
        Ok(muxy_protocol::FilesReply::Entries(entries)) => entries,
        Ok(_) | Err(_) => return,
    };
    let mut stale = Vec::new();
    for entry in entries {
        if !entry.is_directory {
            continue;
        }
        let name = String::from_utf8_lossy(&entry.name.0).into_owned();
        if name == current_run_id {
            continue;
        }
        if is_stale_run_id(&name, now_nanos) {
            stale.push(entry.path);
        }
    }
    if !stale.is_empty() {
        let _ = host
            .client()
            .files(FilesRequest { project: host.home(), action: FilesAction::Delete(stale) });
    }
}

/// Syntax-check a payload through `exec` (byte-exact stdin, no PTY).
///
/// # Errors
///
/// Returns the classified failure, or the check verdict.
pub fn exec_check(
    host: &HostConnection,
    payload: &str,
    timeout: Duration,
) -> Result<(), MuxyError> {
    use muxy_protocol::ExecRequest;
    let destination = host.destination().to_string();
    let timeout_ms =
        u32::try_from(timeout.as_millis().min(u128::from(u32::MAX))).unwrap_or(u32::MAX);
    let result = host
        .client()
        .exec(ExecRequest {
            job: fresh_job(),
            project: host.home(),
            argv: vec!["bash".to_string(), "-n".to_string(), "-s".to_string()],
            shell: None,
            cwd: None,
            env: BTreeMap::new(),
            stdin: payload.as_bytes().to_vec(),
            timeout_ms: timeout_ms.min(300_000),
        })
        .map_err(|err| crate::error::classify_client_error(&destination, &err))?;
    if result.exit_code == 0 {
        Ok(())
    } else {
        Err(MuxyError::Plan { detail: format!("syntax check failed: {}", result.stderr) })
    }
}

fn path_to_std(path: &ServerPath) -> std::path::PathBuf {
    std::path::PathBuf::from(String::from_utf8_lossy(&path.0).into_owned())
}

/// Fresh `exec` job ids: the server rejects `0`, and sequential checks must
/// not reuse an id the server may still track.
fn fresh_job() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_JOB: AtomicU64 = AtomicU64::new(1);
    let job = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    if job == 0 { fresh_job() } else { job }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn params() -> StepParams {
        StepParams {
            run_id: "1".into(),
            step_id: "s1".into(),
            script: "echo hi".into(),
            guard: None,
            trace: false,
            env: Vec::new(),
            has_secrets: false,
            has_guard: false,
            cols: 200,
            rows: 50,
            timeout: None,
            keep_on_cancel: false,
        }
    }

    #[test]
    fn default_size_is_200x50() {
        let size = params().size();
        assert_eq!((size.cols, size.rows), (200, 50));
    }

    /// A `HostConnection` over the fake peer the `client` is attached to.
    fn host(client: Client) -> HostConnection {
        HostConnection::from_client("fake-host", &[], client).expect("from_client")
    }

    #[test]
    fn run_step_refuses_a_payload_the_file_api_cannot_hold() {
        // A payload over the cap must be a plan error before anything is
        // created: a step that cannot upload its script must not leave a
        // session behind.
        let (client, bridge) = crate::harness::connect(std::time::Duration::from_secs(5));
        let mut host = host(client);
        let mut params = params();
        params.script = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let failure = run_step(&mut host, &params, &|_| {}, &cancelled)
            .expect_err("an oversized payload is refused");
        assert!(
            matches!(failure.error, MuxyError::Plan { .. }),
            "the refusal is a plan error: {:?}",
            failure.error
        );
        assert!(
            !bridge.calls().iter().any(|call| call == "create-session"),
            "no session is created for a payload that cannot be uploaded: {:?}",
            bridge.calls()
        );
    }

    #[test]
    fn run_step_removes_the_payload_when_the_session_cannot_start() {
        // The peer refuses the attach (a server that lost its PTY budget, say);
        // the uploaded script must not outlive the step.
        let (client, bridge) = crate::harness::connect(std::time::Duration::from_secs(5));
        let mut host = host(client);
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let failure =
            run_step(&mut host, &params(), &|_| {}, &cancelled).expect_err("the attach fails");
        assert_eq!(
            bridge.deleted(),
            vec![".shellflow/steps/1/s1.sh".to_string()],
            "the payload is cleaned up: {:?}",
            bridge.deleted()
        );
        assert!(!failure.still_running, "no session is left running when none could start");
    }

    #[test]
    fn run_step_refuses_an_environment_the_server_cannot_take() {
        // `auto` routes secret-bearing steps to muxy only when the server can
        // carry an environment; otherwise the step must fail loudly instead
        // of running with the secrets missing.
        let (client, _bridge) =
            crate::harness::connect_with_features(Vec::new(), std::time::Duration::from_secs(5));
        let mut host = host(client);
        let mut params = params();
        params.env = vec![("DB_PASSWORD".to_string(), "hunter2secret".to_string())];
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let failure = run_step(&mut host, &params, &|_| {}, &cancelled)
            .expect_err("a server without SESSION_ENVIRONMENT cannot take an environment");
        assert!(
            matches!(failure.error, MuxyError::Incompatible { .. }),
            "the refusal names the missing capability: {:?}",
            failure.error
        );
    }

    #[test]
    fn exec_check_reports_the_syntax_verdict() {
        // `--check` rides on this: a payload that does not parse must fail the
        // step with the server's own message, not a generic transport error.
        let (client, bridge) = crate::harness::connect(std::time::Duration::from_secs(5));
        let host = host(client);
        bridge.set_exec(0, "");
        exec_check(&host, "echo hi", std::time::Duration::from_secs(2))
            .expect("a payload that parses is accepted");
        bridge.set_exec(1, "bash: line 2: syntax error near unexpected token");
        let err = exec_check(&host, "if", std::time::Duration::from_secs(2))
            .expect_err("a payload that does not parse is rejected");
        assert!(
            err.to_string().contains("syntax error"),
            "the server's reason must reach the operator: {err}"
        );
    }

    #[test]
    fn write_payload_lands_the_script_under_the_run_directory() {
        // The step runs the bytes the controller uploaded; if they land
        // anywhere else (or only in memory) the step runs something else.
        let (client, bridge) = crate::harness::connect(std::time::Duration::from_secs(5));
        write_payload(&client, muxy_protocol::ProjectId::from_u128(1), "run1", "s1", b"echo hi\n")
            .expect("write the payload");
        assert_eq!(
            bridge.file(".shellflow/steps/run1/s1.sh").as_deref(),
            Some(b"echo hi\n".as_slice()),
            "the payload is stored verbatim"
        );
        assert!(bridge.is_dir(".shellflow/steps/run1"), "every ancestor is created first");
        assert!(bridge.is_dir(".shellflow/steps"), "including the steps root");
    }

    #[test]
    fn cleanup_removes_the_payload_and_discards_a_secret_session() {
        let (client, bridge) = crate::harness::connect(std::time::Duration::from_secs(5));
        let mut params = params();
        params.has_secrets = true;
        let session = muxy_protocol::SessionId::new(12).expect("session");
        cleanup(&client, muxy_protocol::ProjectId::from_u128(1), &params, Some(session));
        assert_eq!(
            bridge.deleted(),
            vec![".shellflow/steps/1/s1.sh".to_string()],
            "the payload never outlives its step: {:?}",
            bridge.deleted()
        );
        assert_eq!(bridge.discarded(), vec![12], "a secret-bearing session is discarded");
    }

    #[test]
    fn cleanup_leaves_a_running_session_alone() {
        // `keep_on_cancel` keeps the session so an operator can attach to it;
        // only the payload is removed when no session is handed in.
        let (client, bridge) = crate::harness::connect(std::time::Duration::from_secs(5));
        cleanup(&client, muxy_protocol::ProjectId::from_u128(1), &params(), None);
        assert!(!bridge.deleted().is_empty(), "the payload is removed");
        assert!(bridge.discarded().is_empty(), "no session is discarded");
    }

    #[test]
    fn sweep_stale_collects_only_older_run_directories() {
        // A crashed run leaves a payload directory behind; the sweep is the
        // only thing that removes it, and it must never touch the run that is
        // executing right now (nor a file, nor a non-timestamp name).
        let (client, bridge) = crate::harness::connect(std::time::Duration::from_secs(5));
        let host = host(client);
        let now: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let day = 24 * 60 * 60 * 1_000_000_000u128;
        let old = (now - 2 * day).to_string();
        let fresh = (now - day / 2).to_string();
        let current = now.to_string();
        bridge.set_listed(vec![
            crate::harness::dir_entry(&old, &format!(".shellflow/steps/{old}")),
            crate::harness::file_entry("leftover", ".shellflow/steps/leftover"),
            crate::harness::dir_entry("payloads", ".shellflow/steps/payloads"),
            crate::harness::dir_entry(&fresh, &format!(".shellflow/steps/{fresh}")),
            crate::harness::dir_entry(&current, &format!(".shellflow/steps/{current}")),
        ]);
        sweep_stale(&host, &current);
        assert_eq!(
            bridge.deleted(),
            vec![format!(".shellflow/steps/{old}")],
            "only the directory older than 24 h is collected: {:?}",
            bridge.deleted()
        );
        assert!(
            bridge.calls().iter().any(|call| call.starts_with("list .shellflow/steps")),
            "the sweep lists the steps directory: {:?}",
            bridge.calls()
        );
    }

    #[test]
    fn the_env_limits_reject_too_many_variables() {
        // 128 is the server's ceiling: a step that carries more is rejected at
        // plan time rather than failing on the wire.
        let at_limit: Vec<(String, String)> =
            (0..128).map(|i| (format!("K{i}"), "v".into())).collect();
        assert!(env_limits(&at_limit).is_ok(), "exactly 128 vars is accepted");
        let over: Vec<(String, String)> = (0..129).map(|i| (format!("K{i}"), "v".into())).collect();
        let err = env_limits(&over).expect_err("129 vars must be rejected");
        assert!(err.contains("129"), "{err}");
    }

    #[test]
    fn the_env_limits_reject_a_too_large_environment() {
        let big = "x".repeat(64 * 1024);
        assert!(env_limits(&[("BIG".into(), big.clone())]).is_err(), "64 KiB is the ceiling");
        assert!(
            env_limits(&[("BIG".into(), "x".repeat(64 * 1024 - 3))]).is_ok(),
            "just under the ceiling is accepted (the key counts too)"
        );
    }

    #[test]
    fn an_empty_environment_is_always_within_the_limits() {
        assert!(env_limits(&[]).is_ok());
    }

    #[test]
    fn a_stale_run_id_is_strictly_older_than_a_day() {
        let day = 24 * 60 * 60 * 1_000_000_000u128;
        let now = 1_000_000_000_000_000_000u128;
        assert!(is_stale_run_id(&(now - day - 1).to_string(), now), "older than 24 h is stale");
        assert!(!is_stale_run_id(&(now - day).to_string(), now), "exactly 24 h is not yet stale");
        assert!(!is_stale_run_id(&(now - 1).to_string(), now), "fresh is not stale");
        assert!(!is_stale_run_id(&(now + day).to_string(), now), "a future id is never collected");
    }

    #[test]
    fn a_name_that_is_not_a_timestamp_is_never_swept() {
        // A non-numeric directory is not a run this tool created, so the sweep
        // must leave it alone.
        assert!(!is_stale_run_id("payloads", 1_000_000_000_000_000_000));
        assert!(!is_stale_run_id("", 1_000_000_000_000_000_000));
    }

    #[test]
    fn exec_job_ids_are_monotonic_and_never_zero() {
        // The server rejects job id 0, and a reused id collides with a job it
        // may still be tracking.
        let first = fresh_job();
        let second = fresh_job();
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert!(second > first, "ids must not repeat: {first} -> {second}");
    }

    #[test]
    fn a_server_path_round_trips_into_a_std_path() {
        let path = ServerPath(b".shellflow/steps/run1/s1.sh".to_vec());
        assert_eq!(path_to_std(&path), std::path::PathBuf::from(".shellflow/steps/run1/s1.sh"));
        assert_eq!(path_to_std(&path).to_str(), Some(".shellflow/steps/run1/s1.sh"));
    }

    #[test]
    fn the_loop_expires_only_past_its_deadline() {
        use std::time::{Duration, Instant};
        let past = LoopState {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            reconnected: false,
            budget_warned: false,
        };
        let future = LoopState {
            deadline: Some(Instant::now() + Duration::from_secs(60)),
            reconnected: false,
            budget_warned: false,
        };
        let unbounded = LoopState { deadline: None, reconnected: false, budget_warned: false };
        assert!(past.expired(), "a past deadline is expired");
        assert!(!future.expired(), "a future deadline is not expired");
        assert!(!unbounded.expired(), "no deadline means every loop iteration continues");
    }
}
