//! One connection per host: ssh + bridge + handshake + Home project.
//!
//! The connection lives for the whole run and is shared by every step on
//! that host. A pump thread is the only consumer of `Client::events()`; it
//! owns every channel's `RunGrid`, acks each frame as soon as the grid is
//! updated (so a slow operator terminal can never stall the server's frame
//! pipeline into data loss), runs the [`crate::lines`] assembler, gap-fills
//! from `HistoryPage`, and forwards finished lines to the step that owns the
//! channel.

use std::{
    collections::{HashMap, VecDeque},
    io::Read,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use muxy_client::{
    Client, ClientEvent,
    bridge::{self, BridgeExit, Start},
};
use muxy_protocol::{ChannelId, ProjectId, ServerPath, SessionId};

use crate::{
    error::{MuxyError, classify_client_error},
    lines::{LineAssembler, Push, Screen},
};

/// How long the bridge gets to print its ready line (covers ssh connect,
/// login, and server start).
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a failed ssh gets to exit and finish its error output.
const EXIT_TIMEOUT: Duration = Duration::from_secs(1);

/// How much of ssh's error output is kept for messages.
const STDERR_TAIL: usize = 8 * 1024;

/// The ssh options for the bridge: shared-master reuse is forced off (a
/// connection that must not be multiplexed with the operator's own ssh),
/// keepalives detect a half-open connection between steps.
const SSH_OPTIONS: [&str; 6] = [
    "ConnectTimeout=10",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=3",
    "ControlMaster=no",
    "RemoteCommand=none",
    "ClearAllForwardings=yes",
];

/// Default session size: wide enough that long lines are rarely wrapped.
pub const DEFAULT_COLS: u16 = 200;
/// Default session height.
pub const DEFAULT_ROWS: u16 = 50;

/// A message from the pump to the step that owns a channel.
#[derive(Debug)]
pub(crate) enum PumpMsg {
    /// Complete lines, oldest first.
    Lines(Vec<String>),
    /// The frame redrew the screen instead of scrolling (a full-screen TUI).
    TuiRedraw,
    /// The step's output exceeded the session budget; its head is gone.
    /// Reported once.
    BudgetExceeded,
    /// The session ended with this reason.
    Ended(muxy_protocol::ExitReason),
    /// The connection dropped.
    Disconnected,
}

/// Per-channel state owned by the pump thread.
struct ChannelState {
    session: SessionId,
    grid: muxy_client::RunGrid,
    asm: LineAssembler,
    tx: mpsc::Sender<PumpMsg>,
    history_total: u64,
    budget_warned: bool,
}

/// One connection to a host's muxy server, with its pump thread.
pub struct HostConnection {
    client: Client,
    home: ProjectId,
    home_dir: ServerPath,
    server_version: String,
    server_features: Vec<muxy_protocol::Feature>,
    destination: String,
    ssh_spec: Vec<String>,
    channels: Arc<Mutex<HashMap<ChannelId, ChannelState>>>,
    shutdown: Arc<AtomicBool>,
    /// Set when this connection's client has been adopted by another
    /// connection (`reconnect`): the `Drop` must not disconnect the *new*
    /// connection's client, but the remaining fields still drop normally.
    abandoned: bool,
}

impl std::fmt::Debug for HostConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostConnection")
            .field("destination", &self.destination)
            .field("server_version", &self.server_version)
            .finish_non_exhaustive()
    }
}

impl HostConnection {
    /// Connect to `destination` over ssh and run the handshake.
    ///
    /// `ssh_spec` is the argv fragment for the destination
    /// (`spec.to_ssh_args()`): `["-p", "2222", "deploy@10.0.0.1"]` or
    /// `["api"]`.
    ///
    /// # Errors
    ///
    /// Returns a classified [`MuxyError`] (never a string).
    pub fn connect(destination: &str, ssh_spec: &[String]) -> Result<Self, MuxyError> {
        let mut command = std::process::Command::new("ssh");
        command.arg("-T");
        for option in SSH_OPTIONS {
            command.args(["-o", option]);
        }
        command.args(["-o", "BatchMode=yes"]);
        for arg in ssh_spec {
            command.arg(arg);
        }
        command.arg(bridge::command(Start::IfNeeded));
        command.stderr(std::process::Stdio::piped());
        let mut stream = muxy_protocol::transport::ChildStream::spawn(command).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                MuxyError::Ssh {
                    destination: destination.to_string(),
                    detail: "cannot run ssh".to_string(),
                }
            } else {
                MuxyError::Ssh { destination: destination.to_string(), detail: err.to_string() }
            }
        })?;
        let stderr = ErrorTail::drain(stream.take_stderr());
        let process = stream.process();
        let destination_owned = destination.to_string();
        let client =
            Client::connect_bridge(Box::new(stream), destination, READY_TIMEOUT, || BridgeExit {
                status: process.wait_timeout(EXIT_TIMEOUT).ok().flatten().and_then(|s| s.code()),
                stderr: stderr.wait(EXIT_TIMEOUT),
            })
            .map_err(|err| classify_client_error(&destination_owned, &err))?;
        Self::from_client(destination, ssh_spec, client)
    }

    /// Wrap an already-handshaked client (tests, local sockets).
    ///
    /// # Errors
    ///
    /// Returns [`MuxyError::Request`] when the catalog cannot be read.
    pub fn from_client(
        destination: &str,
        ssh_spec: &[String],
        client: Client,
    ) -> Result<Self, MuxyError> {
        let catalog = client.catalog().map_err(|err| classify_client_error(destination, &err))?;
        let home = catalog.home;
        let home_dir = catalog
            .projects
            .iter()
            .find(|project| project.id == home)
            .map_or_else(|| ServerPath(b"/".to_vec()), |project| project.directory.clone());
        let server_version = client.server_info().build.version.clone();
        let server_features = client.features().to_vec();
        let channels: Arc<Mutex<HashMap<ChannelId, ChannelState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        spawn_pump(
            client.clone(),
            Arc::clone(&channels),
            Arc::clone(&shutdown),
            destination.to_string(),
        )?;
        Ok(Self {
            client,
            home,
            home_dir,
            server_version,
            server_features,
            destination: destination.to_string(),
            ssh_spec: ssh_spec.to_vec(),
            channels,
            shutdown,
            abandoned: false,
        })
    }

    /// The Home project id: payload files are relative to its root.
    #[must_use]
    pub const fn home(&self) -> ProjectId {
        self.home
    }

    /// The Home project's absolute directory on the server.
    #[must_use]
    pub const fn home_dir(&self) -> &ServerPath {
        &self.home_dir
    }

    /// The server's build version, for `-v` logging.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Whether the server offers `feature` (gates `SESSION_ENVIRONMENT`).
    #[must_use]
    pub fn supports(&self, feature: muxy_protocol::Feature) -> bool {
        self.server_features.contains(&feature)
    }

    /// The underlying client (for requests from the step thread).
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// The host as the user named it, for errors.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// Liveness for a connection held across steps; a failed ping drops the
    /// client and the next step reconnects.
    ///
    /// # Errors
    ///
    /// Returns the classified ping failure.
    pub fn ping(&self) -> Result<(), MuxyError> {
        self.client.ping().map_err(|err| classify_client_error(&self.destination, &err))
    }

    /// Whether the server accepts per-session environments (secret-bearing
    /// steps need it; otherwise they stay on ssh under `auto`).
    #[must_use]
    pub fn supports_env(&self) -> bool {
        self.supports(muxy_protocol::Feature::SESSION_ENVIRONMENT)
    }

    /// The features the connected server reports (for diagnostics).
    #[must_use]
    pub fn server_features(&self) -> &[muxy_protocol::Feature] {
        &self.server_features
    }

    /// Whether the transport is still up.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }

    /// Register a channel with its attach snapshot; the pump streams its
    /// lines to `tx` until the step unregisters it.
    pub(crate) fn register(
        &self,
        session: SessionId,
        channel: ChannelId,
        grid: muxy_client::RunGrid,
        history_total: u64,
        marker: &str,
        tx: mpsc::Sender<PumpMsg>,
    ) {
        let mut channels = lock(&self.channels);
        channels.insert(
            channel,
            ChannelState {
                session,
                grid,
                asm: LineAssembler::new(marker),
                tx,
                history_total,
                budget_warned: false,
            },
        );
    }

    /// Stop streaming a channel (after detach).
    pub(crate) fn unregister(&self, channel: &ChannelId) {
        lock(&self.channels).remove(channel);
    }

    /// Reconnect once with a fresh ssh + bridge (the session survives; only
    /// the frames stopped). The pump is restarted on the new client.
    ///
    /// # Errors
    ///
    /// Returns the classified reconnect failure.
    pub fn reconnect(&mut self) -> Result<(), MuxyError> {
        self.shutdown.store(true, Ordering::SeqCst);
        let destination = self.destination.clone();
        let ssh_spec = self.ssh_spec.clone();
        let mut fresh = Self::connect(&destination, &ssh_spec)?;
        self.client = fresh.client.clone();
        self.channels = Arc::clone(&fresh.channels);
        self.shutdown = Arc::clone(&fresh.shutdown);
        // Adopt the new client without running its `Drop` (which would
        // disconnect the *new* connection) and without leaking the rest of
        // the object the way `mem::forget` did: mark it abandoned, then drop
        // it normally so its strings and metadata are released.
        fresh.abandoned = true;
        drop(fresh);
        Ok(())
    }
}

impl Drop for HostConnection {
    fn drop(&mut self) {
        if self.abandoned {
            return;
        }
        self.shutdown.store(true, Ordering::SeqCst);
        self.client.disconnect();
    }
}

/// The pump: the only consumer of `Client::events()`.
///
/// # Errors
///
/// Returns [`MuxyError::PumpSpawn`] when the thread cannot be spawned: a
/// connection without a pump streams nothing, so the caller must fail.
fn spawn_pump(
    client: Client,
    channels: Arc<Mutex<HashMap<ChannelId, ChannelState>>>,
    shutdown: Arc<AtomicBool>,
    destination: String,
) -> Result<(), MuxyError> {
    let _ = destination;
    thread::Builder::new()
        .name("shellflow-muxy-pump".into())
        .spawn(move || {
            let events = match client.events() {
                Some(events) => events,
                None => return,
            };
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                let event = match events.recv_timeout(Duration::from_millis(200)) {
                    Ok(event) => event,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        notify_all(&channels, PumpMsg::Disconnected);
                        return;
                    }
                };
                match event {
                    ClientEvent::Frame { channel, frame } => {
                        handle_frame(&client, &channels, channel, &frame);
                    }
                    ClientEvent::SessionEnded { session, reason } => {
                        notify_ended(&channels, session, reason);
                    }
                    ClientEvent::Disconnected | ClientEvent::ServerRestarting => {
                        notify_all(&channels, PumpMsg::Disconnected);
                        return;
                    }
                    _ => {}
                }
            }
        })
        .map_err(|_| MuxyError::PumpSpawn { destination })?;
    Ok(())
}

/// Apply one frame: update the grid, ack immediately, assemble lines.
fn handle_frame(
    client: &Client,
    channels: &Arc<Mutex<HashMap<ChannelId, ChannelState>>>,
    channel: ChannelId,
    frame: &muxy_protocol::ScreenFrame,
) {
    let seq = frame.seq;
    let mut state = match lock(channels).remove(&channel) {
        Some(state) => state,
        None => return,
    };
    state.grid.apply(frame);
    let after = state.grid.history_total;
    state.history_total = after;
    // Ack as soon as the grid is updated — never after the UI consumes the
    // line — so a slow operator terminal cannot stall the server's frame
    // pipeline into data loss.
    let _ = client.ack(channel, seq);
    let rows: Vec<String> = (0..state.grid.rows.len()).map(|i| state.grid.row_text(i)).collect();
    let push = state.asm.push(&Screen { rows, reset: frame.reset, history_total: after });
    forward_push(client, channel, &mut state, push, after);
    lock(channels).insert(channel, state);
}

/// Forward an assembler's output, gap-filling merged frames from history.
///
/// Departed rows are older than the bypassed gap rows (both entered the
/// scrollback, oldest first), so `lines` go out before the gap.
fn forward_push(
    client: &Client,
    channel: ChannelId,
    state: &mut ChannelState,
    push: Push,
    history_after: u64,
) {
    if push.tui_redraw {
        let _ = state.tx.send(PumpMsg::TuiRedraw);
        return;
    }
    if !push.lines.is_empty() {
        let _ = state.tx.send(PumpMsg::Lines(push.lines));
    }
    if push.missing > 0 {
        // `before=0` fetches the newest scrollback first; older pages follow
        // through `next`. Every page carries its own `total_rows`, so rows
        // that arrived after our frame can be skipped by alignment instead
        // of being emitted early (and duplicated when they later scroll off).
        let mut before = muxy_protocol::HistoryCursor(0);
        let mut pages: Vec<muxy_protocol::HistoryPage> = Vec::new();
        let mut fetched_total: u64 = 0;
        while fetched_total < push.missing {
            let page = match client.history_page(channel, before, 200) {
                Ok(page) => page,
                Err(_) => break,
            };
            if page.rows.is_empty() {
                break;
            }
            fetched_total = fetched_total.saturating_add(page.rows.len() as u64);
            let next = page.next;
            pages.push(page);
            match next {
                Some(next) => before = next,
                None => break,
            }
            if pages.len() > 64 {
                break;
            }
        }
        // Oldest first, with absolute history indices anchored at the newest
        // page's `total_rows`.
        let anchor = pages.first().map_or(history_after, |page| page.total_rows);
        let mut all: Vec<String> = Vec::new();
        for page in pages.iter().rev() {
            for row in &page.rows {
                all.push(row.runs.iter().map(|run| run.text.as_str()).collect());
            }
        }
        let first_index = anchor.saturating_sub(all.len() as u64);
        let want_start = history_after.saturating_sub(push.missing);
        let mut gap: Vec<String> = Vec::new();
        for (offset, text) in all.into_iter().enumerate() {
            let index = first_index.saturating_add(offset as u64);
            if index >= want_start && index < history_after {
                gap.push(text);
            }
        }
        let gap_lines = state.asm.feed_gap(&gap);
        if !gap_lines.is_empty() {
            let _ = state.tx.send(PumpMsg::Lines(gap_lines));
        }
        // The 16 MiB scrollback budget evicts the head: a gap fetch that
        // under-delivers means those rows are gone for good. Warn once.
        if (gap.len() as u64) < push.missing && !state.budget_warned {
            state.budget_warned = true;
            let _ = state.tx.send(PumpMsg::BudgetExceeded);
        }
    }
}

fn notify_ended(
    channels: &Arc<Mutex<HashMap<ChannelId, ChannelState>>>,
    session: SessionId,
    reason: muxy_protocol::ExitReason,
) {
    let channels = lock(channels);
    for state in channels.values() {
        if state.session == session {
            let _ = state.tx.send(PumpMsg::Ended(reason));
        }
    }
}

fn notify_all(channels: &Arc<Mutex<HashMap<ChannelId, ChannelState>>>, msg: PumpMsg) {
    let channels = lock(channels);
    match msg {
        PumpMsg::Disconnected => {
            for state in channels.values() {
                let _ = state.tx.send(PumpMsg::Disconnected);
            }
        }
        other => {
            let _ = other;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The end of ssh's error output, drained on its own thread so ssh never
/// blocks on a full pipe.
struct ErrorTail {
    state: Mutex<TailState>,
    ended: Condvar,
}

#[derive(Default)]
struct TailState {
    bytes: VecDeque<u8>,
    ended: bool,
}

impl ErrorTail {
    fn drain(stderr: Option<std::process::ChildStderr>) -> Arc<Self> {
        let tail =
            Arc::new(Self { state: Mutex::new(TailState::default()), ended: Condvar::new() });
        let filling = Arc::clone(&tail);
        match stderr {
            Some(stderr) => {
                thread::Builder::new()
                    .name("shellflow-muxy-stderr".into())
                    .spawn(move || filling.fill(stderr))
                    .ok();
            }
            None => filling.finish(),
        }
        tail
    }

    fn fill(&self, mut stderr: impl Read) {
        let mut chunk = [0; 4096];
        loop {
            match stderr.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => self.push(&chunk[..read]),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        self.finish();
    }

    fn push(&self, bytes: &[u8]) {
        let mut state = lock(&self.state);
        state.bytes.extend(bytes);
        let excess = state.bytes.len().saturating_sub(STDERR_TAIL);
        state.bytes.drain(..excess);
    }

    fn finish(&self) {
        lock(&self.state).ended = true;
        self.ended.notify_all();
    }

    fn wait(&self, timeout: Duration) -> String {
        let (mut state, _) = self
            .ended
            .wait_timeout_while(lock(&self.state), timeout, |state| !state.ended)
            .unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(state.bytes.make_contiguous()).into_owned()
    }
}

#[cfg(test)]
mod tests {

    use muxy_protocol::Message;

    use super::*;

    #[test]
    fn ssh_options_force_no_master_and_keepalives() {
        assert!(SSH_OPTIONS.contains(&"ControlMaster=no"));
        assert!(SSH_OPTIONS.iter().any(|o| o.starts_with("ServerAliveInterval")));
    }

    #[test]
    fn the_host_connection_takes_its_identity_from_the_handshake() {
        // The accessors are the transport's contract with the rest of the
        // tool: `--transport muxy` is chosen from `supports_env`, and the
        // version lands in `-v`. They are only observable over a live
        // handshake, which the fake peer provides.
        let (client, bridge) = crate::harness::connect(Duration::from_secs(5));
        let host = HostConnection::from_client("fake-host", &[], client).expect("from_client");
        assert_eq!(host.destination(), "fake-host");
        assert!(host.server_version().contains("fake"), "{}", host.server_version());
        assert!(host.supports_env(), "the peer advertises SESSION_ENVIRONMENT");
        assert!(host.is_connected(), "a fresh connection is connected");
        assert!(host.ping().is_ok(), "a healthy peer answers a ping");
        assert!(bridge.calls().iter().any(|call| call == "ping"), "{:?}", bridge.calls());
    }

    #[test]
    fn a_refused_ping_is_an_error_not_a_silent_success() {
        // Liveness is what decides whether the next step reconnects; a ping
        // that cannot fail would keep a dead connection in service.
        let (client, bridge) = crate::harness::connect(Duration::from_secs(5));
        let host = HostConnection::from_client("fake-host", &[], client).expect("from_client");
        bridge.set_ping(false);
        let err = host.ping().expect_err("a refused ping must fail");
        assert!(
            matches!(err, MuxyError::Request { .. }),
            "a refused ping is a classified request failure, not a string: {err:?}"
        );
        assert!(
            err.to_string().contains("ping refused"),
            "the server's own reason must survive classification: {err}"
        );
    }

    /// A grid of `rows` rows for `register`: the channel state needs one, and
    /// the frames the pump applies are the point of the grid, not the grid
    /// itself.
    fn grid(rows: u16) -> muxy_client::RunGrid {
        muxy_client::RunGrid {
            graphics: muxy_protocol::Graphics::default(),
            prompts: std::collections::BTreeSet::new(),
            prompt_state: muxy_client::ScreenPrompts::default(),
            links: muxy_client::ScreenLinks::default(),
            size: muxy_protocol::Size { cols: 80, rows },
            rows: vec![Vec::new(); rows as usize],
            cursor: muxy_protocol::Cursor {
                shape: muxy_protocol::CursorShape::default(),
                row: 0,
                col: 0,
                visible: false,
            },
            modes: muxy_protocol::Modes::default(),
            history: std::collections::VecDeque::new(),
            history_cursor: None,
            history_total: 0,
            history_fresh: true,
        }
    }

    #[test]
    fn a_registered_channel_stops_streaming_when_unregistered() {
        use std::sync::mpsc;
        let (client, _bridge) = crate::harness::connect(Duration::from_secs(5));
        let host = HostConnection::from_client("fake-host", &[], client).expect("from_client");
        let session = muxy_protocol::SessionId::new(11).expect("session");
        let channel = muxy_protocol::ChannelId(4);
        let (tx, _rx) = mpsc::channel();
        host.register(session, channel, grid(24), 0, "@@shellflow:begin:r/s@@", tx);
        assert!(
            host.channels.lock().unwrap_or_else(PoisonError::into_inner).contains_key(&channel)
        );
        host.unregister(&channel);
        assert!(
            !host.channels.lock().unwrap_or_else(PoisonError::into_inner).contains_key(&channel),
            "an unregistered channel must stop receiving frames"
        );
    }

    /// An `ErrorTail` with no stderr attached: nothing drains into it, so it
    /// stays empty and unfinished.
    fn tail() -> Arc<ErrorTail> {
        Arc::new(ErrorTail { state: Mutex::new(TailState::default()), ended: Condvar::new() })
    }

    #[test]
    fn the_tail_keeps_only_the_most_recent_output() {
        // The tail is bounded: a bridge that floods stderr must not grow the
        // controller's memory, and the operator still sees the reason it
        // died — which is at the *end* of the stream.
        let tail = tail();
        tail.push(b"first");
        tail.push(&vec![b'x'; STDERR_TAIL + 100]);
        tail.push(b"last");
        let text = tail.wait(Duration::from_millis(50));
        assert!(text.ends_with("last"), "the newest output survives: {text:?}");
        assert!(!text.starts_with("first"), "the oldest output is dropped: {text:?}");
        assert!(text.len() <= STDERR_TAIL, "the tail is bounded: {}", text.len());
    }

    #[test]
    fn filling_a_reader_collects_it_and_ends_the_tail() {
        let tail = tail();
        tail.fill(std::io::Cursor::new(b"ssh: connect to host h port 22: refused".to_vec()));
        assert_eq!(
            tail.wait(Duration::from_millis(50)),
            "ssh: connect to host h port 22: refused",
            "the error text is what the operator is shown"
        );
    }

    #[test]
    fn an_ended_tail_waits_without_blocking() {
        // `wait` is what turns "ssh died" into a message; without `finish` it
        // would sit out its whole timeout on every failed handshake.
        let tail = tail();
        tail.push(b"partial");
        tail.finish();
        let started = std::time::Instant::now();
        assert_eq!(tail.wait(Duration::from_secs(5)), "partial");
        assert!(started.elapsed() < Duration::from_secs(1), "an ended tail returns immediately");
    }

    #[test]
    fn an_empty_tail_waits_out_its_timeout() {
        let tail = tail();
        assert_eq!(tail.wait(Duration::from_millis(10)), "");
    }

    /// One screen frame carrying `rows`, padded to a full screen of `ROWS`.
    ///
    /// `seq` must increase per channel: the client drops a frame whose
    /// sequence it already applied.
    fn frame(rows: &[&str], reset: bool, seq: u64) -> muxy_protocol::ScreenFrame {
        let mut filled: Vec<&str> = rows.to_vec();
        filled.resize(ROWS, "");
        let rows = filled;
        muxy_protocol::ScreenFrame {
            size: muxy_protocol::Size { cols: 80, rows: rows.len() as u16 },
            graphics: Some(muxy_protocol::Graphics::default()),
            seq,
            reset,
            rows: rows
                .iter()
                .enumerate()
                .map(|(index, text)| muxy_protocol::Row {
                    index: index as u16,
                    runs: vec![muxy_protocol::Run {
                        text: (*text).to_string(),
                        width: text.len() as u16,
                        style: muxy_protocol::Style::default(),
                    }],
                })
                .collect(),
            cursor: muxy_protocol::Cursor {
                shape: muxy_protocol::CursorShape::default(),
                row: 0,
                col: 0,
                visible: false,
            },
            modes: muxy_protocol::Modes::default(),
        }
    }

    /// The screen height used by the frame tests: small enough that three
    /// lines of output scroll the first one off the top.
    const ROWS: usize = 3;

    /// Collect pump messages until `budget` expires.
    fn drain(rx: &mpsc::Receiver<PumpMsg>, budget: Duration) -> Vec<PumpMsg> {
        let deadline = std::time::Instant::now() + budget;
        let mut out = Vec::new();
        while std::time::Instant::now() < deadline {
            if let Ok(message) = rx.recv_timeout(Duration::from_millis(50)) {
                out.push(message);
            }
        }
        out
    }

    #[test]
    fn the_pump_delivers_the_lines_that_left_the_screen() {
        // The whole point of the transport: a row that scrolled off the top
        // is a complete line, and it reaches `Ui::host_line` — everything
        // before the begin marker does not.
        let (client, bridge) = crate::harness::connect(Duration::from_secs(5));
        let host = HostConnection::from_client("fake-host", &[], client).expect("from_client");
        let channel = muxy_protocol::ChannelId(4);
        let (tx, rx) = mpsc::channel();
        host.register(
            muxy_protocol::SessionId::new(11).expect("session"),
            channel,
            grid(ROWS as u16),
            0,
            "@@shellflow:begin:r/s@@",
            tx,
        );
        bridge
            .push(channel, &Message::Frame(frame(&["@@shellflow:begin:r/s@@", "", ""], false, 1)));
        bridge.push(
            channel,
            &Message::Frame(frame(&["@@shellflow:begin:r/s@@", "one", ""], false, 2)),
        );
        // The screen scrolls: the marker row leaves the top, "one" follows.
        bridge.push(channel, &Message::Frame(frame(&["one", "two", ""], false, 3)));
        let lines: Vec<String> = drain(&rx, Duration::from_secs(5))
            .into_iter()
            .filter_map(|message| match message {
                PumpMsg::Lines(lines) => Some(lines),
                _ => None,
            })
            .flatten()
            .collect();
        // The marker itself is dropped by the assembler once it is armed,
        // which `lines.rs` pins frame by frame; what this test pins is the
        // path from a wire frame to a line in the operator's stream.
        assert!(lines.iter().any(|line| line == "one"), "the departed row is a line: {lines:?}");
    }

    #[test]
    fn a_full_screen_redraw_is_reported_as_one() {
        // A TUI that rewrites the screen must not be streamed as hundreds of
        // departed lines; the UI is told to redraw instead.
        let (client, bridge) = crate::harness::connect(Duration::from_secs(5));
        let host = HostConnection::from_client("fake-host", &[], client).expect("from_client");
        let channel = muxy_protocol::ChannelId(5);
        let (tx, rx) = mpsc::channel();
        host.register(
            muxy_protocol::SessionId::new(12).expect("session"),
            channel,
            grid(ROWS as u16),
            0,
            "@@shellflow:begin:r/s@@",
            tx,
        );
        bridge
            .push(channel, &Message::Frame(frame(&["@@shellflow:begin:r/s@@", "", ""], false, 1)));
        bridge.push(channel, &Message::Frame(frame(&["a", "b", "c"], true, 2)));
        let messages = drain(&rx, Duration::from_secs(5));
        assert!(
            messages.iter().any(|message| matches!(message, PumpMsg::TuiRedraw)),
            "a reset that advances no history is a redraw: {messages:?}"
        );
    }

    #[test]
    fn the_pump_reports_why_the_session_ended() {
        let (client, bridge) = crate::harness::connect(Duration::from_secs(5));
        let host = HostConnection::from_client("fake-host", &[], client).expect("from_client");
        let channel = muxy_protocol::ChannelId(6);
        let session = muxy_protocol::SessionId::new(13).expect("session");
        let (tx, rx) = mpsc::channel();
        host.register(session, channel, grid(24), 0, "@@shellflow:begin:r/s@@", tx);
        // The end of a session is a control-channel notification: the client
        // turns it into `ClientEvent::SessionEnded` for the pump.
        bridge.push(
            muxy_protocol::CONTROL,
            &Message::SessionEnded { session, reason: muxy_protocol::ExitReason::Exited(3) },
        );
        let messages = drain(&rx, Duration::from_secs(5));
        assert!(
            messages.iter().any(|message| matches!(
                message,
                PumpMsg::Ended(muxy_protocol::ExitReason::Exited(3))
            )),
            "the exit reason reaches the step: {messages:?}"
        );
    }

    #[test]
    fn a_disconnected_peer_wakes_every_registered_channel() {
        // A dropped ssh must not leave a step waiting on output that will
        // never arrive; every channel is told the transport is gone.
        let (client, bridge) = crate::harness::connect(Duration::from_secs(5));
        let host = HostConnection::from_client("fake-host", &[], client).expect("from_client");
        let channel = muxy_protocol::ChannelId(7);
        let (tx, rx) = mpsc::channel();
        host.register(
            muxy_protocol::SessionId::new(14).expect("session"),
            channel,
            grid(ROWS as u16),
            0,
            "@@shellflow:begin:r/s@@",
            tx,
        );
        bridge.close();
        let messages = drain(&rx, Duration::from_secs(5));
        assert!(
            messages.iter().any(|message| matches!(message, PumpMsg::Disconnected)),
            "the channel is woken on disconnect: {messages:?}"
        );
    }
}
