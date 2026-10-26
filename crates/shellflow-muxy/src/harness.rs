//! A fake **peer** for the transport tests.
//!
//! `shellflow-muxy` speaks the real muxy wire protocol (frames encoded by
//! `muxy_protocol::wire`) over a stream, so testing it needs a peer that
//! speaks that protocol. `muxy-server` cannot be built in this environment
//! (its terminal crate builds ghostty's VT with `zig` and a network download
//! that is unavailable), so this harness plays the *server's* side of the same
//! protocol over a socket pair: the frames, the handshake, and the `Client`
//! are the production ones, and nothing in the crate under test changes.
//!
//! The peer answers only what the transport asks for (catalog, ping, files,
//! exec, session bookkeeping) and records every call, so a test asserts on
//! what the transport *did* rather than on the server's opinion of it.

use std::{
    collections::BTreeMap,
    io::Write as _,
    sync::{Arc, Mutex, PoisonError, mpsc},
    thread,
    time::Duration,
};

use muxy_client::{Client, bridge::BridgeExit};
use muxy_protocol::{
    BuildInfo, COMPATIBILITY, CURRENT, CatalogPage, ChannelId, ErrorCode, ErrorReply, ExecResult,
    Feature, FileEntry, FilesAction, FilesReply, Message, ProjectDescriptor, ProjectId, ReplyBody,
    RequestBody, RequestId, ServerInfo, ServerPath, SessionId, SessionInfo,
    wire::{Decoder, Encoder},
};

/// One node of the fake filesystem.
#[derive(Clone, Debug, Default)]
pub(crate) struct Entry {
    /// Whether the node is a directory (sessions list directories).
    pub is_dir: bool,
    /// The file's bytes.
    pub bytes: Vec<u8>,
}

/// Everything the fake peer recorded, for assertions.
#[derive(Default)]
pub(crate) struct Record {
    /// One line per request the peer served (`"ping"`, `"stat /a"`, …).
    pub calls: Vec<String>,
    /// `FilesAction::Delete` targets, in order.
    pub deleted: Vec<Vec<u8>>,
    /// Sessions the transport discarded.
    pub discarded: Vec<u64>,
}

/// The shared fake-server state.
#[derive(Default)]
struct State {
    fs: BTreeMap<Vec<u8>, Entry>,
    record: Record,
    /// What `FilesAction::List` returns.
    listed: Vec<FileEntry>,
    /// The exit code `exec` answers with.
    exec_exit: i32,
    /// The stderr `exec` answers with.
    exec_stderr: String,
    /// Whether `ping` succeeds.
    ping_ok: bool,
    /// The session id the peer hands out on `CreateSession`.
    next_session: u64,
}

/// A running fake peer plus the client connected to it.
pub(crate) struct Bridge {
    state: Arc<Mutex<State>>,
    encoder: Arc<Mutex<Encoder<std::os::unix::net::UnixStream>>>,
    /// A second handle to the peer's socket, used to end the connection.
    closer: std::os::unix::net::UnixStream,
    /// Kept alive: dropping it ends the peer's read loop.
    _waker: mpsc::Sender<()>,
}

impl Bridge {
    /// Read the recorded calls.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).record.calls.clone()
    }

    /// The bytes of `path`, if the peer has it.
    pub(crate) fn file(&self, path: &str) -> Option<Vec<u8>> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.fs.get(path.as_bytes()).map(|entry| entry.bytes.clone())
    }

    /// Whether `path` exists as a directory.
    pub(crate) fn is_dir(&self, path: &str) -> bool {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.fs.get(path.as_bytes()).is_some_and(|entry| entry.is_dir)
    }

    /// The deleted paths, in order.
    pub(crate) fn deleted(&self) -> Vec<String> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.record.deleted.iter().map(|path| String::from_utf8_lossy(path).into_owned()).collect()
    }

    /// The sessions the transport discarded.
    pub(crate) fn discarded(&self) -> Vec<u64> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).record.discarded.clone()
    }

    /// Set what `FilesAction::List` returns.
    pub(crate) fn set_listed(&self, entries: Vec<FileEntry>) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).listed = entries;
    }

    /// Set the exit code and stderr `exec` answers with.
    pub(crate) fn set_exec(&self, exit_code: i32, stderr: &str) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.exec_exit = exit_code;
        state.exec_stderr = stderr.to_string();
    }

    /// Set whether `ping` succeeds.
    pub(crate) fn set_ping(&self, ok: bool) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).ping_ok = ok;
    }

    /// Push an unsolicited message to the client (a screen frame, an end).
    pub(crate) fn push(&self, channel: ChannelId, message: &Message) {
        let mut encoder = self.encoder.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = encoder.send(channel, message);
    }

    /// End the connection: both peers see EOF, so the client's pump reports
    /// `Disconnected` exactly as a dropped ssh would.
    pub(crate) fn close(&self) {
        let _ = self.closer.shutdown(std::net::Shutdown::Both);
    }
}

/// Connect a `Client` to a fake peer and return both.
///
/// The peer writes the bridge's ready line (`MUXY-STDIO/1`) first, exactly
/// like `muxy stdio` does, then serves the wire protocol.
pub(crate) fn connect(timeout: Duration) -> (Client, Bridge) {
    connect_with_features(vec![Feature::SESSION_ENVIRONMENT], timeout)
}

/// Connect a `Client` to a fake peer that advertises `features`.
pub(crate) fn connect_with_features(features: Vec<Feature>, timeout: Duration) -> (Client, Bridge) {
    let (ours, theirs) = muxy_protocol::transport::socket_pair().expect("socket pair");
    let writer = theirs.try_clone().expect("clone the peer's socket");
    (&writer).write_all(b"MUXY-STDIO/1\n").expect("write the ready line");

    let state = Arc::new(Mutex::new(State { ping_ok: true, next_session: 7, ..State::default() }));
    let closer = writer.try_clone().expect("clone for shutdown");
    let encoder = Arc::new(Mutex::new(Encoder::new(writer)));
    let (waker, woke) = mpsc::channel::<()>();
    let reader_state = Arc::clone(&state);
    let reader_encoder = Arc::clone(&encoder);
    thread::Builder::new()
        .name("shellflow-muxy-fake-peer".into())
        .spawn(move || serve(theirs, reader_state, reader_encoder, woke, features))
        .expect("spawn the fake peer");

    let client = Client::connect_bridge(Box::new(ours), "fake-host", timeout, || BridgeExit {
        status: None,
        stderr: String::new(),
    })
    .expect("connect to the fake peer");
    (client, Bridge { state, encoder, closer, _waker: waker })
}

/// The peer's read loop: answer requests until the stream ends.
fn serve(
    reader: std::os::unix::net::UnixStream,
    state: Arc<Mutex<State>>,
    encoder: Arc<Mutex<Encoder<std::os::unix::net::UnixStream>>>,
    _woke: mpsc::Receiver<()>,
    features: Vec<Feature>,
) {
    let mut decoder = Decoder::new(reader);
    while let Ok((channel, message)) = decoder.next() {
        let reply = match message {
            Message::Hello { .. } => Some(Message::HelloReply {
                versions: vec![CURRENT],
                server: ServerInfo {
                    build: BuildInfo {
                        version: "0.0.0-fake".to_string(),
                        compatibility: COMPATIBILITY,
                        protocol: vec![CURRENT],
                    },
                    instance: 1,
                },
                features: features.clone(),
            }),
            Message::Request { id, body } => answer(&state, id, body),
            other => {
                let _ = other;
                None
            }
        };
        let Some(reply) = reply else { continue };
        let mut encoder = encoder.lock().unwrap_or_else(PoisonError::into_inner);
        if encoder.send(channel, &reply).is_err() {
            return;
        }
    }
}

/// The reply to one request, or `None` for "unsupported" (an error reply).
fn answer(state: &Arc<Mutex<State>>, id: RequestId, body: RequestBody) -> Option<Message> {
    let reply = match body {
        RequestBody::Ping => {
            let ok = {
                let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
                state.record.calls.push("ping".to_string());
                state.ping_ok
            };
            if ok { ReplyBody::Pong } else { return error(id, "ping refused") }
        }
        RequestBody::ReadCatalog { .. } => ReplyBody::Catalog(catalog()),
        RequestBody::Files(request) => {
            let action = request.action.clone();
            files(state, action)
        }
        RequestBody::Exec(_) => {
            let (exit_code, stderr) = {
                let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
                state.record.calls.push("exec".to_string());
                (state.exec_exit, state.exec_stderr.clone())
            };
            ReplyBody::Exec(ExecResult {
                stdout: String::new(),
                stderr,
                exit_code,
                timed_out: false,
                truncated: false,
                cancelled: false,
            })
        }
        RequestBody::CreateSession { .. } => {
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            state.record.calls.push("create-session".to_string());
            state.next_session += 1;
            ReplyBody::SessionCreated(SessionInfo {
                project: ProjectId::from_u128(1),
                id: SessionId::new(state.next_session).expect("non-zero session id"),
                directory: ServerPath(b"/work".to_vec()),
            })
        }
        RequestBody::EndSession(session) => {
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            state.record.calls.push(format!("end-session {}", session.get()));
            ReplyBody::SessionEnded
        }
        RequestBody::DiscardSession(session) => {
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            state.record.calls.push(format!("discard-session {}", session.get()));
            state.record.discarded.push(session.get());
            ReplyBody::SessionDiscarded
        }
        // Anything else is refused *with a reply*: a peer that stays silent
        // leaves the client waiting out its request timeout, and then every
        // later request on that connection fails too — which is not the
        // behaviour any caller is trying to test.
        _ => return error(id, "the fake peer does not implement this request"),
    };
    Some(Message::Reply { id, body: reply })
}

fn error(id: RequestId, message: &str) -> Option<Message> {
    Some(Message::Reply {
        id,
        body: ReplyBody::Error(ErrorReply { code: ErrorCode::BadRequest, message: message.into() }),
    })
}

/// The catalog: one Home project at `/work`.
fn catalog() -> CatalogPage {
    CatalogPage {
        server: muxy_protocol::ServerIdentity::from_u128(9),
        home: ProjectId::from_u128(1),
        revision: 1,
        projects: vec![ProjectDescriptor {
            id: ProjectId::from_u128(1),
            home: true,
            directory: ServerPath(b"/work".to_vec()),
            name: "home".to_string(),
            icon: None,
            logo: None,
            color: "#30a46c".to_string(),
            kind: None,
            parent_id: None,
        }],
        next: None,
        legacy_home: None,
    }
}

/// Serve one file action against the fake filesystem.
fn files(state: &Arc<Mutex<State>>, action: FilesAction) -> ReplyBody {
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    match action {
        FilesAction::List(path) => {
            state.record.calls.push(format!("list {}", String::from_utf8_lossy(&path.0)));
            ReplyBody::Files(FilesReply::Entries(state.listed.clone()))
        }
        FilesAction::Stat(path) => {
            state.record.calls.push(format!("stat {}", String::from_utf8_lossy(&path.0)));
            if state.fs.contains_key(&path.0) {
                ReplyBody::Files(FilesReply::Done)
            } else {
                ReplyBody::Error(ErrorReply {
                    code: ErrorCode::BadPath,
                    message: "no such path".to_string(),
                })
            }
        }
        FilesAction::Mkdir(path) => {
            state.record.calls.push(format!("mkdir {}", String::from_utf8_lossy(&path.0)));
            state.fs.insert(path.0.clone(), Entry { is_dir: true, bytes: Vec::new() });
            ReplyBody::Files(FilesReply::Done)
        }
        FilesAction::WriteBytes { path, bytes } => {
            state.record.calls.push(format!("write {}", String::from_utf8_lossy(&path.0)));
            state.fs.insert(path.0.clone(), Entry { is_dir: false, bytes });
            ReplyBody::Files(FilesReply::Done)
        }
        FilesAction::Delete(paths) => {
            for path in &paths {
                state.record.calls.push(format!("delete {}", String::from_utf8_lossy(&path.0)));
                state.record.deleted.push(path.0.clone());
                state.fs.remove(&path.0);
            }
            ReplyBody::Files(FilesReply::Done)
        }
        _ => ReplyBody::Error(ErrorReply {
            code: ErrorCode::BadRequest,
            message: "unsupported file action".to_string(),
        }),
    }
}

/// A directory entry for `FilesAction::List`.
pub(crate) fn dir_entry(name: &str, path: &str) -> FileEntry {
    FileEntry {
        name: ServerPath(name.as_bytes().to_vec()),
        path: ServerPath(path.as_bytes().to_vec()),
        is_directory: true,
        is_ignored: false,
    }
}

/// A file entry for `FilesAction::List`.
pub(crate) fn file_entry(name: &str, path: &str) -> FileEntry {
    FileEntry {
        name: ServerPath(name.as_bytes().to_vec()),
        path: ServerPath(path.as_bytes().to_vec()),
        is_directory: false,
        is_ignored: false,
    }
}
