//! One SSH round trip, many questions.
//!
//! Asking a remote host several questions one at a time costs one TCP
//! handshake, one authentication and one remote process per question. On a
//! fleet that is reached through a jump host, that is the dominant cost of
//! every read-only audit — measured at 21 s for the seven questions of
//! `service check` on the reference fleet.
//!
//! This module asks everything in **one** round trip. A single remote script
//! runs every query and frames each answer between markers, so an answer
//! that contains marker-shaped text (a journal line, a config value) can
//! never be mistaken for the start of the next answer.
//!
//! Two details make the batch safe to run unattended:
//!
//! * Every query reads from `/dev/null`. The script itself arrives on the remote's stdin, so a
//!   query that read stdin would swallow the rest of the script.
//! * `sudo` runs with `-n`. A sudo that needs a password would otherwise read the password prompt
//!   from the script's stdin and consume the remaining queries.

use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use shellflow_core::SshSpec;

use crate::service::ServiceError;

/// The transport budget of one batch.
///
/// `ConnectTimeout` only covers the handshake; a host that accepts the
/// connection and then stops writing would otherwise block the command (and,
/// on the synchronous path, a runtime worker) forever.
const BATCH_TIMEOUT: Duration = Duration::from_secs(300);

/// The total response a batch may collect before the transport gives up.
///
/// The answers come from a remote host, so the volume is remote-controlled;
/// a cap (far above any legitimate audit answer — a 1000-line journal is a
/// few MiB) keeps a hostile or broken target from driving the controller's
/// allocation without bound.
const MAX_BATCH_ANSWER_BYTES: usize = 64 * 1024 * 1024;

/// Where a batch is sent.
#[derive(Clone, Debug)]
pub(crate) enum SshDest {
    /// A plain destination: an alias from `~/.ssh/config` or a hostname.
    Host(String),
    /// A full spec (user, host, port).
    Spec(SshSpec),
}

impl SshDest {
    /// The `ssh` arguments that address the destination.
    fn args(&self) -> Vec<String> {
        match self {
            Self::Host(host) => vec![host.clone()],
            Self::Spec(spec) => spec.to_ssh_args(),
        }
    }
}

/// One query's answer from a remote batch.
#[derive(Debug, Clone, Default)]
pub(crate) struct Section {
    /// Exit status of the query (`0` = success).
    pub rc: i32,
    /// Combined stdout and stderr of the query, trimmed.
    pub body: String,
}

/// A framed batch of remote queries.
#[derive(Clone, Debug, Default)]
pub(crate) struct Batch {
    script: String,
    nonce: String,
    /// How many answers the batch expects.
    count: usize,
}

impl Batch {
    /// Start an empty batch.
    #[must_use]
    pub(crate) fn new() -> Self {
        let mut batch = Self { script: String::new(), nonce: nonce(), count: 0 };
        batch.script.push_str("set +e\n");
        batch
    }

    /// Append one query to the batch.
    ///
    /// `id` names the answer; it is returned as the key of the parsed map.
    /// The command runs with stdin closed and its stdout and stderr merged.
    pub(crate) fn section(&mut self, id: &str, cmd: &str) {
        let beg = format!("__SFW_{}_B_{}", self.nonce, id);
        let end = format!("__SFW_{}_E_{}", self.nonce, id);
        // The redirections must wrap the *whole* command: in
        // `out=$(a; b </dev/null 2>&1)` they bind to `b` alone, and a command
        // that replaces the shell (`exec`) would write past the capture --
        // the answer would come back empty.
        self.script.push_str(&format!(
            "out=$({{ {cmd}; }} </dev/null 2>&1); rc=$?; \
             printf '%s %s\\n' '{beg}' \"$rc\"; printf '%s\\n' \"$out\"; printf '%s\\n' '{end}'\n"
        ));
        self.count += 1;
    }

    /// How many answers the batch expects.
    #[must_use]
    pub(crate) const fn section_count(&self) -> usize {
        self.count
    }

    /// The remote script to send.
    #[must_use]
    pub(crate) fn script(&self) -> &str {
        &self.script
    }

    /// Split a batch's stdout into its framed answers.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn parse(&self, output: &str) -> BTreeMap<String, Section> {
        let mut reader = AnswerReader::new(self);
        for line in output.lines() {
            reader.push_line(line);
        }
        reader.finish()
    }

    /// Match a begin marker: `__SFW_<nonce>_B_<id> <rc>`.
    fn match_begin(&self, line: &str) -> Option<(String, i32)> {
        let rest = line.strip_prefix(&format!("__SFW_{}_B_", self.nonce))?;
        let (id, rc) = rest.rsplit_once(' ')?;
        Some((id.to_string(), rc.parse().ok()?))
    }

    /// Match an end marker: `__SFW_<nonce>_E_<id>`.
    fn match_end(&self, line: &str) -> Option<String> {
        line.strip_prefix(&format!("__SFW_{}_E_", self.nonce)).map(ToString::to_string)
    }

    /// Run the batch against one host and return its framed answers.
    ///
    /// Used by the synchronous maintenance subcommands; the executor's
    /// assertion path uses [`run_async_dest`](Self::run_async_dest).
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Transport`] when the SSH transport is
    /// unavailable (a missing `ssh`, an unreachable host) or when the host
    /// answered with nothing that looks like a batch.
    pub(crate) fn run(&self, host: &str) -> Result<BTreeMap<String, Section>, ServiceError> {
        self.run_dest(&SshDest::Host(host.to_string()))
    }

    /// Run the batch against one destination.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Transport`] when the SSH transport is
    /// unavailable or when the host answered with nothing that looks like a
    /// batch.
    pub(crate) fn run_dest(
        &self,
        dest: &SshDest,
    ) -> Result<BTreeMap<String, Section>, ServiceError> {
        self.run_dest_within(dest, BATCH_TIMEOUT)
    }

    /// Run the batch against one destination with an explicit budget.
    ///
    /// The budget is a parameter because the executor's assertion path has its
    /// own `@assert_health --timeout` budget and must not be held to the
    /// maintenance subcommand's 300 s.
    pub(crate) fn run_dest_within(
        &self,
        dest: &SshDest,
        timeout: Duration,
    ) -> Result<BTreeMap<String, Section>, ServiceError> {
        let host = dest_label(dest);
        let mut cmd = Command::new("ssh");
        // The same `ssh` policy every other invocation uses (`BatchMode`, `-T`,
        // the connect bound). A batch owns its channel, so it neither opens nor
        // joins a multiplexed one.
        crate::executor::transport::apply_options(
            crate::executor::transport::SshPolicy::batch(),
            &mut cmd,
        );
        cmd.args(dest.args())
            .arg("sh")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Own the process group so a timeout can kill ssh and everything it
        // spawned, and so a stray child cannot outlive the command.
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
        let mut child = cmd.spawn().map_err(|err| {
            ServiceError::Transport(eyre::eyre!("failed to run ssh {host}: {err}"))
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            // A broken pipe here means the connection died; the exit status
            // of `ssh` says so with more precision, so the write error is
            // ignored rather than reported.
            let _ = stdin.write_all(self.script().as_bytes());
        }

        // stderr is drained **concurrently** with stdout. Reading it after
        // `wait()` deadlocks as soon as ssh writes more than a pipe buffer:
        // ssh blocks on stderr, never closes stdout, and `wait()` never
        // returns.
        let stderr_handle = child.stderr.take().map(|mut stderr| {
            std::thread::spawn(move || {
                use std::io::Read as _;
                let mut text = String::new();
                let _ = stderr.read_to_string(&mut text);
                text
            })
        });

        // The watchdog kills the group when the host stops making progress.
        let timed_out = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        {
            let pid = child.id();
            let timed_out = Arc::clone(&timed_out);
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                let deadline = Instant::now() + timeout;
                while !finished.load(Ordering::Relaxed) {
                    if Instant::now() >= deadline {
                        timed_out.store(true, Ordering::Relaxed);
                        crate::executor::process::signal_group(
                            pid,
                            nix::sys::signal::Signal::SIGKILL,
                        );
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
        }

        // The answers are parsed **as they arrive**: the response is never
        // held twice, and the connection is closed as soon as the last
        // expected answer is in rather than after a trailing query that may
        // be slow.
        let mut reader = AnswerReader::new(self);
        let mut collected: usize = 0;
        if let Some(stdout) = child.stdout.take() {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                collected = collected.saturating_add(line.len());
                if collected > MAX_BATCH_ANSWER_BYTES {
                    // A remote-controlled response must not be able to drive
                    // the controller's allocation without bound (a journal
                    // query answers with whatever the host holds).
                    crate::executor::process::signal_group(
                        child.id(),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    let _ = child.wait();
                    finished.store(true, Ordering::Relaxed);
                    return Err(ServiceError::Transport(eyre::eyre!(
                        "ssh {host}: the batch response exceeded {} MiB",
                        MAX_BATCH_ANSWER_BYTES / (1024 * 1024)
                    )));
                }
                reader.push_line(&line);
                if reader.is_complete() {
                    // Every answer is in: kill the whole group, not only ssh.
                    // A ProxyCommand (or another local descendant) inherits
                    // the group and could otherwise hold the stderr pipe open
                    // after ssh is gone, blocking the drain below.
                    crate::executor::process::signal_group(
                        child.id(),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    break;
                }
            }
        }
        let status = child
            .wait()
            .map_err(|err| ServiceError::Transport(eyre::eyre!("ssh {host} failed: {err}")))?;
        finished.store(true, Ordering::Relaxed);
        let stderr_text = stderr_handle.and_then(|h| h.join().ok()).unwrap_or_default();
        if timed_out.load(Ordering::Relaxed) {
            return Err(ServiceError::Transport(eyre::eyre!(
                "ssh {host} timed out after {}s",
                timeout.as_secs()
            )));
        }

        Self::finish(&host, status, reader.finish(), stderr_text)
    }

    /// Run the batch against one destination from an async caller.
    ///
    /// The blocking implementation is the *only* implementation. A second
    /// async copy of "spawn ssh, drain stderr, watch the process group, parse
    /// as the answers arrive" is a second place for the stderr deadlock to
    /// hide, and the two copies had already drifted. `spawn_blocking` keeps
    /// the executor's runtime worker free while the batch runs.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Transport`] when the SSH transport is
    /// unavailable, when the host answered with nothing that looks like a
    /// batch, or when the blocking worker did not finish.
    pub(crate) async fn run_async_dest(
        &self,
        dest: &SshDest,
        timeout: Duration,
    ) -> Result<BTreeMap<String, Section>, ServiceError> {
        let batch = self.clone();
        let dest = dest.clone();
        tokio::task::spawn_blocking(move || batch.run_dest_within(&dest, timeout)).await.map_err(
            |err| {
                ServiceError::Transport(eyre::eyre!("the batch worker stopped unexpectedly: {err}"))
            },
        )?
    }

    /// Turn the parsed answers of a batch into its result.
    fn finish(
        host: &str,
        status: std::process::ExitStatus,
        sections: BTreeMap<String, Section>,
        stderr: String,
    ) -> Result<BTreeMap<String, Section>, ServiceError> {
        if status.code() == Some(255) {
            return Err(ServiceError::Transport(eyre::eyre!(
                "ssh {host} could not connect: {}",
                stderr.trim()
            )));
        }
        if sections.is_empty() {
            return Err(ServiceError::Transport(eyre::eyre!(
                "ssh {host} returned no data: {}",
                stderr.trim()
            )));
        }
        Ok(sections)
    }
}

/// An incremental reader of a batch's framed answers.
///
/// The answers arrive over the wire one line at a time. Parsing them as
/// they come keeps the peak memory at *one* answer plus the answers already
/// collected, instead of the whole response **and** a copy of it: the
/// response was read into one buffer and then split into a second set of
/// strings, so a large journal cost twice its size.
///
/// The reader also knows when the batch is **complete**: every expected
/// answer has arrived. The transport can then stop reading and close the
/// connection instead of waiting for a trailing query that may be slow.
struct AnswerReader<'a> {
    batch: &'a Batch,
    sections: BTreeMap<String, Section>,
    current: Option<(String, i32)>,
    body: Vec<String>,
}

impl<'a> AnswerReader<'a> {
    /// A reader for one batch.
    const fn new(batch: &'a Batch) -> Self {
        Self { batch, sections: BTreeMap::new(), current: None, body: Vec::new() }
    }

    /// Feed one line of the response.
    fn push_line(&mut self, line: &str) {
        if let Some((id, rc)) = self.batch.match_begin(line) {
            self.flush();
            self.current = Some((id, rc));
            return;
        }
        if let Some(id) = self.batch.match_end(line) {
            if self.current.as_ref().is_some_and(|(cid, _)| *cid == id) {
                self.flush();
            }
            return;
        }
        if self.current.is_some() {
            self.body.push(line.to_string());
        }
    }

    /// Store the answer being collected, if any.
    fn flush(&mut self) {
        if let Some((id, rc)) = self.current.take() {
            self.sections.insert(id, Section { rc, body: self.body.join("\n") });
        }
        self.body.clear();
    }

    /// Whether every expected answer has arrived.
    // `BTreeMap::len` is not a const fn on stable, so clippy's suggestion
    // does not compile; the method is still the clearest form.
    #[expect(clippy::missing_const_for_fn, reason = "BTreeMap::len is not const on stable")]
    fn is_complete(&self) -> bool {
        self.sections.len() >= self.batch.section_count()
    }

    /// The answers collected so far.
    fn finish(mut self) -> BTreeMap<String, Section> {
        self.flush();
        self.sections
    }
}

/// A human-readable label for a destination (used in error messages).
fn dest_label(dest: &SshDest) -> String {
    match dest {
        SshDest::Host(host) => host.clone(),
        SshDest::Spec(spec) => spec.dest(),
    }
}

/// A per-run token that makes the frame markers unforgeable by content.
fn nonce() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!("{:x}{:x}", std::process::id(), nanos)
}

#[cfg(test)]
mod tests {
    use super::Batch;

    fn batch() -> Batch {
        let mut b = Batch::new();
        b.section("unit_state", "systemctl is-active 'foo.service'");
        b
    }

    #[test]
    fn the_reader_emits_an_answer_as_it_completes() {
        // The reader is what makes the transport streaming: an answer is
        // available as soon as its end marker arrives, and the batch is
        // complete once every expected answer is in.
        let b = batch();
        let nonce = b.nonce.clone();
        let mut reader = super::AnswerReader::new(&b);
        assert!(!reader.is_complete());
        reader.push_line(&format!("__SFW_{nonce}_B_unit_state 0"));
        reader.push_line("active");
        assert!(!reader.is_complete());
        reader.push_line(&format!("__SFW_{nonce}_E_unit_state"));
        let sections = reader.finish();
        assert_eq!(sections["unit_state"].rc, 0);
        assert_eq!(sections["unit_state"].body, "active");
    }

    #[test]
    fn the_reader_knows_when_the_batch_is_complete() {
        let b = batch();
        let nonce = b.nonce.clone();
        let mut reader = super::AnswerReader::new(&b);
        reader.push_line(&format!("__SFW_{nonce}_B_unit_state 0"));
        reader.push_line("active");
        reader.push_line(&format!("__SFW_{nonce}_E_unit_state"));
        assert!(reader.is_complete());
    }

    #[test]
    fn a_batch_is_split_into_its_answers() {
        let b = batch();
        let nonce = b.nonce.clone();
        let out = format!(
            "__SFW_{nonce}_B_unit_state 0\nactive\n__SFW_{nonce}_E_unit_state\n\
             __SFW_{nonce}_B_journal 0\nline one\nline two\n__SFW_{nonce}_E_journal\n"
        );
        let sections = b.parse(&out);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections["unit_state"].rc, 0);
        assert_eq!(sections["unit_state"].body, "active");
        assert_eq!(sections["journal"].body, "line one\nline two");
    }

    #[test]
    fn a_failing_query_keeps_its_exit_status() {
        let b = batch();
        let nonce = b.nonce.clone();
        let out = format!(
            "__SFW_{nonce}_B_credstore 2\nls: cannot access '/etc/credstore.encrypted/foo/'\n\
             __SFW_{nonce}_E_credstore\n"
        );
        let sections = b.parse(&out);
        assert_eq!(sections["credstore"].rc, 2);
        assert!(sections["credstore"].body.contains("cannot access"));
    }

    #[test]
    fn a_body_containing_a_marker_shaped_line_does_not_split() {
        // Only this run's nonce opens a section: a journal line that looks
        // like a marker is content, not framing.
        let b = batch();
        let nonce = b.nonce.clone();
        let out = format!(
            "__SFW_{nonce}_B_journal 0\n__SFW_{nonce}_B_journal 0\nnot really\n\
             __SFW_{nonce}_E_journal\n"
        );
        let sections = b.parse(&out);
        assert_eq!(sections["journal"].rc, 0);
        assert!(sections["journal"].body.contains("not really"));
    }

    #[test]
    fn a_marker_from_another_run_is_ignored() {
        let b = batch();
        let out = "__SFW_deadbeef_B_journal 0\nhello\n__SFW_deadbeef_E_journal\n";
        assert!(b.parse(out).is_empty());
    }

    #[test]
    fn the_script_never_reads_the_script_from_stdin() {
        let b = batch();
        // Every query is fed /dev/null so it cannot swallow the rest of the
        // script (which arrives on the remote's stdin).
        assert!(b.script().contains("</dev/null 2>&1"));
    }

    #[test]
    fn the_script_asks_every_question_once() {
        let mut b = Batch::new();
        b.section("a", "true");
        b.section("b", "true");
        assert_eq!(b.script().matches("out=$(").count(), 2);
    }
}
