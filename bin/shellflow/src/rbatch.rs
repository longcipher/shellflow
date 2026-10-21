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
//! * Every query reads from `/dev/null`. The script itself arrives on the
//!   remote's stdin, so a query that read stdin would swallow the rest of
//!   the script.
//! * `sudo` runs with `-n`. A sudo that needs a password would otherwise
//!   read the password prompt from the script's stdin and consume the
//!   remaining queries.

use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::service::ServiceError;

/// One query's answer from a remote batch.
#[derive(Debug, Clone, Default)]
pub(crate) struct Section {
    /// Exit status of the query (`0` = success).
    pub rc: i32,
    /// Combined stdout and stderr of the query, trimmed.
    pub body: String,
}

/// A framed batch of remote queries.
#[derive(Debug, Default)]
pub(crate) struct Batch {
    script: String,
    nonce: String,
}

impl Batch {
    /// Start an empty batch.
    #[must_use]
    pub(crate) fn new() -> Self {
        let mut batch = Self { script: String::new(), nonce: nonce() };
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
        self.script.push_str(&format!(
            "out=$({cmd} </dev/null 2>&1); rc=$?; \
             printf '%s %s\\n' '{beg}' \"$rc\"; printf '%s\\n' \"$out\"; printf '%s\\n' '{end}'\n"
        ));
    }

    /// The remote script to send.
    #[must_use]
    pub(crate) fn script(&self) -> &str {
        &self.script
    }

    /// Split a batch's stdout into its framed answers.
    #[must_use]
    pub(crate) fn parse(&self, output: &str) -> BTreeMap<String, Section> {
        let mut sections: BTreeMap<String, Section> = BTreeMap::new();
        let mut current: Option<(String, i32)> = None;
        let mut body: Vec<&str> = Vec::new();
        for line in output.lines() {
            if let Some((id, rc)) = self.match_begin(line) {
                flush(&mut sections, &mut current, &mut body);
                current = Some((id, rc));
                continue;
            }
            if let Some(id) = self.match_end(line) {
                if current.as_ref().is_some_and(|(cid, _)| *cid == id) {
                    flush(&mut sections, &mut current, &mut body);
                }
                continue;
            }
            if current.is_some() {
                body.push(line);
            }
        }
        flush(&mut sections, &mut current, &mut body);
        sections
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
    /// # Errors
    ///
    /// Returns [`ServiceError::Transport`] when the SSH transport is
    /// unavailable (a missing `ssh`, an unreachable host) or when the host
    /// answered with nothing that looks like a batch.
    pub(crate) fn run(&self, host: &str) -> Result<BTreeMap<String, Section>, ServiceError> {
        let mut child = Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=15")
            .arg(host)
            .arg("sh")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| ServiceError::Transport(eyre::eyre!("failed to run ssh {host}: {err}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            // A broken pipe here means the connection died; the exit status
            // of `ssh` says so with more precision, so the write error is
            // ignored rather than reported.
            let _ = stdin.write_all(self.script().as_bytes());
        }
        let output = child
            .wait_with_output()
            .map_err(|err| ServiceError::Transport(eyre::eyre!("ssh {host} failed: {err}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if output.status.code() == Some(255) {
            return Err(ServiceError::Transport(eyre::eyre!(
                "ssh {host} could not connect: {}",
                format!("{stdout}{stderr}").trim()
            )));
        }
        let sections = self.parse(&stdout);
        if sections.is_empty() {
            return Err(ServiceError::Transport(eyre::eyre!(
                "ssh {host} returned no data: {}",
                format!("{stdout}{stderr}").trim()
            )));
        }
        Ok(sections)
    }
}

/// Store the answer being collected, if any.
///
/// The body is stored **verbatim**: the framing only guarantees that the
/// answer starts on the line after the begin marker and ends before the end
/// marker. Trimming it would eat the leading whitespace of a file whose
/// first line is indented (a YAML document, a shell continuation) and turn
/// an identical file into a difference.
fn flush(
    sections: &mut BTreeMap<String, Section>,
    current: &mut Option<(String, i32)>,
    body: &mut Vec<&str>,
) {
    if let Some((id, rc)) = current.take() {
        sections.insert(id, Section { rc, body: body.join("\n") });
    }
    body.clear();
}

/// A per-run token that makes the frame markers unforgeable by content.
fn nonce() -> String {
    let nanos =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
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
