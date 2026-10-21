//! The batched remote probe behind `shellflow service check`.
//!
//! The audit asks the target about the unit, its socket, its properties, its
//! unit file, its credential store, its journal and the paths it references.
//! Asking each of those over its own SSH connection costs one TCP handshake
//! and one authentication per question — measured at 21 s per service on the
//! reference fleet, and paid again by every playbook that ends with a
//! `service check`.
//!
//! This module asks everything in **one** round trip: a single remote script
//! runs every query and frames each answer between markers, so a journal line
//! can never be mistaken for the start of the next answer.
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

/// One query's answer from the remote batch.
#[derive(Debug, Clone, Default)]
pub(super) struct Section {
    /// Exit status of the query (`0` = success).
    pub rc: i32,
    /// Combined stdout and stderr of the query, trailing newline trimmed.
    pub body: String,
}

/// The framed answers of one remote batch.
#[derive(Debug, Default)]
pub(super) struct Probe {
    script: String,
    nonce: String,
}

impl Probe {
    /// Build the remote script that answers every audit question.
    ///
    /// `unit` is the systemd unit (`foo.service`), `service` the bare service
    /// name used for the credential store path.
    pub(super) fn new(unit: &str, service: &str, journal_lines: usize) -> Self {
        let nonce = nonce();
        let socket_unit = unit.replace(".service", ".socket");
        let mut script = String::with_capacity(4096);
        script.push_str("set +e\n");

        section(&mut script, &nonce, "unit_state", &format!("systemctl is-active '{unit}'"));
        section(
            &mut script,
            &nonce,
            "socket_load",
            &format!("systemctl show '{socket_unit}' -p LoadState --value"),
        );
        section(
            &mut script,
            &nonce,
            "socket_state",
            &format!("systemctl is-active '{socket_unit}'"),
        );
        section(
            &mut script,
            &nonce,
            "props",
            &format!(
                "sudo -n systemctl show '{unit}' -p \
                 ExecStart,Environment,EnvironmentFile,LoadCredentialEncrypted,ImportCredential,\
                 User,Type,NotifyAccess,WatchdogUSec,TimeoutStartSec,ExecReload,StatusText,\
                 ActiveState,Result"
            ),
        );
        section(&mut script, &nonce, "unit_file", &format!("sudo -n systemctl cat '{unit}'"));
        section(
            &mut script,
            &nonce,
            "credstore",
            &format!("sudo -n ls -l '/etc/credstore.encrypted/{service}/'"),
        );
        section(
            &mut script,
            &nonce,
            "journal",
            &format!("sudo -n journalctl -u '{unit}' --no-pager -n {journal_lines}"),
        );
        // Path-existence preflight. systemd fails a unit with
        // `226/NAMESPACE` when `ReadWritePaths=` (or `WorkingDirectory=`, or
        // a non-`-`-prefixed `EnvironmentFile=`) names a path that does not
        // exist — and the unit stays *enabled*, so nothing looks wrong until
        // the unit is started. `systemd-analyze verify` does not catch it.
        let paths_cmd = format!(
            "sfw_paths() {{\n\
             u='{unit}'\n\
             for prop in WorkingDirectory ReadWritePaths ReadOnlyPaths InaccessiblePaths; do\n\
             sudo -n systemctl show \"$u\" -p \"$prop\" --value 2>/dev/null | tr ' ' '\\n' | \
             while IFS= read -r p; do\n\
             [ -n \"$p\" ] || continue\n\
             case \"$p\" in -*) continue ;; esac\n\
             if [ -e \"$p\" ]; then printf 'ok %s %s\\n' \"$prop\" \"$p\"; \
             else printf 'missing %s %s\\n' \"$prop\" \"$p\"; fi\n\
             done\n\
             done\n\
             sudo -n systemctl show \"$u\" -p EnvironmentFile --value 2>/dev/null | tr ' ' '\\n' | \
             while IFS= read -r p; do\n\
             [ -n \"$p\" ] || continue\n\
             case \"$p\" in -*) continue ;; esac\n\
             if [ -e \"$p\" ]; then printf 'ok EnvironmentFile %s\\n' \"$p\"; \
             else printf 'missing EnvironmentFile %s\\n' \"$p\"; fi\n\
             done\n\
             }}; sfw_paths"
        );
        section(&mut script, &nonce, "paths", &paths_cmd);

        Self { script, nonce }
    }

    /// The remote script to send.
    pub(super) fn script(&self) -> &str {
        &self.script
    }

    /// Split a batch's stdout into its framed answers.
    pub(super) fn parse(&self, output: &str) -> BTreeMap<String, Section> {
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
        line.strip_prefix(&format!("__SFW_{}_E_", self.nonce))
            .map(ToString::to_string)
    }
}

/// Store the answer being collected, if any.
fn flush(
    sections: &mut BTreeMap<String, Section>,
    current: &mut Option<(String, i32)>,
    body: &mut Vec<&str>,
) {
    if let Some((id, rc)) = current.take() {
        sections.insert(id, Section { rc, body: body.join("\n").trim().to_string() });
    }
    body.clear();
}

/// Append one framed query to the remote script.
fn section(script: &mut String, nonce: &str, id: &str, cmd: &str) {
    let beg = format!("__SFW_{nonce}_B_{id}");
    let end = format!("__SFW_{nonce}_E_{id}");
    script.push_str(&format!(
        "out=$({cmd} </dev/null 2>&1); rc=$?; \
         printf '%s %s\\n' '{beg}' \"$rc\"; printf '%s\\n' \"$out\"; printf '%s\\n' '{end}'\n"
    ));
}

/// A per-run token that makes the frame markers unforgeable by content.
fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// Run the batch against one host and return its framed answers.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when the SSH transport is unavailable
/// (a missing `ssh`, an unreachable host) or when the host answered with
/// nothing that looks like a batch.
pub(super) fn run(host: &str, probe: &Probe) -> Result<BTreeMap<String, Section>, ServiceError> {
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
        // A broken pipe here means the connection died; the exit status of
        // `ssh` says so with more precision, so the write error is ignored.
        let _ = stdin.write_all(probe.script().as_bytes());
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
    let sections = probe.parse(&stdout);
    if sections.is_empty() {
        return Err(ServiceError::Transport(eyre::eyre!(
            "ssh {host} returned no audit data: {}",
            format!("{stdout}{stderr}").trim()
        )));
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::{Probe, Section};

    fn probe() -> Probe {
        Probe::new("foo.service", "foo", 50)
    }

    #[test]
    fn a_batch_is_split_into_its_answers() {
        let probe = probe();
        let nonce = probe.nonce.clone();
        let out = format!(
            "__SFW_{nonce}_B_unit_state 0\nactive\n__SFW_{nonce}_E_unit_state\n\
             __SFW_{nonce}_B_journal 0\nline one\nline two\n__SFW_{nonce}_E_journal\n"
        );
        let sections = probe.parse(&out);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections["unit_state"].rc, 0);
        assert_eq!(sections["unit_state"].body, "active");
        assert_eq!(sections["journal"].body, "line one\nline two");
    }

    #[test]
    fn a_failing_query_keeps_its_exit_status() {
        let probe = probe();
        let nonce = probe.nonce.clone();
        let out = format!(
            "__SFW_{nonce}_B_credstore 2\nls: cannot access '/etc/credstore.encrypted/foo/'\n\
             __SFW_{nonce}_E_credstore\n"
        );
        let sections = probe.parse(&out);
        assert_eq!(sections["credstore"].rc, 2);
        assert!(sections["credstore"].body.contains("cannot access"));
    }

    #[test]
    fn a_body_containing_a_marker_shaped_line_does_not_split() {
        // Only this run's nonce opens a section: a journal line that looks
        // like a marker is content, not framing.
        let probe = probe();
        let nonce = probe.nonce.clone();
        let out = format!(
            "__SFW_{nonce}_B_journal 0\n__SFW_{nonce}_B_journal 0\nnot really\n\
             __SFW_{nonce}_E_journal\n"
        );
        let sections = probe.parse(&out);
        assert_eq!(sections["journal"].rc, 0);
        assert!(sections["journal"].body.contains("not really"));
    }

    #[test]
    fn a_marker_from_another_run_is_ignored() {
        let probe = probe();
        let out = "__SFW_deadbeef_B_journal 0\nhello\n__SFW_deadbeef_E_journal\n";
        assert!(probe.parse(out).is_empty());
    }

    #[test]
    fn the_script_asks_every_question_once() {
        let script = probe().script().to_string();
        for id in [
            "unit_state",
            "socket_load",
            "socket_state",
            "props",
            "unit_file",
            "credstore",
            "journal",
            "paths",
        ] {
            assert!(script.contains(&format!("_B_{id}")), "missing query {id}");
        }
        // One remote invocation: the whole batch is one `ssh` with one script.
        assert_eq!(script.matches("out=$(").count(), 8);
    }

    #[test]
    fn the_script_never_reads_the_script_from_stdin() {
        let script = probe().script().to_string();
        // Every query is fed /dev/null so it cannot swallow the rest of the
        // script (which arrives on the remote's stdin).
        assert!(script.contains("</dev/null 2>&1"));
    }

    #[test]
    fn the_script_uses_non_interactive_sudo() {
        let script = probe().script().to_string();
        assert!(script.contains("sudo -n "));
        assert!(!script.contains("sudo systemctl"));
    }

    #[test]
    fn a_section_body_is_trimmed() {
        let section = Section { rc: 0, body: "value".to_string() };
        assert_eq!(section.body, "value");
    }
}
