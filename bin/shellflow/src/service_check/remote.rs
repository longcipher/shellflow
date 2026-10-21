//! The remote script that answers every `service check` question.
//!
//! The framing, the parsing and the transport live in [`crate::rbatch`];
//! this module only says *what* to ask.

use crate::rbatch::{Batch, Section};

/// The framed answers of one `service check` batch.
#[derive(Debug, Default)]
pub(super) struct Probe {
    batch: Batch,
}

impl Probe {
    /// Build the remote script that answers every audit question.
    ///
    /// `unit` is the systemd unit (`foo.service`), `service` the bare service
    /// name used for the credential store path.
    pub(super) fn new(unit: &str, service: &str, journal_lines: usize) -> Self {
        let socket_unit = unit.replace(".service", ".socket");
        let mut batch = Batch::new();

        batch.section("unit_state", &format!("systemctl is-active '{unit}'"));
        batch.section(
            "socket_load",
            &format!("systemctl show '{socket_unit}' -p LoadState --value"),
        );
        batch.section("socket_state", &format!("systemctl is-active '{socket_unit}'"));
        batch.section(
            "props",
            &format!(
                "sudo -n systemctl show '{unit}' -p \
                 ExecStart,Environment,EnvironmentFile,LoadCredentialEncrypted,ImportCredential,\
                 User,Type,NotifyAccess,WatchdogUSec,TimeoutStartSec,ExecReload,StatusText,\
                 ActiveState,Result"
            ),
        );
        batch.section("unit_file", &format!("sudo -n systemctl cat '{unit}'"));
        batch.section(
            "credstore",
            &format!("sudo -n ls -l '/etc/credstore.encrypted/{service}/'"),
        );
        batch.section(
            "journal",
            &format!("sudo -n journalctl -u '{unit}' --no-pager -n {journal_lines}"),
        );
        // Path-existence preflight. systemd fails a unit with
        // `226/NAMESPACE` when `ReadWritePaths=` (or `WorkingDirectory=`, or
        // a non-`-`-prefixed `EnvironmentFile=`) names a path that does not
        // exist — and the unit stays *enabled*, so nothing looks wrong until
        // the unit is started. `systemd-analyze verify` does not catch it.
        //
        // `systemd` creates `RuntimeDirectory=`, `StateDirectory=`,
        // `CacheDirectory=` and `LogsDirectory=` itself, so those are not
        // checked: their absence is normal.
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
        batch.section("paths", &paths_cmd);

        Self { batch }
    }

    /// Run the probe against one host.
    ///
    /// # Errors
    ///
    /// Returns [`crate::service::ServiceError::Transport`] when the SSH
    /// transport is unavailable.
    pub(super) fn run(&self, host: &str) -> Result<std::collections::BTreeMap<String, Section>, crate::service::ServiceError> {
        self.batch.run(host)
    }
}

#[cfg(test)]
mod tests {
    use super::Probe;

    #[test]
    fn the_script_asks_every_question_once() {
        let probe = Probe::new("foo.service", "foo", 50);
        let script = probe.batch.script();
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
        assert_eq!(script.matches("out=$(").count(), 8);
    }

    #[test]
    fn the_script_uses_non_interactive_sudo() {
        // A sudo that needs a password would read the prompt from the
        // script's stdin and swallow the remaining queries.
        let script = Probe::new("foo.service", "foo", 50).batch.script().to_string();
        assert!(script.contains("sudo -n "));
        assert!(!script.contains("sudo systemctl"));
    }

    #[test]
    fn the_path_preflight_covers_the_paths_systemd_must_find() {
        let script = Probe::new("foo.service", "foo", 50).batch.script().to_string();
        for prop in [
            "WorkingDirectory",
            "ReadWritePaths",
            "ReadOnlyPaths",
            "InaccessiblePaths",
            "EnvironmentFile",
        ] {
            assert!(script.contains(prop), "missing path property {prop}");
        }
    }

    #[test]
    fn the_path_preflight_skips_the_directories_systemd_creates() {
        let script = Probe::new("foo.service", "foo", 50).batch.script().to_string();
        for prop in ["RuntimeDirectory", "StateDirectory", "CacheDirectory", "LogsDirectory"] {
            assert!(!script.contains(prop), "systemd creates {prop} itself");
        }
    }
}
