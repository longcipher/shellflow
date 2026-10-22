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
        Self::new_many(&[(service.to_string(), unit.to_string())], journal_lines)
    }

    /// Build the remote script for **several** units.
    ///
    /// Every question of every unit travels in the **one** batch, so the
    /// audit of a whole host costs a single SSH round trip instead of one
    /// per service.
    pub(super) fn new_many(units: &[(String, String)], journal_lines: usize) -> Self {
        let mut batch = Batch::new();
        for (service, unit) in units {
            add_unit_sections(&mut batch, service, unit, journal_lines);
        }
        // The fleet's runtime directories. systemd **removes and recreates**
        // `RuntimeDirectory=` on every unit start, so two units that claim
        // the same directory destroy each other's files: starting one wipes
        // the rendered configuration of the other. Only the fleet can show
        // this, so the query is host-wide and asked once.
        batch.section(
            "fleet_dirs",
            "sfw_units=$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
             | awk '{print $1}'); \
             [ -n \"$sfw_units\" ] || exit 0; \
             sudo -n systemctl show $sfw_units -p Id,RuntimeDirectory 2>/dev/null",
        );
        Self { batch }
    }

    /// Run the probe against one host.
    ///
    /// # Errors
    ///
    /// Returns [`crate::service::ServiceError::Transport`] when the SSH
    /// transport is unavailable.
    pub(super) fn run(
        &self,
        host: &str,
    ) -> Result<std::collections::BTreeMap<String, Section>, crate::service::ServiceError> {
        self.batch.run(host)
    }
}

/// The section id of one question about one unit.
pub(super) fn section_id(unit: &str, kind: &str) -> String {
    format!("{unit}_{kind}")
}

/// Add every question about one unit to the batch.
fn add_unit_sections(batch: &mut Batch, service: &str, unit: &str, journal_lines: usize) {
    let socket_unit = unit.replace(".service", ".socket");

    batch.section(&section_id(unit, "unit_state"), &format!("systemctl is-active '{unit}'"));
    batch.section(
        &section_id(unit, "socket_load"),
        &format!("systemctl show '{socket_unit}' -p LoadState --value"),
    );
    batch.section(
        &section_id(unit, "socket_state"),
        &format!("systemctl is-active '{socket_unit}'"),
    );
    batch.section(
        &section_id(unit, "props"),
        &format!(
            "sudo -n systemctl show '{unit}' -p \
             ExecStart,Environment,EnvironmentFile,LoadCredentialEncrypted,ImportCredential,\
             User,Type,NotifyAccess,WatchdogUSec,TimeoutStartSec,TimeoutStartUSec,\
             ExecReload,StatusText,ActiveState,Result,Restart,RestartUSec,\
             StartLimitBurst,StartLimitIntervalUSec,ProtectHome,ReadWritePaths,\
             RuntimeDirectory,NoNewPrivileges,ProtectSystem,PrivateTmp"
        ),
    );
    batch.section(&section_id(unit, "unit_file"), &format!("sudo -n systemctl cat '{unit}'"));
    batch.section(
        &section_id(unit, "credstore"),
        &format!("sudo -n ls -l '/etc/credstore.encrypted/{service}/'"),
    );
    batch.section(
        &section_id(unit, "journal"),
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
    batch.section(&section_id(unit, "paths"), &paths_cmd);
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
            assert!(script.contains(&format!("_B_foo.service_{id}")), "missing query {id}");
        }
        assert!(script.contains("_B_fleet_dirs"), "missing the fleet query");
        assert_eq!(script.matches("out=$(").count(), 9);
    }

    #[test]
    fn several_units_travel_in_one_batch() {
        // The audit of a whole host must cost one round trip, not one per
        // service: every question of every unit is in the same script.
        let probe = Probe::new_many(
            &[
                ("dufs".to_string(), "dufs.service".to_string()),
                ("sws".to_string(), "sws.service".to_string()),
            ],
            50,
        );
        let script = probe.batch.script();
        for unit in ["dufs.service", "sws.service"] {
            assert!(script.contains(&format!("_B_{unit}_props")), "missing {unit}");
        }
        // The fleet query is asked once, not once per unit.
        assert_eq!(script.matches("_B_fleet_dirs").count(), 1);
    }

    #[test]
    fn the_fleet_query_asks_for_the_runtime_directories() {
        // A shared `RuntimeDirectory=` is a cross-unit data-loss bug, and
        // only the fleet can show it.
        let script = Probe::new("foo.service", "foo", 50).batch.script().to_string();
        assert!(script.contains("fleet_dirs"), "{script}");
        assert!(script.contains("RuntimeDirectory"), "{script}");
        assert!(script.contains("list-unit-files"), "{script}");
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
        // The path preflight walks a fixed list of properties; the
        // directories systemd creates itself must not be in it (they are
        // legitimately absent before the first start).
        let props =
            script.lines().find(|line| line.contains("for prop in")).expect("the property list");
        for prop in ["RuntimeDirectory", "StateDirectory", "CacheDirectory", "LogsDirectory"] {
            assert!(!props.contains(prop), "systemd creates {prop} itself: {props}");
        }
    }
}
