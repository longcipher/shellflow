//! The target-side systemd helper protocol: the commands a `@wait_active` or
//! `@reload` step sends, the state lines it reads back, and the exit-code
//! vocabulary those helpers answer with.
//!
//! These used to live in `remote.rs` next to the step dispatcher, which is how
//! the same exit-code ladder came to be spelled out four times (the ssh path of
//! each step plus its muxy `explain_exit`). The protocol is one thing, so it is
//! one module: [`helper_note`] is the only place that knows what `3` and `4`
//! mean.
//!
//! The two step functions that *run* these commands stay in `remote.rs` — they
//! are fan-out plus muxy/ssh selection, not protocol.

use super::{HostOutcome, RunError, stream};

/// Default wait budget in seconds when neither `@timeout` nor `--timeout`
/// bounds a `@wait_active` step (slow starters: substrate nodes, JVMs,
/// container image pulls).
pub(super) const DEFAULT_WAIT_SECS: u64 = 300;

/// The default budget for a graceful reload handshake.
pub(super) const DEFAULT_RELOAD_SECS: u64 = 120;

/// The remote command that waits for a unit to become ready.
///
/// The helper does the waiting **on the target**: it polls systemd there and
/// streams one state line per poll, so the whole wait costs a single SSH
/// round-trip instead of one per poll.
///
/// When the helper is not installed yet (a host that has never seen this
/// shellflow), a self-contained fallback polls `systemctl is-active` so the
/// step still works — it just cannot show the service's own `STATUS=` text.
///
/// The unit name is validated at parse time (`[A-Za-z0-9._-]` plus `@`/`:`,
/// no leading dots, no `..`), so interpolating it into the script cannot
/// smuggle a quote or a shell metacharacter.
pub(super) fn wait_command(unit: &str, budget_secs: u64) -> String {
    format!(
        "if [ -x /usr/local/bin/shellflow ]; then exec /usr/local/bin/shellflow systemd wait '{unit}' --timeout {budget_secs} --for ready; fi; \
         u='{unit}'; d=$(( $(date +%s) + {budget_secs} )); \
         while :; do \
           if systemctl is-active --quiet \"$u\"; then echo 'SFW active'; exit 0; fi; \
           if systemctl is-failed --quiet \"$u\"; then echo 'SFW failed'; exit 3; fi; \
           echo 'SFW pending'; \
           if [ \"$(date +%s)\" -ge \"$d\" ]; then exit 4; fi; \
           sleep 5; \
         done"
    )
}

/// Interpret the state lines the target-side helper streams.
///
/// The helper emits `SFW<TAB>type<TAB>active<TAB>sub<TAB>result<TAB>status`;
/// the fallback emits a single word. The operator sees the service's own
/// `STATUS=` text when it publishes one (that is the whole point of the notify
/// protocol) and the raw systemd state otherwise.
pub(super) fn wait_collector(unit: &str) -> stream::LineCollector {
    let unit = unit.to_string();
    stream::LineCollector::new(move |line| {
        if let Some(state) = crate::systemd::parse_state_line(line) {
            let mut bits = Vec::new();
            if !state.unit_type.is_empty() {
                bits.push(format!("type={}", state.unit_type));
            }
            if !state.active.is_empty() {
                bits.push(format!("active={}", state.active));
            }
            if !state.sub.is_empty() {
                bits.push(format!("sub={}", state.sub));
            }
            if !state.result.is_empty() {
                bits.push(format!("result={}", state.result));
            }
            let bits = bits.join(" ");
            return Some(if state.status.is_empty() {
                format!("waiting {unit}: {bits}")
            } else {
                format!("waiting {unit}: {}", state.status)
            });
        }
        let rest = line.strip_prefix("SFW")?;
        let word = rest.trim();
        if word.is_empty() {
            return None;
        }
        Some(format!("waiting {unit}: {word}"))
    })
}

/// Which target-side helper verb a step drives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HelperVerb {
    /// `shellflow systemd reload`, or the inline `systemctl reload` fallback.
    Reload,
    /// `shellflow systemd wait --for ready`, or the inline `is-active` poll.
    Wait,
}

impl HelperVerb {
    /// The word that completes `<unit> …` when the verb succeeded.
    const fn done(self) -> &'static str {
        match self {
            Self::Reload => "reloaded",
            Self::Wait => "active",
        }
    }

    /// The word that completes `<unit> …` when the condition did not hold.
    const fn failed(self) -> &'static str {
        match self {
            Self::Reload => "reload failed",
            Self::Wait => "failed",
        }
    }

    /// The verb as it appears in the "some other exit code" report.
    const fn noun(self) -> &'static str {
        match self {
            Self::Reload => "reload failed",
            Self::Wait => "wait failed",
        }
    }
}

/// The operator-facing wording of one helper exit code.
///
/// This is the target-side protocol in [`crate::exit::helper`]. It used to be
/// spelled out four times — the ssh ladder of `@reload`, the ssh ladder of
/// `@wait_active`, and the two muxy `explain_exit` closures — and the copies
/// had already drifted (`4` read "did not finish reloading" in one place and
/// "not ready" in another, for the same condition).
fn helper_note(code: i32, unit: &str, verb: HelperVerb, budget_secs: u64) -> Option<String> {
    if code == 255 {
        // ssh's own failure: the connection never reached the unit, so there
        // is nothing to say about it.
        return None;
    }
    Some(match code {
        crate::exit::helper::OK => format!("{unit} {}", verb.done()),
        crate::exit::helper::FAILED => format!("{unit} {}", verb.failed()),
        crate::exit::helper::TIMEOUT => format!("{unit} not ready after {budget_secs}s"),
        crate::exit::helper::NOT_FOUND if verb == HelperVerb::Wait => {
            format!("{unit} does not exist")
        }
        other => format!("{unit} {} (exit {other})", verb.noun()),
    })
}

/// Classify one helper exit code into a step outcome plus the line to show.
pub(super) fn classify_helper_exit(
    code: i32,
    unit: &str,
    verb: HelperVerb,
    budget_secs: u64,
    alias: &str,
) -> (HostOutcome, String) {
    let outcome = match code {
        crate::exit::helper::OK => HostOutcome::Ok,
        // ssh exits 255 when the connection itself failed: a transport
        // failure, not an inactive unit.
        255 => HostOutcome::Failed(RunError::Transport),
        // The helper's own budget expired. A timeout, not a script failure:
        // the exit code (5) says a retry may well succeed.
        crate::exit::helper::TIMEOUT => HostOutcome::TimedOut,
        _ => HostOutcome::Failed(RunError::Script),
    };
    let note = helper_note(code, unit, verb, budget_secs)
        .map_or_else(String::default, |note| format!("[{alias}] {note}"));
    (outcome, note)
}

/// The exit-code vocabulary of a `@wait` helper, for the muxy path.
#[cfg(feature = "muxy")]
pub(super) fn wait_explain(unit: &str, secs: u64) -> super::muxy::ExplainExit {
    let unit = unit.to_string();
    std::sync::Arc::new(move |code: i32| helper_note(code, &unit, HelperVerb::Wait, secs))
}

/// The exit-code vocabulary of a `@reload` helper, for the muxy path.
#[cfg(feature = "muxy")]
pub(super) fn reload_explain(unit: &str, secs: u64) -> super::muxy::ExplainExit {
    let unit = unit.to_string();
    std::sync::Arc::new(move |code: i32| helper_note(code, &unit, HelperVerb::Reload, secs))
}

/// The remote command that reloads a unit.
///
/// The helper does the work on the target — it knows the unit's `ExecReload=`,
/// it can send the notify handshake, and it can wait for the reload to
/// finish. The inline fallback covers a host that has never seen this
/// shellflow: it still refuses to degrade into a restart.
pub(super) fn reload_command(
    unit: &str,
    signal: Option<&str>,
    wait: bool,
    timeout_secs: u64,
) -> String {
    let mut helper = format!("systemd reload '{unit}'");
    if let Some(sig) = signal {
        helper.push_str(&format!(" --signal {sig}"));
    }
    if wait {
        helper.push_str(&format!(" --wait --timeout {timeout_secs}"));
    }
    let fallback_signal = signal.unwrap_or("SIGUSR1");
    format!(
        "if [ -x /usr/local/bin/shellflow ]; then exec /usr/local/bin/shellflow {helper}; fi; \
         u='{unit}'; \
         if [ \"$(id -u)\" = 0 ]; then SC=systemctl; else SC='sudo -n systemctl'; fi; \
         if [ -n \"$($SC show \"$u\" -p ExecReload --value 2>/dev/null)\" ]; then $SC reload \"$u\"; \
         else $SC kill --signal '{fallback_signal}' \"$u\"; fi"
    )
}
