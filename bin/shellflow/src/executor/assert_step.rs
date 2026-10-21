//! The `@assert` / `@assert_health` step: verify conditions on the target.
//!
//! Every playbook used to end with a hand-written tail — `systemctl
//! is-active`, a `curl -f`, a `grep` over the journal — and every one of
//! those tails differed: a different port, a different unit name, a check
//! that quietly stopped being checked when somebody edited the file.
//!
//! An assertion step replaces that tail with a declaration:
//!
//! ```text
//! # @assert dufs active
//! # @assert_health http://127.0.0.1:8080/health
//! ```
//!
//! All the assertions of a step travel in **one** round trip: a single
//! remote script runs every check and answers with one verdict per check,
//! so the operator sees exactly which condition failed.

use std::{sync::Arc, time::Duration};

use shellflow_core::{Assertion, AssertStep, ResolvedHost};
use tokio::sync::Semaphore;

use crate::{
    executor::{ArcUi, HostOutcome, LogFile, RunError, StepConfig, cancel::Cancel},
    rbatch::Batch,
};

/// The default budget for one health probe, in seconds.
const DEFAULT_HEALTH_TIMEOUT_SECS: u64 = 10;

/// Run an assertion step on every host.
///
/// # Errors
///
/// Returns an error only when the fan-out itself cannot be set up; a
/// failed *assertion* is reported per host as a failed step.
pub(super) async fn run_assert_step(
    ui: &ArcUi,
    assert: &AssertStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
    semaphore: &Option<Arc<Semaphore>>,
    log_file: &LogFile,
    cancel: &Cancel,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    if config.check || config.dry_run {
        crate::ui::note(
            &format!(
                "  assert {} check(s) (no-op in check/dry-run)",
                assert.checks.len()
            ),
            log_file,
        );
        return Ok(hosts.into_iter().map(|host| (host.alias, HostOutcome::Ok)).collect());
    }

    let timeout_secs = config.timeout.unwrap_or(DEFAULT_HEALTH_TIMEOUT_SECS);
    let mut tasks = tokio::task::JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let checks = assert.checks.clone();
        let semaphore = semaphore.clone();
        let log_file = log_file.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let _permit = match semaphore.as_ref() {
                Some(sem) => match sem.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                    }
                },
                None => None,
            };
            if cancel.is_cancelled() {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
            let outcome = run_on_host(&ui, &host, &checks, timeout_secs, &log_file).await;
            (host.alias.clone(), outcome)
        });
    }

    let mut out = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(pair) => {
                ui.lock().await.host_finished(&pair.0);
                out.push(pair);
            }
            Err(err) => {
                crate::ui::warn(&format!("assert task failed: {err}"), log_file);
            }
        }
    }
    Ok(out)
}

/// Run every check on one host and report the verdicts.
async fn run_on_host(
    ui: &ArcUi,
    host: &ResolvedHost,
    checks: &[Assertion],
    timeout_secs: u64,
    log_file: &LogFile,
) -> HostOutcome {
    let mut batch = Batch::new();
    for (idx, check) in checks.iter().enumerate() {
        batch.section(&format!("c{idx}"), &command_for(check, timeout_secs));
    }

    let run = batch.run_async(&host.alias);
    let sections = match tokio::time::timeout(Duration::from_secs(timeout_secs + 15), run).await {
        Ok(Ok(sections)) => sections,
        Ok(Err(err)) => {
            crate::ui::warn(
                &format!("[{}] assert could not reach the host: {err}", host.alias),
                log_file,
            );
            return HostOutcome::Failed(RunError::Transport);
        }
        Err(_) => {
            crate::ui::warn(
                &format!("[{}] assert timed out after {timeout_secs}s", host.alias),
                log_file,
            );
            return HostOutcome::Failed(RunError::Script);
        }
    };

    let mut failed = 0usize;
    for idx in 0..checks.len() {
        let section = sections.get(&format!("c{idx}"));
        let ok = section.is_some_and(|s| s.rc == 0);
        let message = section.map_or_else(
            || "the check did not answer".to_string(),
            |s| s.body.lines().next().unwrap_or_default().to_string(),
        );
        if ok {
            ui.lock().await.masked_note(&format!("[{}] ok: {message}", host.alias));
        } else {
            failed += 1;
            ui.lock().await.masked_note(&format!("[{}] FAIL: {message}", host.alias));
        }
    }
    if failed > 0 {
        HostOutcome::Failed(RunError::Script)
    } else {
        HostOutcome::Ok
    }
}

/// The remote command that checks one condition.
///
/// The command exits `0` when the condition holds and `1` when it does
/// not, and prints a one-line verdict either way.
fn command_for(check: &Assertion, timeout_secs: u64) -> String {
    match check {
        Assertion::UnitState { unit, state } => format!(
            "s=$(systemctl is-active {unit} 2>/dev/null); \
             if [ \"$s\" = {state} ]; then echo \"{unit} is $s\"; \
             else echo \"{unit} is $s (want {state})\"; false; fi",
            unit = quote(unit),
            state = quote(state),
        ),
        Assertion::Port { ports } => {
            // The wait happens on the target: one round trip covers the
            // whole budget, not one round trip per poll.
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            let budget = timeout_secs;
            let checks: Vec<String> = list
                .iter()
                .map(|port| {
                    format!(
                        "if sfw_wait_port {port} {budget}; then echo 'port {port} is listening'; \
                         else echo 'port {port} is not listening after {budget}s'; false; fi"
                    )
                })
                .collect();
            format!(
                "sfw_wait_port() {{ p=\"$1\"; d=$(( $(date +%s) + $2 )); \
                 while :; do \
                 if ss -tln 2>/dev/null | grep -qE \":${{p}}[[:space:]]\"; then return 0; fi; \
                 if [ \"$(date +%s)\" -ge \"$d\" ]; then return 1; fi; \
                 sleep 2; \
                 done; }}; {checks}",
                checks = checks.join("; "),
            )
        }
        Assertion::Rendered { path } => {
            let quoted = quote(path);
            // The pattern is passed as an argument, so the format string
            // never has to escape the braces itself.
            let pattern = r"\$\{[A-Z_][A-Z0-9_]*\}";
            format!(
                "if [ -f {quoted} ] && ! grep -qE '{pattern}' {quoted} 2>/dev/null; then \
                 echo '{path} is fully rendered'; \
                 else echo '{path} is missing or still carries unexpanded placeholders'; \
                 false; fi",
                quoted = quoted,
                pattern = pattern,
                path = path,
            )
        }
        Assertion::Health { url, expect } => {
            let accepted = if expect.is_empty() {
                // Any 2xx or 3xx is a healthy answer. The pattern must stay
                // unquoted: inside `case` a quoted pattern is a literal
                // string, so `2??` would never match `200`.
                "2??|3??".to_string()
            } else {
                let codes: Vec<String> = expect.iter().map(u16::to_string).collect();
                codes.join("|")
            };
            format!(
                "c=$( {probe} ); \
                 case \"$c\" in {accepted}) echo \"{url} answered $c\" ;; \
                 *) echo \"{url} answered $c (want {want})\"; false ;; esac",
                probe = http_probe(url, timeout_secs),
                accepted = accepted,
                url = url,
                want = if expect.is_empty() {
                    "2xx/3xx".to_string()
                } else {
                    expect.iter().map(u16::to_string).collect::<Vec<_>>().join("|")
                },
            )
        }
    }
}

/// A shell command that prints the HTTP status code of a URL.
///
/// `curl` is preferred; `wget` is the fallback for hosts without it. A
/// host with neither reports `000`, which never matches an accepted code.
fn http_probe(url: &str, timeout_secs: u64) -> String {
    let quoted = quote(url);
    format!(
        "if command -v curl >/dev/null 2>&1; then \
         curl -s -o /dev/null -w '%{{http_code}}' --max-time {timeout_secs} {quoted} 2>/dev/null; \
         elif command -v wget >/dev/null 2>&1; then \
         if wget -q -O /dev/null --timeout={timeout_secs} {quoted} 2>/dev/null; then echo 200; \
         else echo 000; fi; \
         else echo 000; fi",
        timeout_secs = timeout_secs,
        quoted = quoted,
    )
}

/// Quote a value for the remote shell.
///
/// The value comes from the playbook (a unit name, a state, a URL), so it
/// is quoted rather than trusted: a unit name with a space must not become
/// two arguments.
fn quote(value: &str) -> String {
    shellflow_core::env::shell_quote_single(value)
}

#[cfg(test)]
mod tests {
    use super::{command_for, http_probe, quote};
    use shellflow_core::Assertion;

    #[test]
    fn a_unit_check_asks_systemd_for_the_state() {
        let cmd = command_for(
            &Assertion::UnitState { unit: "dufs.service".to_string(), state: "active".to_string() },
            10,
        );
        assert!(cmd.contains("systemctl is-active 'dufs.service'"), "{cmd}");
        assert!(cmd.contains("'active'"), "{cmd}");
        // The command fails when the state does not match.
        assert!(cmd.contains("false;"), "{cmd}");
    }

    #[test]
    fn a_health_check_probes_the_url() {
        let cmd = command_for(
            &Assertion::Health {
                url: "http://127.0.0.1:8080/health".to_string(),
                expect: Vec::new(),
            },
            5,
        );
        assert!(cmd.contains("http://127.0.0.1:8080/health"), "{cmd}");
        assert!(cmd.contains("curl"), "{cmd}");
        assert!(cmd.contains("wget"), "{cmd}");
        assert!(cmd.contains("2??|3??"), "{cmd}");
    }

    #[test]
    fn a_health_check_with_explicit_codes_accepts_only_those() {
        let cmd = command_for(
            &Assertion::Health { url: "http://x/".to_string(), expect: vec![200, 204] },
            5,
        );
        assert!(cmd.contains("200|204"), "{cmd}");
        assert!(!cmd.contains("2??"), "{cmd}");
    }

    #[test]
    fn a_url_is_quoted() {
        let cmd = http_probe("http://x/a b", 3);
        assert!(cmd.contains("'http://x/a b'"), "{cmd}");
    }

    #[test]
    fn a_value_with_a_quote_is_escaped() {
        assert_eq!(quote("it's"), "'it'\\''s'");
    }
}
