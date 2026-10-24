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

use shellflow_core::{AssertStep, Assertion, ResolvedHost};
use tokio::sync::Semaphore;

use crate::{
    executor::{ArcUi, HostOutcome, LogFile, RunError, StepConfig, cancel::Cancel},
    rbatch::Batch,
};

/// The default budget for one health probe, in seconds.
///
/// The probe *waits*: a service that was just started needs a moment before
/// it answers, and a single probe would fail the deploy for the wrong
/// reason.
const DEFAULT_HEALTH_TIMEOUT_SECS: u64 = 60;

/// The margin the transport gets on top of the checks' own budgets.
const TRANSPORT_MARGIN_SECS: u64 = 15;

/// The budget one check may spend waiting.
fn check_budget(check: &Assertion, step_timeout: Option<u64>) -> u64 {
    match check {
        Assertion::Port { .. } => step_timeout.unwrap_or(DEFAULT_PORT_TIMEOUT_SECS),
        Assertion::Health { .. } => step_timeout.unwrap_or(DEFAULT_HEALTH_TIMEOUT_SECS),
        // The unit-state, enablement, port-free, and rendered checks answer
        // at once.
        Assertion::UnitState { .. } |
        Assertion::Enabled { .. } |
        Assertion::PortFree { .. } |
        Assertion::Rendered { .. } |
        Assertion::NoLeak { .. } |
        Assertion::Digest { .. } |
        Assertion::Credstore { .. } => 0,
    }
}

/// The default budget for waiting for a port, in seconds.
///
/// A service that is restarting is not listening *yet*: the wait is the
/// point of the check, and it used to be a hand-written `for`/`sleep` loop
/// in every playbook.
const DEFAULT_PORT_TIMEOUT_SECS: u64 = 60;

/// Run an assertion step on every host.
///
/// # Errors
///
/// Returns an error only when the fan-out itself cannot be set up; a
/// failed *assertion* is reported per host as a failed step.
/// The shared handles of an assertion step.
pub(super) struct AssertStepArgs<'a> {
    pub ui: &'a ArcUi,
    pub assert: &'a AssertStep,
    pub hosts: Vec<ResolvedHost>,
    pub config: StepConfig,
    pub semaphore: &'a Option<Arc<Semaphore>>,
    pub log_file: &'a LogFile,
    pub cancel: &'a Cancel,
    pub run_state: &'a Arc<tokio::sync::Mutex<shellflow_core::RunState>>,
}

pub(super) async fn run_assert_step(
    args: AssertStepArgs<'_>,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    let AssertStepArgs { ui, assert, hosts, config, semaphore, log_file, cancel, run_state } = args;
    if config.check || config.dry_run {
        crate::ui::note(
            &format!("  assert {} check(s) (no-op in check/dry-run)", assert.checks.len()),
            log_file,
        );
        return Ok(hosts.into_iter().map(|host| (host.alias, HostOutcome::Ok)).collect());
    }

    // A path or URL may reference a captured variable (`/run/${SVC}/…`),
    // exactly like a `@copy` path does.
    let checks = {
        let state = run_state.lock().await;
        let mut resolved = Vec::with_capacity(assert.checks.len());
        for check in &assert.checks {
            match interpolate_check(check, &state) {
                Ok(check) => resolved.push(check),
                Err(err) => {
                    crate::ui::step_failed(0, &err.to_string(), log_file);
                    return Err(err);
                }
            }
        }
        resolved
    };

    // Each check picks its own default budget; an explicit `@timeout`
    // overrides them all.
    let step_timeout = config.timeout;
    // The transport budget must cover *every* wait: the checks run one after
    // another on the target, so their budgets add up. A budget that only
    // covered the longest one would cut a group of checks short.
    let wait_budget: u64 =
        assert.checks.iter().map(|check| check_budget(check, step_timeout)).sum::<u64>() +
            TRANSPORT_MARGIN_SECS;
    let mut tasks = tokio::task::JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let checks = checks.clone();
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
            let outcome =
                run_on_host(&ui, &host, &checks, step_timeout, wait_budget, &log_file).await;
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
                out.push(("unknown".to_string(), HostOutcome::Failed(RunError::Transport)));
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
    step_timeout: Option<u64>,
    wait_budget: u64,
    log_file: &LogFile,
) -> HostOutcome {
    let mut batch = Batch::new();
    for (idx, check) in checks.iter().enumerate() {
        batch.section(&format!("c{idx}"), &command_for(check, step_timeout));
    }

    let run = batch.run_async(&host.alias);
    let sections = match tokio::time::timeout(Duration::from_secs(wait_budget), run).await {
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
                &format!("[{}] assert timed out after {wait_budget}s", host.alias),
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
    if failed > 0 { HostOutcome::Failed(RunError::Script) } else { HostOutcome::Ok }
}

/// Resolve the run-state references in one check.
///
/// A path or a URL may name a captured variable (`/run/${SVC}/config.toml`):
/// the assertion runs on the target, where that variable does not exist.
fn interpolate_check(
    check: &Assertion,
    state: &shellflow_core::RunState,
) -> eyre::Result<Assertion> {
    let resolved = match check {
        Assertion::Rendered { path } => Assertion::Rendered {
            path: shellflow_core::interpolate(path, state).map_err(eyre::Error::from)?,
        },
        Assertion::Enabled { unit, state: expected } => Assertion::Enabled {
            unit: shellflow_core::interpolate(unit, state).map_err(eyre::Error::from)?,
            state: expected.clone(),
        },
        Assertion::NoLeak { unit, lines } => Assertion::NoLeak {
            unit: shellflow_core::interpolate(unit, state).map_err(eyre::Error::from)?,
            lines: *lines,
        },
        Assertion::Digest { path, sha256, local } => Assertion::Digest {
            path: shellflow_core::interpolate(path, state).map_err(eyre::Error::from)?,
            sha256: sha256.clone(),
            local: local.clone(),
        },
        Assertion::Health { url, expect, method, body, headers } => Assertion::Health {
            url: shellflow_core::interpolate(url, state).map_err(eyre::Error::from)?,
            expect: expect.clone(),
            method: method.clone(),
            body: body.clone(),
            headers: headers.clone(),
        },
        other => other.clone(),
    };
    Ok(resolved)
}

/// The remote command that checks one condition.
///
/// The command exits `0` when the condition holds and `1` when it does
/// not, and prints a one-line verdict either way.
fn command_for(check: &Assertion, step_timeout: Option<u64>) -> String {
    match check {
        Assertion::UnitState { unit, state } => format!(
            "s=$(systemctl is-active {unit} 2>/dev/null); \
             if [ \"$s\" = {state} ]; then echo \"{unit} is $s\"; \
             else echo \"{unit} is $s (want {state})\"; false; fi",
            unit = quote(unit),
            state = quote(state),
        ),
        Assertion::Enabled { unit, state } => format!(
            "s=$(systemctl is-enabled {unit} 2>/dev/null); \
             if [ \"$s\" = {state} ]; then echo \"{unit} is-enabled $s\"; \
             else echo \"{unit} is-enabled $s (want {state})\"; false; fi",
            unit = quote(unit),
            state = quote(state),
        ),
        Assertion::PortFree { ports } => {
            // A bind conflict is diagnosed where it happens: the check names
            // the occupant (the listening process, a NAT redirect, or a
            // container publish mapping) instead of just "address in use".
            // Only listening sockets count: TIME-WAIT connections after a
            // stop are not occupants.
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            let checks: Vec<String> = list
                .iter()
                .map(|port| {
                    format!(
                        "if ss -ltn 2>/dev/null | grep -qE \":${{p}}[[:space:]]\"; then \
                         echo 'port {port} is occupied:'; \
                         sfw_occupant {port}; false; \
                         else echo 'port {port} is free'; fi"
                    )
                })
                .collect();
            format!(
                "sfw_occupant() {{ p=\"$1\"; \
                 ss -ltnp 2>/dev/null | grep -E \":${{p}}[[:space:]]\" | head -2; \
                 (sudo -n nft list ruleset 2>/dev/null || nft list ruleset 2>/dev/null) \
                   | grep -E \"dport ${{p}}[^0-9]\" | head -3; \
                 (podman ps --format '{{{{.Names}}}} {{{{.Ports}}}}' 2>/dev/null || true) \
                   | grep -E \"(^|[\\s:])${{p}}->\" | head -3; \
                 return 0; }}; {checks}",
                checks = checks.join("; "),
            )
        }
        Assertion::Port { ports, udp } => {
            // The wait happens on the target: one round trip covers the
            // whole budget, not one round trip per poll.
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            let budget = step_timeout.unwrap_or(DEFAULT_PORT_TIMEOUT_SECS);
            // `-u` asks for the UDP sockets; a UDP service listens on a
            // different socket family than a TCP one.
            let sockets = if *udp { "-uln" } else { "-tln" };
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
                 if ss {sockets} 2>/dev/null | grep -qE \":${{p}}[[:space:]]\"; then return 0; fi; \
                 if [ \"$(date +%s)\" -ge \"$d\" ]; then return 1; fi; \
                 sleep 2; \
                 done; }}; {checks}",
                sockets = sockets,
                checks = checks.join("; "),
            )
        }
        Assertion::Rendered { path } => {
            let quoted = quote(path);
            // The pattern is passed as an argument, so the format string
            // never has to escape the braces itself.
            let pattern = r"\$\{[A-Z_][A-Z0-9_]*\}";
            // The rendered file belongs to the service: it is written to a
            // root-owned tmpfs with mode 0600, so the check has to look with
            // the same rights the service reads it with.
            format!(
                "if sudo test -f {quoted} && ! sudo grep -qE '{pattern}' {quoted} 2>/dev/null; then \
                 echo '{path} is fully rendered'; \
                 else echo '{path} is missing or still carries unexpanded placeholders'; \
                 false; fi",
                quoted = quoted,
                pattern = pattern,
                path = path,
            )
        }
        Assertion::Health { url, expect, method, body, headers } => {
            let timeout_secs = step_timeout.unwrap_or(DEFAULT_HEALTH_TIMEOUT_SECS); // The accepted patterns become `case` globs. The pattern must
            // stay unquoted: inside `case` a quoted pattern is a literal
            // string, so `2??` would never match `200`.
            let accepted = if expect.is_empty() {
                // Any 2xx or 3xx is a healthy answer.
                "2??|3??".to_string()
            } else {
                expect.iter().map(|code| status_glob(code)).collect::<Vec<_>>().join("|")
            };
            // The probe *waits*: a service that was just started is not
            // answering yet, and a single probe would fail the deploy for
            // the wrong reason. The wait happens on the target, so the
            // whole budget costs one round trip.
            format!(
                "sfw_http() {{ d=$(( $(date +%s) + $1 )); \
                 while :; do \
                 c=$( {probe} ); \
                 case \"$c\" in {accepted}) echo \"$c\"; return 0 ;; esac; \
                 if [ \"$(date +%s)\" -ge \"$d\" ]; then echo \"$c\"; return 1; fi; \
                 sleep 2; \
                 done; }}; \
                 if c=$(sfw_http {timeout_secs}); then echo \"{url} answered $c\"; \
                 else echo \"{url} answered $c (want {want})\"; false; fi",
                probe = http_probe(url, timeout_secs, method.as_deref(), body.as_deref(), headers),
                accepted = accepted,
                timeout_secs = timeout_secs,
                url = url,
                want = if expect.is_empty() { "2xx/3xx".to_string() } else { expect.join("|") },
            )
        }
        Assertion::NoLeak { unit, lines } => {
            // The helper compares the *real* credential values, so no
            // per-service regular expression is needed and the plaintext never
            // reaches the script or the command line.
            let mut args = vec![quote(unit)];
            args.push("--lines".to_string());
            args.push(lines.unwrap_or(200).to_string());
            format!(
                "if [ -x {helper} ]; then exec {helper} host assert-no-leak {args}; fi; \
                 echo 'the target-side shellflow helper is required for @assert_no_leak'; false",
                helper = quote(crate::executor::host::HELPER_PATH),
                args = args.join(" "),
            )
        }
        Assertion::Digest { path, sha256, local } => {
            let mut args = vec![quote(path)];
            if let Some(digest) = sha256 {
                args.push("--sha256".to_string());
                args.push(quote(digest));
            }
            if let Some(local) = local {
                args.push("--local".to_string());
                args.push(quote(local));
            }
            format!(
                "if [ -x {helper} ]; then exec {helper} host assert-digest {args}; fi; \
                 echo 'the target-side shellflow helper is required for @assert_digest'; false",
                helper = quote(crate::executor::host::HELPER_PATH),
                args = args.join(" "),
            )
        }
        Assertion::Credstore { service } => format!(
            "if [ -x {helper} ]; then exec {helper} host assert-credstore {service}; fi; \
             echo 'the target-side shellflow helper is required for @assert_credstore'; false",
            helper = quote(crate::executor::host::HELPER_PATH),
            service = quote(service),
        ),
    }
}

/// A shell command that prints the HTTP status code of a URL.
///
/// `curl` is preferred; `wget` is the fallback for hosts without it. A
/// host with neither reports `000`, which never matches an accepted code.
fn http_probe(
    url: &str,
    timeout_secs: u64,
    method: Option<&str>,
    body: Option<&str>,
    headers: &[String],
) -> String {
    let quoted = quote(url);
    // `curl` is the only probe that can carry a method, a body and headers;
    // `wget` is the fallback for a plain GET.
    let mut curl = format!("curl -s -o /dev/null -w '%{{http_code}}' --max-time {timeout_secs}");
    if let Some(method) = method {
        curl.push_str(&format!(" -X {}", quote(method)));
    }
    for header in headers {
        curl.push_str(&format!(" -H {}", quote(header)));
    }
    if let Some(body) = body {
        curl.push_str(&format!(" --data {}", quote(body)));
    }
    format!(
        "if command -v curl >/dev/null 2>&1; then \
         {curl} {quoted} 2>/dev/null; \
         elif command -v wget >/dev/null 2>&1; then \
         if wget -q -O /dev/null --timeout={timeout_secs} {quoted} 2>/dev/null; then echo 200; \
         else echo 000; fi; \
         else echo 000; fi",
        curl = curl,
        timeout_secs = timeout_secs,
        quoted = quoted,
    )
}

/// The `case` glob for a status pattern: `200` stays `200`, `2xx` becomes
/// `2??`.
fn status_glob(pattern: &str) -> String {
    if pattern.len() == 3 && pattern.ends_with("xx") {
        return format!("{}??", &pattern[..1]);
    }
    pattern.to_string()
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
    use shellflow_core::Assertion;

    use super::{command_for, http_probe, quote};

    #[test]
    fn a_unit_check_asks_systemd_for_the_state() {
        let cmd = command_for(
            &Assertion::UnitState { unit: "dufs.service".to_string(), state: "active".to_string() },
            Some(10),
        );
        assert!(cmd.contains("systemctl is-active 'dufs.service'"), "{cmd}");
        assert!(cmd.contains("'active'"), "{cmd}");
        // The command fails when the state does not match.
        assert!(cmd.contains("false;"), "{cmd}");
    }

    #[test]
    fn a_health_check_waits_rather_than_probes_once() {
        let cmd = command_for(
            &Assertion::Health {
                url: "http://127.0.0.1:8080/health".to_string(),
                expect: Vec::new(),
                method: None,
                body: None,
                headers: Vec::new(),
            },
            Some(30),
        );
        assert!(cmd.contains("sfw_http 30"), "{cmd}");
        assert!(cmd.contains("sleep 2"), "{cmd}");
    }

    #[test]
    fn a_health_check_probes_the_url() {
        let cmd = command_for(
            &Assertion::Health {
                url: "http://127.0.0.1:8080/health".to_string(),
                expect: Vec::new(),
                method: None,
                body: None,
                headers: Vec::new(),
            },
            Some(5),
        );
        assert!(cmd.contains("http://127.0.0.1:8080/health"), "{cmd}");
        assert!(cmd.contains("curl"), "{cmd}");
        assert!(cmd.contains("wget"), "{cmd}");
        assert!(cmd.contains("2??|3??"), "{cmd}");
    }

    #[test]
    fn a_health_check_with_explicit_codes_accepts_only_those() {
        let cmd = command_for(
            &Assertion::Health {
                url: "http://x/".to_string(),
                expect: vec!["200".to_string(), "204".to_string()],
                method: None,
                body: None,
                headers: Vec::new(),
            },
            Some(5),
        );
        assert!(cmd.contains("200|204"), "{cmd}");
        assert!(!cmd.contains("2??"), "{cmd}");
    }

    #[test]
    fn a_port_check_waits_on_the_target() {
        let cmd = command_for(&Assertion::Port { ports: vec![5000], udp: false }, Some(90));
        assert!(cmd.contains("sfw_wait_port 5000 90"), "{cmd}");
        assert!(cmd.contains("ss -tln"), "{cmd}");
    }

    #[test]
    fn a_port_check_has_its_own_default_budget() {
        let cmd = command_for(&Assertion::Port { ports: vec![5000], udp: false }, None);
        assert!(cmd.contains("sfw_wait_port 5000 60"), "{cmd}");
    }

    #[test]
    fn a_rendered_check_looks_for_placeholders() {
        let cmd =
            command_for(&Assertion::Rendered { path: "/run/app/config.toml".to_string() }, None);
        assert!(cmd.contains("/run/app/config.toml"), "{cmd}");
        assert!(cmd.contains("[A-Z_]"), "{cmd}");
    }

    #[test]
    fn a_udp_port_check_asks_for_udp_sockets() {
        let cmd = command_for(&Assertion::Port { ports: vec![9900], udp: true }, Some(30));
        assert!(cmd.contains("ss -uln"), "{cmd}");
    }

    #[test]
    fn a_status_class_becomes_a_glob() {
        assert_eq!(super::status_glob("2xx"), "2??");
        assert_eq!(super::status_glob("200"), "200");
    }

    #[test]
    fn a_health_check_carries_its_method_body_and_headers() {
        let cmd = command_for(
            &Assertion::Health {
                url: "http://127.0.0.1:8645/".to_string(),
                expect: vec!["2xx".to_string()],
                method: Some("POST".to_string()),
                body: Some("{\"jsonrpc\":\"2.0\"}".to_string()),
                headers: vec!["Content-Type: application/json".to_string()],
            },
            Some(10),
        );
        assert!(cmd.contains("-X 'POST'"), "{cmd}");
        assert!(cmd.contains("--data "), "{cmd}");
        assert!(cmd.contains("Content-Type: application/json"), "{cmd}");
        assert!(cmd.contains("2??"), "{cmd}");
    }

    #[test]
    fn a_url_is_quoted() {
        let cmd = http_probe("http://x/a b", 3, None, None, &[]);
        assert!(cmd.contains("'http://x/a b'"), "{cmd}");
    }

    #[test]
    fn a_value_with_a_quote_is_escaped() {
        assert_eq!(quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn an_enabled_check_asks_systemd_for_the_boot_state() {
        let cmd = command_for(
            &Assertion::Enabled { unit: "smg.service".to_string(), state: "disabled".to_string() },
            Some(10),
        );
        assert!(cmd.contains("systemctl is-enabled 'smg.service'"), "{cmd}");
        assert!(cmd.contains("'disabled'"), "{cmd}");
        assert!(cmd.contains("false;"), "{cmd}");
    }

    #[test]
    fn a_port_free_check_names_the_occupant() {
        let cmd = command_for(&Assertion::PortFree { ports: vec![3000] }, Some(10));
        assert!(cmd.contains("ss -ltn"), "{cmd}");
        assert!(cmd.contains("sfw_occupant 3000"), "{cmd}");
        // The occupant attribution covers the three sources operators
        // otherwise check by hand: the listening process, NAT rules, and
        // container publish mappings. TIME-WAIT sockets must not count.
        assert!(cmd.contains("ss -ltnp"), "{cmd}");
        assert!(cmd.contains("nft list ruleset"), "{cmd}");
        assert!(cmd.contains("podman ps"), "{cmd}");
        assert!(cmd.contains("false;"), "{cmd}");
    }

    #[test]
    fn port_free_checks_only_match_listening_sockets() {
        let cmd = command_for(&Assertion::PortFree { ports: vec![8080] }, Some(10));
        assert!(!cmd.contains("-tan"), "{cmd}");
    }
}
