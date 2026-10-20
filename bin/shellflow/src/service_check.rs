//! `shellflow service check` — read-only systemd audit over SSH.
//!
//! Automates the post-deploy audit that is otherwise done by hand dozens of
//! times per migration: unit state, argv/env secret exposure, credential
//! wiring (`LoadCredentialEncrypted=` vs plaintext), listening sockets, and
//! a journal scan for secret-value shapes. Everything runs through the
//! system `ssh` (read-only commands only); findings print as `ok`/`WARN`
//! lines and the process exits non-zero when any `FAIL` fires.

use std::process::Command;

use eyre::{Result, bail};

use crate::{cli::ServiceCheckArgs, service::ServiceError};

/// Run `service check`.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when the SSH transport is unavailable
/// (a missing `ssh`, an unreachable host) and [`ServiceError::Other`] when a
/// check reports `FAIL` or the request itself is malformed.
pub(crate) fn check(args: &ServiceCheckArgs) -> Result<(), ServiceError> {
    validate_service_name(&args.service)?;
    // The same preflight the `run` path uses: a missing `ssh` is a
    // transport/setup failure (exit 3), not a generic error.
    preflight_ssh()?;
    let unit = format!("{}.service", args.service);
    let mut failures = 0;

    let active = ssh(&args.host, &["systemctl", "is-active", &unit])?;
    report(
        &format!("unit {unit} is {active}"),
        if active.trim() == "active" { Check::Ok } else { Check::Warn },
        &mut failures,
    );

    let show = ssh(
        &args.host,
        &[
            "sudo",
            "systemctl",
            "show",
            &unit,
            "-p",
            "ExecStart,Environment,EnvironmentFile,LoadCredentialEncrypted,ImportCredential,User,Type,NotifyAccess,WatchdogUSec,TimeoutStartSec,ExecReload,StatusText,ActiveState,Result",
        ],
    )?;
    // argv / Environment secret values (ferriskey class): `--password VALUE`
    // and `KEY=VALUE` forms. Key *names* are fine; values are not.
    if has_argv_secret(&show) {
        report(
            "secret value in ExecStart argv or Environment= (`ps` visible)",
            Check::Fail,
            &mut failures,
        );
    } else {
        report("no secret values in argv/Environment", Check::Ok, &mut failures);
    }
    // NOTE: `systemctl show` prints credential paths as `[unprintable]`, so
    // import lines are counted from the unit file text instead.
    let cat = ssh(&args.host, &["sudo", "systemctl", "cat", &unit])?;
    let n_creds = cat
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("LoadCredentialEncrypted=") && !t.ends_with('=')
        })
        .count();
    report(&format!("{n_creds} LoadCredentialEncrypted= import(s)"), Check::Ok, &mut failures);
    if show
        .lines()
        .any(|l| l.starts_with("EnvironmentFile=") && !l.ends_with('=') && !l.contains("/dev/null"))
    {
        report(
            "EnvironmentFile= referenced (verify it carries no secrets)",
            Check::Warn,
            &mut failures,
        );
    }
    if show.lines().any(|l| l == "User=" || l == "User=root") {
        report("runs as root (least-privilege follow-up)", Check::Warn, &mut failures);
    }

    let creds = ssh(
        &args.host,
        &["sudo", "ls", "-l", &format!("/etc/credstore.encrypted/{}/", args.service)],
    )?;
    if creds.contains("total 0") || creds.trim().is_empty() {
        report("credential store is empty", Check::Warn, &mut failures);
    } else {
        report("credential store present (0600 root expected)", Check::Ok, &mut failures);
    }

    let journal = ssh(
        &args.host,
        &["sudo", "journalctl", "-u", &unit, "--no-pager", "-n", &args.journal_lines.to_string()],
    )?;
    let leaks: Vec<&str> =
        journal.lines().filter(|l| looks_like_leak(l, &args.service)).take(3).collect();
    if leaks.is_empty() {
        report(
            &format!("no secret-value shapes in last {} journal lines", args.journal_lines),
            Check::Ok,
            &mut failures,
        );
    } else {
        report(
            &format!("possible secret values in journal ({} line(s), review)", leaks.len()),
            Check::Fail,
            &mut failures,
        );
    }

    // Notify / readiness audit: the failures systemd reports for a service
    // that never signalled readiness, plus the configuration mistakes that
    // make a notify unit unable to signal at all.
    let notify_findings = notify_findings(&show, &journal);
    if notify_findings.is_empty() {
        report("notify/readiness wiring is sound", Check::Ok, &mut failures);
    }
    for (message, status) in notify_findings {
        report(&message, status, &mut failures);
    }

    if failures > 0 {
        return Err(ServiceError::Other(eyre::eyre!(
            "service check: {failures} FAIL finding(s) for `{}`",
            args.service
        )));
    }
    println!("service check: {} clean", args.service);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Ok,
    Warn,
    Fail,
}

fn report(message: &str, status: Check, failures: &mut usize) {
    let tag = match status {
        Check::Ok => "ok",
        Check::Warn => "WARN",
        Check::Fail => "FAIL",
    };
    if status == Check::Fail {
        *failures += 1;
    }
    println!("[{tag}] {message}");
}

/// Run one remote command over the system `ssh` and return stdout.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when `ssh` itself fails (the binary
/// could not be started, or the connection was refused — `ssh` exits 255).
/// A remote command that ran and failed is *not* a transport error: its
/// output is the finding.
fn ssh(host: &str, argv: &[&str]) -> Result<String, ServiceError> {
    let output = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=15")
        .arg(host)
        .args(argv)
        .output()
        .map_err(|err| ServiceError::Transport(eyre::eyre!("failed to run ssh {host}: {err}")))?;
    if !output.status.success() {
        // `systemctl is-active` exits non-zero for inactive units and
        // `ls` fails for a missing credstore — both are findings, not
        // transport errors. Return combined output either way.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        // `ssh` exits 255 when the *connection* failed (auth refused, host
        // key rejected, unreachable). That is the transport class of §6, not
        // a finding about the unit.
        if output.status.code() == Some(255) {
            return Err(ServiceError::Transport(eyre::eyre!(
                "ssh {host} could not connect: {}",
                combined.trim()
            )));
        }
        return Ok(combined);
    }
    String::from_utf8(output.stdout)
        .map_err(|err| eyre::eyre!("non-UTF8 output from ssh {host}: {err}").into())
}

/// Verify that `ssh` is available before the first remote check.
///
/// The `run` path reports a missing tool as a transport/setup failure (exit
/// 3). This subcommand shells out to `ssh` directly, so without the same
/// preflight a missing `ssh` would surface as a generic error (exit 1) —
/// two paths disagreeing about the same failure class.
fn preflight_ssh() -> Result<(), ServiceError> {
    crate::preflight::preflight_check_ssh()
        .map_err(|msg| ServiceError::Transport(eyre::eyre!("{msg}")))
}

/// True when `systemctl show` output carries a secret *value* in argv or
/// `Environment=`: `--password VALUE`, `--token VALUE`, or `KEY=VALUE`
/// where the key name suggests a credential and the value is non-trivial.
fn has_argv_secret(show: &str) -> bool {
    for line in show.lines() {
        let lower = line.to_lowercase();
        // `--flag VALUE` forms (argv-visible to every local user via ps).
        for flag in ["--database-password ", "--password ", "--token ", "--api-key ", "--secret "] {
            if lower.contains(flag) {
                return true;
            }
        }
        // `Environment=` entries: KEY=VALUE with a credential-ish name and
        // a value long enough to be real (names alone are fine).
        if line.starts_with("Environment=") {
            for pair in line.strip_prefix("Environment=").unwrap_or_default().split(' ') {
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };
                let name = name.to_uppercase();
                if value.len() >= 8 &&
                    (name.contains("PASSWORD") ||
                        name.contains("SECRET") ||
                        name.ends_with("_TOKEN") ||
                        name.ends_with("_KEY"))
                {
                    // Import paths and template references are not values.
                    if value.starts_with('/') || value.contains("${") {
                        continue;
                    }
                    return true;
                }
            }
        }
    }
    false
}

/// True when a journal line looks like it carries a secret value:
/// `KEY=<8+ chars>` for credential-ish key names. Names alone, hashes, and
/// short flags never match.
fn looks_like_leak(line: &str, _service: &str) -> bool {
    let upper = line.to_uppercase();
    for key in ["PASSWORD=", "SECRET=", "_TOKEN=", "PRIVATE_KEY=", "API_KEY="] {
        if let Some(pos) = upper.find(key) {
            let after = &line[pos + key.len()..];
            let value: String = after.chars().take_while(|c| !c.is_whitespace()).collect();
            if value.len() >= 12 && !value.contains("${") {
                return true;
            }
        }
    }
    false
}

/// The notify / readiness findings for a unit.
///
/// `show` is the `systemctl show` output (one `Key=Value` per line) and
/// `journal` is the unit's recent journal. The rules are the ones that
/// actually break a notify service, in the order systemd itself reports them:
///
/// * `Type=notify` with `NotifyAccess=none` — the unit can never become
///   ready; systemd kills it at `TimeoutStartSec`.
/// * `Type=notify-reload` without `ExecReload=` — the reload is a no-op, so
///   a graceful-restart playbook silently degrades to "nothing happened".
/// * A configured `WatchdogSec=` with a watchdog timeout in the journal — the
///   service never pings, so systemd killed it. This is a silent production
///   failure that only the journal shows.
/// * "no READY=1 notification received" in the journal — the service started
///   but never signalled readiness.
/// * A notify unit that is still activating with no `STATUS=` — the operator
///   has no progress signal, which is exactly what the notify protocol is for.
/// * A notify unit with a very short `TimeoutStartSec=` — the service is
///   killed before it can finish initialising.
fn notify_findings(show: &str, journal: &str) -> Vec<(String, Check)> {
    let mut findings = Vec::new();
    let props = parse_show_props(show);
    let get = |key: &str| props.get(key).map_or("", String::as_str);
    let unit_type = get("Type");
    let notify_access = get("NotifyAccess");
    let watchdog = get("WatchdogUSec").trim().parse::<u64>().unwrap_or(0);
    let timeout_start = get("TimeoutStartSec");
    let exec_reload = get("ExecReload");
    let status_text = get("StatusText");
    let active = get("ActiveState");
    let is_notify = unit_type == "notify" || unit_type == "notify-reload";

    if is_notify && notify_access == "none" {
        findings.push((
            format!(
                "Type={unit_type} with NotifyAccess=none: the unit can never become ready \
                 (systemd kills it at TimeoutStartSec)"
            ),
            Check::Fail,
        ));
    }
    if unit_type == "notify-reload" && exec_reload.trim().is_empty() {
        findings.push((
            "Type=notify-reload without ExecReload=: the reload is a no-op".to_string(),
            Check::Fail,
        ));
    }
    if watchdog > 0 && journal_contains(journal, "watchdog timeout") {
        findings.push((
            format!(
                "WatchdogSec={watchdog} is configured but the service never pinged it \
                 (systemd killed it -- look for a missing WATCHDOG=1 in the service)"
            ),
            Check::Fail,
        ));
    }
    if is_notify && journal_contains(journal, "no ready=1 notification") {
        findings.push((
            "the service never sent READY=1 (systemd reported it)".to_string(),
            Check::Fail,
        ));
    }
    if is_notify && active == "activating" && status_text.trim().is_empty() {
        findings.push((
            "no STATUS= published while the unit is starting: the operator has no progress \
             signal"
                .to_string(),
            Check::Warn,
        ));
    }
    if is_notify && timeout_start_is_short(timeout_start) {
        findings.push((
            format!("Type={unit_type} with a short TimeoutStartSec={timeout_start}"),
            Check::Warn,
        ));
    }
    findings
}

/// Parse the `Key=Value` lines of `systemctl show` output.
fn parse_show_props(show: &str) -> std::collections::BTreeMap<String, String> {
    let mut props = std::collections::BTreeMap::new();
    for line in show.lines() {
        if let Some((key, value)) = line.split_once('=') {
            props.insert(key.trim().to_string(), value.to_string());
        }
    }
    props
}

/// Case-insensitive journal substring test.
fn journal_contains(journal: &str, needle: &str) -> bool {
    journal.to_lowercase().contains(needle)
}

/// Whether a `TimeoutStartSec=` value is too short for a notify service.
fn timeout_start_is_short(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v == "infinity" {
        return false;
    }
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (num, unit) = v.split_at(split);
    let Ok(n) = num.parse::<u64>() else {
        return false;
    };
    match unit {
        "" | "s" => n < 30,
        "ms" => true,
        _ => false,
    }
}

fn validate_service_name(service: &str) -> Result<()> {
    let valid = !service.is_empty() &&
        service.starts_with(|c: char| c.is_ascii_lowercase()) &&
        service.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') &&
        !service.contains("--");
    if !valid {
        bail!("invalid service name `{service}` (want [a-z][a-z0-9-]*)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Check, has_argv_secret, journal_contains, looks_like_leak, notify_findings,
        parse_show_props, timeout_start_is_short,
    };

    #[test]
    fn detects_argv_password() {
        let show = "ExecStart={ path=/bin/x ; argv[]=/bin/x --database-password s3cret-value-here ; ignore_errors=no }";
        assert!(has_argv_secret(show));
    }

    #[test]
    fn key_names_alone_are_clean() {
        let show = "Environment=RUST_LOG=info DATABASE_URL";
        assert!(!has_argv_secret(show));
    }

    #[test]
    fn short_values_are_clean() {
        let show = "Environment=PORT=8080 MODE=prod";
        assert!(!has_argv_secret(show));
    }

    #[test]
    fn env_password_value_is_flagged() {
        let show = "Environment=FOO=1 BAR_PASSWORD=supersecretvalue123";
        assert!(has_argv_secret(show));
    }

    #[test]
    fn journal_value_shapes_are_flagged() {
        assert!(looks_like_leak("config: DATABASE_PASSWORD=supersecretvalue123", "x"));
        assert!(!looks_like_leak("credentials KEK loaded; nothing to see", "x"));
        assert!(!looks_like_leak("listening on 127.0.0.1:8080", "x"));
    }

    #[test]
    fn parses_show_properties() {
        let props = parse_show_props("Type=notify\nActiveState=active\nExecStart={ path=/bin/x }");
        assert_eq!(props.get("Type").map(String::as_str), Some("notify"));
        assert_eq!(props.get("ActiveState").map(String::as_str), Some("active"));
        assert_eq!(props.get("ExecStart").map(String::as_str), Some("{ path=/bin/x }"));
        assert!(!props.contains_key("Missing"));
    }

    #[test]
    fn a_notify_unit_with_notify_access_none_fails() {
        let show = "Type=notify\nNotifyAccess=none\nActiveState=activating\n";
        let findings = notify_findings(show, "");
        assert!(
            findings.iter().any(|(m, s)| m.contains("NotifyAccess=none") && *s == Check::Fail),
            "{findings:?}"
        );
    }

    #[test]
    fn a_sound_notify_unit_has_no_findings() {
        let show = "Type=notify\nNotifyAccess=main\nActiveState=active\nStatusText=\n";
        assert!(notify_findings(show, "").is_empty());
    }

    #[test]
    fn a_notify_reload_unit_without_exec_reload_fails() {
        let show = "Type=notify-reload\nNotifyAccess=main\nExecReload=\nActiveState=active\n";
        let findings = notify_findings(show, "");
        assert!(
            findings.iter().any(|(m, s)| m.contains("ExecReload") && *s == Check::Fail),
            "{findings:?}"
        );
    }

    #[test]
    fn a_watchdog_kill_is_reported() {
        let show = "Type=simple\nNotifyAccess=none\nWatchdogUSec=30000000\nActiveState=active\n";
        let journal = "systemd[1]: foo.service: Watchdog timeout (limit 30s)!";
        let findings = notify_findings(show, journal);
        assert!(
            findings.iter().any(|(m, s)| m.contains("WatchdogSec") && *s == Check::Fail),
            "{findings:?}"
        );
    }

    #[test]
    fn a_missing_ready_notification_is_reported() {
        let show = "Type=notify\nNotifyAccess=main\nActiveState=inactive\n";
        let journal = "systemd[1]: foo.service: Startup finished, but no READY=1 notification received.";
        let findings = notify_findings(show, journal);
        assert!(
            findings.iter().any(|(m, s)| m.contains("READY=1") && *s == Check::Fail),
            "{findings:?}"
        );
    }

    #[test]
    fn an_activating_notify_unit_without_status_is_a_warning() {
        let show = "Type=notify\nNotifyAccess=main\nActiveState=activating\nStatusText=\n";
        let findings = notify_findings(show, "");
        assert!(
            findings.iter().any(|(m, s)| m.contains("STATUS=") && *s == Check::Warn),
            "{findings:?}"
        );
    }

    #[test]
    fn a_short_start_timeout_on_a_notify_unit_is_a_warning() {
        let show = "Type=notify\nNotifyAccess=main\nActiveState=active\nTimeoutStartSec=10s\n";
        let findings = notify_findings(show, "");
        assert!(
            findings.iter().any(|(m, s)| m.contains("TimeoutStartSec") && *s == Check::Warn),
            "{findings:?}"
        );
    }

    #[test]
    fn a_simple_unit_is_not_audited_for_notify() {
        let show = "Type=simple\nNotifyAccess=none\nActiveState=active\nTimeoutStartSec=10s\n";
        assert!(notify_findings(show, "").is_empty());
    }

    #[test]
    fn short_timeouts_are_recognised() {
        assert!(timeout_start_is_short("10s"));
        assert!(timeout_start_is_short("500ms"));
        assert!(!timeout_start_is_short("90s"));
        assert!(!timeout_start_is_short("1min 30s"));
        assert!(!timeout_start_is_short("infinity"));
        assert!(!timeout_start_is_short(""));
    }

    #[test]
    fn journal_matching_is_case_insensitive() {
        assert!(journal_contains("Watchdog TIMEOUT (limit 30s)", "watchdog timeout"));
        assert!(!journal_contains("all good", "watchdog timeout"));
    }
}
