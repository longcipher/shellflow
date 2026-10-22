//! `shellflow service check` — read-only systemd audit over SSH.
//!
//! Automates the post-deploy audit that is otherwise done by hand dozens of
//! times per migration: unit state, argv/env secret exposure, credential
//! wiring (`LoadCredentialEncrypted=` vs plaintext), the paths the unit
//! references (a missing `ReadWritePaths=` target fails the unit with
//! `226/NAMESPACE` while leaving it *enabled*), listening sockets, and a
//! journal scan for secret-value shapes.
//!
//! Every question is asked in **one** SSH round trip (see
//! [`remote`]); the audit of a service costs one connection instead of
//! seven. Findings print as `ok`/`WARN`/`FAIL` lines and the process exits
//! non-zero when any `FAIL` fires.

mod remote;

use std::collections::BTreeMap;

use eyre::{Result, bail};
use remote::Probe;

use crate::{
    cli::ServiceCheckArgs,
    rbatch::Section,
    service::{ServiceError, ServiceError::Other},
};

/// Run `service check`.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when the SSH transport is unavailable
/// (a missing `ssh`, an unreachable host) and [`ServiceError::Other`] when a
/// check reports `FAIL` or the request itself is malformed.
pub(crate) fn check(args: &ServiceCheckArgs) -> Result<(), ServiceError> {
    // The same preflight the `run` path uses: a missing `ssh` is a
    // transport/setup failure (exit 3), not a generic error.
    preflight_ssh()?;
    let mut failures = 0;

    if args.all {
        let units = host_units(args)?;
        if units.is_empty() {
            return Err(Other(eyre::eyre!(
                "service check --all: the repository declares no service for the host `{}`",
                args.host
            )));
        }
        // One batch: every question of every service travels together.
        let probe = Probe::new_many(&units, args.journal_lines);
        let sections = probe.run(&args.host)?;
        for (service, unit) in &units {
            check_unit(service, unit, &sections, &mut failures);
        }
        if failures > 0 {
            return Err(Other(eyre::eyre!(
                "service check --all: {failures} FAIL finding(s) on `{}`",
                args.host
            )));
        }
        println!("service check --all: {} clean", args.host);
        return Ok(());
    }

    let Some(service) = args.service.as_deref() else {
        return Err(Other(eyre::eyre!(
            "service check: name a service, or pass --all to audit every service of the host"
        )));
    };
    validate_service_name(service)?;
    let unit = format!("{service}.service");

    let probe = Probe::new(&unit, service, args.journal_lines);
    let sections = probe.run(&args.host)?;
    check_unit(service, &unit, &sections, &mut failures);

    if failures > 0 {
        return Err(ServiceError::Other(eyre::eyre!(
            "service check: {failures} FAIL finding(s) for `{service}`"
        )));
    }
    println!("service check: {service} clean");
    Ok(())
}

/// The services of the audited host, from the repository's manifests.
///
/// The manifests state the host of every service outright, so the audit
/// covers exactly the services the host is supposed to run.
fn host_units(args: &ServiceCheckArgs) -> Result<Vec<(String, String)>, ServiceError> {
    let manifests =
        crate::manifest::load_all(&args.repo).map_err(|err| Other(eyre::eyre!("{err}")))?;
    let mut units: Vec<(String, String)> = Vec::new();
    for manifest in manifests.values() {
        if manifest.host != args.host {
            continue;
        }
        units.push((manifest.service.clone(), manifest.unit.clone()));
    }
    units.sort();
    Ok(units)
}

/// Check one unit's answers.
fn check_unit(
    service: &str,
    unit: &str,
    sections: &BTreeMap<String, Section>,
    failures: &mut usize,
) {
    let body = |kind: &str| {
        sections.get(&remote::section_id(unit, kind)).map_or_else(String::new, |s| s.body.clone())
    };
    let show = body("props");
    let journal = body("journal");

    let active = body("unit_state");
    report(
        &format!("unit {unit} is {}", active.trim()),
        if active.trim() == "active" { Check::Ok } else { Check::Warn },
        failures,
    );

    // A socket-activated service is enabled through its `.socket` unit: the
    // socket owns the port and the service inherits the fd. Auditing only the
    // `.service` would miss a service that is simply never started.
    // `is-active` reports "inactive" for a unit that does not exist at all,
    // so the unit's load state decides whether it is really there.
    let socket_unit = format!("{}.socket", service);
    let load_state = body("socket_load");
    if load_state.trim() != "not-found" && !load_state.trim().is_empty() {
        let socket_state = body("socket_state");
        report(
            &format!(
                "socket unit {socket_unit} is {} (the port is systemd's)",
                socket_state.trim()
            ),
            if socket_state.trim() == "active" { Check::Ok } else { Check::Warn },
            failures,
        );
    }

    // argv / Environment secret values (ferriskey class): `--password VALUE`
    // and `KEY=VALUE` forms. Key *names* are fine; values are not.
    if has_argv_secret(&show) {
        report(
            "secret value in ExecStart argv or Environment= (`ps` visible)",
            Check::Fail,
            failures,
        );
    } else {
        report("no secret values in argv/Environment", Check::Ok, failures);
    }
    // NOTE: `systemctl show` prints credential paths as `[unprintable]`, so
    // import lines are counted from the unit file text instead.
    let unit_file = body("unit_file");
    let n_creds = unit_file
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("LoadCredentialEncrypted=") && !t.ends_with('=')
        })
        .count();
    report(&format!("{n_creds} LoadCredentialEncrypted= import(s)"), Check::Ok, failures);
    if show
        .lines()
        .any(|l| l.starts_with("EnvironmentFile=") && !l.ends_with('=') && !l.contains("/dev/null"))
    {
        report("EnvironmentFile= referenced (verify it carries no secrets)", Check::Warn, failures);
    }
    if show.lines().any(|l| l == "User=root") {
        report("runs as root (least-privilege follow-up)", Check::Warn, failures);
    }

    // Path-existence preflight: a unit that names a path systemd must find
    // (WorkingDirectory=, ReadWritePaths=, a non-optional EnvironmentFile=)
    // fails to start with `226/NAMESPACE` — and stays enabled, so the
    // breakage is invisible until the unit is started.
    let missing = missing_paths(&body("paths"));
    if missing.is_empty() {
        report("every path the unit references exists", Check::Ok, failures);
    } else {
        for path in &missing {
            report(&format!("unit references a missing path: {path}"), Check::Fail, failures);
        }
    }

    let credstore = sections.get("credstore");
    let credstore_missing = credstore.is_none_or(|s| s.rc != 0 || s.body.trim().is_empty());
    if credstore_missing {
        report("credential store is empty", Check::Warn, failures);
    } else {
        report("credential store present (0600 root expected)", Check::Ok, failures);
    }

    let leaks: Vec<&str> =
        journal.lines().filter(|l| looks_like_leak(l, service)).take(3).collect();
    if leaks.is_empty() {
        report("no secret-value shapes in the last journal lines", Check::Ok, failures);
    } else {
        report(
            &format!("possible secret values in journal ({} line(s), review)", leaks.len()),
            Check::Fail,
            failures,
        );
    }

    // Notify / readiness audit: the failures systemd reports for a service
    // that never signalled readiness, plus the configuration mistakes that
    // make a notify unit unable to signal at all.
    let notify_findings = notify_findings(&show, &journal);
    if notify_findings.is_empty() {
        report("notify/readiness wiring is sound", Check::Ok, failures);
    }
    for (message, status) in notify_findings {
        report(&message, status, failures);
    }

    // The unit-level invariants: the mistakes that cost an outage and that
    // nothing else reports.
    let fleet = body("fleet_dirs");
    let invariants = unit_invariant_findings(&show, &fleet);
    if invariants.is_empty() {
        report("unit invariants hold", Check::Ok, failures);
    }
    for (message, status) in invariants {
        report(&message, status, failures);
    }
}

/// The paths the unit references that do not exist on the target.
///
/// The remote half of the preflight prints one `ok <property> <path>` or
/// `missing <property> <path>` line per referenced path.
fn missing_paths(paths: &str) -> Vec<String> {
    paths
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let status = parts.next()?;
            if status != "missing" {
                return None;
            }
            let property = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            if path.is_empty() {
                return None;
            }
            Some(format!("{property}={path}"))
        })
        .collect()
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
/// * `Type=notify` with `NotifyAccess=none` — the unit can never become ready; systemd kills it at
///   `TimeoutStartSec`.
/// * `Type=notify-reload` without `ExecReload=` — the reload is a no-op, so a graceful-restart
///   playbook silently degrades to "nothing happened".
/// * A configured `WatchdogSec=` with a watchdog timeout in the journal — the service never pings,
///   so systemd killed it. This is a silent production failure that only the journal shows.
/// * "no READY=1 notification received" in the journal — the service started but never signalled
///   readiness.
/// * A notify unit that is still activating with no `STATUS=` — the operator has no progress
///   signal, which is exactly what the notify protocol is for.
/// * A notify unit with a very short `TimeoutStartSec=` — the service is killed before it can
///   finish initialising.
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

/// The unit-level invariants the audit checks.
///
/// These are the mistakes that cost an outage and that nothing else reports:
///
/// * **A shared `RuntimeDirectory=`.** systemd removes and recreates the directory on every unit
///   start, so two units that claim the same directory destroy each other's files — starting one
///   wipes the rendered configuration of the other.
/// * **A notify unit without a start timeout.** systemd's 90 s default kills a service that needs
///   longer to initialise, and the failure looks like a crash rather than a timeout.
/// * **A restart policy without a start limit.** `Restart=always` with the default burst (5
///   restarts in 10 s) means a flapping service is killed and stays dead.
/// * **No hardening at all.** A unit with neither `NoNewPrivileges=` nor `ProtectSystem=` nor
///   `PrivateTmp=` runs with the full privileges of its user and the host's full filesystem.
fn unit_invariant_findings(show: &str, fleet: &str) -> Vec<(String, Check)> {
    let mut findings = Vec::new();
    let props = parse_show_props(show);
    let get = |key: &str| props.get(key).map_or("", String::as_str);

    // A runtime directory that more than one unit claims.
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = String::new();
    for line in fleet.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "Id" => current = value.trim().to_string(),
            "RuntimeDirectory" => {
                let value = value.trim();
                if value.is_empty() || current.is_empty() {
                    continue;
                }
                for dir in value.split_whitespace() {
                    owners.entry(dir.to_string()).or_default().push(current.clone());
                }
            }
            _ => {}
        }
    }
    let own_dir = get("RuntimeDirectory").trim().to_string();
    for (dir, units) in &owners {
        if units.len() < 2 {
            continue;
        }
        let severity =
            if own_dir.split_whitespace().any(|d| d == dir) { Check::Fail } else { Check::Warn };
        findings.push((
            format!(
                "RuntimeDirectory={dir} is claimed by {} units ({}): systemd removes and recreates \
                 it on every start, so starting one wipes the files of the others",
                units.len(),
                units.join(", ")
            ),
            severity,
        ));
    }

    let unit_type = get("Type");
    let is_notify = unit_type == "notify" || unit_type == "notify-reload";
    if is_notify && get("TimeoutStartUSec").trim().is_empty() {
        findings.push((
            format!(
                "Type={unit_type} without TimeoutStartSec=: systemd's 90 s default kills a \
                 service that needs longer to initialise"
            ),
            Check::Warn,
        ));
    }

    let restart = get("Restart").trim();
    if !restart.is_empty() && restart != "no" && get("StartLimitBurst").trim().is_empty() {
        findings.push((
            format!(
                "Restart={restart} without StartLimitBurst=: systemd's default burst (5 restarts \
                 in 10 s) kills a flapping service and leaves it dead"
            ),
            Check::Warn,
        ));
    }

    if get("NoNewPrivileges").trim().is_empty() &&
        get("ProtectSystem").trim().is_empty() &&
        get("PrivateTmp").trim().is_empty()
    {
        findings.push((
            "the unit has no hardening at all (no NoNewPrivileges=, ProtectSystem=, or \
             PrivateTmp=)"
                .to_string(),
            Check::Warn,
        ));
    }

    let protect_home = get("ProtectHome").trim();
    if !protect_home.is_empty() &&
        protect_home != "false" &&
        protect_home != "no" &&
        get("ReadWritePaths").split_whitespace().any(|p| p.starts_with("/home/"))
    {
        findings.push((
            format!(
                "ProtectHome={protect_home} with a ReadWritePaths= under /home: the path depends \
                 on a home directory, which a home-directory cleanup silently breaks"
            ),
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
        Check, has_argv_secret, journal_contains, looks_like_leak, missing_paths, notify_findings,
        parse_show_props, timeout_start_is_short, unit_invariant_findings,
    };

    #[test]
    fn a_shared_runtime_directory_is_a_failure() {
        // systemd removes and recreates `RuntimeDirectory=` on every start, so
        // two units that claim it destroy each other's files.
        let show = "RuntimeDirectory=cidx\nType=simple\n";
        let fleet = "Id=cidx-bsc.service\nRuntimeDirectory=cidx\n\
                     Id=cidx-sol.service\nRuntimeDirectory=cidx\n";
        let findings = unit_invariant_findings(show, fleet);
        let shared = findings
            .iter()
            .find(|(message, _)| message.contains("RuntimeDirectory=cidx"))
            .expect("the shared runtime directory must be reported");
        assert_eq!(shared.1, Check::Fail, "{findings:?}");
    }

    #[test]
    fn a_runtime_directory_of_another_unit_is_only_a_warning() {
        let show = "RuntimeDirectory=\nType=simple\n";
        let fleet = "Id=cidx-bsc.service\nRuntimeDirectory=cidx\n\
                     Id=cidx-sol.service\nRuntimeDirectory=cidx\n";
        let findings = unit_invariant_findings(show, fleet);
        let shared = findings
            .iter()
            .find(|(message, _)| message.contains("RuntimeDirectory=cidx"))
            .expect("the shared runtime directory must be reported");
        assert_eq!(shared.1, Check::Warn, "{findings:?}");
    }

    #[test]
    fn a_notify_unit_without_a_start_timeout_is_a_warning() {
        let show = "Type=notify\nNotifyAccess=main\n";
        let findings = unit_invariant_findings(show, "");
        assert!(
            findings.iter().any(|(m, s)| m.contains("TimeoutStartSec") && *s == Check::Warn),
            "{findings:?}"
        );
    }

    #[test]
    fn a_restart_policy_without_a_start_limit_is_a_warning() {
        let show = "Type=simple\nRestart=always\nRestartUSec=5s\n";
        let findings = unit_invariant_findings(show, "");
        assert!(
            findings.iter().any(|(m, s)| m.contains("StartLimitBurst") && *s == Check::Warn),
            "{findings:?}"
        );
    }

    #[test]
    fn a_hardened_unit_has_no_hardening_finding() {
        let show = "Type=simple\nNoNewPrivileges=yes\nProtectSystem=strict\nPrivateTmp=yes\n";
        let findings = unit_invariant_findings(show, "");
        assert!(!findings.iter().any(|(m, _)| m.contains("no hardening")), "{findings:?}");
    }

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
    fn missing_paths_are_listed_with_their_property() {
        let out = "ok WorkingDirectory /srv/app\nmissing ReadWritePaths /var/lib/app\n\
                   missing EnvironmentFile /etc/app/secrets.env\n";
        let missing = missing_paths(out);
        assert_eq!(missing.len(), 2);
        assert!(missing.iter().any(|m| m == "ReadWritePaths=/var/lib/app"));
        assert!(missing.iter().any(|m| m == "EnvironmentFile=/etc/app/secrets.env"));
    }

    #[test]
    fn every_path_present_reports_nothing_missing() {
        assert!(
            missing_paths("ok WorkingDirectory /srv/app\nok ReadWritePaths /var/lib/app\n")
                .is_empty()
        );
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
        let journal =
            "systemd[1]: foo.service: Startup finished, but no READY=1 notification received.";
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
