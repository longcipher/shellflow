//! Target-side systemd helpers: `shellflow systemd …`.
//!
//! These subcommands run **on the target host** (the binary is installed once
//! per host by a deploy playbook). They never open the network and never
//! touch an age identity; they talk to the local systemd only.
//!
//! The helper exists so that a *waiting* operation costs **one** SSH
//! round-trip instead of one per poll: the whole wait loop runs here, on the
//! host that owns the unit, and streams a machine-readable state line per
//! poll back to the controller.
//!
//! ## Exit codes (the contract the controller depends on)
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | the unit reached the wanted state |
//! | 1 | usage / internal error |
//! | 3 | the unit failed (systemd `Result` explains why) |
//! | 4 | the budget expired before the unit was ready |
//! | 5 | the unit does not exist |
//!
//! A non-zero exit from `systemctl` itself is reported as code 1 with the
//! systemctl stderr, so the controller can tell "the unit failed" from "the
//! host could not tell us".

use std::{
    fmt,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use crate::cli::{
    SystemdCmd, SystemdNotifyArgs, SystemdReloadArgs, SystemdStatusArgs, SystemdTransientArgs,
    SystemdWaitArgs, SystemdWatchArgs,
};

/// The unit reached the wanted state.
pub(crate) const EXIT_READY: i32 = 0;
/// Usage or internal error.
pub(crate) const EXIT_USAGE: i32 = 1;
/// The unit failed.
pub(crate) const EXIT_FAILED: i32 = 3;
/// The budget expired.
pub(crate) const EXIT_TIMEOUT: i32 = 4;
/// The unit does not exist.
pub(crate) const EXIT_NOT_FOUND: i32 = 5;

/// Prefix of the machine-readable state line the wait loop streams.
pub(crate) const STATE_PREFIX: &str = "SFW";

/// A systemd unit's observable state, as reported by `systemctl show`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UnitState {
    /// `Type=` — `simple`, `exec`, `notify`, `notify-reload`, `oneshot`, …
    pub unit_type: String,
    /// `ActiveState=` — `active`, `activating`, `inactive`, `failed`, …
    pub active: String,
    /// `SubState=` — `running`, `start`, `exited`, `reload`, …
    pub sub: String,
    /// `Result=` — `success`, `exit-code`, `timeout`, `watchdog`, …
    pub result: String,
    /// `StatusText=` — the service's own human-readable status line.
    pub status: String,
}

/// What the observed state means for a waiter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    /// The unit is up (or a oneshot that finished successfully).
    Ready,
    /// The unit failed; the payload is the systemd `Result` (or a generic
    /// reason when systemd gave none).
    Failed(String),
    /// Still starting, reloading, or otherwise not there yet.
    Pending,
}

impl Verdict {
    /// The process exit code this verdict maps to.
    #[must_use]
    pub(crate) const fn exit_code(&self) -> i32 {
        match self {
            Self::Ready => EXIT_READY,
            Self::Failed(_) => EXIT_FAILED,
            Self::Pending => EXIT_TIMEOUT,
        }
    }
}

/// A target-side systemd error.
#[derive(Debug)]
pub(crate) struct SystemdError {
    pub(crate) message: String,
    pub(crate) code: i32,
}

impl SystemdError {
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: EXIT_USAGE }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: EXIT_USAGE }
    }

    /// The process exit code this error maps to.
    #[must_use]
    pub(crate) const fn exit_code(&self) -> i32 {
        self.code
    }
}

impl fmt::Display for SystemdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SystemdError {}

/// Unit names are validated with the same charset the DSL accepts, so a unit
/// name can never smuggle a path or a shell metacharacter into the helpers.
fn validate_unit(unit: &str) -> Result<(), SystemdError> {
    if unit.is_empty() {
        return Err(SystemdError::usage("empty unit name"));
    }
    if unit.starts_with('.') || unit.contains("..") {
        return Err(SystemdError::usage(format!("invalid unit name `{unit}`")));
    }
    if !unit
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
    {
        return Err(SystemdError::usage(format!("invalid unit name `{unit}`")));
    }
    Ok(())
}

/// The `systemctl show` properties the helper reads.
const SHOW_PROPS: [&str; 5] = ["Type", "ActiveState", "SubState", "Result", "StatusText"];

/// Read a unit's state from the local systemd.
pub(crate) fn show_state(unit: &str) -> Result<UnitState, SystemdError> {
    let mut args: Vec<&str> = vec!["show", unit];
    for prop in SHOW_PROPS {
        args.push("-p");
        args.push(prop);
    }
    let out = systemctl_output(&args)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(SystemdError::internal(format!(
            "`systemctl show {unit}` failed: {}",
            stderr.trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_show_output(&text))
}

/// Parse the `Key=Value` output of `systemctl show` into a [`UnitState`].
///
/// Unknown keys are ignored, and a missing key leaves its field empty, so a
/// systemd that does not know a property still yields a usable state.
fn parse_show_output(text: &str) -> UnitState {
    let mut state = UnitState::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.to_string();
        match key.trim() {
            "Type" => state.unit_type = value,
            "ActiveState" => state.active = value,
            "SubState" => state.sub = value,
            "Result" => state.result = value,
            "StatusText" => state.status = value,
            _ => {}
        }
    }
    state
}

/// Decide what a state means for a waiter.
///
/// The rules, in order:
///
/// 1. `ActiveState=active` → **ready**. For a `Type=notify` unit systemd only
///    reports `active` after the service sent `READY=1`, so a notify service
///    that never signalled is never "ready" here — exactly the property the
///    notify protocol exists to provide.
/// 2. `ActiveState=failed` → **failed**.
/// 3. A `Type=oneshot` that finished with `Result=success` → **ready**. A
///    oneshot without `RemainAfterExit=yes` reports `inactive` once it is
///    done, so rule 1 alone would never fire for it.
/// 4. A failing `Result=` while the unit is not active → **failed**.
/// 5. Anything else → **pending**.
pub(crate) fn verdict(state: &UnitState) -> Verdict {
    if state.active == "active" {
        return Verdict::Ready;
    }
    if state.active == "failed" {
        return Verdict::Failed(failure_reason(state));
    }
    if state.unit_type == "oneshot" && state.result == "success" && state.sub == "exited" {
        return Verdict::Ready;
    }
    if is_failure_result(&state.result) {
        return Verdict::Failed(failure_reason(state));
    }
    Verdict::Pending
}

/// Whether a systemd `Result=` value means the unit failed.
fn is_failure_result(result: &str) -> bool {
    !result.is_empty() && result != "success" && result != "done" && result != "none"
}

/// The human-readable reason for a failure.
fn failure_reason(state: &UnitState) -> String {
    if state.result.is_empty() || state.result == "success" || state.result == "none" {
        return format!("unit is {}", if state.active.is_empty() { "not active" } else { &state.active });
    }
    format!("unit is {} (result: {})", if state.active.is_empty() { "not active" } else { &state.active }, state.result)
}

/// Render a state as the machine-readable line the controller parses.
pub(crate) fn state_line(state: &UnitState) -> String {
    let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        STATE_PREFIX,
        clean(&state.unit_type),
        clean(&state.active),
        clean(&state.sub),
        clean(&state.result),
        clean(&state.status)
    )
}

/// Parse a machine-readable state line back into a [`UnitState`].
pub(crate) fn parse_state_line(line: &str) -> Option<UnitState> {
    let rest = line.strip_prefix(STATE_PREFIX)?.strip_prefix('\t')?;
    let mut parts = rest.split('\t');
    let mut next = || parts.next().unwrap_or_default().to_string();
    Some(UnitState {
        unit_type: next(),
        active: next(),
        sub: next(),
        result: next(),
        status: next(),
    })
}

/// The state a caller is waiting for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitFor {
    /// The unit is active (or a oneshot that finished successfully).
    Ready,
    /// The unit is up and running (`SubState=running`).
    Running,
}

impl WaitFor {
    fn matches(self, state: &UnitState) -> bool {
        match self {
            Self::Ready => matches!(verdict(state), Verdict::Ready),
            Self::Running => state.active == "active" && state.sub == "running",
        }
    }
}

/// Run a `shellflow systemd` subcommand.
pub(crate) async fn run(cmd: &SystemdCmd) -> Result<(), SystemdError> {
    match cmd {
        SystemdCmd::Notify(args) => notify(args),
        SystemdCmd::Wait(args) => wait(args),
        SystemdCmd::Reload(args) => reload(args),
        SystemdCmd::Status(args) => status(args),
        SystemdCmd::Watch(args) => watch(args).await,
        SystemdCmd::Transient(args) => transient(args),
    }
}

/// `shellflow systemd notify` — send a systemd notification for the unit we
/// are running in.
///
/// The notification is only meaningful for the unit that spawned us: systemd
/// attributes a message to the unit whose cgroup the sender is in, and the
/// socket address comes from `$NOTIFY_SOCKET` (set by systemd for every unit).
fn notify(args: &SystemdNotifyArgs) -> Result<(), SystemdError> {
    let states = notify_states(args)?;
    send_notify(&states)
}

/// Build the notification states from the CLI arguments.
fn notify_states(args: &SystemdNotifyArgs) -> Result<Vec<sd_notify::NotifyState<'_>>, SystemdError> {
    let mut states: Vec<sd_notify::NotifyState<'_>> = Vec::new();
    if args.ready {
        states.push(sd_notify::NotifyState::Ready);
    }
    if args.reloading {
        // systemd >= 253 requires MONOTONIC_USEC with RELOADING=1.
        states.push(sd_notify::NotifyState::Reloading);
        states.push(
            sd_notify::NotifyState::monotonic_usec_now()
                .map_err(|err| SystemdError::internal(format!("cannot read the monotonic clock: {err}")))?,
        );
    }
    if args.stopping {
        states.push(sd_notify::NotifyState::Stopping);
    }
    if args.watchdog {
        states.push(sd_notify::NotifyState::Watchdog);
    }
    if let Some(status) = &args.status {
        states.push(sd_notify::NotifyState::Status(status));
    }
    if let Some(pid) = args.main_pid {
        states.push(sd_notify::NotifyState::MainPid(pid));
    }
    for raw in &args.raw {
        if !raw.contains('=') {
            return Err(SystemdError::usage(format!(
                "`--raw` expects KEY=VALUE, got `{raw}`"
            )));
        }
        states.push(sd_notify::NotifyState::Custom(raw));
    }
    if states.is_empty() {
        return Err(SystemdError::usage(
            "nothing to notify: pass --ready / --reloading / --stopping / --watchdog / --status / --main-pid / --raw",
        ));
    }
    Ok(states)
}

/// Send the notification datagram to `$NOTIFY_SOCKET`.
///
/// `sd-notify` is the reference implementation and is dependency-free, but it
/// only speaks to the socket named by `$NOTIFY_SOCKET` — which is the whole
/// point: a notification is only accepted from a process inside the unit's
/// own cgroup.
fn send_notify(states: &[sd_notify::NotifyState<'_>]) -> Result<(), SystemdError> {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return Err(SystemdError::usage(
            "NOTIFY_SOCKET is not set: this helper only works inside a systemd unit",
        ));
    }
    sd_notify::notify(states)
        .map_err(|err| SystemdError::internal(format!("cannot send notification: {err}")))
}

/// `shellflow systemd wait` — wait for a unit to reach a state.
///
/// The loop runs here, on the host that owns the unit, so the controller
/// spends exactly one SSH round-trip. Each poll emits a machine-readable state
/// line; the verdict is the exit code.
fn wait(args: &SystemdWaitArgs) -> Result<(), SystemdError> {
    validate_unit(&args.unit)?;
    let want = match args.for_ {
        crate::cli::WaitForArg::Ready => WaitFor::Ready,
        crate::cli::WaitForArg::Running => WaitFor::Running,
    };
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let interval = Duration::from_secs(args.interval.max(1));

    loop {
        let state = show_state(&args.unit)?;
        if state.active.is_empty() && state.unit_type.is_empty() {
            println!("{STATE_PREFIX}\tNOTFOUND");
            return Err(SystemdError {
                message: format!("unit `{}` does not exist", args.unit),
                code: EXIT_NOT_FOUND,
            });
        }
        println!("{}", state_line(&state));

        if want.matches(&state) {
            return Ok(());
        }
        let current = verdict(&state);
        if let Verdict::Failed(reason) = &current {
            return Err(SystemdError { message: reason.clone(), code: current.exit_code() });
        }
        if Instant::now() >= deadline {
            return Err(SystemdError {
                message: format!(
                    "`{}` did not reach the wanted state within {}s",
                    args.unit,
                    args.timeout
                ),
                code: EXIT_TIMEOUT,
            });
        }
        sleep(interval);
    }
}

/// `shellflow systemd status` — print a unit's state once.
fn status(args: &SystemdStatusArgs) -> Result<(), SystemdError> {
    validate_unit(&args.unit)?;
    let state = show_state(&args.unit)?;
    println!("{}", state_line(&state));
    match verdict(&state) {
        Verdict::Ready => Ok(()),
        Verdict::Failed(reason) => Err(SystemdError { message: reason, code: EXIT_FAILED }),
        Verdict::Pending => Err(SystemdError {
            message: format!("unit `{}` is not ready", args.unit),
            code: EXIT_TIMEOUT,
        }),
    }
}

/// `shellflow systemd reload` — trigger a graceful reload and wait for it.
///
/// The ladder mirrors what a unit can offer:
///
/// 1. the unit declares `ExecReload=` → `systemctl reload`;
/// 2. `--signal` is given → `systemctl kill --signal <sig>` (the
///    nginx/USR1 convention);
/// 3. otherwise → refuse, because a silent fallback to `restart` would drop
///    connections the operator explicitly asked not to drop.
fn reload(args: &SystemdReloadArgs) -> Result<(), SystemdError> {
    validate_unit(&args.unit)?;
    let has_exec_reload = unit_has_property(&args.unit, "ExecReload");
    let signal = args.signal.as_deref().unwrap_or("SIGUSR1");

    if has_exec_reload {
        run_systemctl(&["reload", &args.unit])?;
    } else if args.signal.is_some() {
        run_systemctl(&["kill", "--signal", signal, &args.unit])?;
    } else {
        return Err(SystemdError::usage(format!(
            "`{}` has no ExecReload= and no --signal was given: declare ExecReload= in the unit \
             or pass --signal (e.g. --signal SIGUSR1). Refusing to fall back to a restart, which \
             would drop the connections a reload is meant to preserve.",
            args.unit
        )));
    }

    if !args.wait {
        return Ok(());
    }
    wait_for_reload(&args.unit, Duration::from_secs(args.timeout), Duration::from_secs(args.interval.max(1)))
}

/// Run `systemctl`, elevating when the caller is not root.
///
/// The helper is installed for the deploy user, but `systemctl reload` and
/// `systemctl kill` are privileged. Passwordless sudo is the same assumption
/// the `cred-env` helper already makes, so the elevation is attempted the
/// same way; a host without it gets a clear error instead of a silent no-op.
fn systemctl_output(args: &[&str]) -> Result<std::process::Output, SystemdError> {
    let mut cmd = if nix::unistd::Uid::effective().is_root() {
        let mut cmd = Command::new("systemctl");
        cmd.args(args);
        cmd
    } else {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg("systemctl").args(args);
        cmd
    };
    cmd.stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|err| SystemdError::internal(format!("cannot run `systemctl`: {err}")))
}

/// Whether the unit declares a given property (`systemctl show -p X`).
fn unit_has_property(unit: &str, property: &str) -> bool {
    let Ok(out) = systemctl_output(&["show", unit, "-p", property]) else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().any(|line| !line.ends_with('=') && !line.is_empty())
}

/// Run `systemctl` with the given arguments, mapping a failure to an error.
fn run_systemctl(args: &[&str]) -> Result<(), SystemdError> {
    let out = systemctl_output(args)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(SystemdError::internal(format!(
            "`systemctl {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Wait for a reload handshake.
///
/// A service that speaks the notify protocol announces the reload with
/// `RELOADING=1` and finishes with `READY=1`, so systemd passes through
/// `ActiveState=reloading`. We watch for that transition and then for the unit
/// to be active again. A service that does not implement the protocol is
/// accepted as soon as it is active — the wait never invents a failure.
fn wait_for_reload(unit: &str, timeout: Duration, interval: Duration) -> Result<(), SystemdError> {
    let deadline = Instant::now() + timeout;
    let mut saw_reloading = false;
    loop {
        let state = show_state(unit)?;
        println!("{}", state_line(&state));
        if state.active == "reloading" || state.sub == "reload" {
            saw_reloading = true;
        }
        if saw_reloading && state.active == "active" {
            return Ok(());
        }
        if !saw_reloading && state.active == "active" {
            // The service did not announce the reload; accept it as done.
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SystemdError {
                message: format!("`{unit}` did not finish reloading within {}s", timeout.as_secs()),
                code: EXIT_TIMEOUT,
            });
        }
        sleep(interval);
    }
}

/// `shellflow systemd watch` — stream a unit's state until it changes or the
/// budget expires.
///
/// With the `dbus` feature the state changes are *events* (systemd's
/// `PropertiesChanged` signal), so the wait is instantaneous instead of
/// polled. Without it, the same output is produced by polling.
async fn watch(args: &SystemdWatchArgs) -> Result<(), SystemdError> {
    validate_unit(&args.unit)?;
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let interval = Duration::from_secs(args.interval.max(1));

    #[cfg(feature = "dbus")]
    {
        return crate::systemd_dbus::watch(&args.unit, deadline, interval).await;
    }
    #[cfg(not(feature = "dbus"))]
    {
        let mut last = String::new();
        loop {
            let state = show_state(&args.unit)?;
            let line = state_line(&state);
            if line != last {
                println!("{line}");
                last = line;
            }
            if matches!(verdict(&state), Verdict::Ready) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(SystemdError {
                    message: format!("`{}` did not become ready within {}s", args.unit, args.timeout),
                    code: EXIT_TIMEOUT,
                });
            }
            tokio::time::sleep(interval).await;
        }
    }
}

/// `shellflow systemd transient` — run a command as a transient systemd unit.
///
/// This is the `systemd-run` equivalent, with the same exit-code contract:
/// the unit's own exit status becomes the command's exit status.
fn transient(args: &SystemdTransientArgs) -> Result<(), SystemdError> {
    if args.command.is_empty() {
        return Err(SystemdError::usage("no command given"));
    }
    let mut argv: Vec<String> = vec!["run".to_string()];
    if args.scope {
        argv.push("--scope".to_string());
    }
    if let Some(unit) = &args.unit {
        argv.push(format!("--unit={unit}"));
    }
    if let Some(property) = &args.property {
        argv.push(format!("--property={property}"));
    }
    argv.push("--".to_string());
    argv.extend(args.command.iter().cloned());

    let status = Command::new("systemd-run")
        .args(&argv)
        .status()
        .map_err(|err| SystemdError::internal(format!("cannot run `systemd-run`: {err}")))?;
    let code = status.code().unwrap_or(EXIT_USAGE);
    if code == 0 {
        return Ok(());
    }
    Err(SystemdError { message: format!("transient unit exited with {code}"), code })
}

#[cfg(test)]
mod tests {
    use super::{
        EXIT_FAILED, EXIT_NOT_FOUND, EXIT_READY, EXIT_TIMEOUT, EXIT_USAGE, UnitState, Verdict,
        parse_show_output, parse_state_line, state_line, validate_unit, verdict,
    };

    fn state(unit_type: &str, active: &str, sub: &str, result: &str) -> UnitState {
        UnitState {
            unit_type: unit_type.to_string(),
            active: active.to_string(),
            sub: sub.to_string(),
            result: result.to_string(),
            status: String::new(),
        }
    }

    #[test]
    fn an_active_unit_is_ready() {
        assert_eq!(verdict(&state("simple", "active", "running", "success")), Verdict::Ready);
    }

    #[test]
    fn a_notify_unit_is_only_ready_after_ready_1() {
        // systemd keeps a Type=notify unit in `activating` until it sends
        // READY=1; that is the whole point of the protocol.
        assert_eq!(
            verdict(&state("notify", "activating", "start", "success")),
            Verdict::Pending
        );
        assert_eq!(
            verdict(&state("notify", "active", "running", "success")),
            Verdict::Ready
        );
    }

    #[test]
    fn a_notify_reload_unit_is_ready_when_active() {
        assert_eq!(
            verdict(&state("notify-reload", "active", "running", "success")),
            Verdict::Ready
        );
    }

    #[test]
    fn a_failed_unit_is_failed() {
        let v = verdict(&state("simple", "failed", "failed", "exit-code"));
        assert!(matches!(v, Verdict::Failed(ref r) if r.contains("exit-code")));
        assert_eq!(v.exit_code(), EXIT_FAILED);
    }

    #[test]
    fn a_oneshot_that_finished_successfully_is_ready() {
        // A oneshot without RemainAfterExit=yes reports `inactive` once done.
        assert_eq!(
            verdict(&state("oneshot", "inactive", "exited", "success")),
            Verdict::Ready
        );
    }

    #[test]
    fn a_oneshot_that_failed_is_failed() {
        assert!(matches!(
            verdict(&state("oneshot", "inactive", "failed", "exit-code")),
            Verdict::Failed(_)
        ));
    }

    #[test]
    fn a_starting_unit_is_pending() {
        assert_eq!(
            verdict(&state("simple", "activating", "start", "")),
            Verdict::Pending
        );
    }

    #[test]
    fn a_failing_result_while_inactive_is_failed() {
        assert!(matches!(
            verdict(&state("simple", "inactive", "dead", "timeout")),
            Verdict::Failed(_)
        ));
    }

    #[test]
    fn a_successful_result_while_inactive_is_pending() {
        // The unit has not been started yet — keep waiting, do not fail.
        assert_eq!(
            verdict(&state("simple", "inactive", "dead", "success")),
            Verdict::Pending
        );
    }

    #[test]
    fn exit_codes_are_the_documented_contract() {
        assert_eq!(Verdict::Ready.exit_code(), EXIT_READY);
        assert_eq!(Verdict::Failed(String::new()).exit_code(), EXIT_FAILED);
        assert_eq!(Verdict::Pending.exit_code(), EXIT_TIMEOUT);
        assert_ne!(EXIT_USAGE, EXIT_NOT_FOUND);
    }

    #[test]
    fn parses_systemctl_show_output() {
        let text = "Type=notify\nActiveState=active\nSubState=running\nResult=success\nStatusText=syncing 42%\n";
        let parsed = parse_show_output(text);
        assert_eq!(parsed.unit_type, "notify");
        assert_eq!(parsed.active, "active");
        assert_eq!(parsed.sub, "running");
        assert_eq!(parsed.result, "success");
        assert_eq!(parsed.status, "syncing 42%");
    }

    #[test]
    fn ignores_unknown_and_malformed_lines() {
        let parsed = parse_show_output("Type=simple\nnonsense\nActiveState=active\n");
        assert_eq!(parsed.unit_type, "simple");
        assert_eq!(parsed.active, "active");
        assert_eq!(parsed.sub, "");
    }

    #[test]
    fn the_state_line_round_trips() {
        let original = UnitState {
            unit_type: "notify".to_string(),
            active: "active".to_string(),
            sub: "running".to_string(),
            result: "success".to_string(),
            status: "syncing 42%".to_string(),
        };
        let line = state_line(&original);
        assert_eq!(parse_state_line(&line), Some(original));
    }

    #[test]
    fn the_state_line_flattens_control_characters() {
        let original = UnitState {
            unit_type: "notify".to_string(),
            active: "active".to_string(),
            sub: "running".to_string(),
            result: "success".to_string(),
            status: "line one\nline two\tend".to_string(),
        };
        let line = state_line(&original);
        assert!(!line.contains('\n'));
        assert!(!line.contains('\t') || line.matches('\t').count() == 5);
        let parsed = parse_state_line(&line).expect("parses");
        assert_eq!(parsed.status, "line one line two end");
    }

    #[test]
    fn a_non_state_line_is_not_parsed() {
        assert!(parse_state_line("hello").is_none());
        assert!(parse_state_line("SFW no-tab").is_none());
    }

    #[test]
    fn unit_names_are_validated() {
        assert!(validate_unit("foo.service").is_ok());
        assert!(validate_unit("foo@bar.service").is_ok());
        assert!(validate_unit("dbus-org.example.timer").is_ok());
        assert!(validate_unit("").is_err());
        assert!(validate_unit("../escape").is_err());
        assert!(validate_unit("foo;rm -rf /").is_err());
        assert!(validate_unit(".hidden").is_err());
    }
}
