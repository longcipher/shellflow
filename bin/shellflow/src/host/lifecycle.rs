//! The unit lifecycle: verify, reload the manager, enable, restart, wait.
//!
//! The ordering rules (verify before reload, never start a stopped unit) are
//! the whole reason this is a verb rather than a shell snippet.

use super::{
    Duration, HostError, HostServiceArgs,
    privileged::run_systemctl,
    probe::{reload_unit, unit_enabled_state, unit_state, verify_unit, wait_for_ready},
    validate_unit,
};

/// Drive a unit's lifecycle: verify, reload the manager, enable, restart, wait.
///
/// The sequence is the one every deploy playbook spelled out, with the rules
/// it kept getting wrong:
///
/// * `--verify` runs `systemd-analyze verify` **before** the manager is reloaded, so an invalid
///   unit aborts the deploy instead of poisoning the manager's view of it;
/// * `--restart` restarts a unit that was running and **leaves a unit that was not running alone**
///   — restarting an inactive unit starts it, which is the opposite of what an operator who keeps a
///   unit stopped wants. `--force-start` overrides that deliberately.
/// * `--wait` uses the notify-aware verdict: a `Type=notify` unit counts as ready only after it
///   said `READY=1`, a `Type=oneshot` counts when it finished successfully, and a failing `Result=`
///   is a failure rather than a wait that runs into the budget.
pub(super) fn service(args: &HostServiceArgs) -> Result<(), HostError> {
    let unit = shellflow_text::normalize_unit(&args.unit);
    validate_unit(&unit)?;

    if args.verify {
        verify_unit(&unit)?;
    }

    let state = unit_state(&unit);
    let was_active = was_active(&state);
    crate::ui::report!("{}", start_line(&unit, &state, was_active));

    // The unit file may have just been replaced, so the manager always needs
    // a reload before it can act on the new definition.
    run_systemctl(&["daemon-reload"])?;

    if enable_action(args.enable, &unit_enabled_state(&unit)?) {
        // A Quadlet container's unit is generated: `enable` refuses it
        // ("transient or generated") while reporting it as enabled. Enabling
        // what is already enabled is a no-op everywhere else, so ask first.
        run_systemctl(&["enable", &unit])?;
        crate::ui::report!("==> enabled {unit}");
    }

    if args.reload {
        reload_unit(&unit)?;
        crate::ui::report!("==> reloaded {unit}");
    }

    if args.restart {
        match restart_action(args, was_active) {
            Action::Restart => {
                run_systemctl(&["restart", &unit])?;
                crate::ui::report!("==> restarted {unit}");
            }
            Action::Start => {
                run_systemctl(&["start", &unit])?;
                crate::ui::report!("==> started {unit} (forced)");
            }
            Action::Skip => crate::ui::report!(
                "==> {unit} was not running: left it stopped (pass --force-start to start it \
                 anyway)"
            ),
        }
    }

    if args.wait {
        if wait_has_something_to_wait_for(was_active, args.force_start) {
            wait_for_ready(&unit, Duration::from_secs(args.timeout))?;
        } else {
            // The unit was left stopped on purpose; waiting for it to
            // become ready would wait for nothing.
            crate::ui::report!("==> {unit} was left stopped: not waiting for readiness");
        }
    }
    Ok(())
}

/// The first line the verb reports: what the unit was doing before the deploy.
///
/// A failed unit is called out separately, because a deploy that restarts it is
/// the fix rather than a surprise.
fn start_line(unit: &str, state: &str, active: bool) -> String {
    if state == "failed" {
        format!("==> {unit} was failed: the deploy restarts it")
    } else {
        format!("==> {unit} was {}", if active { "active" } else { "not active" })
    }
}

/// Whether `--enable` should run `systemctl enable`.
///
/// `false` when the operator did not ask, and `false` when the unit is already
/// enabled — asking first is what keeps a Quadlet container's generated unit
/// from failing the deploy.
fn enable_action(enable: bool, state: &str) -> bool {
    enable && enable_is_needed(state)
}

/// Whether the unit was doing something before the deploy touched it.
///
/// A restart is only a *restart* when the unit was running: restarting an
/// inactive unit starts it, which is the opposite of what an operator who
/// keeps a unit stopped wants.
fn was_active(state: &str) -> bool {
    !matches!(state, "" | "inactive" | "unknown")
}

/// What `--restart` does, given what the unit was doing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    /// The unit was running: restart it.
    Restart,
    /// The unit was stopped and `--force-start` was given: start it.
    Start,
    /// Leave the unit alone.
    Skip,
}

const fn restart_action(args: &HostServiceArgs, active: bool) -> Action {
    if !args.restart {
        return Action::Skip;
    }
    if active {
        Action::Restart
    } else if args.force_start {
        Action::Start
    } else {
        Action::Skip
    }
}

/// Whether `--wait` has anything to wait for.
///
/// A unit left stopped never becomes ready, so waiting would burn the whole
/// budget and then report a timeout the operator cannot act on.
const fn wait_has_something_to_wait_for(active: bool, force_start: bool) -> bool {
    active || force_start
}

/// Whether `systemctl enable` is worth running.
///
/// A Quadlet container's unit is generated: `enable` refuses it ("transient or
/// generated") while `is-enabled` reports it as enabled.
fn enable_is_needed(state: &str) -> bool {
    !matches!(state, "enabled" | "enabled-runtime" | "generated")
}

#[cfg(test)]
mod tests {
    use super::{
        Action, enable_action, enable_is_needed, restart_action, start_line,
        wait_has_something_to_wait_for, was_active,
    };
    use crate::cli::HostServiceArgs;

    fn args(restart: bool, force_start: bool) -> HostServiceArgs {
        HostServiceArgs {
            unit: "app.service".to_string(),
            enable: false,
            restart,
            reload: false,
            wait: false,
            verify: false,
            force_start,
            timeout: 300,
        }
    }

    #[test]
    fn only_a_running_unit_counts_as_active() {
        for state in ["active", "activating", "reloading", "failed"] {
            assert!(was_active(state), "{state} is running or dying");
        }
        // An unknown unit was never running, and an empty answer means the
        // manager has never heard of it.
        for state in ["", "inactive", "unknown"] {
            assert!(!was_active(state), "{state} is not running");
        }
    }

    #[test]
    fn a_restart_never_starts_a_stopped_unit_without_force() {
        assert_eq!(restart_action(&args(false, true), true), Action::Skip);
        assert_eq!(restart_action(&args(true, false), true), Action::Restart);
        assert_eq!(restart_action(&args(true, false), false), Action::Skip);
        assert_eq!(restart_action(&args(true, true), false), Action::Start);
    }

    #[test]
    fn waiting_for_a_unit_left_stopped_waits_for_nothing() {
        assert!(wait_has_something_to_wait_for(true, false));
        assert!(wait_has_something_to_wait_for(false, true));
        assert!(!wait_has_something_to_wait_for(false, false));
    }

    #[test]
    fn enabling_what_is_already_enabled_is_a_no_op() {
        // `generated` is a Quadlet container's unit: `is-enabled` claims it is
        // enabled while `enable` refuses it, so asking first is what keeps the
        // deploy green.
        for state in ["enabled", "enabled-runtime", "generated"] {
            assert!(!enable_is_needed(state), "{state} needs no `enable`");
        }
        for state in ["disabled", "masked", "indirect", "static"] {
            assert!(enable_is_needed(state), "{state} needs `enable`");
        }
    }

    #[test]
    fn the_report_names_a_failed_unit_separately() {
        assert_eq!(
            start_line("app.service", "failed", true),
            "==> app.service was failed: the deploy restarts it"
        );
        assert_eq!(start_line("app.service", "active", true), "==> app.service was active");
        assert_eq!(start_line("app.service", "inactive", false), "==> app.service was not active");
    }

    #[test]
    fn enabling_runs_only_when_asked_and_only_when_needed() {
        assert!(!enable_action(false, "disabled"), "not asked for");
        assert!(!enable_action(true, "enabled"), "already enabled");
        assert!(enable_action(true, "disabled"));
    }

    #[test]
    fn a_malformed_unit_name_is_rejected_before_anything_runs() {
        // The whole verb is the unit; a name that is not a unit must fail
        // before a `daemon-reload` can poison the manager.
        let mut args = args(true, false);
        args.unit = "not a unit!".to_string();
        assert!(super::service(&args).is_err());
    }
}
