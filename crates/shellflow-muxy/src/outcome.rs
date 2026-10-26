//! Outcome mapping: muxy `ExitReason` to shellflow step outcomes.
//!
//! The exit-code contract is unchanged: `0` ok, `42` skipped (`@only_if`),
//! other codes are script failures, transport failures stay distinguishable.

/// The exit code a folded guard uses to say "skip this block".
pub const GUARD_SKIP_EXIT: i32 = 42;

/// What a muxy step produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MuxyOutcome {
    /// Completed successfully.
    Ok,
    /// Skipped because `@only_if` failed.
    Skipped,
    /// The command exited non-zero or was signalled.
    FailedScript {
        /// Human-readable cause, already naming the session.
        message: String,
        /// The exit code, when the session reported one (a signalled step has
        /// none). Step classes with their own exit-code vocabulary — a wait,
        /// a reload — use it to name the outcome.
        exit: Option<i32>,
    },
    /// The transport/setup failed.
    FailedTransport {
        /// Human-readable cause.
        message: String,
    },
    /// The step exceeded its timeout.
    TimedOut,
    /// The run was interrupted before the host finished.
    Cancelled,
}

/// Map a muxy exit reason to a step outcome.
///
/// The `42` channel is only honoured when the payload actually folded a
/// guard, mirroring the current `has_guard` rule in `executor/remote.rs`: a
/// block that exits 42 for its own reason must not be mistaken for a skip.
#[must_use]
pub fn map_exit_reason(reason: &muxy_protocol::ExitReason, has_guard: bool) -> MuxyOutcome {
    use muxy_protocol::ExitReason as R;
    match *reason {
        R::Exited(0) => MuxyOutcome::Ok,
        R::Exited(GUARD_SKIP_EXIT) if has_guard => MuxyOutcome::Skipped,
        R::Exited(code) => MuxyOutcome::FailedScript {
            message: format!("the block failed (exit {code})"),
            exit: Some(code),
        },
        R::Signaled(signum) => MuxyOutcome::FailedScript {
            message: format!("the block was signalled ({signum})"),
            exit: None,
        },
        R::Ended => MuxyOutcome::Cancelled,
        R::ServerStopped => {
            MuxyOutcome::FailedTransport { message: "the muxy server stopped mid-step".to_string() }
        }
        R::Unrecognized(n) => MuxyOutcome::FailedTransport {
            message: format!("the session ended with an unrecognized reason ({n})"),
        },
    }
}

#[cfg(test)]
mod tests {

    use muxy_protocol::ExitReason as R;

    use super::*;

    #[test]
    fn zero_is_ok() {
        assert_eq!(map_exit_reason(&R::Exited(0), false), MuxyOutcome::Ok);
    }

    #[test]
    fn forty_two_is_a_skip_only_with_a_guard() {
        assert_eq!(map_exit_reason(&R::Exited(42), true), MuxyOutcome::Skipped);
        assert!(matches!(map_exit_reason(&R::Exited(42), false), MuxyOutcome::FailedScript { .. }));
    }

    #[test]
    fn nonzero_exits_are_script_failures() {
        assert!(matches!(map_exit_reason(&R::Exited(7), true), MuxyOutcome::FailedScript { .. }));
        assert!(matches!(
            map_exit_reason(&R::Signaled(15), false),
            MuxyOutcome::FailedScript { .. }
        ));
    }

    #[test]
    fn ended_without_a_local_end_is_a_cancel() {
        assert_eq!(map_exit_reason(&R::Ended, false), MuxyOutcome::Cancelled);
    }

    #[test]
    fn server_stopped_is_a_transport_failure() {
        assert!(matches!(
            map_exit_reason(&R::ServerStopped, false),
            MuxyOutcome::FailedTransport { .. }
        ));
    }
}
