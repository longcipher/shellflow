//! The executor's error taxonomy and run outcome.
//!
//! These live in their own module because they are *crate-level* types: the
//! copy, host, assert and local executors all classify into [`RunError`], and
//! `main` maps it to the process exit code. They used to be defined inside
//! `remote.rs`, which made the leaf module the owner of the crate taxonomy and
//! forced every sibling to import it from there.

use crate::exit::Code;

/// The error classification mapped to the CLI exit code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    /// A configuration/plan-build failure, e.g. secrets resolution.
    Config,
    /// A plan error: a bad script, an unresolved `@export` variable, an
    /// unresolvable target, or a syntax error found by a dry-run check.
    ///
    /// Design §6 assigns these to exit 1, distinct from a script that ran and
    /// failed (exit 4): CI can tell "the playbook is wrong" from "the
    /// deployment failed".
    Plan,
    /// A transport/setup failure (ssh exit 255, a broken payload pipe).
    Transport,
    /// A script execution failure (a step exited non-zero).
    Script,
    /// A step exceeded `--timeout`/`@timeout`.
    ///
    /// Distinct from [`Self::Script`] because the operator's response differs:
    /// a slow host is a retry, a failed deploy is a rollback.
    Timeout,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config => write!(f, "configuration failure"),
            Self::Plan => write!(f, "plan error"),
            Self::Transport => write!(f, "transport/setup failure"),
            Self::Script => write!(f, "script execution failure"),
            Self::Timeout => write!(f, "step timed out"),
        }
    }
}

impl RunError {
    /// The CLI exit code for this failure (design §6).
    #[must_use]
    pub(crate) const fn code(self) -> Code {
        match self {
            Self::Config | Self::Plan => Code::Plan,
            Self::Transport => Code::Transport,
            Self::Script => Code::Script,
            Self::Timeout => Code::Timeout,
        }
    }

    /// The process exit code for this failure.
    #[must_use]
    pub(crate) const fn into_exit_code(self) -> i32 {
        self.code().code()
    }
}

/// The overall run outcome.
#[derive(Debug)]
pub(crate) enum RunOutcome {
    /// Everything succeeded (or was skipped).
    Success,
    /// At least one step failed.
    Failed(RunError),
    /// Interrupted by a signal; `total` is the step count for reporting.
    ///
    /// The audit-log handle is *not* carried here: the caller owns the UI (and
    /// therefore the file), so the interrupt summary is recorded in the same
    /// trail as every other line of the run — including when the teardown did
    /// not finish inside the grace period.
    ///
    /// `torn_down` reports whether every in-flight process group was reaped
    /// before returning. When the grace period expires the executor is aborted
    /// and the run must not claim the groups are gone.
    Interrupted { total: usize, torn_down: bool },
}
