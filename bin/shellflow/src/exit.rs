//! The two exit-code protocols this binary speaks.
//!
//! # The CLI protocol
//!
//! `run` and the maintenance subcommands report *the tool's own* outcome
//! (`docs/design.md` §6):
//!
//! | code | meaning                                                        |
//! |------|----------------------------------------------------------------|
//! | 0    | success (skipped blocks and clean dry-runs included)           |
//! | 1    | the playbook is wrong; nothing was attempted                    |
//! | 2    | CLI usage error (clap prints this itself)                       |
//! | 3    | the transport or the setup could not be reached                 |
//! | 4    | a step ran and failed                                           |
//! | 5    | a step exceeded its budget                                      |
//! | 130  | interrupted by SIGINT/SIGTERM                                   |
//!
//! 1 versus 4 is the distinction a CI gate reads: "the playbook is wrong" is
//! not "the deployment failed", and a timeout is neither — retrying a slow box
//! is reasonable, retrying a broken deploy is not.
//!
//! # The target-side helper protocol
//!
//! `shellflow systemd …` and `shellflow host …` run **on the target** and
//! report on a unit or a file, not on the tool. Their codes are a wire
//! contract with the payloads that call them (`remote::reload_command`,
//! `remote::wait_command`, `executor::host`), so they must not be renumbered,
//! and `3` there means "the condition did not hold" while `3` in the CLI
//! protocol means "the transport could not reach the host". The two protocols
//! are deliberately separate types/functions so a literal cannot drift
//! between them.

/// The CLI's own exit code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Code {
    /// The run completed (skips and dry-runs included).
    Success,
    /// The playbook is wrong: a parse error, an unresolved target, a syntax
    /// error found by `--check`.
    Plan,
    /// The transport or the setup could not be reached: a missing tool, ssh
    /// exit 255, a broken payload pipe.
    Transport,
    /// A step ran and failed.
    Script,
    /// A step exceeded `--timeout`/`@timeout`. Kept distinct from [`Code::Script`]
    /// so a retry policy can tell a slow host from a broken deploy.
    Timeout,
    /// Interrupted by SIGINT/SIGTERM.
    Interrupted,
}

impl Code {
    /// The process exit code.
    #[must_use]
    pub(crate) const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Plan => 1,
            Self::Transport => 3,
            Self::Script => 4,
            Self::Timeout => 5,
            Self::Interrupted => 130,
        }
    }
}

/// The codes the target-side helper verbs use, and the codes the payloads
/// interpret. Kept in one module so `host` and `systemd` cannot disagree.
pub(crate) mod helper {
    /// The condition held (or the unit reached the wanted state).
    pub(crate) const OK: i32 = 0;
    /// Usage or internal error on the target.
    pub(crate) const USAGE: i32 = 1;
    /// The operation ran but the condition did not hold (the unit is not
    /// active, the digest differs, the file leaks a secret).
    pub(crate) const FAILED: i32 = 3;
    /// The budget expired before the condition held.
    pub(crate) const TIMEOUT: i32 = 4;
    /// The unit does not exist.
    pub(crate) const NOT_FOUND: i32 = 5;
}
