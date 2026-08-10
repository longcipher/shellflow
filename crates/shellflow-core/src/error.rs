//! Error types for script parsing and path interpolation.

use thiserror::Error;

/// Errors produced while parsing a deploy script into an [`ExecutionPlan`].
#[derive(Debug, Error)]
pub enum ParseError {
    /// An ssh spec was malformed.
    #[error("line {line}: invalid ssh spec `{spec}`: {reason}")]
    InvalidSshSpec {
        /// 1-based line number in the script.
        line: usize,
        /// The offending spec string.
        spec: String,
        /// Human-readable reason.
        reason: String,
    },

    /// A server alias was defined twice.
    #[error("line {line}: server `{name}` is already defined")]
    DuplicateServer {
        /// 1-based line number in the script.
        line: usize,
        /// The duplicated server alias.
        name: String,
    },

    /// A group referenced an unknown server alias.
    #[error("line {line}: group `{group}` references unknown server `{server}`")]
    UnknownGroupMember {
        /// 1-based line number in the script.
        line: usize,
        /// The group name.
        group: String,
        /// The missing server alias.
        server: String,
    },

    /// A directive was recognized but had an invalid payload.
    #[error("line {line}: invalid `@{directive}` directive: {reason}")]
    InvalidDirective {
        /// 1-based line number in the script.
        line: usize,
        /// The directive keyword (without the leading `@`).
        directive: String,
        /// Human-readable reason.
        reason: String,
    },

    /// An unknown `# @` directive was found.
    #[error("line {line}: unknown directive `@{directive}`")]
    UnknownDirective {
        /// 1-based line number in the script.
        line: usize,
        /// The unknown directive keyword.
        directive: String,
    },

    /// `@export` was used where no preceding local block exists.
    #[error("line {line}: `@export` must follow a local block")]
    ExportNotAfterLocal {
        /// 1-based line number in the script.
        line: usize,
    },

    /// `--target` filtered out every host for a step.
    #[error("`--target` matches no host for `{target}`")]
    EmptyTarget {
        /// The target text that resolved to zero hosts after restriction.
        target: String,
    },
}

/// Errors produced while interpolating `$VAR` / `${VAR}` references in copy
/// paths against captured run state.
#[derive(Debug, Error)]
pub enum InterpolateError {
    /// A referenced variable is not present in the run state.
    #[error("unresolved variable `{var}` in `{template}`")]
    Unresolved {
        /// The missing variable name.
        var: String,
        /// The full template that failed to interpolate.
        template: String,
    },
}
