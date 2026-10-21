//! Error types for the runtime helpers: payload rendering and capture parsing.
//!
//! The script parser's own errors live in `shellflow-dsl`, next to the
//! grammar that produces them.

use thiserror::Error;

/// Errors produced while rendering the payload environment header.
///
/// The header is shell source that is streamed to a remote host, so a key that
/// is not a shell identifier must never be emitted: it would break out of the
/// `export` statement and inject shell into the payload.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RenderEnvError {
    /// A key was not a valid shell identifier.
    #[error("environment variable name `{name}` is not a valid shell identifier")]
    InvalidKey {
        /// The offending key.
        name: String,
    },
}

/// Errors produced while parsing the NUL-delimited `@export` capture file
/// written by the runner (design §7.6).
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CaptureError {
    /// A record carried no `=` separator.
    #[error("malformed `@export` capture record: missing `=` separator")]
    MissingSeparator,

    /// A record name or value was not valid UTF-8.
    #[error("malformed `@export` capture record: not valid UTF-8")]
    NotUtf8,

    /// A record named a variable that was not listed in `@export`.
    #[error("malformed `@export` capture record: unexpected variable `{name}`")]
    UnexpectedVar {
        /// The name found in the capture file.
        name: String,
    },
}
