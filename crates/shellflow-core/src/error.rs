//! Error types for the runtime helpers: payload rendering, capture parsing,
//! and credential-template rendering.
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

/// A template references a `${KEY}` placeholder the value map does not
/// provide.
///
/// Rendering is fail closed: nothing is rendered, so a service never starts
/// with a half-substituted config.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("missing template key(s): {}", Self::join(.missing))]
pub struct MissingKeysError {
    /// Every missing key with the byte offset of its first `${KEY}`
    /// occurrence, sorted by key.
    pub missing: Vec<MissingKey>,
}

impl MissingKeysError {
    fn join(missing: &[MissingKey]) -> String {
        missing.iter().map(|key| key.key.as_str()).collect::<Vec<_>>().join(", ")
    }
}

/// One missing `${KEY}` placeholder.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("`{key}` (byte {offset})")]
pub struct MissingKey {
    /// The referenced key.
    pub key: String,
    /// Byte offset of the `$` that opens the first `${KEY}` occurrence.
    pub offset: usize,
}

#[cfg(test)]
mod tests {
    use super::{MissingKey, MissingKeysError};

    fn keys(names: &[&str]) -> Vec<MissingKey> {
        names
            .iter()
            .enumerate()
            .map(|(index, name)| MissingKey { key: (*name).to_string(), offset: index })
            .collect()
    }

    #[test]
    fn the_missing_keys_error_names_every_key() {
        // The message is the operator's only pointer at the placeholders the
        // value map did not provide; dropping the list would name nothing.
        let message = MissingKeysError { missing: keys(&["DB_PASSWORD", "API_TOKEN"]) }.to_string();
        assert!(message.contains("DB_PASSWORD"), "{message}");
        assert!(message.contains("API_TOKEN"), "{message}");
        assert!(message.contains("missing template key(s)"), "{message}");
    }

    #[test]
    fn several_keys_are_joined_with_a_comma() {
        let message = MissingKeysError { missing: keys(&["A", "B"]) }.to_string();
        assert!(message.ends_with("A, B"), "the keys must be joined, not concatenated: {message}");
    }

    #[test]
    fn one_missing_key_reports_its_offset() {
        let message = keys(&["ONLY"])[0].to_string();
        assert!(message.contains("`ONLY`"), "{message}");
        assert!(message.contains("byte 0"), "{message}");
    }
}
