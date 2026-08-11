//! Error type for the secrets crate.

use thiserror::Error;

/// Errors produced by identity, encryption, and env parsing operations.
#[derive(Debug, Error)]
pub enum SecretsError {
    /// The identity file does not exist or `SHELLFLOW_AGE_IDENTITY` is unset.
    #[error("age identity not found: {0} (generate one with `shellflow keys generate`)")]
    MissingIdentity(
        /// The identity path that was looked up.
        String,
    ),

    /// The identity file could not be read.
    #[error("failed to read identity file {path}: {source}")]
    ReadIdentity {
        /// The identity file path.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The identity file did not parse as an age identity.
    #[error("failed to parse identity from {path}: {reason}")]
    InvalidIdentity {
        /// The identity file path.
        path: String,
        /// Why the identity is invalid.
        reason: String,
    },

    /// The identity file could not be written.
    #[error("failed to write identity file {path}: {source}")]
    WriteIdentity {
        /// The identity file path.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The encrypted file could not be read.
    #[error("failed to read input: {source}")]
    ReadInput {
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Encryption failed (invalid recipients, incompatible recipients, ...).
    #[error("encryption failed: {0}")]
    Encrypt(
        /// Human-readable reason.
        String,
    ),

    /// Decryption failed (wrong identity, corrupted file, ...).
    #[error("decryption failed: {0}")]
    Decrypt(
        /// Human-readable reason.
        String,
    ),

    /// No recipients were supplied for encryption.
    #[error("no recipients given for encryption (use `-r age1...`)")]
    MissingRecipients,

    /// A recipient string was not a valid `age1...` key.
    #[error("invalid recipient `{recipient}`: {reason}")]
    InvalidRecipient {
        /// The offending recipient string.
        recipient: String,
        /// Why the recipient is invalid.
        reason: String,
    },

    /// An env line did not match `KEY=VALUE`.
    #[error("line {line}: malformed env entry: {reason}")]
    MalformedEnv {
        /// 1-based line number in the env file.
        line: usize,
        /// Why the line is malformed.
        reason: String,
    },

    /// The input was not a valid age file (bad header, bad base64, ...).
    #[error("invalid age file: {0}")]
    InvalidAgeFile(
        /// Human-readable reason.
        String,
    ),

    /// The configured `$EDITOR` could not be spawned.
    #[error("failed to launch editor `{0}`")]
    Editor(
        /// The editor command string.
        String,
    ),
}
