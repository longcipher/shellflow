//! `age` (X25519) secrets: identity handling, file encryption/decryption, and
//! `KEY=VALUE` env parsing for encrypted configuration files.
//!
//! This crate embeds the Rust `age` crate (the implementation that the `rage`
//! CLI wraps), so encrypted files are interoperable with `rage`/`age`.
//! Targets never need this crate or any crypto tooling: decryption happens on
//! the controller only.

pub mod crypto;
pub mod env;
pub mod error;
pub mod identity;

pub use error::SecretsError;
