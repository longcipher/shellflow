//! `age` (X25519) secrets: identity handling, file encryption/decryption, and
//! `KEY=VALUE` env parsing for encrypted configuration files.
//!
//! This crate embeds the Rust `age` crate (the implementation that the `rage`
//! CLI wraps), so encrypted files are interoperable with `rage`/`age`.
//! Targets never need this crate or any crypto tooling: decryption happens on
//! the controller only.

// See `shellflow-core`: the workspace denies `panic`/`unwrap`/`expect` in
// production code; test modules need them and opt out explicitly. `pedantic`
// is scoped the same way — style guidance has no value in a test fixture.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(test, allow(clippy::pedantic, clippy::nursery))]

pub mod crypto;
pub mod env;
pub mod error;
pub mod fsx;
pub mod identity;
pub mod recipients;

pub use age::x25519::{Identity, Recipient};
pub use error::SecretsError;
