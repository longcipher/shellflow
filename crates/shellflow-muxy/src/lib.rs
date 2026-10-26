//! ShellFlow over Muxy: native-protocol transport.
//!
//! This crate owns everything the Muxy transport needs except the actual
//! rendering of lines (which stays in `bin/shellflow`'s `Ui`, so masking,
//! grouping, and the audit log keep working unchanged):
//!
//! - [`lines`]: the frame-to-line assembler (pure, property-tested).
//! - [`payload`]: the payload file layout and the typed bootstrap line.
//! - [`outcome`]: the muxy exit-reason mapping.
//! - [`policy`]: which steps may use the transport.
//! - [`conn`]: one connection per host (handshake, Home project, keepalive).
//! - [`session`]: one session per step (create, stream, outcome, cleanup).

// The workspace denies `panic`/`unwrap`/`expect` in production code. Unit
// tests need them by construction (`assert!`, fixtures), so the constraint
// is scoped explicitly here rather than left unenforced by simply not
// linting test targets. `pedantic` is likewise scoped to production code:
// it is style guidance, and test fixtures legitimately clone and assert on
// emptiness. The safety-relevant `deny` lints above still apply.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(test, allow(clippy::pedantic, clippy::nursery))]

pub mod conn;
pub mod error;
#[cfg(test)]
mod harness;
pub mod lines;
pub mod outcome;
pub mod payload;
pub mod policy;
pub mod session;

pub use conn::HostConnection;
pub use error::MuxyError;
pub use muxy_protocol::SessionId;
pub use session::{MuxyFailure, StepParams, StepResult, exec_check, run_step, sweep_stale};
