//! The shellflow deploy-script DSL: the grammar and the plan it produces.
//!
//! A deploy script is a Bash script whose comment lines carry directives
//! (`# @server`, `# @remote`, `# @copy`, `@secrets`, …). This crate owns
//! that grammar:
//!
//! * [`parser`] — the single-pass scanner that turns a script into a plan.
//! * [`plan`] — the plan model ([`Step`], [`ExecutionPlan`]) and the target
//!   resolution that turns a step's target into concrete hosts.
//! * [`ssh_spec`] — the ssh destination model the targets resolve to.
//! * [`heredoc`] — the here-document tracker that keeps a `# @` line inside
//!   a here-document body from being read as a directive.
//! * [`text`] — the two text rules the grammar and the runtime share
//!   (shell quoting, surrounding-quote stripping).
//! * [`error`] — the errors the scanner and the interpolator report.
//!
//! The crate has no I/O and no dependencies beyond `thiserror`: it is
//! unit- and property-testable without a network or a shell. The runtime
//! helpers that *do* touch the environment (rendering the payload header,
//! masking secret values) live in `shellflow-core`, which builds on this
//! crate.

// The workspace denies `panic`/`unwrap`/`expect` in production code. Unit
// tests need them by construction (`assert!`, `.expect("...")` on fixtures),
// so the constraint is scoped explicitly here rather than left unenforced by
// simply not linting test targets.
//
// `pedantic` is likewise scoped to production code: it is style guidance, and
// test fixtures legitimately clone, use single-character patterns, and assert
// on emptiness. The safety-relevant `deny` lints above still apply.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(test, allow(clippy::pedantic, clippy::nursery))]

pub mod error;
pub mod heredoc;
pub mod parser;
pub mod plan;
pub mod ssh_spec;
pub mod text;

pub use error::{InterpolateError, ParseError};
pub use heredoc::{Heredoc, HeredocTracker};
pub use parser::parse_script;
pub use plan::{
    AssertStep, Assertion, CopyEntry, CopyStep, EnvEntry, ExecutionPlan, LocalStep, ReloadStep,
    RemoteStep, ResolvedHost, RunState, SecretEntry, Step, Target, WaitStep, interpolate,
    is_valid_var_name, resolve_hosts,
};
pub use ssh_spec::SshSpec;
pub use text::{shell_quote_single, strip_surrounding_quotes};
