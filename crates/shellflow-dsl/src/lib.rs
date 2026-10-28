//! The shellflow deploy-script DSL: the grammar and the plan it produces.
//!
//! A deploy script is a Bash script whose comment lines carry directives
//! (`# @server`, `# @remote`, `# @copy`, `@secrets`, …). This crate owns
//! that grammar:
//!
//! * [`parser`] — the single-pass scanner that turns a script into a plan.
//! * [`plan`] — the plan model ([`Step`], [`ExecutionPlan`]) and the target resolution that turns a
//!   step's target into concrete hosts.
//! * [`ssh_spec`] — the ssh destination model the targets resolve to.
//! * [`heredoc`] — the here-document tracker that keeps a `# @` line inside a here-document body
//!   from being read as a directive.
//! * [`error`] — the errors the scanner and the interpolator report.
//!
//! The shell-text rules (shell quoting, surrounding-quote stripping, the
//! shell-identifier rule) live in `shellflow-text`, the zero-dependency leaf
//! the DSL, the runtime, and the secrets crate all share; they are
//! re-exported here so the public API is unchanged.
//!
//! The crate has no I/O: it is unit- and property-testable without a network
//! or a shell. The runtime helpers that *do* touch the environment (rendering
//! the payload header, masking secret values) live in `shellflow-core`, which
//! builds on this crate.

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

pub use error::{InterpolateError, ParseError};
pub use heredoc::{Heredoc, HeredocTracker};
pub use parser::parse_script;
pub use plan::{
    ActiveState, AssertStep, Assertion, BackupStep, BuildStep, CopyEntry, CopyStep, CredstoreStep,
    EnabledState, EnvEntry, ExecutionPlan, ExportVar, HelperStep, ImageStep, InstallStep,
    LocalStep, ReleaseStep, ReloadStep, RemoteStep, ResolvedHost, RunState, SecretEntry,
    ServiceStep, Step, Target, ToolchainStep, UnitInventoryStep, WaitStep, Workdir, interpolate,
    resolve_hosts,
};
pub use shellflow_text::{
    is_valid_unit_name, is_valid_var_name, normalize_unit, shell_quote_single,
    strip_surrounding_quotes,
};
pub use ssh_spec::SshSpec;
