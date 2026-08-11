//! Pure parsing and planning for `shellflow` deploy scripts.
//!
//! This crate has no I/O: it turns a Bash script with `# @` comment
//! directives into an [`ExecutionPlan`], resolves targets to concrete hosts,
//! and renders shell-safe payload helpers. Everything here is unit- and
//! property-testable without a network or a shell.

pub mod env;
pub mod error;
pub mod parser;
pub mod plan;
pub mod ssh_spec;

pub use env::{MASK, mask_line, render_env, shell_quote_single};
pub use error::{InterpolateError, ParseError};
pub use parser::parse_script;
pub use plan::{
    CopyStep, EnvEntry, ExecutionPlan, LocalStep, RemoteStep, ResolvedHost, RunState, SecretEntry,
    Step, Target, interpolate, resolve_hosts,
};
pub use ssh_spec::SshSpec;
