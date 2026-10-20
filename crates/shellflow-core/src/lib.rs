//! Pure parsing and planning for `shellflow` deploy scripts.
//!
//! This crate has no I/O: it turns a Bash script with `# @` comment
//! directives into an [`ExecutionPlan`], resolves targets to concrete hosts,
//! and renders shell-safe payload helpers. Everything here is unit- and
//! property-testable without a network or a shell.

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

pub mod env;
pub mod error;
pub mod heredoc;
pub mod parser;
pub mod plan;
pub mod ssh_spec;
pub mod template;

pub use env::{
    CAPTURE_SEPARATOR, MASK, SecretMasker, mask_keyed, mask_line, mask_token,
    parse_capture_records, prepare_masks, render_env, shell_quote_single, strip_surrounding_quotes,
};
pub use error::{CaptureError, InterpolateError, ParseError, RenderEnvError};
pub use heredoc::{Heredoc, HeredocTracker};
pub use parser::parse_script;
pub use plan::{
    CopyStep, EnvEntry, ExecutionPlan, LocalStep, ReloadStep, RemoteStep, ResolvedHost,
    RunState, SecretEntry, Step, Target, WaitStep, interpolate, is_valid_var_name, resolve_hosts,
};
pub use ssh_spec::SshSpec;
pub use template::{render_template, template_keys};
