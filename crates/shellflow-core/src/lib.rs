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
pub mod template;

pub use env::{
    CAPTURE_SEPARATOR, MASK, SecretMasker, mask_keyed, mask_line, mask_token,
    parse_capture_records, prepare_masks, render_env,
};
pub use error::{CaptureError, RenderEnvError};
// The deploy-script grammar and the plan model live in `shellflow-dsl`.
// They are re-exported here so that a consumer of the runtime helpers does
// not have to know which of the two crates owns which half of the language.
pub use shellflow_dsl::{
    AssertStep, Assertion, BackupStep, CopyEntry, CopyStep, CredstoreStep, EnvEntry, ExecutionPlan,
    HelperStep, InstallStep, InterpolateError, LocalStep, ParseError, ReloadStep, RemoteStep,
    ResolvedHost, RunState, SecretEntry, ServiceStep, SshSpec, Step, Target, UnitInventoryStep,
    WaitStep, Workdir, interpolate, is_valid_var_name, parse_script, shell_quote_single,
    strip_surrounding_quotes,
};
pub use shellflow_dsl::{Heredoc, HeredocTracker, resolve_hosts};
pub use template::{render_template, template_keys};
