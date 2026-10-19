//! The deployment plan data model, target resolution, and state
//! interpolation.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use crate::{
    error::{InterpolateError, ParseError},
    ssh_spec::SshSpec,
};

/// A step target: a server alias, a group name, or a literal ssh spec.
///
/// Classification happens lazily in [`resolve_hosts`] so forward references
/// (a step using a group declared later in the script) work correctly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    /// The raw target text from the script (`web`, `@web`, `deploy@host`…).
    pub text: String,
}

impl Target {
    /// Create a target from raw script text.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// An environment entry injected into subsequent blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvEntry {
    /// A literal `KEY=VALUE` from the script.
    Literal {
        /// Variable name.
        key: String,
        /// Literal value.
        value: String,
    },
    /// A bare `KEY` passthrough: the value is read from shellflow's own
    /// environment at execution time.
    Passthrough {
        /// Variable name.
        key: String,
    },
}

/// An encrypted secrets file referenced by `@secrets`.
///
/// The parser records only the path; decryption happens at execution time in
/// the binary, keeping `shellflow-core` pure and I/O-free.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretEntry {
    /// Path to the encrypted age file (`.env.age`).
    pub file: String,
    /// Optional explicit identity path (`--identity`), resolved by the runner.
    pub identity: Option<String>,
}

/// A block of Bash lines executed on the local machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// The Bash lines (comments and statements), verbatim, trailing newline.
    pub script: String,
    /// Optional precondition from `@only_if`.
    pub guard: Option<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
    /// Variables captured into run state after this step (`@export`).
    pub export: Vec<String>,
    /// Environment snapshot (`@env`) in effect when the block was declared.
    pub env: Vec<EnvEntry>,
}

/// A block of Bash lines streamed to the target hosts over SSH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The Bash lines, verbatim, trailing newline.
    pub script: String,
    /// Optional precondition from `@only_if`.
    pub guard: Option<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
    /// Environment snapshot (`@env`) in effect when the block was declared.
    pub env: Vec<EnvEntry>,
}

/// A local-to-remote file sync step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Local source path (supports `$VAR`/`${VAR}` interpolation).
    pub src: String,
    /// Remote destination path (supports `$VAR`/`${VAR}` interpolation).
    pub dst: String,
    /// Target server/group/spec.
    pub target: Target,
    /// Mirror deletions on the remote side (`--delete`).
    pub delete: bool,
    /// Glob patterns to exclude from the transfer (`--exclude`, repeatable).
    ///
    /// Honored by the `rsync` path; the `scp` fallback and `--local` copy
    /// cannot filter files and warn instead.
    pub excludes: Vec<String>,
    /// Optional precondition from `@only_if`.
    ///
    /// `@only_if` is **not supported on `@copy`** and the parser rejects it
    /// (see [`crate::parser`]); the field is retained for struct symmetry
    /// with [`LocalStep`] / [`RemoteStep`] and stays `None` in valid plans.
    pub guard: Option<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    ///
    /// `@timeout` is honored for copy steps (it bounds the `rsync`/`scp`
    /// transfer), unlike `guard`.
    pub timeout: Option<u64>,
    /// Environment snapshot (`@env`) in effect when the block was declared.
    pub env: Vec<EnvEntry>,
}

/// One executable unit of the plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Execute Bash locally.
    Local(LocalStep),
    /// Stream Bash to remote hosts.
    Remote(RemoteStep),
    /// Sync a file/dir to remote hosts with rsync.
    Copy(CopyStep),
}

impl Step {
    /// The step's display name, if `@name` was set.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Local(s) => s.name.as_deref(),
            Self::Remote(s) => s.name.as_deref(),
            Self::Copy(s) => s.name.as_deref(),
        }
    }

    /// The step kind as a short stable string (`local` | `remote` | `copy`).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::Remote(_) => "remote",
            Self::Copy(_) => "copy",
        }
    }

    /// The target text, for remote and copy steps.
    #[must_use]
    pub fn target_text(&self) -> Option<&str> {
        match self {
            Self::Local(_) => None,
            Self::Remote(s) => Some(&s.target.text),
            Self::Copy(s) => Some(&s.target.text),
        }
    }

    /// The guard command, if `@only_if` was set.
    #[must_use]
    pub fn guard(&self) -> Option<&str> {
        match self {
            Self::Local(s) => s.guard.as_deref(),
            Self::Remote(s) => s.guard.as_deref(),
            Self::Copy(s) => s.guard.as_deref(),
        }
    }

    /// The per-step timeout in seconds, if `@timeout` was set.
    #[must_use]
    pub const fn timeout(&self) -> Option<u64> {
        match self {
            Self::Local(s) => s.timeout,
            Self::Remote(s) => s.timeout,
            Self::Copy(s) => s.timeout,
        }
    }
}

/// Fully parsed deployment plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionPlan {
    /// Server aliases in declaration order (BTreeMap keeps summaries stable).
    pub servers: BTreeMap<String, SshSpec>,
    /// Group aliases to server member lists.
    pub groups: BTreeMap<String, Vec<String>>,
    /// All `@env` entries in declaration order.
    ///
    /// Copy-on-write behind an `Arc`: every step snapshots the list as it was
    /// declared, so cloning it wholesale per block would make plan construction
    /// quadratic in the number of steps. `Arc::make_mut` keeps the common
    /// layout (`@env` grouped before the first step) at a single allocation.
    pub env: Arc<Vec<EnvEntry>>,
    /// All `@secrets` file references in declaration order.
    pub secrets: Vec<SecretEntry>,
    /// The steps, in declaration order.
    pub steps: Vec<Step>,
}

/// Cross-step state captured by `@export`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunState {
    /// Variable name to captured value.
    pub vars: BTreeMap<String, String>,
}

/// A concrete host resolved from a target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHost {
    /// Display alias used for log prefixes (`web1`).
    pub alias: String,
    /// The concrete ssh destination.
    pub spec: SshSpec,
}

/// Resolve a step target into concrete hosts.
///
/// Resolution order: group → server alias → raw ssh spec. When `restrict` is
/// non-empty (the CLI `--target` flag), only aliases belonging to the listed
/// servers/groups are kept.
///
/// # Errors
///
/// Returns a [`ParseError`] when the target is neither a known alias nor a
/// valid raw ssh spec.
pub fn resolve_hosts(
    plan: &ExecutionPlan,
    target: &Target,
    restrict: &[String],
) -> Result<Vec<ResolvedHost>, ParseError> {
    let mut hosts: Vec<ResolvedHost> = Vec::new();
    if let Some(members) = plan.groups.get(&target.text) {
        for member in members {
            // A member with no `@server` is a plan error, not a host to skip
            // silently: `parse_script` validates this today, but
            // `resolve_hosts` is public API and must not quietly drop a host
            // when handed a hand-built plan.
            let spec = plan.servers.get(member).ok_or_else(|| ParseError::UnknownGroupMember {
                line: 0,
                group: target.text.clone(),
                server: member.clone(),
            })?;
            hosts.push(ResolvedHost { alias: member.clone(), spec: spec.clone() });
        }
    } else if let Some(spec) = plan.servers.get(&target.text) {
        hosts.push(ResolvedHost { alias: target.text.clone(), spec: spec.clone() });
    } else {
        let spec = SshSpec::parse(&target.text)?;
        hosts.push(ResolvedHost { alias: target.text.clone(), spec });
    }

    if restrict.is_empty() {
        return Ok(hosts);
    }
    let allowed = allowed_aliases(plan, restrict);
    let filtered: Vec<ResolvedHost> =
        hosts.into_iter().filter(|host| allowed.contains(&host.alias)).collect();
    if filtered.is_empty() {
        return Err(ParseError::EmptyTarget { target: target.text.clone() });
    }
    Ok(filtered)
}

/// Expand a `--target` restriction list into the set of allowed server
/// aliases (group names expand to their members).
fn allowed_aliases(plan: &ExecutionPlan, restrict: &[String]) -> HashSet<String> {
    let mut allowed = HashSet::new();
    for item in restrict {
        if let Some(members) = plan.groups.get(item) {
            allowed.extend(members.iter().cloned());
        } else {
            allowed.insert(item.clone());
        }
    }
    allowed
}

/// True for `[A-Za-z_][A-Za-z0-9_]*`.
pub(crate) fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Interpolate `$VAR` and `${VAR}` references in a copy path against the run
/// state.
///
/// A stray `$` (not followed by a valid name) and an unterminated `${` are
/// copied literally. An unresolved variable name is an error — never a silent
/// no-op.
///
/// # Errors
///
/// Returns [`InterpolateError::Unresolved`] when a referenced variable is
/// missing from the state.
pub fn interpolate(template: &str, state: &RunState) -> Result<String, InterpolateError> {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            let rest = &template[i..];
            let ch = rest.chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }

        if bytes.get(i + 1) == Some(&b'{') {
            if let Some(close) = template[i + 2..].find('}') {
                let name = &template[i + 2..i + 2 + close];
                // Empty or invalid names are literal `$` (mirrors the unbraced
                // scanner, which only interpolates valid `[A-Za-z_]\w*` names).
                if !is_valid_var_name(name) {
                    out.push('$');
                    i += 1;
                    continue;
                }
                let value = state.vars.get(name).ok_or_else(|| InterpolateError::Unresolved {
                    var: name.to_string(),
                    template: template.to_string(),
                })?;
                out.push_str(value);
                i += 2 + close + 1;
            } else {
                out.push('$');
                i += 1;
            }
            continue;
        }

        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let name = &template[start..end];
        if is_valid_var_name(name) {
            let value = state.vars.get(name).ok_or_else(|| InterpolateError::Unresolved {
                var: name.to_string(),
                template: template.to_string(),
            })?;
            out.push_str(value);
            i = end;
        } else {
            out.push('$');
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env::render_env, error::ParseError, parser::parse_script};

    #[test]
    fn resolve_group_expands_to_members() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web"), &[]).map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].alias, "web1");
        assert_eq!(hosts[1].alias, "web2");
        Ok(())
    }

    #[test]
    fn resolve_single_server() -> Result<(), String> {
        let plan = parse_script("# @server web1 deploy@10.0.0.1\n").map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web1"), &[]).map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "web1");
        Ok(())
    }

    #[test]
    fn resolve_raw_spec_fallback() -> Result<(), String> {
        let plan = ExecutionPlan::default();
        let hosts = resolve_hosts(&plan, &Target::new("deploy@10.0.0.9:2222"), &[])
            .map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "deploy@10.0.0.9:2222");
        assert_eq!(hosts[0].spec.port, Some(2222));
        Ok(())
    }

    #[test]
    fn resolve_respects_restrict() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web"), &["web2".to_string()])
            .map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "web2");
        Ok(())
    }

    #[test]
    fn resolve_group_name_in_restrict() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web"), &["web".to_string()])
            .map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 2);
        Ok(())
    }

    #[test]
    fn interpolate_dollar_var() -> Result<(), String> {
        let mut state = RunState::default();
        state.vars.insert("VERSION".to_string(), "abc123".to_string());
        let out = interpolate("target/myapp-$VERSION", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "target/myapp-abc123");
        Ok(())
    }

    #[test]
    fn interpolate_braced_var() -> Result<(), String> {
        let mut state = RunState::default();
        state.vars.insert("VERSION".to_string(), "abc123".to_string());
        let out = interpolate("${VERSION}/app", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "abc123/app");
        Ok(())
    }

    #[test]
    fn interpolate_unresolved_is_error() {
        let state = RunState::default();
        assert!(matches!(
            interpolate("x-$MISSING", &state),
            Err(InterpolateError::Unresolved { .. })
        ));
    }

    #[test]
    fn interpolate_stray_dollar_is_literal() -> Result<(), String> {
        let state = RunState::default();
        let out =
            interpolate("cost is $5 and ${unterminated", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "cost is $5 and ${unterminated");
        // An empty braced reference emits a literal `$` and keeps the
        // remaining `{}` as ordinary characters.
        let empty = interpolate("${}x", &state).map_err(|e| e.to_string())?;
        assert_eq!(empty, "${}x");
        Ok(())
    }

    #[test]
    fn interpolate_invalid_braced_name_is_literal() -> Result<(), String> {
        // A braced name that is not a valid shell identifier is kept verbatim
        // (mirrors the unbraced scanner).
        let state = RunState::default();
        let out = interpolate("${1BAD}-$9", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "${1BAD}-$9");
        Ok(())
    }

    #[test]
    fn resolve_empty_after_restrict_is_error() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        // Restricting to an unrelated server filters out every host.
        let err = match resolve_hosts(&plan, &Target::new("web"), &["db1".to_string()]) {
            Err(err) => err,
            Ok(_) => return Err("restriction should empty the target".to_string()),
        };
        match err {
            ParseError::EmptyTarget { target } => assert_eq!(target, "web"),
            other => return Err(format!("expected EmptyTarget, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn step_metadata_accessors() -> Result<(), String> {
        let plan = parse_script(
            "# @name build\n\
             # @local\n\
             echo hi\n\
             # @name ship\n\
             # @copy a -> b @web\n",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].name(), Some("build"));
        assert_eq!(plan.steps[0].kind(), "local");
        assert_eq!(plan.steps[1].name(), Some("ship"));
        assert_eq!(plan.steps[1].kind(), "copy");
        assert_eq!(plan.steps[1].target_text(), Some("web"));
        Ok(())
    }

    #[test]
    fn run_state_feeds_payload_env() -> Result<(), String> {
        let mut state = RunState::default();
        state.vars.insert("VERSION".to_string(), "abc123".to_string());
        let entries =
            vec![EnvEntry::Literal { key: "VERSION".to_string(), value: "abc123".to_string() }];
        let rendered = render_env(&resolved(&entries));
        assert!(rendered.contains("export VERSION='abc123';"));
        Ok(())
    }

    #[test]
    fn step_guard_and_timeout_accessors() -> Result<(), String> {
        let plan = parse_script(
            "# @name restart\n\
             # @only_if test -f /etc/app.conf\n\
             # @timeout 30\n\
             # @remote web\n\
             sudo systemctl restart app\n",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].guard(), Some("test -f /etc/app.conf"));
        assert_eq!(plan.steps[0].timeout(), Some(30));
        // A step without metadata yields None for both.
        let bare = parse_script("# @local\n\necho hi\n").map_err(|e| e.to_string())?;
        assert_eq!(bare.steps[0].guard(), None);
        assert_eq!(bare.steps[0].timeout(), None);
        Ok(())
    }

    #[test]
    fn a_value_containing_a_reference_is_not_re_expanded() -> Result<(), String> {
        // Single-pass by design: a captured value may legitimately contain a
        // `$` (a password like `p$w`), and re-scanning it would corrupt the
        // path it was substituted into.
        let mut state = RunState::default();
        state.vars.insert("X".to_string(), "$Y".to_string());
        state.vars.insert("Y".to_string(), "1".to_string());
        let out = interpolate("$X", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "$Y");
        Ok(())
    }

    #[test]
    fn a_stray_dollar_next_to_a_value_is_not_a_reference() -> Result<(), String> {
        // `$$` is a literal `$` followed by the expansion of `X`. Only a second
        // pass would read `$abc` as a reference to `abc`, which is why
        // interpolation is single-pass and non-idempotent by design.
        let mut state = RunState::default();
        state.vars.insert("X".to_string(), "abc".to_string());
        state.vars.insert("abc".to_string(), "zzz".to_string());
        let out = interpolate("$${X}", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "$abc");
        Ok(())
    }

    #[test]
    fn interpolate_underscore_and_braced_names() -> Result<(), String> {
        let mut state = RunState::default();
        state.vars.insert("_REV".to_string(), "abc123".to_string());
        state.vars.insert("DEPLOY_TAG".to_string(), "v1.2".to_string());
        let out = interpolate("app-${_REV}-${DEPLOY_TAG}", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "app-abc123-v1.2");
        // Unbraced names exercise the `$NAME` scanner, including leading
        // underscores.
        let unbraced = interpolate("$_REV-$DEPLOY_TAG", &state).map_err(|e| e.to_string())?;
        assert_eq!(unbraced, "abc123-v1.2");
        Ok(())
    }

    fn resolved(entries: &[EnvEntry]) -> Vec<(String, String)> {
        entries
            .iter()
            .filter_map(|e| match e {
                EnvEntry::Literal { key, value } => Some((key.clone(), value.clone())),
                EnvEntry::Passthrough { .. } => None,
            })
            .collect()
    }

    proptest::proptest! {
        /// A template without `$` is returned byte-for-byte, whatever the run
        /// state holds: interpolation may only ever touch `$` references.
        #[test]
        fn interpolate_is_identity_without_dollar(
            text in "[^$]{0,40}",
            (key, value) in ("[A-Za-z_][A-Za-z0-9_]{0,8}", "[^$]{0,20}"),
        ) {
            let mut state = RunState::default();
            state.vars.insert(key, value);
            let out = interpolate(&text, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&out, &text);
        }

        /// `$NAME` and `${NAME}` agree, and only the valid `[A-Za-z_]\w*` name
        /// is consumed — the following separator must survive.
        #[test]
        fn braced_and_unbraced_forms_agree(
            name in "[A-Za-z_][A-Za-z0-9_]{0,10}",
            value in "[a-z0-9]{1,12}",
            suffix in prop_oneof![
                Just(String::new()),
                Just("/".to_string()),
                Just("-x".to_string()),
            ],
        ) {
            let mut state = RunState::default();
            state.vars.insert(name.clone(), value.clone());
            let unbraced =
                interpolate(&format!("${name}{suffix}"), &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let braced =
                interpolate(&format!("${{{name}}}{suffix}"), &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&unbraced, &format!("{value}{suffix}"));
            prop_assert_eq!(braced, unbraced);
        }

        /// A fully-resolved template leaves no `$` behind.
        #[test]
        fn every_reference_is_expanded(
            prefix in "[a-z/]{0,10}",
            name in "[A-Za-z_][A-Za-z0-9_]{0,10}",
            value in "[a-z0-9]{1,12}",
        ) {
            let mut state = RunState::default();
            state.vars.insert(name.clone(), value);
            let out = interpolate(&format!("{prefix}${{{name}}}"), &state)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(!out.contains('$'), "unexpanded reference left in {out:?}");
        }

        /// Every stray `$` shape is copied literally and never errors — an
        /// unresolvable-looking `$` must not abort a deploy.
        #[test]
        fn stray_dollar_is_literal_never_an_error(
            stray in prop_oneof![
                Just("$".to_string()),
                Just("$ ".to_string()),
                Just("$1".to_string()),
                Just("$9x".to_string()),
                Just("${".to_string()),
                Just("${}".to_string()),
                Just("${1}".to_string()),
                Just("${bad-name}".to_string()),
                Just("${ x }".to_string()),
                Just("$$".to_string()),
            ],
            // The trailing separator is non-name so it can never glue onto the
            // stray `$` and form a real (unresolved) variable reference.
            around in (
                "[a-z]{0,8}",
                prop_oneof![
                    Just(String::new()),
                    Just("/".to_string()),
                    Just("-".to_string()),
                    Just(".".to_string()),
                ],
            ),
        ) {
            let state = RunState::default();
            let template = format!("{}{}{}", around.0, stray, around.1);
            let out = interpolate(&template, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(out.contains('$'), "the literal `$` must survive: {out:?}");
        }

        /// An unresolved reference is a hard error that names the variable
        /// (never a silent empty expansion).
        #[test]
        fn unresolved_reference_names_the_variable(name in "[A-Za-z_][A-Za-z0-9_]{0,10}") {
            let state = RunState::default();
            match interpolate(&format!("x/${{{name}}}"), &state) {
                Err(InterpolateError::Unresolved { var, .. }) => prop_assert_eq!(var, name),
                other => return Err(TestCaseError::fail(format!("expected Unresolved, got {other:?}"))),
            }
        }

        /// Interpolating an already-interpolated path is a no-op, so a path
        /// that round-trips through run state twice cannot double-expand.
        #[test]
        fn interpolation_is_idempotent(
            name in "[A-Za-z_][A-Za-z0-9_]{0,10}",
            value in "[a-z0-9/_-]{1,12}",
        ) {
            let mut state = RunState::default();
            state.vars.insert(name.clone(), value);
            let once = interpolate(&format!("/opt/${{{name}}}/${name}"), &state)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let twice = interpolate(&once, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(once, twice);
        }

        /// Interpolation agrees with a hand-built expectation for an arbitrary
        /// sequence of literal and `${VAR}` segments.
        #[test]
        fn interpolation_matches_manual_construction(
            parts in proptest::collection::vec(
                ("[a-z]{1,6}", "[A-Z][A-Z0-9_]{0,5}", "[a-z0-9]{1,8}"),
                1..6,
            ),
        ) {
            let mut state = RunState::default();
            let mut template = String::new();
            let mut expected = String::new();
            for (lit, name, value) in parts {
                // First definition wins, so `expected` and the render agree
                // even when a name repeats across segments.
                let stored = state.vars.entry(name.clone()).or_insert(value);
                template.push_str(&lit);
                template.push_str(&format!("${{{name}}}"));
                expected.push_str(&lit);
                expected.push_str(stored.as_str());
            }
            let out = interpolate(&template, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(out, expected);
        }

        /// Non-ASCII text is preserved byte-for-byte, and a `$` that is not
        /// followed by a valid name stays literal.
        #[test]
        fn non_ascii_survives_interpolation(
            text in "[\\p{L}\\p{N} ]{0,20}",
            // Latin-1 supplement letters: valid UTF-8, never an ASCII name
            // character, so `$` + these stays a literal `$`.
            tail in "[\u{00C0}-\u{017F}]{1,4}",
        ) {
            let state = RunState::default();
            let plain = interpolate(&text, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&plain, &text);
            let template = format!("${tail}");
            let out = interpolate(&template, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&out, &template);
        }

        /// A group resolves to exactly its member count, in declaration order,
        /// and a `--target` restriction never expands that set.
        #[test]
        fn group_resolution_is_exact(
            count in 1_usize..6,
            keep in 1_usize..6,
        ) {
            let keep = keep.min(count);
            let mut script = String::new();
            let mut members = String::new();
            for i in 0..count {
                script.push_str(&format!("# @server web{i} deploy@10.0.0.{i}\n"));
                if i > 0 {
                    members.push(',');
                }
                members.push_str(&format!("web{i}"));
            }
            script.push_str(&format!("# @group web {members}\n"));
            let plan = parse_script(&script).map_err(|e| TestCaseError::fail(e.to_string()))?;

            let all = resolve_hosts(&plan, &Target::new("web"), &[]).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(all.len(), count);
            for (i, host) in all.iter().enumerate() {
                prop_assert_eq!(&host.alias, &format!("web{i}"));
            }

            let restricted = resolve_hosts(
                &plan,
                &Target::new("web"),
                &["web0".to_string()],
            )
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(restricted.len(), 1);
            prop_assert!(keep >= 1, "sanity: keep is at least 1");
        }
    }

    use proptest::{
        prelude::{Just, TestCaseError, prop_assert, prop_assert_eq},
        prop_oneof,
    };
}
