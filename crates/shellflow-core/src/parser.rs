//! Single-pass line scanner that turns a Bash deploy script into an
//! [`ExecutionPlan`].

use std::collections::BTreeMap;

use crate::{
    error::ParseError,
    plan::{CopyStep, EnvEntry, ExecutionPlan, LocalStep, RemoteStep, SecretEntry, Step, Target},
    ssh_spec::SshSpec,
};

/// Block modes: lines accumulate in `local` mode until a `@remote`/`@copy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    /// Lines run on the local machine.
    Local,
    /// Lines stream to the target hosts.
    Remote,
}

/// Mutable state threaded through the scan.
struct State {
    plan: ExecutionPlan,
    mode: Mode,
    /// Target text when `mode` is [`Mode::Remote`]; empty in local mode.
    target: String,
    /// Lines of the current (unflushed) block.
    pending: Vec<String>,
    /// `@name` for the next block.
    pending_name: Option<String>,
    /// `@only_if` guard for the next block.
    pending_guard: Option<String>,
    /// `@timeout` for the next block.
    pending_timeout: Option<u64>,
    /// `@export` variables for the pending local block.
    pending_export: Vec<String>,
    /// Line number of each group declaration (for validation errors).
    group_lines: BTreeMap<String, usize>,
}

impl State {
    fn new() -> Self {
        Self {
            plan: ExecutionPlan::default(),
            mode: Mode::Local,
            target: String::new(),
            pending: Vec::new(),
            pending_name: None,
            pending_guard: None,
            pending_timeout: None,
            pending_export: Vec::new(),
            group_lines: BTreeMap::new(),
        }
    }

    /// Whether the pending block contains at least one executable (non-blank,
    /// non-comment) line.
    fn has_executable(&self) -> bool {
        self.pending.iter().any(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
    }

    /// Flush the pending block into the plan as a step.
    ///
    /// Blocks with no executable statement are dropped; in that case pending
    /// metadata (`@name`/`@only_if`/`@timeout`/`@export`) is preserved for the
    /// next block. Infallible: `@remote` validates its target before any block
    /// can be flushed in remote mode.
    fn flush(&mut self) {
        if !self.has_executable() {
            self.pending.clear();
            return;
        }

        let script = {
            let mut script = self.pending.join("\n");
            script.push('\n');
            script
        };
        self.pending.clear();
        let name = self.pending_name.take();
        let guard = self.pending_guard.take();
        let timeout = self.pending_timeout.take();
        let export = std::mem::take(&mut self.pending_export);
        let env = self.plan.env.clone();

        let step = match self.mode {
            Mode::Local => Step::Local(LocalStep { name, script, guard, timeout, export, env }),
            Mode::Remote => Step::Remote(RemoteStep {
                name,
                target: Target::new(self.target.clone()),
                script,
                guard,
                timeout,
                env,
            }),
        };
        self.plan.steps.push(step);
    }

    fn apply_directive(
        &mut self,
        keyword: &str,
        payload: &str,
        line: usize,
    ) -> Result<(), ParseError> {
        match keyword {
            "server" => {
                self.flush();
                self.declare_server(payload, line)
            }
            "group" => {
                self.flush();
                self.declare_group(payload, line)
            }
            "env" => {
                self.flush();
                self.declare_env(payload, line)
            }
            "secrets" => {
                self.flush();
                self.declare_secrets(payload, line)
            }
            "local" => {
                self.flush();
                self.mode = Mode::Local;
                self.target.clear();
                Ok(())
            }
            "remote" => {
                self.flush();
                self.mode = Mode::Remote;
                let target = payload.trim_start_matches('@').trim();
                if target.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "remote".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                self.target = target.to_string();
                Ok(())
            }
            "copy" => {
                self.flush();
                self.add_copy(payload, line)
            }
            "export" => self.declare_export(payload, line),
            "timeout" => {
                self.flush();
                let seconds =
                    payload.trim().parse::<u64>().map_err(|_| ParseError::InvalidDirective {
                        line,
                        directive: "timeout".to_string(),
                        reason: format!("invalid seconds `{payload}`"),
                    })?;
                if seconds == 0 {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "timeout".to_string(),
                        reason: "must be greater than zero".to_string(),
                    });
                }
                self.pending_timeout = Some(seconds);
                Ok(())
            }
            "name" => {
                self.flush();
                let name = payload.trim();
                if name.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "name".to_string(),
                        reason: "missing label".to_string(),
                    });
                }
                self.pending_name = Some(name.to_string());
                Ok(())
            }
            "only_if" => {
                self.flush();
                let command = payload.trim();
                if command.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "only_if".to_string(),
                        reason: "missing command".to_string(),
                    });
                }
                self.pending_guard = Some(command.to_string());
                Ok(())
            }
            other => Err(ParseError::UnknownDirective { line, directive: other.to_string() }),
        }
    }

    fn declare_server(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        let mut parts = payload.split_whitespace();
        let name = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "server".to_string(),
            reason: "missing name".to_string(),
        })?;
        let spec = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "server".to_string(),
            reason: format!("missing ssh spec for `{name}`"),
        })?;
        if parts.next().is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "server".to_string(),
                reason: format!("too many arguments for `{name}`"),
            });
        }
        if self.plan.servers.contains_key(name) {
            return Err(ParseError::DuplicateServer { line, name: name.to_string() });
        }
        let parsed = match SshSpec::parse(spec) {
            Ok(parsed) => parsed,
            Err(ParseError::InvalidSshSpec { spec, reason, .. }) => {
                return Err(ParseError::InvalidSshSpec { line, spec, reason });
            }
            Err(other) => return Err(other),
        };
        self.plan.servers.insert(name.to_string(), parsed);
        Ok(())
    }

    fn declare_group(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        let mut parts = payload.split_whitespace();
        let name = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "group".to_string(),
            reason: "missing name".to_string(),
        })?;
        let members = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "group".to_string(),
            reason: format!("missing members for `{name}`"),
        })?;
        if parts.next().is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "group".to_string(),
                reason: format!("too many arguments for `{name}`"),
            });
        }
        if self.plan.servers.contains_key(name) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "group".to_string(),
                reason: format!("group `{name}` collides with a server name"),
            });
        }
        if self.plan.groups.contains_key(name) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "group".to_string(),
                reason: format!("group `{name}` is already defined"),
            });
        }
        let members: Vec<String> = members
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if members.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "group".to_string(),
                reason: format!("no members for `{name}`"),
            });
        }
        self.group_lines.insert(name.to_string(), line);
        self.plan.groups.insert(name.to_string(), members);
        Ok(())
    }

    fn declare_env(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        let payload = payload.trim();
        if payload.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "env".to_string(),
                reason: "missing variable".to_string(),
            });
        }
        let entry = if let Some((key, value)) = payload.split_once('=') {
            let key = key.trim();
            if !is_valid_var_name(key) {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "env".to_string(),
                    reason: format!("invalid variable name `{key}`"),
                });
            }
            EnvEntry::Literal { key: key.to_string(), value: value.to_string() }
        } else {
            if !is_valid_var_name(payload) {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "env".to_string(),
                    reason: format!("invalid variable name `{payload}`"),
                });
            }
            EnvEntry::Passthrough { key: payload.to_string() }
        };
        self.plan.env.push(entry);
        Ok(())
    }

    fn declare_secrets(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        let mut parts = payload.split_whitespace();
        let file = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "secrets".to_string(),
            reason: "missing encrypted file path".to_string(),
        })?;

        let mut identity: Option<String> = None;
        while let Some(token) = parts.next() {
            match token {
                "--identity" => {
                    let value = parts.next().ok_or_else(|| ParseError::InvalidDirective {
                        line,
                        directive: "secrets".to_string(),
                        reason: "`--identity` requires a path".to_string(),
                    })?;
                    identity = Some(value.to_string());
                }
                other => {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "secrets".to_string(),
                        reason: format!("unexpected token `{other}`"),
                    });
                }
            }
        }

        self.plan.secrets.push(SecretEntry { file: file.to_string(), identity });
        Ok(())
    }

    fn declare_export(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        let vars: Vec<String> = payload
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if vars.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "export".to_string(),
                reason: "missing variable name(s)".to_string(),
            });
        }
        for var in &vars {
            if !is_valid_var_name(var) {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "export".to_string(),
                    reason: format!("invalid variable name `{var}`"),
                });
            }
        }
        if self.mode != Mode::Local || !self.has_executable() {
            return Err(ParseError::ExportNotAfterLocal { line });
        }
        self.pending_export.extend(vars);
        Ok(())
    }

    fn add_copy(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        let name = self.pending_name.take();
        let guard = self.pending_guard.take();
        let timeout = self.pending_timeout.take();

        let (src, rest) = payload.split_once("->").ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "copy".to_string(),
            reason: "expected `src -> dst @target [--delete]`".to_string(),
        })?;
        let src = src.trim();
        if src.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "copy".to_string(),
                reason: "missing source path".to_string(),
            });
        }

        let mut tokens: Vec<&str> = rest.split_whitespace().collect();
        let mut delete = false;
        if tokens.last() == Some(&"--delete") {
            delete = true;
            tokens.pop();
        }
        let target = tokens.pop().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "copy".to_string(),
            reason: "missing target".to_string(),
        })?;
        let target = target.trim_start_matches('@').trim();
        if target.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "copy".to_string(),
                reason: "missing target".to_string(),
            });
        }
        let dst = tokens.join(" ");
        if dst.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "copy".to_string(),
                reason: "missing destination path".to_string(),
            });
        }

        self.plan.steps.push(Step::Copy(CopyStep {
            name,
            src: src.to_string(),
            dst,
            target: Target::new(target),
            delete,
            guard,
            timeout,
        }));
        Ok(())
    }
}

/// True for `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Extract `(keyword, payload)` from a possible directive line.
///
/// A directive is a comment whose content starts with `@` followed by an
/// identifier. Non-directive lines return `None` and are treated as script
/// content.
fn directive(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('#') {
        return None;
    }
    let after_hash = trimmed[1..].trim_start();
    if !after_hash.starts_with('@') {
        return None;
    }
    let after_at = &after_hash[1..];
    let keyword_end = after_at
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(after_at.len());
    let keyword = &after_at[..keyword_end];
    if keyword.is_empty() {
        return None;
    }
    let payload = after_at[keyword_end..].trim();
    Some((keyword.to_string(), payload.to_string()))
}

/// Parse a deploy script into an [`ExecutionPlan`].
///
/// # Errors
///
/// Returns a [`ParseError`] for malformed directives, duplicate or unknown
/// aliases, invalid specs, and `@export` used without a preceding local block.
pub fn parse_script(input: &str) -> Result<ExecutionPlan, ParseError> {
    let mut state = State::new();

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some((keyword, payload)) = directive(line) {
            state.apply_directive(&keyword, &payload, line_no)?;
        } else {
            state.pending.push(line.to_string());
        }
    }

    state.flush();

    for (group, members) in &state.plan.groups {
        let line = state.group_lines[group];
        for member in members {
            if !state.plan.servers.contains_key(member) {
                return Err(ParseError::UnknownGroupMember {
                    line,
                    group: group.clone(),
                    server: member.clone(),
                });
            }
        }
    }

    Ok(state.plan)
}

#[cfg(test)]
mod tests {
    use super::{directive, parse_script};
    use crate::{
        error::ParseError,
        plan::{CopyStep, EnvEntry, LocalStep, RemoteStep, Step},
    };

    fn parse(input: &str) -> Result<crate::plan::ExecutionPlan, String> {
        parse_script(input).map_err(|e| e.to_string())
    }

    fn as_local(step: &Step) -> Result<&LocalStep, String> {
        match step {
            Step::Local(s) => Ok(s),
            other => Err(format!("expected local step, got {other:?}")),
        }
    }

    fn as_remote(step: &Step) -> Result<&RemoteStep, String> {
        match step {
            Step::Remote(s) => Ok(s),
            other => Err(format!("expected remote step, got {other:?}")),
        }
    }

    fn as_copy(step: &Step) -> Result<&CopyStep, String> {
        match step {
            Step::Copy(s) => Ok(s),
            other => Err(format!("expected copy step, got {other:?}")),
        }
    }

    #[test]
    fn directive_detection() {
        assert_eq!(
            directive("# @server web1 deploy@10.0.0.1"),
            Some(("server".to_string(), "web1 deploy@10.0.0.1".to_string()))
        );
        assert_eq!(directive("   # @local"), Some(("local".to_string(), String::new())));
        assert_eq!(directive("#@remote @web"), Some(("remote".to_string(), "@web".to_string())));
        assert_eq!(directive("# plain comment"), None);
        assert_eq!(directive("echo hi"), None);
        assert_eq!(directive("# @"), None);
        assert_eq!(directive(""), None);
    }

    #[test]
    fn header_comments_are_dropped() -> Result<(), String> {
        let plan = parse(
            "#!/usr/bin/env shellflow\n\
             # a header comment\n\
             # @local\n\
             echo hi\n",
        )?;
        assert_eq!(plan.steps.len(), 1);
        Ok(())
    }

    #[test]
    fn local_then_remote_block() -> Result<(), String> {
        let plan = parse(
            "# @local\n\
             echo build\n\
             # @remote web\n\
             echo deploy\n",
        )?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].kind(), "local");
        assert_eq!(plan.steps[1].kind(), "remote");
        assert_eq!(plan.steps[1].target_text(), Some("web"));
        Ok(())
    }

    #[test]
    fn copy_step_parses_target_and_delete() -> Result<(), String> {
        let plan = parse("# @copy a/b -> /srv/c @web --delete\n")?;
        assert_eq!(plan.steps.len(), 1);
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(copy.src, "a/b");
        assert_eq!(copy.dst, "/srv/c");
        assert_eq!(copy.target.text, "web");
        assert!(copy.delete);
        Ok(())
    }

    #[test]
    fn copy_with_at_prefixed_target_and_path() -> Result<(), String> {
        let plan = parse("# @copy out -> /tmp/@deploy/app @web\n")?;
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(copy.dst, "/tmp/@deploy/app");
        assert_eq!(copy.target.text, "web");
        assert!(!copy.delete);
        Ok(())
    }

    #[test]
    fn copy_missing_arrow_is_error() {
        assert!(matches!(
            parse_script("# @copy a b c\n"),
            Err(ParseError::InvalidDirective { directive, .. }) if directive == "copy"
        ));
    }

    #[test]
    fn servers_and_groups_collected() -> Result<(), String> {
        let plan = parse(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2:2222\n\
             # @group web web1,web2\n",
        )?;
        assert_eq!(plan.servers.len(), 2);
        assert_eq!(plan.servers["web1"].host, "10.0.0.1");
        assert_eq!(plan.servers["web2"].port, Some(2222));
        assert_eq!(plan.groups["web"], vec!["web1".to_string(), "web2".to_string()]);
        Ok(())
    }

    #[test]
    fn duplicate_server_is_error() {
        assert!(matches!(
            parse_script("# @server web1 a@h\n# @server web1 b@h\n"),
            Err(ParseError::DuplicateServer { .. })
        ));
    }

    #[test]
    fn unknown_group_member_is_error() {
        assert!(matches!(
            parse_script("# @group web web1,ghost\n# @server web1 a@h\n"),
            Err(ParseError::UnknownGroupMember { server, .. }) if server == "ghost"
        ));
    }

    #[test]
    fn env_literal_and_passthrough() -> Result<(), String> {
        let plan = parse("# @env KEY=value\n# @env PASSWORD\n")?;
        assert_eq!(plan.env.len(), 2);
        assert_eq!(
            plan.env[0],
            EnvEntry::Literal { key: "KEY".to_string(), value: "value".to_string() }
        );
        assert_eq!(plan.env[1], EnvEntry::Passthrough { key: "PASSWORD".to_string() });
        Ok(())
    }

    #[test]
    fn env_snapshot_applies_to_subsequent_blocks() -> Result<(), String> {
        let plan = parse(
            "# @local\n\
             echo before\n\
             # @env KEY=value\n\
             # @local\n\
             echo after\n",
        )?;
        assert_eq!(plan.steps.len(), 2);
        let before_env = &as_local(&plan.steps[0])?.env;
        let after_env = &as_local(&plan.steps[1])?.env;
        assert_eq!(before_env.as_slice(), []);
        assert_eq!(after_env.len(), 1);
        Ok(())
    }

    #[test]
    fn export_attaches_to_preceding_local_block() -> Result<(), String> {
        let plan = parse(
            "# @local\n\
             VERSION=$(git rev-parse --short HEAD)\n\
             # @export VERSION\n\
             # @copy target/app-$VERSION -> /srv/app-$VERSION @web\n",
        )?;
        assert_eq!(plan.steps.len(), 2);
        let export = &as_local(&plan.steps[0])?.export;
        assert_eq!(export, &vec!["VERSION".to_string()]);
        Ok(())
    }

    #[test]
    fn export_without_preceding_local_block_is_error() {
        assert!(matches!(
            parse_script("# @remote web\n# @export X\n"),
            Err(ParseError::ExportNotAfterLocal { .. })
        ));
    }

    #[test]
    fn export_after_remote_with_content_is_error() {
        // Even with an executable remote block, `@export` is only valid after
        // a *local* block.
        assert!(matches!(
            parse_script("# @remote web\necho hi\n# @export X\n"),
            Err(ParseError::ExportNotAfterLocal { .. })
        ));
    }

    #[test]
    fn name_only_if_timeout_attach_to_next_block() -> Result<(), String> {
        let plan = parse(
            "# @name restart\n\
             # @only_if test -f /etc/app.conf\n\
             # @timeout 30\n\
             # @remote web\n\
             sudo systemctl restart app\n",
        )?;
        assert_eq!(plan.steps.len(), 1);
        let step = as_remote(&plan.steps[0])?;
        assert_eq!(step.name.as_deref(), Some("restart"));
        assert_eq!(step.guard.as_deref(), Some("test -f /etc/app.conf"));
        assert_eq!(step.timeout, Some(30));
        Ok(())
    }

    #[test]
    fn comment_only_block_is_dropped() -> Result<(), String> {
        let plan = parse(
            "# @local\n\
             # just a comment\n\
             # @local\n\
             echo real\n",
        )?;
        assert_eq!(plan.steps.len(), 1);
        Ok(())
    }

    #[test]
    fn crlf_lines_are_tolerated() -> Result<(), String> {
        let plan = parse("# @local\r\necho hi\r\n")?;
        assert_eq!(plan.steps.len(), 1);
        Ok(())
    }

    #[test]
    fn unknown_directive_is_error() {
        assert!(matches!(
            parse_script("# @frobnicate x\n"),
            Err(ParseError::UnknownDirective { directive, .. }) if directive == "frobnicate"
        ));
    }

    #[test]
    fn timeout_zero_is_error() {
        assert!(matches!(
            parse_script("# @timeout 0\n"),
            Err(ParseError::InvalidDirective { directive, .. }) if directive == "timeout"
        ));
    }

    #[test]
    fn env_variable_name_validation() -> Result<(), String> {
        // Underscore-leading names are valid.
        let plan = parse("# @env _PRIVATE=1\n# @env A_B=2\n")?;
        assert_eq!(plan.env.len(), 2);
        // Digit-leading and dash-leading names are rejected.
        assert!(parse_script("# @env 1BAD=1\n").is_err());
        assert!(parse_script("# @env -BAD=1\n").is_err());
        assert!(parse_script("# @env BAD-NAME=1\n").is_err());
        Ok(())
    }

    #[test]
    fn error_reports_correct_line_number() -> Result<(), String> {
        // The unknown directive is on line 3.
        let err = match parse_script(
            "# @local\n\
             echo hi\n\
             # @frobnicate x\n",
        ) {
            Err(err) => err,
            Ok(_) => return Err("expected a parse error".to_string()),
        };
        match err {
            ParseError::UnknownDirective { line, directive } => {
                assert_eq!(line, 3);
                assert_eq!(directive, "frobnicate");
            }
            other => return Err(format!("expected UnknownDirective, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn secrets_directive_records_file_and_identity() -> Result<(), String> {
        let plan = parse(
            "# @secrets conf/prod.env.age\n# @secrets extra.env.age --identity /tmp/key.txt\n",
        )?;
        assert_eq!(plan.secrets.len(), 2);
        assert_eq!(plan.secrets[0].file, "conf/prod.env.age");
        assert_eq!(plan.secrets[0].identity, None);
        assert_eq!(plan.secrets[1].file, "extra.env.age");
        assert_eq!(plan.secrets[1].identity.as_deref(), Some("/tmp/key.txt"));
        Ok(())
    }

    #[test]
    fn secrets_requires_a_file() {
        assert!(matches!(
            parse_script("# @secrets\n"),
            Err(ParseError::InvalidDirective { directive, .. }) if directive == "secrets"
        ));
        assert!(matches!(
            parse_script("# @secrets x.age --identity\n"),
            Err(ParseError::InvalidDirective { directive, .. }) if directive == "secrets"
        ));
        assert!(matches!(
            parse_script("# @secrets x.age --bogus\n"),
            Err(ParseError::InvalidDirective { directive, .. }) if directive == "secrets"
        ));
    }

    #[test]
    fn secrets_flush_pending_block_like_env() -> Result<(), String> {
        let plan = parse("# @local\necho before\n# @secrets s.age\n# @local\necho after\n")?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.secrets.len(), 1);
        Ok(())
    }

    proptest::proptest! {
        #[test]
        fn non_directive_body_becomes_single_local_step(
            // Non-blank, non-comment lines guarantee exactly one executable
            // block (whitespace/comment-only bodies are dropped by design).
            lines in proptest::collection::vec("[a-z]{1,40}", 1..8),
        ) {
            let script = lines.join("\n");
            let plan = parse_prop(&script)?;
            proptest::prop_assert_eq!(plan.steps.len(), 1);
            let step = as_local(&plan.steps[0]).map_err(proptest::prelude::TestCaseError::fail)?;
            proptest::prop_assert_eq!(&step.script, &format!("{script}\n"));
        }

        #[test]
        fn whitespace_only_body_is_dropped(
            lines in proptest::collection::vec(" ", 1..8),
        ) {
            let script = lines.join("\n");
            let plan = parse_prop(&script)?;
            proptest::prop_assert_eq!(plan.steps.len(), 0);
        }

        #[test]
        fn server_spec_round_trips(
            name in "[a-z][a-z0-9]{0,12}",
            host in "[a-z0-9.\\-]{1,40}",
            port in 1_u16..65535,
        ) {
            let script = format!("# @server {name} deploy@{host}:{port}\n");
            let plan = parse_prop(&script)?;
            proptest::prop_assert_eq!(plan.servers.len(), 1);
            let spec = &plan.servers[name.as_str()];
            proptest::prop_assert_eq!(&spec.host, &host);
            proptest::prop_assert_eq!(spec.port, Some(port));
        }
    }

    fn parse_prop(
        input: &str,
    ) -> Result<crate::plan::ExecutionPlan, proptest::prelude::TestCaseError> {
        parse_script(input).map_err(|e| proptest::prelude::TestCaseError::fail(e.to_string()))
    }
}
