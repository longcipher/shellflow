//! Single-pass line scanner that turns a Bash deploy script into an
//! [`ExecutionPlan`].

use std::{collections::BTreeMap, sync::Arc};

use crate::{
    error::ParseError,
    heredoc::HeredocTracker,
    plan::{
        AssertStep, Assertion, CopyEntry, CopyStep, EnvEntry, ExecutionPlan, LocalStep, ReloadStep,
        RemoteStep, SecretEntry, Step, Target, WaitStep, is_valid_var_name,
    },
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
    /// The target of the most recent step, inherited by an assertion that
    /// does not name one.
    last_target: Option<String>,
    /// Line number of each group declaration (for validation errors).
    group_lines: BTreeMap<String, usize>,
    /// Here-document bodies opened by earlier lines and not yet terminated.
    heredocs: HeredocTracker,
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
            heredocs: HeredocTracker::default(),
            last_target: None,
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
        let env = Arc::clone(&self.plan.env);

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
        if matches!(step, Step::Remote(_)) {
            self.last_target = Some(self.target.clone());
        }
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
                // A copy step is self-contained: it carries its own target in
                // its payload and is not a script block. The block mode
                // therefore returns to `local` (design §4.1 rule 3 lists
                // `@copy` among the mode-setting directives), so the lines
                // that follow are not silently streamed to the copy's remote
                // target.
                self.mode = Mode::Local;
                self.target.clear();
                self.add_copy(payload, line)
            }
            "wait_active" => {
                self.flush();
                self.add_wait(payload, line)
            }
            "reload" => {
                self.flush();
                self.add_reload(payload, line)
            }
            "assert" => {
                self.flush();
                self.add_assert(payload, line)
            }
            "assert_health" => {
                self.flush();
                self.add_assert_health(payload, line)
            }
            "assert_port" => {
                self.flush();
                self.add_assert_port(payload, line)
            }
            "assert_rendered" => {
                self.flush();
                self.add_assert_rendered(payload, line)
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
        Arc::make_mut(&mut self.plan.env).push(entry);
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
        // `@export` binds to the *preceding* local block (design §4.1 rule 4).
        //
        // "Preceding" is the block that the operator just wrote, which is not
        // always the *pending* one: an intervening directive (`@name`,
        // `@timeout`, `@only_if`, `@remote`, …) flushes the pending block
        // (design §4.1 rule 1), so by the time `@export` is read the local
        // block may already have been emitted. Binding to the pending buffer
        // only would reject a script the design accepts.
        //
        // So: bind to the pending block when there is one, and otherwise to the
        // last emitted local step. A remote block in between is still an error
        // — remote variables cannot be captured.
        if self.has_executable() {
            if self.mode != Mode::Local {
                return Err(ParseError::ExportNotAfterLocal { line });
            }
            self.pending_export.extend(vars);
            return Ok(());
        }
        match self.plan.steps.last_mut() {
            Some(Step::Local(local)) => {
                local.export.extend(vars);
                Ok(())
            }
            _ => Err(ParseError::ExportNotAfterLocal { line }),
        }
    }

    fn add_copy(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        // `@only_if` is unsupported on `@copy`: a copy step transfers files,
        // not a script, so a guard has no well-defined evaluation context.
        // Rejecting at parse time prevents a silently-ignored guard (which
        // would copy even where the precondition fails).
        if self.pending_guard.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "copy".to_string(),
                reason: "`@only_if` is not supported on `@copy`".to_string(),
            });
        }
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();
        let env = Arc::clone(&self.plan.env);

        let (src, rest) = payload.split_once("->").ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "copy".to_string(),
            reason: "expected `src -> dst @target [--delete] [--exclude <glob>]`".to_string(),
        })?;
        let src = src.trim();
        if src.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "copy".to_string(),
                reason: "missing source path".to_string(),
            });
        }

        // Grammar: `src -> dst @target [--delete] [--exclude <glob>]…`.
        // The target is the last token once the trailing flags are peeled off.
        let mut tokens: Vec<&str> = rest.split_whitespace().collect();
        let mut delete = false;
        let mut excludes: Vec<String> = Vec::new();
        loop {
            match tokens.last().copied() {
                Some("--delete") => {
                    delete = true;
                    tokens.pop();
                }
                Some("--exclude") => {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "copy".to_string(),
                        reason: "`--exclude` requires a glob pattern".to_string(),
                    });
                }
                _ if tokens.len() >= 2 && tokens[tokens.len() - 2] == "--exclude" => {
                    let glob = tokens.pop().ok_or_else(|| ParseError::InvalidDirective {
                        line,
                        directive: "copy".to_string(),
                        reason: "`--exclude` requires a glob pattern".to_string(),
                    })?;
                    tokens.pop(); // the `--exclude` flag itself
                    let glob = strip_surrounding_quotes(glob).trim().to_string();
                    if glob.is_empty() {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "copy".to_string(),
                            reason: "`--exclude` glob must not be empty".to_string(),
                        });
                    }
                    excludes.push(glob);
                }
                _ => break,
            }
        }
        // Flags are peeled from the right, so restore the written order.
        excludes.reverse();
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

        self.last_target = Some(target.to_string());
        let entry = CopyEntry { src: src.to_string(), dst };
        // Consecutive copies that share a target *and* their options travel
        // in one transfer: a playbook that ships five templates to the same
        // directory costs one round trip instead of five.
        let mergeable = name.is_none() &&
            self.plan.steps.last().is_some_and(
                |step| matches!(step, Step::Copy(existing)
                    if existing.target.text == target
                        && existing.delete == delete
                        && existing.excludes == excludes
                        && existing.timeout == timeout),
            );
        if mergeable
            && let Some(Step::Copy(existing)) = self.plan.steps.last_mut()
        {
            existing.entries.push(entry);
            return Ok(());
        }
        self.plan.steps.push(Step::Copy(CopyStep {
            name,
            entries: vec![entry],
            target: Target::new(target),
            delete,
            excludes,
            guard: None,
            timeout,
            env,
        }));
        Ok(())
    }

    /// Parse `# @wait_active <unit> @<target> [--timeout SECS]`.
    ///
    /// The unit accepts `foo` or `foo.service`. Like `@copy`, `@only_if` is
    /// rejected (a wait has no script context to evaluate a guard in) while
    /// `@name` and `@timeout` apply.
    fn add_wait(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        if self.pending_guard.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: "`@only_if` is not supported on `@wait_active`".to_string(),
            });
        }
        let name = self.pending_name.take();
        let pending_timeout = self.pending_timeout.take();
        let mut tokens: Vec<&str> = payload.split_whitespace().collect();
        let timeout = if tokens.len() >= 2 && tokens[tokens.len() - 2] == "--timeout" {
            // Peel an optional trailing `--timeout SECS`.
            let secs_str = tokens.pop().unwrap_or_default();
            let flag = tokens.pop().unwrap_or_default();
            debug_assert_eq!(flag, "--timeout");
            let secs: u64 = secs_str.parse().map_err(|_| ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: format!("invalid seconds `{secs_str}`"),
            })?;
            if secs == 0 {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "wait_active".to_string(),
                    reason: "must be greater than zero".to_string(),
                });
            }
            Some(secs)
        } else {
            pending_timeout
        };
        if tokens.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: "expected `<unit> @<target> [--timeout SECS]`".to_string(),
            });
        }
        let mut unit = tokens[0].trim().to_string();
        if unit.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: "missing unit name".to_string(),
            });
        }
        if !unit.ends_with(".service") {
            unit.push_str(".service");
        }
        if !unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':')) ||
            unit.starts_with('.') ||
            unit.contains("..")
        {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let target = tokens[1].trim_start_matches('@').trim();
        if target.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: "missing target".to_string(),
            });
        }
        self.last_target = Some(target.to_string());
        self.plan.steps.push(Step::Wait(WaitStep {
            name,
            target: Target::new(target),
            unit,
            timeout,
            interval_secs: 5,
        }));
        Ok(())
    }

    /// Parse `# @assert <unit> [@<target>] [<state>]`.
    ///
    /// The unit accepts `foo` or `foo.service`. The expected `ActiveState`
    /// defaults to `active` — the state a deployed service is supposed to
    /// be in — and the target is inherited from the previous step when it is
    /// not given, so the common case is one short line.
    ///
    /// Like `@wait_active`, `@only_if` is rejected (an assertion has no
    /// script context to evaluate a guard in) while `@name` and `@timeout`
    /// apply.
    fn add_assert(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        if self.pending_guard.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert".to_string(),
                reason: "`@only_if` is not supported on `@assert`".to_string(),
            });
        }
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut unit: Option<String> = None;
        let mut state: Option<String> = None;
        let mut target: Option<String> = None;
        for token in payload.split_whitespace() {
            if let Some(name) = token.strip_prefix('@') {
                if name.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                if target.is_some() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert".to_string(),
                        reason: "more than one target".to_string(),
                    });
                }
                target = Some(name.to_string());
            } else if unit.is_none() {
                unit = Some(token.to_string());
            } else if state.is_none() {
                state = Some(token.to_string());
            } else {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "assert".to_string(),
                    reason: "expected `<unit> [@<target>] [<state>]`".to_string(),
                });
            }
        }

        let Some(unit) = unit else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert".to_string(),
                reason: "missing unit name".to_string(),
            });
        };
        let unit = normalize_unit(&unit);
        if !is_safe_unit(&unit) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let state = state.unwrap_or_else(|| "active".to_string());
        if !state.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert".to_string(),
                reason: format!("unsafe state `{state}`"),
            });
        }
        let target = self.resolve_assert_target(target, "assert", line)?;
        self.push_assertion(
            name,
            target,
            Assertion::UnitState { unit, state },
            timeout,
        );
        Ok(())
    }

    /// Parse `# @assert_health <url> [@<target>] [--expect CODES]`.
    ///
    /// The URL must be an `http`/`https` address. The accepted status codes
    /// default to any 2xx or 3xx; `--expect 200,204` narrows them.
    fn add_assert_health(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        if self.pending_guard.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_health".to_string(),
                reason: "`@only_if` is not supported on `@assert_health`".to_string(),
            });
        }
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut url: Option<String> = None;
        let mut target: Option<String> = None;
        let mut expect: Vec<String> = Vec::new();
        let mut method: Option<String> = None;
        let mut body: Option<String> = None;
        let mut headers: Vec<String> = Vec::new();
        let mut tokens = payload.split_whitespace();
        while let Some(token) = tokens.next() {
            match token {
                "--expect" => {
                    let Some(codes) = tokens.next() else {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: "`--expect` requires a list of status codes".to_string(),
                        });
                    };
                    for code in codes.split(',') {
                        let code = code.trim();
                        if !is_status_pattern(code) {
                            return Err(ParseError::InvalidDirective {
                                line,
                                directive: "assert_health".to_string(),
                                reason: format!("invalid status code `{code}`"),
                            });
                        }
                        expect.push(code.to_string());
                    }
                }
                "--method" => {
                    let Some(raw) = tokens.next() else {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: "`--method` requires an HTTP method".to_string(),
                        });
                    };
                    let raw = raw.to_ascii_uppercase();
                    if !raw.chars().all(|c| c.is_ascii_alphabetic()) {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: format!("invalid HTTP method `{raw}`"),
                        });
                    }
                    method = Some(raw);
                }
                "--body" => {
                    let Some(raw) = tokens.next() else {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: "`--body` requires a request body".to_string(),
                        });
                    };
                    body = Some(strip_surrounding_quotes(raw));
                }
                "--header" => {
                    let Some(raw) = tokens.next() else {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: "`--header` requires a `Name: value` pair".to_string(),
                        });
                    };
                    if !raw.contains(':') {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: format!("invalid header `{raw}` (want `Name:value`)"),
                        });
                    }
                    headers.push(strip_surrounding_quotes(raw));
                }
                other if other.starts_with("--") => {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_health".to_string(),
                        reason: format!("unknown flag `{other}`"),
                    });
                }
                other if let Some(name) = other.strip_prefix('@') => {
                    if name.is_empty() {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: "missing target".to_string(),
                        });
                    }
                    if target.is_some() {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: "more than one target".to_string(),
                        });
                    }
                    target = Some(name.to_string());
                }
                other => {
                    if url.is_some() {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_health".to_string(),
                            reason: "expected `<url> [@<target>] [--expect CODES]`".to_string(),
                        });
                    }
                    url = Some(strip_surrounding_quotes(other));
                }
            }
        }

        let Some(url) = url else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_health".to_string(),
                reason: "missing URL".to_string(),
            });
        };
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_health".to_string(),
                reason: format!("only http and https URLs can be probed (got `{url}`)"),
            });
        }
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_health".to_string(),
                reason: "the URL must not contain whitespace".to_string(),
            });
        }
        let target = self.resolve_assert_target(target, "assert_health", line)?;
        self.push_assertion(
            name,
            target,
            Assertion::Health { url, expect, method, body, headers },
            timeout,
        );
        Ok(())
    }

    /// Parse `# @assert_port <port>[,<port>…] [@<target>]`.
    ///
    /// The ports must be listening on the target. The check waits for the
    /// step's budget (`@timeout`), which is what the hand-rolled
    /// `for i in $(seq 1 12); do ss … ; sleep 5; done` loop did — in one
    /// round trip instead of one per poll.
    fn add_assert_port(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        if self.pending_guard.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_port".to_string(),
                reason: "`@only_if` is not supported on `@assert_port`".to_string(),
            });
        }
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut ports: Vec<u16> = Vec::new();
        let mut target: Option<String> = None;
        let mut udp = false;
        for token in payload.split_whitespace() {
            if token == "--udp" {
                udp = true;
                continue;
            }
            if let Some(alias) = token.strip_prefix('@') {
                if alias.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_port".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                if target.is_some() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_port".to_string(),
                        reason: "more than one target".to_string(),
                    });
                }
                target = Some(alias.to_string());
                continue;
            }
            for part in token.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let Ok(port) = part.parse::<u16>() else {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_port".to_string(),
                        reason: format!("invalid port `{part}`"),
                    });
                };
                if port == 0 {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_port".to_string(),
                        reason: "port 0 is not a listening port".to_string(),
                    });
                }
                ports.push(port);
            }
        }
        if ports.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_port".to_string(),
                reason: "missing port".to_string(),
            });
        }
        let target = self.resolve_assert_target(target, "assert_port", line)?;
        self.push_assertion(name, target, Assertion::Port { ports, udp }, timeout);
        Ok(())
    }

    /// Parse `# @assert_rendered <path> [@<target>]`.
    ///
    /// The file must exist and hold no unexpanded `${…}` placeholder: a
    /// rendered config that still carries a placeholder is a config that
    /// was never rendered.
    fn add_assert_rendered(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        if self.pending_guard.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_rendered".to_string(),
                reason: "`@only_if` is not supported on `@assert_rendered`".to_string(),
            });
        }
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut path: Option<String> = None;
        let mut target: Option<String> = None;
        for token in payload.split_whitespace() {
            if let Some(alias) = token.strip_prefix('@') {
                if alias.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_rendered".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                if target.is_some() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_rendered".to_string(),
                        reason: "more than one target".to_string(),
                    });
                }
                target = Some(alias.to_string());
                continue;
            }
            if path.is_some() {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "assert_rendered".to_string(),
                    reason: "expected `<path> [@<target>]`".to_string(),
                });
            }
            path = Some(strip_surrounding_quotes(token));
        }
        let Some(path) = path else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_rendered".to_string(),
                reason: "missing path".to_string(),
            });
        };
        if !path.starts_with('/') {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_rendered".to_string(),
                reason: format!("the path must be absolute (got `{path}`)"),
            });
        }
        let target = self.resolve_assert_target(target, "assert_rendered", line)?;
        self.push_assertion(name, target, Assertion::Rendered { path }, timeout);
        Ok(())
    }

    /// The target an assertion runs against: the explicit one, or the
    /// target of the previous step.
    fn resolve_assert_target(
        &self,
        explicit: Option<String>,
        directive: &str,
        line: usize,
    ) -> Result<String, ParseError> {
        if let Some(target) = explicit {
            return Ok(target);
        }
        self.last_target.clone().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: directive.to_string(),
            reason: "missing target (no previous step to inherit it from)".to_string(),
        })
    }

    /// Add an assertion to the plan.
    ///
    /// Consecutive assertions that share a target are one step: the whole
    /// group then costs a single round trip.
    fn push_assertion(
        &mut self,
        name: Option<String>,
        target: String,
        check: Assertion,
        timeout: Option<u64>,
    ) {
        let mergeable = name.is_none() &&
            self.plan.steps.last().is_some_and(
                |step| matches!(step, Step::Assert(existing) if existing.target.text == target),
            );
        if mergeable
            && let Some(Step::Assert(existing)) = self.plan.steps.last_mut()
        {
            existing.checks.push(check);
            return;
        }
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Assert(AssertStep {
            name,
            target: Target::new(target),
            checks: vec![check],
            timeout,
        }));
    }

    /// Parse `# @reload <unit> @<target> [--signal SIG] [--wait] [--timeout SECS]`.
    ///
    /// A graceful reload: the unit's own `ExecReload=` is preferred, an
    /// explicit `--signal` is the second choice, and a reload that cannot be
    /// performed fails rather than silently degrading into a restart (a restart
    /// drops the connections the reload exists to preserve).
    ///
    /// Like `@wait_active`, the unit accepts `foo` or `foo.service`, `@only_if`
    /// is rejected (a reload has no script context), and `@name`/`@timeout`
    /// apply.
    fn add_reload(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        if self.pending_guard.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "reload".to_string(),
                reason: "`@only_if` is not supported on `@reload`".to_string(),
            });
        }
        let name = self.pending_name.take();
        let pending_timeout = self.pending_timeout.take();
        let mut tokens: Vec<&str> = payload.split_whitespace().collect();
        let mut signal: Option<String> = None;
        let mut wait = false;
        let mut timeout = pending_timeout;

        // Peel the optional trailing flags. They are peeled from the end so the
        // `<unit> @<target>` prefix stays where the operator expects it.
        loop {
            let last = tokens.last().copied();
            let flag_before = if tokens.len() >= 2 { tokens[tokens.len() - 2] } else { "" };
            match last {
                Some("--wait") => {
                    tokens.pop();
                    wait = true;
                }
                Some(value)
                    if (flag_before == "--timeout" || flag_before == "--signal") &&
                        value != "--wait" =>
                {
                    tokens.pop();
                    let flag = tokens.pop().unwrap_or_default();
                    if flag == "--timeout" {
                        let secs: u64 =
                            value.parse().map_err(|_| ParseError::InvalidDirective {
                                line,
                                directive: "reload".to_string(),
                                reason: format!("invalid seconds `{value}`"),
                            })?;
                        if secs == 0 {
                            return Err(ParseError::InvalidDirective {
                                line,
                                directive: "reload".to_string(),
                                reason: "must be greater than zero".to_string(),
                            });
                        }
                        timeout = Some(secs);
                    } else {
                        // The signal is interpolated into a remote command, so
                        // only a bare signal name is accepted.
                        if value.is_empty() ||
                            !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            return Err(ParseError::InvalidDirective {
                                line,
                                directive: "reload".to_string(),
                                reason: format!("invalid signal `{value}` (want e.g. SIGUSR1)"),
                            });
                        }
                        signal = Some(value.to_string());
                    }
                }
                Some(flag) if flag == "--timeout" || flag == "--signal" => {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "reload".to_string(),
                        reason: format!("`{flag}` expects a value"),
                    });
                }
                _ => break,
            }
        }

        if tokens.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "reload".to_string(),
                reason: "expected `<unit> @<target> [--signal SIG] [--wait] [--timeout SECS]`"
                    .to_string(),
            });
        }
        let mut unit = tokens[0].trim().to_string();
        if unit.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "reload".to_string(),
                reason: "missing unit name".to_string(),
            });
        }
        if !unit.ends_with(".service") {
            unit.push_str(".service");
        }
        if !unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':')) ||
            unit.starts_with('.') ||
            unit.contains("..")
        {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "reload".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let target = tokens[1].trim_start_matches('@').trim();
        if target.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "reload".to_string(),
                reason: "missing target".to_string(),
            });
        }
        self.last_target = Some(target.to_string());
        self.plan.steps.push(Step::Reload(ReloadStep {
            name,
            target: Target::new(target),
            unit,
            signal,
            wait,
            timeout,
        }));
        Ok(())
    }
}

/// Whether a status pattern is an exact code (`200`) or a class (`2xx`).
fn is_status_pattern(pattern: &str) -> bool {
    if pattern.len() == 3 && pattern.ends_with("xx") {
        return pattern.starts_with(|c: char| c.is_ascii_digit());
    }
    pattern.parse::<u16>().is_ok_and(|code| (100..600).contains(&code))
}

/// Normalize a unit name: `foo` becomes `foo.service`.
///
/// A bare name is the common case in a playbook, and writing `.service`
/// every time is noise the reader has to skip.
fn normalize_unit(unit: &str) -> String {
    let unit = unit.trim();
    if unit.ends_with(".service") {
        unit.to_string()
    } else {
        format!("{unit}.service")
    }
}

/// Whether a unit name is safe to hand to `systemctl`.
///
/// The name ends up inside a remote shell command, so it must not be able to
/// carry shell syntax.
fn is_safe_unit(unit: &str) -> bool {
    !unit.is_empty() &&
        !unit.starts_with('.') &&
        !unit.contains("..") &&
        unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

/// Strip one layer of surrounding `"` or `'` quotes.
///
/// A directive is a comment line, so no shell quoting applies and quotes are
/// literal characters; stripping them lets `--exclude '*.key'` read naturally.
///
/// The rule lives in [`crate::text::strip_surrounding_quotes`] so the parser
/// and the secrets crate share one definition.
fn strip_surrounding_quotes(raw: &str) -> String {
    crate::text::strip_surrounding_quotes(raw)
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
    let rest = &after_at[keyword_end..];
    // The keyword must be a whole word. `# @server-web x` is not `@server`
    // with the name `-web` — it is a malformed directive, and reporting it as
    // unknown beats silently creating a server alias named `-web`.
    if !rest.is_empty() && !rest.chars().next().is_some_and(char::is_whitespace) {
        // Report the malformed token (`server-web`), not the whole line.
        let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        return Some((format!("{keyword}{}", &rest[..token_end]), String::new()));
    }
    let payload = rest.trim();
    Some((keyword.to_string(), payload.to_string()))
}

/// Parse a deploy script into an [`ExecutionPlan`].
///
/// Lines inside a here-document body are always script content: a `# @…`
/// line there belongs to the user's data (a unit file, a template), not to
/// shellflow, so it is never interpreted as a directive.
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

        // A here-document body wins over directive detection: its lines are
        // data, and the body may not be split by a block boundary.
        if state.heredocs.consume_body(line) {
            state.pending.push(line.to_string());
            continue;
        }

        if let Some((keyword, payload)) = directive(line) {
            state.apply_directive(&keyword, &payload, line_no)?;
        } else {
            state.heredocs.open_in(line);
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
    use proptest::sample::select;

    use super::{directive, parse_script};
    use crate::{
        error::ParseError,
        plan::{
            AssertStep, Assertion, CopyStep, EnvEntry, LocalStep, RemoteStep, Step,
            WaitStep,
        },
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

    fn as_wait(step: &Step) -> Result<&WaitStep, String> {
        match step {
            Step::Wait(s) => Ok(s),
            other => Err(format!("expected wait step, got {other:?}")),
        }
    }

    fn as_assert(step: &Step) -> Result<&AssertStep, String> {
        match step {
            Step::Assert(s) => Ok(s),
            other => Err(format!("expected assert step, got {other:?}")),
        }
    }

    #[test]
    fn assert_parses_unit_and_target() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert dufs @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(step.target.text, "api");
        assert_eq!(
            step.checks,
            vec![Assertion::UnitState {
                unit: "dufs.service".to_string(),
                state: "active".to_string(),
            }]
        );
        Ok(())
    }

    #[test]
    fn assert_inherits_the_target_of_the_previous_step() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @remote api\n\
             sudo systemctl restart dufs\n\
             # @assert dufs\n",
        )?;
        let step = plan.steps.last().ok_or("no step")?;
        let assert = as_assert(step)?;
        assert_eq!(assert.target.text, "api");
        Ok(())
    }

    #[test]
    fn assert_accepts_an_explicit_state() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert dufs failed @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::UnitState {
                unit: "dufs.service".to_string(),
                state: "failed".to_string(),
            }]
        );
        Ok(())
    }

    #[test]
    fn consecutive_assertions_share_one_step() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @assert dufs @api\n\
             # @assert_health http://127.0.0.1:8080/health @api\n",
        )?;
        // Two checks, one step: the group costs one round trip.
        assert_eq!(plan.steps.len(), 1, "{:?}", plan.steps);
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(step.checks.len(), 2);
        Ok(())
    }

    #[test]
    fn an_assertion_with_its_own_name_stays_its_own_step() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @assert dufs @api\n\
             # @name second\n\
             # @assert dufs @api\n",
        )?;
        assert_eq!(plan.steps.len(), 2, "{:?}", plan.steps);
        Ok(())
    }

    #[test]
    fn assert_health_parses_the_url_and_the_expected_codes() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @assert_health http://127.0.0.1:8080/health --expect 200,204 @api\n",
        )?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::Health {
                url: "http://127.0.0.1:8080/health".to_string(),
                expect: vec!["200".to_string(), "204".to_string()],
                method: None,
                body: None,
                headers: Vec::new(),
            }]
        );
        Ok(())
    }

    #[test]
    fn assert_health_defaults_to_any_2xx_or_3xx() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_health http://x/health @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::Health {
                url: "http://x/health".to_string(),
                expect: Vec::new(),
                method: None,
                body: None,
                headers: Vec::new(),
            }]
        );
        Ok(())
    }

    #[test]
    fn assert_rejects_bad_shapes() {
        for script in [
            // No unit.
            "# @server api api\n# @assert @api\n",
            // No target and nothing to inherit from.
            "# @server api api\n# @assert dufs\n",
            // A unit name that could carry shell syntax.
            "# @server api api\n# @assert 'dufs; rm -rf /' @api\n",
            // A state that could carry shell syntax.
            "# @server api api\n# @assert dufs 'a b' @api\n",
            // Two targets.
            "# @server api api\n# @assert dufs @api @api2\n",
            // A URL that is not http.
            "# @server api api\n# @assert_health file:///etc/passwd @api\n",
            // A malformed status code.
            "# @server api api\n# @assert_health http://x/ --expect abc @api\n",
        ] {
            assert!(
                parse(script).is_err(),
                "expected an error for:\n{script}"
            );
        }
    }

    #[test]
    fn assert_port_parses_the_ports() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_port 5000 8080,9090 @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::Port { ports: vec![5000, 8080, 9090], udp: false }]
        );
        Ok(())
    }

    #[test]
    fn assert_rendered_parses_the_path() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_rendered /run/app/config.toml @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::Rendered { path: "/run/app/config.toml".to_string() }]
        );
        Ok(())
    }

    #[test]
    fn assert_port_and_rendered_inherit_the_target() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @remote api\n\
             sudo systemctl restart app\n\
             # @assert_port 8080\n\
             # @assert_rendered /run/app/config.toml\n",
        )?;
        let step = plan.steps.last().ok_or("no step")?;
        let assert = as_assert(step)?;
        assert_eq!(assert.target.text, "api");
        assert_eq!(assert.checks.len(), 2);
        Ok(())
    }

    #[test]
    fn assert_port_rejects_bad_shapes() {
        for script in [
            // No port.
            "# @server api api\n# @assert_port @api\n",
            // A port that is not a number.
            "# @server api api\n# @assert_port http @api\n",
            // Port zero.
            "# @server api api\n# @assert_port 0 @api\n",
        ] {
            assert!(parse(script).is_err(), "expected an error for:\n{script}");
        }
    }

    #[test]
    fn assert_rendered_rejects_a_relative_path() {
        let script = "# @server api api\n# @assert_rendered config.toml @api\n";
        let err = parse(script).expect_err("should fail");
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn assert_rejects_only_if() {
        let err = parse("# @server api api\n# @only_if true\n# @assert dufs @api\n")
            .expect_err("should fail");
        assert!(err.contains("@only_if"), "{err}");
    }

    #[test]
    fn wait_active_parses_unit_and_target() -> Result<(), String> {
        let plan = parse("# @server api api\n# @wait_active zenoh.service @api\n")?;
        let step = as_wait(&plan.steps[0])?;
        assert_eq!(step.unit, "zenoh.service");
        assert_eq!(step.target.text, "api");
        assert_eq!(step.interval_secs, 5);
        Ok(())
    }

    #[test]
    fn wait_active_appends_service_suffix_and_timeout() -> Result<(), String> {
        let plan = parse("# @server api api\n# @wait_active sws @api --timeout 60\n")?;
        let step = as_wait(&plan.steps[0])?;
        assert_eq!(step.unit, "sws.service");
        assert_eq!(step.timeout, Some(60));
        Ok(())
    }

    #[test]
    fn reload_parses_unit_target_and_flags() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @reload sws @api --signal SIGUSR1 --wait --timeout 60\n",
        )?;
        let step = plan.steps.first().ok_or("no step")?;
        let crate::plan::Step::Reload(reload) = step else {
            return Err("not a reload step".to_string());
        };
        assert_eq!(reload.unit, "sws.service");
        assert_eq!(reload.target.text, "api");
        assert_eq!(reload.signal.as_deref(), Some("SIGUSR1"));
        assert!(reload.wait);
        assert_eq!(reload.timeout, Some(60));
        Ok(())
    }

    #[test]
    fn reload_defaults_to_no_signal_and_no_wait() -> Result<(), String> {
        let plan = parse("# @server api api\n# @reload sws @api\n")?;
        let step = plan.steps.first().ok_or("no step")?;
        let crate::plan::Step::Reload(reload) = step else {
            return Err("not a reload step".to_string());
        };
        assert!(reload.signal.is_none());
        assert!(!reload.wait);
        Ok(())
    }

    #[test]
    fn reload_rejects_bad_shapes() {
        for bad in [
            "# @server api api\n# @reload @api\n",
            "# @server api api\n# @reload ../evil @api\n",
            "# @server api api\n# @reload sws\n",
            "# @server api api\n# @reload 'sws; id' @api\n",
            "# @server api api\n# @reload sws @api --signal 'SIG; id'\n",
            "# @server api api\n# @reload sws @api --timeout 0\n",
        ] {
            assert!(parse(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn wait_active_rejects_bad_shapes() {
        for script in [
            "# @server api api\n# @wait_active @api\n",
            "# @server api api\n# @wait_active ../evil @api\n",
            "# @server api api\n# @wait_active sws @api --timeout 0\n",
            "# @server api api\n# @wait_active sws\n",
            // A unit name is interpolated into `systemctl is-active <unit>`,
            // so anything that is not a plain unit name is refused: a space
            // or a `;` would inject a second command.
            "# @server api api\n# @wait_active 'sws; id' @api\n",
            "# @server api api\n# @wait_active 'sws id' @api\n",
            // A leading dot is not a unit name either.
            "# @server api api\n# @wait_active .hidden @api\n",
            // The `--timeout` flag needs a unit and a target beside it.
            "# @server api api\n# @wait_active --timeout 30\n",
        ] {
            parse_script(script).expect_err("malformed wait_active must fail");
        }
    }

    #[test]
    fn wait_active_accepts_a_unit_with_the_usual_punctuation() -> Result<(), String> {
        // systemd unit names carry `-`, `_`, `.`, `@` and `:`.
        let plan = parse("# @server api api\n# @wait_active my-app_2.service @api\n")?;
        let step = as_wait(&plan.steps[0])?;
        assert_eq!(step.unit, "my-app_2.service");
        Ok(())
    }

    #[test]
    fn wait_active_takes_pending_name() -> Result<(), String> {
        let plan = parse("# @server api api\n# @name ready\n# @wait_active sws @api\n")?;
        let step = as_wait(&plan.steps[0])?;
        assert_eq!(step.name.as_deref(), Some("ready"));
        Ok(())
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
        assert_eq!(copy.entries[0].src, "a/b");
        assert_eq!(copy.entries[0].dst, "/srv/c");
        assert_eq!(copy.target.text, "web");
        assert!(copy.delete);
        Ok(())
    }

    #[test]
    fn copy_with_at_prefixed_target_and_path() -> Result<(), String> {
        let plan = parse("# @copy out -> /tmp/@deploy/app @web\n")?;
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(copy.entries[0].dst, "/tmp/@deploy/app");
        assert_eq!(copy.target.text, "web");
        assert!(!copy.delete);
        Ok(())
    }

    #[test]
    fn copy_step_parses_exclude_globs() -> Result<(), String> {
        let plan = parse("# @copy services/app -> /opt/app @web --exclude *.env.age\n")?;
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(copy.entries[0].src, "services/app");
        assert_eq!(copy.entries[0].dst, "/opt/app");
        assert_eq!(copy.excludes, vec!["*.env.age"]);
        assert!(!copy.delete);
        Ok(())
    }

    #[test]
    fn copy_excludes_are_repeatable_and_combine_with_delete() -> Result<(), String> {
        let plan = parse("# @copy a -> /srv/b @web --delete --exclude *.env --exclude '*.key'\n")?;
        let copy = as_copy(&plan.steps[0])?;
        assert!(copy.delete);
        assert_eq!(copy.excludes, vec!["*.env", "*.key"]);
        Ok(())
    }

    #[test]
    fn copy_exclude_keeps_destination_with_spaces() -> Result<(), String> {
        let plan = parse("# @copy a -> /srv/my app @web --exclude *.tmp\n")?;
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(copy.entries[0].dst, "/srv/my app");
        assert_eq!(copy.excludes, vec!["*.tmp"]);
        Ok(())
    }

    #[test]
    fn copy_exclude_without_value_is_error() {
        assert!(matches!(
            parse_script("# @copy a -> b @web --exclude\n"),
            Err(ParseError::InvalidDirective { directive, .. }) if directive == "copy"
        ));
    }

    #[test]
    fn copy_exclude_rejects_empty_glob() {
        // A glob is a whitespace-delimited token, so only the empty quoted
        // forms can express "no pattern" — both must be rejected (an empty
        // rsync `--exclude` pattern is a hard rsync error).
        for empty in ["--exclude ''", "--exclude \"\""] {
            let script = format!("# @copy a -> b @web {empty}\n");
            assert!(
                matches!(
                    parse_script(&script),
                    Err(ParseError::InvalidDirective { directive, .. }) if directive == "copy"
                ),
                "expected rejection for `{empty}`"
            );
        }
    }

    #[test]
    fn copy_exclude_quotes_are_stripped_only_when_matched() -> Result<(), String> {
        // Matching quotes are stripped; a single-sided quote is a literal
        // character of the glob (rsync patterns legitimately contain neither).
        let plan = parse(
            "# @copy a -> /srv/b @web --exclude \"*.log\" --exclude '*.tmp' \
             --exclude 'oops --exclude oops'\n",
        )?;
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(copy.excludes, vec!["*.log", "*.tmp", "'oops", "oops'"]);
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
    fn export_binds_to_the_preceding_local_block_across_an_intervening_directive()
    -> Result<(), String> {
        // An intervening directive flushes the pending block (design §4.1
        // rule 1), so by the time `@export` is read the local block has
        // already been emitted. `@export` must still bind to it (design
        // §4.1 rule 4) instead of failing with "must follow a local block".
        let plan = parse(
            "# @local\n\
             VERSION=$(git rev-parse --short HEAD)\n\
             # @name build\n\
             # @export VERSION\n",
        )?;
        assert_eq!(plan.steps.len(), 1);
        let export = &as_local(&plan.steps[0])?.export;
        assert_eq!(export, &vec!["VERSION".to_string()]);
        Ok(())
    }

    #[test]
    fn export_after_a_remote_block_is_still_an_error() {
        // A remote block in between remains an error: remote variables cannot
        // be captured (design §4.1 rule 4).
        let err = parse_script("# @remote web\necho hi\n# @export X\n").expect_err("must fail");
        assert!(matches!(err, ParseError::ExportNotAfterLocal { .. }), "unexpected error: {err}");
    }

    #[test]
    fn export_after_an_intervening_remote_directive_binds_to_the_local_block() -> Result<(), String>
    {
        // `@remote` flushes the local block but does not create a remote
        // block, so the preceding block is still local and `@export` binds to
        // it.
        let plan = parse(
            "# @local\n\
             VERSION=1\n\
             # @remote web\n\
             # @export VERSION\n",
        )?;
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(as_local(&plan.steps[0])?.export, vec!["VERSION".to_string()]);
        Ok(())
    }

    #[test]
    fn copy_resets_the_block_mode_to_local() -> Result<(), String> {
        // `@copy` is a self-contained step with its own target, and design
        // §4.1 rule 3 lists it among the mode-setting directives: the lines
        // that follow must not be silently streamed to the copy's target.
        let plan = parse(
            "# @remote web\n\
             echo deploy\n\
             # @copy app -> /srv/app @web\n\
             echo after\n",
        )?;
        assert_eq!(plan.steps.len(), 3);
        assert!(matches!(plan.steps[0], Step::Remote(_)));
        assert!(matches!(plan.steps[1], Step::Copy(_)));
        let after = as_local(&plan.steps[2])?;
        assert_eq!(after.script, "echo after\n");
        Ok(())
    }

    #[test]
    fn a_directive_keyword_must_be_a_whole_word() {
        // `# @server-web x` is not `@server` with the name `-web`; it is a
        // malformed directive and must be reported as one.
        let err = parse_script("# @server-web x\n").expect_err("must fail");
        assert!(
            matches!(&err, ParseError::UnknownDirective { directive, .. } if directive == "server-web"),
            "unexpected error: {err}"
        );
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
    fn copy_rejects_only_if_guard() {
        // `@only_if` is not valid on `@copy`; the parser must reject it at
        // parse time rather than silently skipping the guard.
        assert!(matches!(
            parse_script("# @only_if test -f /etc/x\n# @copy a -> b @web\n"),
            Err(ParseError::InvalidDirective { directive, .. }) if directive == "copy"
        ));
    }

    #[test]
    fn copy_captures_env_snapshot() -> Result<(), String> {
        let plan = parse("# @env KEY=value\n# @copy a -> b @web\n")?;
        assert_eq!(plan.steps.len(), 1);
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(
            copy.env.as_ref(),
            &[EnvEntry::Literal { key: "KEY".to_string(), value: "value".to_string() }]
        );
        Ok(())
    }

    #[test]
    fn secrets_flush_pending_block_like_env() -> Result<(), String> {
        let plan = parse("# @local\necho before\n# @secrets s.age\n# @local\necho after\n")?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.secrets.len(), 1);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Here-document bodies are data, never directives
    // -----------------------------------------------------------------

    #[test]
    fn heredoc_body_directive_is_script_content() -> Result<(), String> {
        // The reported failure: a `# @remote` line inside a here-document was
        // interpreted as a real directive, so the block was redirected to a
        // host the author never named.
        let plan = parse(
            "# @local\n\
             cat <<'INNER'\n\
             # @remote web\n\
             echo pwned\n\
             INNER\n\
             echo after\n",
        )?;
        assert_eq!(plan.steps.len(), 1, "heredoc body must not split blocks");
        let step = as_local(&plan.steps[0])?;
        assert_eq!(step.script, "cat <<'INNER'\n# @remote web\necho pwned\nINNER\necho after\n");
        Ok(())
    }

    #[test]
    fn heredoc_body_cannot_shadow_a_later_directive() -> Result<(), String> {
        // A directive *after* the terminator must still take effect.
        let plan = parse(
            "# @server web1 deploy@h1\n\
             # @local\n\
             cat <<'EOF'\n\
             body\n\
             EOF\n\
             # @remote web1\n\
             echo deployed\n",
        )?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].target_text(), Some("web1"));
        Ok(())
    }

    #[test]
    fn heredoc_body_cannot_break_the_plan() -> Result<(), String> {
        // An unknown directive inside a body is data, so parsing succeeds.
        let plan = parse("# @local\ncat <<EOF\n# @frobnicate x\nEOF\n")?;
        assert_eq!(plan.steps.len(), 1);
        assert!(as_local(&plan.steps[0])?.script.contains("# @frobnicate x"));
        Ok(())
    }

    #[test]
    fn indented_heredoc_body_is_protected() -> Result<(), String> {
        let plan = parse("# @local\ncat <<-EOF\n\t# @remote web\n\tEOF\necho done\n")?;
        assert_eq!(plan.steps.len(), 1);
        assert!(as_local(&plan.steps[0])?.script.contains("# @remote web"));
        Ok(())
    }

    #[test]
    fn space_indented_terminator_does_not_close_a_plain_heredoc() -> Result<(), String> {
        // Only tabs close a `<<-` body; a space-indented `EOF` is body text,
        // so the trailing directive stays inside the block.
        let plan = parse("# @local\ncat <<-EOF\nbody\n  EOF\n# @remote web\n")?;
        assert_eq!(plan.steps.len(), 1);
        Ok(())
    }

    #[test]
    fn two_heredocs_on_one_line_are_both_tracked() -> Result<(), String> {
        let plan = parse(
            "# @local\n\
             diff <(cat <<A) <(cat <<B)\n\
             # @remote web\n\
             A\n\
             # @remote web\n\
             B\n\
             echo done\n",
        )?;
        assert_eq!(plan.steps.len(), 1);
        Ok(())
    }

    #[test]
    fn here_string_is_not_a_heredoc() -> Result<(), String> {
        // `<<<` has no body: the following directive is still a directive.
        let plan = parse("# @local\ngrep x <<<\"$body\"\n# @remote web\necho hi\n")?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].target_text(), Some("web"));
        Ok(())
    }

    #[test]
    fn quoted_heredoc_opener_in_a_string_is_ignored() -> Result<(), String> {
        let plan = parse("# @local\necho 'a << b'\n# @remote web\necho hi\n")?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].target_text(), Some("web"));
        Ok(())
    }

    #[test]
    fn heredoc_opener_in_a_comment_is_ignored() -> Result<(), String> {
        let plan = parse("# @local\necho hi\n# see <<EOF for details\n# @remote web\necho hi\n")?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].target_text(), Some("web"));
        Ok(())
    }

    /// Every malformed directive is rejected at parse time with an error that
    /// names the directive and the 1-based line. One row per validation branch,
    /// so a new rejection path cannot ship without a case.
    #[test]
    fn malformed_directives_name_the_directive_and_reason() {
        // (script, directive the error must name, reason fragment)
        let cases: &[(&str, &str, &str)] = &[
            ("# @remote\n", "remote", "missing target"),
            ("# @timeout soon\n", "timeout", "invalid seconds"),
            ("# @timeout 0\n", "timeout", "greater than zero"),
            ("# @name\n", "name", "missing label"),
            ("# @only_if\n", "only_if", "missing command"),
            ("# @server\n", "server", "missing name"),
            ("# @server web1\n", "server", "missing ssh spec"),
            ("# @server web1 host extra\n", "server", "too many arguments"),
            ("# @group\n", "group", "missing name"),
            ("# @group web\n", "group", "missing members"),
            ("# @group web web1 extra\n", "group", "too many arguments"),
            ("# @group web ,\n", "group", "no members"),
            ("# @env\n", "env", "missing variable"),
            ("# @env 1BAD=value\n", "env", "invalid variable name"),
            ("# @env 1BAD\n", "env", "invalid variable name"),
            ("# @secrets\n", "secrets", "missing encrypted file path"),
            ("# @secrets f.env.age --identity\n", "secrets", "`--identity` requires a path"),
            ("# @secrets f.env.age --bogus\n", "secrets", "unexpected token"),
            ("# @export\n", "export", "missing variable name"),
            ("# @export 1BAD\n", "export", "invalid variable name"),
            ("# @copy a b @web\n", "copy", "expected `src -> dst"),
            ("# @copy  -> /dst @web\n", "copy", "missing source path"),
            ("# @copy a -> @web\n", "copy", "missing destination path"),
            ("# @copy a ->\n", "copy", "missing target"),
            ("# @copy a -> /dst @\n", "copy", "missing target"),
            ("# @copy a -> /dst @web --exclude\n", "copy", "`--exclude` requires a glob"),
            ("# @copy a -> /dst @web --exclude ''\n", "copy", "glob must not be empty"),
        ];
        for (script, directive, reason) in cases {
            let err = match parse_script(script) {
                Err(err) => err,
                Ok(_) => panic!("`{script}` must not parse"),
            };
            let message = err.to_string();
            assert!(
                message.contains(&format!("invalid `@{directive}` directive")),
                "`{script}`: error should name `@{directive}`, got `{message}`"
            );
            assert!(
                message.contains(reason),
                "`{script}`: error should say `{reason}`, got `{message}`"
            );
            assert!(
                message.starts_with("line 1:"),
                "`{script}`: error should report line 1, got `{message}`"
            );
        }
    }

    #[test]
    fn error_reports_the_offending_line_number() {
        // The line number is what an operator acts on, so it must be the
        // directive's own line, not the first or last line of the script.
        let err = parse_script("# @local\necho hi\n# @timeout 0\n").expect_err("must fail");
        assert!(err.to_string().starts_with("line 3:"), "unexpected error: {err}");
    }

    #[test]
    fn copy_rejects_a_guard_at_parse_time() {
        let err = parse_script("# @only_if test -f /etc/app.conf\n# @copy a -> b @web\n")
            .expect_err("a guard on a copy step must be rejected");
        let message = err.to_string();
        assert!(message.contains("invalid `@copy` directive"), "unexpected error: {message}");
        assert!(message.contains("only_if"), "unexpected error: {message}");
    }

    #[test]
    fn copy_parses_quoted_and_bare_exclude_globs() -> Result<(), String> {
        // Quotes around a glob are literal characters in a comment line and are
        // stripped; a bare glob is taken as written.
        let plan =
            parse("# @copy ./out -> /srv/app @web --delete --exclude '*.key' --exclude *.log\n")?;
        let step = as_copy(&plan.steps[0])?;
        assert!(step.delete, "--delete should be recorded");
        assert_eq!(step.excludes, vec!["*.key".to_string(), "*.log".to_string()]);
        Ok(())
    }

    #[test]
    fn copy_keeps_excludes_in_written_order() -> Result<(), String> {
        // Flags are peeled from the right, then restored, so the recorded order
        // matches what the playbook says.
        let plan = parse("# @copy ./out -> /srv/app @web --exclude a --exclude b --exclude c\n")?;
        let step = as_copy(&plan.steps[0])?;
        assert_eq!(step.excludes, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        Ok(())
    }

    #[test]
    fn group_colliding_with_a_server_name_is_rejected() {
        let err = parse_script("# @server web1 deploy@10.0.0.1\n# @group web1 web1\n")
            .expect_err("a group may not shadow a server alias");
        assert!(err.to_string().contains("collides"), "unexpected error: {err}");
    }

    #[test]
    fn duplicate_group_is_rejected() {
        let err = parse_script("# @group web web1\n# @group web web2\n")
            .expect_err("a group may not be defined twice");
        assert!(err.to_string().contains("already defined"), "unexpected error: {err}");
    }

    #[test]
    fn secrets_directive_parses_an_explicit_identity() -> Result<(), String> {
        let plan = parse("# @secrets services/app/api.env.age --identity /keys/app.txt\n")?;
        assert_eq!(plan.secrets.len(), 1);
        assert_eq!(plan.secrets[0].file, "services/app/api.env.age");
        assert_eq!(plan.secrets[0].identity.as_deref(), Some("/keys/app.txt"));
        Ok(())
    }

    #[test]
    fn unterminated_heredoc_consumes_the_rest() -> Result<(), String> {
        // Bash warns and treats EOF as the terminator; matching that keeps
        // shellflow from inventing a directive the shell never saw.
        let plan = parse("# @local\ncat <<EOF\n# @remote web\n")?;
        assert_eq!(plan.steps.len(), 1);
        Ok(())
    }

    #[test]
    fn crlf_heredoc_terminator_is_recognized() -> Result<(), String> {
        let plan = parse(
            "# @local\r\ncat <<'EOF'\r\n# @remote web\r\nEOF\r\n# @remote web2\r\necho hi\r\n",
        )?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].target_text(), Some("web2"));
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

        /// A here-document body containing a directive line never splits the
        /// plan, whatever the body holds.
        #[test]
        fn heredoc_body_never_creates_a_step(
            // Every candidate is deliberately directive-looking or a
            // near-miss terminator; none is exactly `EOF`.
            body in proptest::collection::vec(
                select(vec!["body line", "# @remote web", "# comment", "EOFX", "  EOF", "text"]),
                1..6,
            ),
        ) {
            let body = body.join("\n");
            let block = format!("cat <<'EOF'\n{body}\nEOF\n");
            let plan = parse_prop(&format!("# @local\n{block}"))?;
            proptest::prop_assert_eq!(plan.steps.len(), 1);
            let step = as_local(&plan.steps[0])
                .map_err(proptest::prelude::TestCaseError::fail)?;
            // The whole opener..terminator span survives verbatim, so no body
            // line can have been promoted to a directive.
            proptest::prop_assert_eq!(step.script.as_str(), block.as_str());
        }

        /// The terminator closes the body, so a directive on the next line is
        /// honored exactly once.
        #[test]
        fn directive_after_terminator_applies(
            body in proptest::collection::vec("[a-z]{1,20}", 1..5),
        ) {
            let body = body.join("\n");
            let script = format!("# @local\ncat <<'EOF'\n{body}\nEOF\n# @remote web\necho hi\n");
            let plan = parse_prop(&script)?;
            proptest::prop_assert_eq!(plan.steps.len(), 2);
            proptest::prop_assert_eq!(plan.steps[1].target_text(), Some("web"));
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
