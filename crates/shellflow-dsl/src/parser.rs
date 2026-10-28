//! Single-pass line scanner that turns a Bash deploy script into an
//! [`ExecutionPlan`].

use std::{collections::BTreeMap, sync::Arc};

use crate::{
    error::ParseError,
    heredoc::HeredocTracker,
    is_valid_unit_name, is_valid_var_name, normalize_unit,
    plan::{
        ActiveState, AssertStep, Assertion, BackupStep, BuildStep, CopyEntry, CopyStep,
        CredstoreStep, EnabledState, EnvEntry, ExecutionPlan, ExportVar, HelperStep, ImageStep,
        InstallStep, LocalStep, ReleaseStep, ReloadStep, RemoteStep, SecretEntry, ServiceStep,
        Step, Target, ToolchainStep, UnitInventoryStep, WaitStep, Workdir,
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
    /// Script line of the `@remote` that set `target`.
    target_line: usize,
    /// Lines of the current (unflushed) block.
    pending: Vec<String>,
    /// `@name` for the next block.
    pending_name: Option<String>,
    /// `@only_if` guard for the next block.
    pending_guard: Option<String>,
    /// `@timeout` for the next block.
    pending_timeout: Option<u64>,
    /// `@export` variables for the pending local block.
    pending_export: Vec<ExportVar>,
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
            target_line: 0,
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
                target: Target::at(self.target.clone(), self.target_line),
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
        // Every directive except `@export` flushes the pending block first.
        // The rule lives here, once, instead of being repeated in each arm:
        // a new directive cannot forget it and silently merge blocks.
        // (`@export` binds to the *preceding* local block, so it must not
        // flush — design §4.1 rule 4.)
        if keyword != "export" {
            self.flush();
        }
        match keyword {
            "server" => self.declare_server(payload, line),
            "group" => self.declare_group(payload, line),
            "env" => self.declare_env(payload, line),
            "secrets" => self.declare_secrets(payload, line),
            "local" => {
                self.mode = Mode::Local;
                self.target.clear();
                self.target_line = 0;
                Ok(())
            }
            "remote" => {
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
                self.target_line = line;
                Ok(())
            }
            "copy" => {
                // A copy step is self-contained: it carries its own target in
                // its payload and is not a script block. The block mode
                // therefore returns to `local` (design §4.1 rule 3 lists
                // `@copy` among the mode-setting directives), so the lines
                // that follow are not silently streamed to the copy's remote
                // target.
                self.mode = Mode::Local;
                self.target.clear();
                self.target_line = 0;
                self.add_copy(payload, line)
            }
            "wait_active" => self.add_wait(payload, line),
            "reload" => self.add_reload(payload, line),
            "assert" => self.add_assert(payload, line),
            "assert_health" => self.add_assert_health(payload, line),
            "assert_port" => self.add_assert_port(payload, line),
            "assert_port_free" => self.add_assert_port_free(payload, line),
            "assert_enabled" => self.add_assert_enabled(payload, line),
            "assert_rendered" => self.add_assert_rendered(payload, line),
            "service" => self.add_service(payload, line),
            "install" => self.add_install(payload, line),
            "backup" => self.add_backup(payload, line),
            "credstore" => self.add_credstore(payload, line),
            "assert_no_leak" => self.add_assert_no_leak(payload, line),
            "assert_digest" => self.add_assert_digest(payload, line),
            "assert_credstore" => self.add_assert_credstore(payload, line),
            "unit_inventory" => self.add_unit_inventory(payload, line),
            "helper" => self.add_helper(payload, line),
            "release" => self.add_release(payload, line),
            "build" => self.add_build(payload, line),
            "toolchain" => self.add_toolchain(payload, line),
            "image" => self.add_image(payload, line),
            "workdir" => self.add_workdir(payload, line),
            "export" => self.declare_export(payload, line),
            "timeout" => {
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
        let mut parts = split_words(payload).into_iter();
        let name = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "server".to_string(),
            reason: "missing name".to_string(),
        })?;
        let name = name.as_str();
        if !is_valid_alias_name(name) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "server".to_string(),
                reason: format!(
                    "invalid server name `{name}` (allowed: letters, digits, `_`, `-`, `.`)"
                ),
            });
        }
        let spec = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "server".to_string(),
            reason: format!("missing ssh spec for `{name}`"),
        })?;
        let spec = spec.as_str();
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
        let mut parts = split_words(payload).into_iter();
        let name = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "group".to_string(),
            reason: "missing name".to_string(),
        })?;
        let name = name.as_str();
        if !is_valid_alias_name(name) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "group".to_string(),
                reason: format!(
                    "invalid group name `{name}` (allowed: letters, digits, `_`, `-`, `.`)"
                ),
            });
        }
        let members = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "group".to_string(),
            reason: format!("missing members for `{name}`"),
        })?;
        let members = members.as_str();
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
        let raw_members: Vec<String> = members
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if raw_members.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "group".to_string(),
                reason: format!("no members for `{name}`"),
            });
        }
        if raw_members.iter().any(|m| m == name) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "group".to_string(),
                reason: format!("group `{name}` cannot contain itself"),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut members: Vec<String> = Vec::with_capacity(raw_members.len());
        for member in raw_members {
            if !is_valid_alias_name(&member) {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "group".to_string(),
                    reason: format!("invalid member `{member}` in group `{name}`"),
                });
            }
            if seen.insert(member.clone()) {
                members.push(member);
            }
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
            // A value of `KEY= value` keeps the space: shell assignment would
            // too. Documented in `docs/design.md` §4.4.
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
        let mut parts = split_words(payload).into_iter();
        let file = parts.next().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "secrets".to_string(),
            reason: "missing encrypted file path".to_string(),
        })?;

        let mut identity: Option<String> = None;
        while let Some(token) = parts.next() {
            match token.as_str() {
                "--identity" => {
                    let value = parts.next().ok_or_else(|| ParseError::InvalidDirective {
                        line,
                        directive: "secrets".to_string(),
                        reason: "`--identity` requires a path".to_string(),
                    })?;
                    identity = Some(value);
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

        self.plan.secrets.push(SecretEntry { file, identity });
        Ok(())
    }

    fn declare_export(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        // `# @export <name>[,<name>…] [--public]`.
        //
        // A captured value is masked by default: it is a runtime value, and a
        // playbook routinely exports credentials it just fetched. `--public`
        // is the explicit opt-out for values that are meant to be printed
        // (`VERSION`, `COMMIT`) — the exemption is then visible in the
        // playbook instead of hidden in a name heuristic inside the engine.
        // Same flag parser as every other directive, so `--public` is a flag
        // wherever it stands instead of only as a trailing suffix, and a
        // quoted name survives.
        let (positional, flags) = split_flags(payload, &["--public"], "export", line)?;
        // `split_flags` hands unknown flags back (rather than consuming them)
        // so each directive can name the one it does not accept.
        if let Some((flag, _)) = flags.iter().find(|(flag, _)| flag != "--public") {
            return Err(unknown_flag("export", flag, line));
        }
        let public = flags.iter().any(|(flag, _)| flag == "--public");
        let names = match positional.as_slice() {
            [names] => names.as_str(),
            [] => {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "export".to_string(),
                    reason: "missing variable name(s)".to_string(),
                });
            }
            [_, extra, ..] => {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "export".to_string(),
                    reason: format!("unexpected token `{extra}`"),
                });
            }
        };
        let vars: Vec<ExportVar> = names
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| ExportVar { name: v.to_string(), public })
            .collect();
        if vars.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "export".to_string(),
                reason: "missing variable name(s)".to_string(),
            });
        }
        for var in &vars {
            if !is_valid_var_name(&var.name) {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "export".to_string(),
                    reason: format!("invalid variable name `{}`", var.name),
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
        reject_guard(self.pending_guard.is_some(), "copy", line)?;
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
        // The target is the last positional once the flags are split off;
        // a dst with spaces is joined from the remaining positional tokens.
        let (positional, flags) = split_flags(rest, &["--delete"], "copy", line)?;
        let mut delete = false;
        let mut excludes: Vec<String> = Vec::new();
        for (flag, value) in &flags {
            match flag.as_str() {
                "--delete" => delete = true,
                "--exclude" => {
                    let glob = flag_value(value, flag, "copy", line)?;
                    let glob = shellflow_text::strip_surrounding_quotes(glob).trim().to_string();
                    if glob.is_empty() {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "copy".to_string(),
                            reason: "`--exclude` glob must not be empty".to_string(),
                        });
                    }
                    excludes.push(glob);
                }
                other => {
                    return Err(unknown_flag("copy", other, line));
                }
            }
        }
        let target = positional.last().ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "copy".to_string(),
            reason: "missing target".to_string(),
        })?;
        let target = target.trim_start_matches('@').trim().to_string();
        if target.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "copy".to_string(),
                reason: "missing target".to_string(),
            });
        }

        let dst = positional[..positional.len() - 1].join(" ");
        if dst.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "copy".to_string(),
                reason: "missing destination path".to_string(),
            });
        }

        self.last_target = Some(target.clone());
        let entry = CopyEntry { src: src.to_string(), dst };
        // Consecutive copies that share a target *and* their options travel
        // in one transfer: a playbook that ships five templates to the same
        // directory costs one round trip instead of five. The env snapshot is
        // part of the merge key: an intervening `@env` changes the transfer
        // environment, so it must start a new step.
        let mergeable = name.is_none() &&
            self.plan.steps.last().is_some_and(|step| {
                matches!(step, Step::Copy(existing)
                    if existing.target.text == target
                        && existing.delete == delete
                        && existing.excludes == excludes
                        && existing.timeout == timeout
                        && *existing.env == *env)
            });
        if mergeable && let Some(Step::Copy(existing)) = self.plan.steps.last_mut() {
            existing.entries.push(entry);
            return Ok(());
        }
        self.plan.steps.push(Step::Copy(CopyStep {
            name,
            entries: vec![entry],
            target: Target::at(target, line),
            delete,
            excludes,
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
        reject_guard(self.pending_guard.is_some(), "wait_active", line)?;
        let name = self.pending_name.take();
        let pending_timeout = self.pending_timeout.take();
        let (positional, flags) = split_flags(payload, &[], "wait_active", line)?;
        let mut timeout = pending_timeout;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--timeout" => {
                    let secs = flag_value(value, flag, "wait_active", line)?;
                    timeout = Some(parse_secs(secs, "wait_active", line)?);
                }
                other => {
                    return Err(unknown_flag("wait_active", other, line));
                }
            }
        }
        if positional.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: "expected `<unit> @<target> [--timeout SECS]`".to_string(),
            });
        }
        let unit = normalize_unit(&positional[0]);
        if !is_valid_unit_name(&unit) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "wait_active".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let target = require_target(&positional[1], "wait_active", line)?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Wait(WaitStep {
            name,
            target: Target::at(target, line),
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
        reject_guard(self.pending_guard.is_some(), "assert", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut unit: Option<String> = None;
        let mut state: Option<String> = None;
        let mut target: Option<String> = None;
        for token in split_words(payload) {
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
                unit = Some(token);
            } else if state.is_none() {
                state = Some(token);
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
        if !is_valid_unit_name(&unit) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        // A closed set, not a charset check: `@assert foo banana` used to
        // parse and then fail on the target, because the two assertion
        // directives validated their state with different strengths.
        let state = match state {
            Some(raw) => ActiveState::parse(&raw).ok_or_else(|| ParseError::InvalidDirective {
                line,
                directive: "assert".to_string(),
                reason: format!("invalid state `{raw}` (expected {})", ActiveState::legal()),
            })?,
            None => ActiveState::Active,
        };
        let target = self.resolve_assert_target(target, "assert", line)?;
        self.push_assertion(name, target, line, Assertion::UnitState { unit, state }, timeout);
        Ok(())
    }

    /// Parse `# @assert_health <url> [@<target>] [--expect CODES]`.
    ///
    /// The URL must be an `http`/`https` address. The accepted status codes
    /// default to any 2xx or 3xx; `--expect 200,204` narrows them.
    fn add_assert_health(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "assert_health", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut url: Option<String> = None;
        let mut target: Option<String> = None;
        let mut expect: Vec<String> = Vec::new();
        let mut method: Option<String> = None;
        let mut body: Option<String> = None;
        let mut headers: Vec<String> = Vec::new();
        let mut tokens = split_words(payload).into_iter();
        while let Some(token) = tokens.next() {
            match token.as_str() {
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
                    body = Some(shellflow_text::strip_surrounding_quotes(&raw));
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
                    headers.push(shellflow_text::strip_surrounding_quotes(&raw));
                }
                other if other.starts_with("--") => {
                    return Err(unknown_flag("assert_health", other, line));
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
                    url = Some(shellflow_text::strip_surrounding_quotes(other));
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
            line,
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
        reject_guard(self.pending_guard.is_some(), "assert_port", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut ports: Vec<u16> = Vec::new();
        let mut target: Option<String> = None;
        let mut udp = false;
        for token in split_words(payload) {
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
        self.push_assertion(name, target, line, Assertion::Port { ports, udp }, timeout);
        Ok(())
    }

    /// Parse `# @assert_rendered <path> [@<target>]`.
    ///
    /// The file must exist and hold no unexpanded `${…}` placeholder: a
    /// rendered config that still carries a placeholder is a config that
    /// was never rendered.
    fn add_assert_rendered(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "assert_rendered", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut path: Option<String> = None;
        let mut target: Option<String> = None;
        for token in split_words(payload) {
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
            path = Some(shellflow_text::strip_surrounding_quotes(&token));
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
        self.push_assertion(name, target, line, Assertion::Rendered { path }, timeout);
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
            let trimmed = target.trim_start_matches('@').trim();
            if trimmed.is_empty() {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: directive.to_string(),
                    reason: "missing target".to_string(),
                });
            }
            return Ok(trimmed.to_string());
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
        line: usize,
        check: Assertion,
        timeout: Option<u64>,
    ) {
        let mergeable = name.is_none() &&
            self.plan.steps.last().is_some_and(|step| {
                matches!(step, Step::Assert(existing)
                    if existing.target.text == target && existing.timeout == timeout)
            });
        if mergeable && let Some(Step::Assert(existing)) = self.plan.steps.last_mut() {
            existing.checks.push(check);
            return;
        }
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Assert(AssertStep {
            name,
            target: Target::at(target, line),
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
        reject_guard(self.pending_guard.is_some(), "reload", line)?;
        let name = self.pending_name.take();
        let mut timeout = self.pending_timeout.take();
        let (positional, flags) = split_flags(payload, &["--wait"], "reload", line)?;
        let mut signal: Option<String> = None;
        let mut wait = false;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--wait" => wait = true,
                "--timeout" => {
                    let secs = flag_value(value, flag, "reload", line)?;
                    timeout = Some(parse_secs(secs, "reload", line)?);
                }
                "--signal" => {
                    // The signal is interpolated into a remote command, so
                    // only a bare signal name is accepted.
                    let sig = flag_value(value, flag, "reload", line)?;
                    if sig.is_empty() || !sig.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "reload".to_string(),
                            reason: format!("invalid signal `{sig}` (want e.g. SIGUSR1)"),
                        });
                    }
                    signal = Some(sig.to_string());
                }
                other => {
                    return Err(unknown_flag("reload", other, line));
                }
            }
        }

        if positional.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "reload".to_string(),
                reason: "expected `<unit> @<target> [--signal SIG] [--wait] [--timeout SECS]`"
                    .to_string(),
            });
        }
        let unit = normalize_unit(&positional[0]);
        if !is_valid_unit_name(&unit) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "reload".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let target = require_target(&positional[1], "reload", line)?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Reload(ReloadStep {
            name,
            target: Target::at(target, line),
            unit,
            signal,
            wait,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @service <unit> @<target> [--enable] [--restart] [--reload]
    /// [--wait] [--verify] [--force-start] [--timeout SECS]`.
    ///
    /// The step owns the whole lifecycle sequence, including the rule that
    /// the shell spelling got wrong: `--restart` never *starts* a unit that
    /// was not running. `--force-start` overrides that deliberately.
    fn add_service(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "service", line)?;
        let name = self.pending_name.take();
        let mut timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(
            payload,
            &["--enable", "--restart", "--reload", "--wait", "--verify", "--force-start"],
            "service",
            line,
        )?;

        let mut enable = false;
        let mut restart = false;
        let mut reload = false;
        let mut wait = false;
        let mut verify = false;
        let mut force_start = false;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--enable" => enable = true,
                "--restart" => restart = true,
                "--reload" => reload = true,
                "--wait" => wait = true,
                "--verify" => verify = true,
                "--force-start" => force_start = true,
                "--timeout" => {
                    let secs = flag_value(value, flag, "service", line)?;
                    timeout = Some(parse_secs(secs, "service", line)?);
                }
                other => {
                    return Err(unknown_flag("service", other, line));
                }
            }
        }

        if positional.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "service".to_string(),
                reason: "expected `<unit> @<target> [--enable] [--restart] [--reload] [--wait] \
                         [--verify] [--force-start]`"
                    .to_string(),
            });
        }
        let unit = normalize_unit(&positional[0]);
        if !is_valid_unit_name(&unit) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "service".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let target = require_target(&positional[1], "service", line)?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Service(ServiceStep {
            name,
            target: Target::at(target, line),
            unit,
            enable,
            restart,
            reload,
            wait,
            verify,
            force_start,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @install <src> -> <dst> @<target> [--mode M] [--owner U:G]
    /// [--dir-mode M]`.
    ///
    /// Both paths live **on the target**: the file is shipped by `@copy` and
    /// then installed in place, atomically.
    fn add_install(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "install", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (src, rest) = payload.split_once("->").ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "install".to_string(),
            reason: "expected `src -> dst @target [--mode M] [--owner U:G]`".to_string(),
        })?;
        let src = src.trim();
        if src.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "install".to_string(),
                reason: "missing source path".to_string(),
            });
        }

        let (positional, flags) = split_flags(rest, &[], "install", line)?;
        let mut mode = None;
        let mut owner = None;
        let mut dir_mode = None;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--mode" => {
                    let raw = flag_value(value, flag, "install", line)?;
                    mode = Some(parse_mode(raw, "install", line)?);
                }
                "--dir-mode" => {
                    let raw = flag_value(value, flag, "install", line)?;
                    dir_mode = Some(parse_mode(raw, "install", line)?);
                }
                "--owner" => {
                    let raw = flag_value(value, flag, "install", line)?;
                    owner = Some(parse_owner(raw, "install", line)?);
                }
                other => {
                    return Err(unknown_flag("install", other, line));
                }
            }
        }

        if positional.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "install".to_string(),
                reason: "expected `src -> dst @target [--mode M] [--owner U:G] [--dir-mode M]`"
                    .to_string(),
            });
        }
        let dst = positional[0].trim();
        if !dst.starts_with('/') {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "install".to_string(),
                reason: format!("the destination must be absolute (got `{dst}`)"),
            });
        }
        let target = require_target(&positional[1], "install", line)?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Install(InstallStep {
            name,
            target: Target::at(target, line),
            src: src.to_string(),
            dst: dst.to_string(),
            mode,
            owner,
            dir_mode,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @backup <path>… @<target> [--keep N] [--seal] [--dir PATH]`.
    fn add_backup(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "backup", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &["--seal"], "backup", line)?;
        let mut keep = None;
        let mut seal = false;
        let mut dir = None;
        let mut service = None;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--keep" => {
                    let raw = flag_value(value, flag, "backup", line)?;
                    let parsed: u32 = raw.parse().map_err(|_| ParseError::InvalidDirective {
                        line,
                        directive: "backup".to_string(),
                        reason: format!("invalid keep count `{raw}`"),
                    })?;
                    if parsed == 0 {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "backup".to_string(),
                            reason: "`--keep` must be greater than zero".to_string(),
                        });
                    }
                    keep = Some(parsed);
                }
                "--seal" => seal = true,
                "--service" => {
                    let raw = flag_value(value, flag, "backup", line)?;
                    if !is_valid_unit_name(raw) {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "backup".to_string(),
                            reason: format!("unsafe service name `{raw}`"),
                        });
                    }
                    service = Some(raw.to_string());
                }
                "--dir" => {
                    let raw = flag_value(value, flag, "backup", line)?;
                    dir = Some(raw.to_string());
                }
                other => {
                    return Err(unknown_flag("backup", other, line));
                }
            }
        }

        if positional.len() < 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "backup".to_string(),
                reason: "expected `<path>… @<target> [--keep N] [--seal] [--dir PATH]`".to_string(),
            });
        }
        // The target is the last positional argument; everything before it is
        // a path to snapshot.
        let target = require_target(&positional[positional.len() - 1], "backup", line)?;
        let paths: Vec<String> = positional[..positional.len() - 1].to_vec();
        for path in &paths {
            if !path.starts_with('/') {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "backup".to_string(),
                    reason: format!("the path must be absolute (got `{path}`)"),
                });
            }
        }
        if let Some(dir) = &dir &&
            !dir.starts_with('/')
        {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "backup".to_string(),
                reason: format!("the snapshot directory must be absolute (got `{dir}`)"),
            });
        }
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Backup(BackupStep {
            name,
            target: Target::at(target, line),
            paths,
            service,
            keep,
            seal,
            dir,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @credstore <service> @<target> [--require KEY,…]`.
    fn add_credstore(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "credstore", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &[], "credstore", line)?;
        let mut require: Vec<String> = Vec::new();
        for (flag, value) in &flags {
            match flag.as_str() {
                "--require" => {
                    let raw = flag_value(value, flag, "credstore", line)?;
                    for key in raw.split(',') {
                        let key = key.trim();
                        if key.is_empty() {
                            continue;
                        }
                        if !is_valid_var_name(key) {
                            return Err(ParseError::InvalidDirective {
                                line,
                                directive: "credstore".to_string(),
                                reason: format!("invalid credential key `{key}`"),
                            });
                        }
                        require.push(key.to_string());
                    }
                }
                other => {
                    return Err(unknown_flag("credstore", other, line));
                }
            }
        }
        if positional.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "credstore".to_string(),
                reason: "expected `<service> @<target> [--require KEY,…]`".to_string(),
            });
        }
        let service = positional[0].trim().to_string();
        if !is_valid_unit_name(&service) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "credstore".to_string(),
                reason: format!("unsafe service name `{service}`"),
            });
        }
        let target = require_target(&positional[1], "credstore", line)?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Credstore(CredstoreStep {
            name,
            target: Target::at(target, line),
            service,
            require,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @assert_no_leak <unit> [@<target>] [--lines N]`.
    fn add_assert_no_leak(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "assert_no_leak", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &[], "assert_no_leak", line)?;
        let mut lines = None;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--lines" => {
                    let raw = flag_value(value, flag, "assert_no_leak", line)?;
                    let parsed: u64 = raw.parse().map_err(|_| ParseError::InvalidDirective {
                        line,
                        directive: "assert_no_leak".to_string(),
                        reason: format!("invalid line count `{raw}`"),
                    })?;
                    if parsed == 0 {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_no_leak".to_string(),
                            reason: "`--lines` must be greater than zero".to_string(),
                        });
                    }
                    lines = Some(parsed);
                }
                other => {
                    return Err(unknown_flag("assert_no_leak", other, line));
                }
            }
        }
        if positional.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_no_leak".to_string(),
                reason: "missing unit name".to_string(),
            });
        }
        let unit = normalize_unit(&positional[0]);
        if !is_valid_unit_name(&unit) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_no_leak".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let target = self.resolve_assert_target(
            positional.get(1).map(|t| t.trim_start_matches('@').trim().to_string()),
            "assert_no_leak",
            line,
        )?;
        self.push_assertion(name, target, line, Assertion::NoLeak { unit, lines }, timeout);
        Ok(())
    }

    /// Parse `# @assert_digest <path> [@<target>] [--sha256 HEX] [--local PATH]`.
    fn add_assert_digest(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "assert_digest", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &[], "assert_digest", line)?;
        let mut sha256 = None;
        let mut local = None;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--sha256" => {
                    let raw = flag_value(value, flag, "assert_digest", line)?;
                    let hex = raw.trim().to_ascii_lowercase();
                    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "assert_digest".to_string(),
                            reason: format!("`--sha256` wants 64 hex characters (got `{raw}`)"),
                        });
                    }
                    sha256 = Some(hex);
                }
                "--local" => {
                    let raw = flag_value(value, flag, "assert_digest", line)?;
                    local = Some(raw.to_string());
                }
                other => {
                    return Err(unknown_flag("assert_digest", other, line));
                }
            }
        }
        if positional.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_digest".to_string(),
                reason: "missing path".to_string(),
            });
        }
        let path = positional[0].trim().to_string();
        if !path.starts_with('/') {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_digest".to_string(),
                reason: format!("the path must be absolute (got `{path}`)"),
            });
        }
        let target = self.resolve_assert_target(
            positional.get(1).map(|t| t.trim_start_matches('@').trim().to_string()),
            "assert_digest",
            line,
        )?;
        self.push_assertion(name, target, line, Assertion::Digest { path, sha256, local }, timeout);
        Ok(())
    }

    /// Parse `# @assert_credstore <service> [@<target>]`.
    fn add_assert_credstore(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "assert_credstore", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, _flags) = split_flags(payload, &[], "assert_credstore", line)?;
        if positional.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_credstore".to_string(),
                reason: "missing service name".to_string(),
            });
        }
        let service = positional[0].trim().to_string();
        if !is_valid_unit_name(&service) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_credstore".to_string(),
                reason: format!("unsafe service name `{service}`"),
            });
        }
        let target = self.resolve_assert_target(
            positional.get(1).map(|t| t.trim_start_matches('@').trim().to_string()),
            "assert_credstore",
            line,
        )?;
        self.push_assertion(name, target, line, Assertion::Credstore { service }, timeout);
        Ok(())
    }

    /// Parse `# @unit_inventory [@<target>]`.
    fn add_unit_inventory(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "unit_inventory", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, _flags) = split_flags(payload, &[], "unit_inventory", line)?;
        let target = self.resolve_assert_target(
            positional.first().map(|t| t.trim_start_matches('@').trim().to_string()),
            "unit_inventory",
            line,
        )?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::UnitInventory(UnitInventoryStep {
            name,
            target: Target::at(target, line),
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @helper [@<target>] [--source DIR] [--triple T]
    /// [--install-path PATH]`.
    fn add_helper(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "helper", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &[], "helper", line)?;
        let mut source = None;
        let mut triple = None;
        let mut install_path = "/usr/local/bin/shellflow".to_string();
        for (flag, value) in &flags {
            match flag.as_str() {
                "--source" => {
                    let raw = flag_value(value, flag, "helper", line)?;
                    source = Some(raw.to_string());
                }
                "--triple" => {
                    let raw = flag_value(value, flag, "helper", line)?;
                    triple = Some(raw.to_string());
                }
                "--install-path" => {
                    let raw = flag_value(value, flag, "helper", line)?;
                    if !raw.starts_with('/') {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "helper".to_string(),
                            reason: format!("the install path must be absolute (got `{raw}`)"),
                        });
                    }
                    install_path = raw.to_string();
                }
                other => {
                    return Err(unknown_flag("helper", other, line));
                }
            }
        }
        if positional.len() > 1 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "helper".to_string(),
                reason: "expected `[@<target>] [--source DIR] [--triple T]`".to_string(),
            });
        }
        let target = self.resolve_assert_target(
            positional.first().map(|t| t.trim_start_matches('@').trim().to_string()),
            "helper",
            line,
        )?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Helper(HelperStep {
            name,
            target: Target::at(target, line),
            source,
            triple,
            install_path,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @release <owner/repo> @<target> --installed-cmd CMD
    /// --asset PATTERN --to DIR`.
    ///
    /// Tracks a GitHub repository's releases: the runner resolves the newest
    /// tag, compares it against the installed binary, and downloads the
    /// matching asset only on drift. `{tag}` in the asset pattern expands
    /// to the `v`-prefixed tag, `{version}` to the tag without `v`.
    /// `--installed-cmd` is either a bare binary path (the runner tries the
    /// version-flag chain) or a full command, run as-is.
    fn add_release(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "release", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &[], "release", line)?;
        let mut installed_cmd: Option<String> = None;
        let mut asset: Option<String> = None;
        let mut to_dir: Option<String> = None;
        let mut base_url: Option<String> = None;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--installed-cmd" => {
                    installed_cmd = Some(flag_value(value, flag, "release", line)?.to_string());
                }
                "--asset" => {
                    asset = Some(flag_value(value, flag, "release", line)?.to_string());
                }
                "--to" => {
                    to_dir = Some(flag_value(value, flag, "release", line)?.to_string());
                }
                "--base-url" => {
                    base_url = Some(flag_value(value, flag, "release", line)?.to_string());
                }
                other => {
                    return Err(unknown_flag("release", other, line));
                }
            }
        }
        if positional.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason:
                    "expected `<owner/repo> @<target> --installed-cmd CMD --asset PATTERN --to DIR [--base-url URL]`"
                        .to_string(),
            });
        }
        let repo = positional[0].clone();
        if !repo.contains('/') ||
            repo.starts_with('/') ||
            repo.contains(' ') ||
            repo.split('/').count() != 2
        {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason: format!("the repo must look like `owner/name` (got `{repo}`)"),
            });
        }
        let target = positional[1].trim_start_matches('@').trim().to_string();
        if target.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason: "missing target".to_string(),
            });
        }
        let Some(installed_cmd) = installed_cmd else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason: "missing `--installed-cmd`".to_string(),
            });
        };
        let Some(asset) = asset else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason: "missing `--asset`".to_string(),
            });
        };
        let Some(to_dir) = to_dir else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason: "missing `--to`".to_string(),
            });
        };
        if !to_dir.starts_with('/') {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason: format!("the destination must be absolute (got `{to_dir}`)"),
            });
        }
        if let Some(base) = &base_url &&
            !base.starts_with("https://") &&
            !base.starts_with("http://")
        {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "release".to_string(),
                reason: format!("the base URL must be http(s) (got `{base}`)"),
            });
        }
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Release(ReleaseStep {
            name,
            target: Target::at(target, line),
            repo,
            installed_cmd,
            asset,
            to_dir,
            base_url,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @build <repo-url> @<target> --ref REF --build CMD
    /// --artifacts A… --install-dirs D… [--prep CMD] [--units U…] [--version-flag F]
    /// [--min-free-gb N] [--workdir DIR]`.
    ///
    /// Builds the pinned ref from source on the target: fetch, build
    /// natively, probe the fresh binary, back up the running one, install
    /// atomically. One declarative block replaces the per-service build
    /// script.
    #[expect(
        clippy::too_many_lines,
        reason = "one flag per manifest field; splitting would scatter the grammar"
    )]
    fn add_build(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "build", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &[], "build", line)?;
        let mut git_ref: Option<String> = None;
        let mut build_cmd: Option<String> = None;
        let mut prep_cmd: Option<String> = None;
        let mut workdir: Option<String> = None;
        let mut artifacts: Vec<String> = Vec::new();
        let mut install_dirs: Vec<String> = Vec::new();
        let mut units: Vec<String> = Vec::new();
        let mut version_flag = String::new();
        let mut min_free_gb: u64 = 8;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--ref" => {
                    git_ref = Some(flag_value(value, flag, "build", line)?.to_string());
                }
                "--build" => {
                    build_cmd = Some(flag_value(value, flag, "build", line)?.to_string());
                }
                "--prep" => {
                    prep_cmd = Some(flag_value(value, flag, "build", line)?.to_string());
                }
                "--workdir" => {
                    workdir = Some(flag_value(value, flag, "build", line)?.to_string());
                }
                "--artifacts" => {
                    let raw = flag_value(value, flag, "build", line)?;
                    artifacts.extend(raw.split(',').map(|s| s.trim().to_string()));
                    artifacts.retain(|s| !s.is_empty());
                }
                "--install-dirs" => {
                    let raw = flag_value(value, flag, "build", line)?;
                    install_dirs.extend(raw.split(',').map(|s| s.trim().to_string()));
                    install_dirs.retain(|s| !s.is_empty());
                }
                "--units" => {
                    let raw = flag_value(value, flag, "build", line)?;
                    units.extend(raw.split(',').map(|s| s.trim().to_string()));
                    units.retain(|s| !s.is_empty());
                }
                "--version-flag" => {
                    version_flag = flag_value(value, flag, "build", line)?.to_string();
                }
                "--min-free-gb" => {
                    let raw = flag_value(value, flag, "build", line)?;
                    min_free_gb = raw.parse::<u64>().map_err(|_| ParseError::InvalidDirective {
                        line,
                        directive: "build".to_string(),
                        reason: format!("invalid `--min-free-gb` `{raw}`"),
                    })?;
                }
                other => {
                    return Err(unknown_flag("build", other, line));
                }
            }
        }
        if positional.len() != 2 {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: "expected `<repo-url> @<target> --ref REF --build CMD --artifacts A… --install-dirs D… [--prep CMD] [--workdir DIR]`"
                    .to_string(),
            });
        }
        let repo = positional[0].clone();
        if repo.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: "missing repo url".to_string(),
            });
        }
        let target = positional[1].trim_start_matches('@').trim().to_string();
        if target.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: "missing target".to_string(),
            });
        }
        let Some(git_ref) = git_ref else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: "missing `--ref`".to_string(),
            });
        };
        let Some(build_cmd) = build_cmd else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: "missing `--build`".to_string(),
            });
        };
        if artifacts.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: "missing `--artifacts`".to_string(),
            });
        }
        if install_dirs.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: "missing `--install-dirs`".to_string(),
            });
        }
        if let Some(workdir) = &workdir &&
            !workdir.starts_with('/')
        {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "build".to_string(),
                reason: format!("the workdir must be absolute (got `{workdir}`)"),
            });
        }
        for dir in &install_dirs {
            if !dir.starts_with('/') {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "build".to_string(),
                    reason: format!("install dirs must be absolute (got `{dir}`)"),
                });
            }
        }
        for unit in &units {
            let normalized = normalize_unit(unit);
            if !is_valid_unit_name(&normalized) {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "build".to_string(),
                    reason: format!("unsafe unit name `{unit}`"),
                });
            }
        }
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Build(BuildStep {
            name,
            target: Target::at(target, line),
            repo,
            workdir,
            git_ref,
            build_cmd,
            prep_cmd,
            artifacts,
            install_dirs,
            units: units.iter().map(|u| normalize_unit(u)).collect(),
            version_flag,
            min_free_gb,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @toolchain <tool,…> @<target>`.
    ///
    /// The dozen `command -v X || skip; update X` wrappers in every fleet-wide
    /// update playbook, as data: the runner owns the per-tool quirks, so a
    /// new fleet member adds one tool name instead of a new wrapper.
    ///
    /// The known tool names are `os` (the system package manager), `aur`
    /// (paru/yay, never under sudo), `rustup`, `cargo` (reported, never
    /// reinstalled), `go`, `npm`, `pipx`, `uv`, `foundry` (skipped while
    /// `anvil` runs), `proto`, and `gh`. Unknown names are rejected so a
    /// typo never silently skips an update.
    fn add_toolchain(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "toolchain", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut tools: Vec<String> = Vec::new();
        let mut target: Option<String> = None;
        for token in split_words(payload) {
            if let Some(alias) = token.strip_prefix('@') {
                if alias.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "toolchain".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                if target.is_some() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "toolchain".to_string(),
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
                if !is_known_tool(part) {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "toolchain".to_string(),
                        reason: format!(
                            "unknown tool `{part}` (expected os, aur, rustup, cargo, go, npm, pipx, uv, foundry, proto, gh)"
                        ),
                    });
                }
                if !tools.contains(&part.to_string()) {
                    tools.push(part.to_string());
                }
            }
        }
        if tools.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "toolchain".to_string(),
                reason: "missing tool list".to_string(),
            });
        }
        let target = self.resolve_assert_target(target, "toolchain", line)?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Toolchain(ToolchainStep {
            name,
            target: Target::at(target, line),
            tools,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @image <image…> @<target> [--prune]`.
    fn add_image(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "image", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let (positional, flags) = split_flags(payload, &["--prune"], "image", line)?;
        let mut prune = false;
        for (flag, value) in &flags {
            match flag.as_str() {
                "--prune" => {
                    if value.is_some() {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "image".to_string(),
                            reason: "`--prune` takes no value".to_string(),
                        });
                    }
                    prune = true;
                }
                other => {
                    return Err(unknown_flag("image", other, line));
                }
            }
        }
        let mut images: Vec<String> = Vec::new();
        let mut target: Option<String> = None;
        for token in positional {
            if let Some(alias) = token.strip_prefix('@') {
                if alias.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "image".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                if target.is_some() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "image".to_string(),
                        reason: "more than one target".to_string(),
                    });
                }
                target = Some(alias.to_string());
                continue;
            }
            images.push(token);
        }
        if images.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "image".to_string(),
                reason: "missing image".to_string(),
            });
        }
        let target = self.resolve_assert_target(target, "image", line)?;
        self.last_target = Some(target.clone());
        self.plan.steps.push(Step::Image(ImageStep {
            name,
            target: Target::at(target, line),
            images,
            prune,
            timeout,
        }));
        Ok(())
    }

    /// Parse `# @assert_enabled <unit> <enabled|disabled|static|masked> [@<target>]`.
    fn add_assert_enabled(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "assert_enabled", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut unit: Option<String> = None;
        let mut state: Option<String> = None;
        let mut target: Option<String> = None;
        for token in split_words(payload) {
            if let Some(alias) = token.strip_prefix('@') {
                if alias.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_enabled".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                if target.is_some() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_enabled".to_string(),
                        reason: "more than one target".to_string(),
                    });
                }
                target = Some(alias.to_string());
                continue;
            }
            if unit.is_none() {
                unit = Some(normalize_unit(&token));
            } else if state.is_none() {
                state = Some(token);
            } else {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: "assert_enabled".to_string(),
                    reason: "expected `<unit> <state> [@<target>]`".to_string(),
                });
            }
        }
        let Some(unit) = unit else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_enabled".to_string(),
                reason: "missing unit".to_string(),
            });
        };
        let Some(state) = state else {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_enabled".to_string(),
                reason: "missing state (expected enabled, disabled, static, or masked)".to_string(),
            });
        };
        let state = EnabledState::parse(&state).ok_or_else(|| ParseError::InvalidDirective {
            line,
            directive: "assert_enabled".to_string(),
            reason: format!("invalid state `{state}` (expected {})", EnabledState::legal()),
        })?;
        if !is_valid_unit_name(&unit) {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_enabled".to_string(),
                reason: format!("unsafe unit name `{unit}`"),
            });
        }
        let target = self.resolve_assert_target(target, "assert_enabled", line)?;
        self.push_assertion(name, target, line, Assertion::Enabled { unit, state }, timeout);
        Ok(())
    }

    /// Parse `# @assert_port_free <port>,… [@<target>]`.
    fn add_assert_port_free(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        reject_guard(self.pending_guard.is_some(), "assert_port_free", line)?;
        let name = self.pending_name.take();
        let timeout = self.pending_timeout.take();

        let mut ports: Vec<u16> = Vec::new();
        let mut target: Option<String> = None;
        for token in split_words(payload) {
            if let Some(alias) = token.strip_prefix('@') {
                if alias.is_empty() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_port_free".to_string(),
                        reason: "missing target".to_string(),
                    });
                }
                if target.is_some() {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_port_free".to_string(),
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
                        directive: "assert_port_free".to_string(),
                        reason: format!("invalid port `{part}`"),
                    });
                };
                if port == 0 {
                    return Err(ParseError::InvalidDirective {
                        line,
                        directive: "assert_port_free".to_string(),
                        reason: "port 0 is not a listening port".to_string(),
                    });
                }
                ports.push(port);
            }
        }
        if ports.is_empty() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "assert_port_free".to_string(),
                reason: "missing port".to_string(),
            });
        }
        let target = self.resolve_assert_target(target, "assert_port_free", line)?;
        self.push_assertion(name, target, line, Assertion::PortFree { ports }, timeout);
        Ok(())
    }

    /// Parse `# @workdir [--prefix NAME]`.
    ///
    /// A plan-level directive: it declares the managed temporary directory
    /// for the whole run, published to the run state as `WORKDIR`.
    fn add_workdir(&mut self, payload: &str, line: usize) -> Result<(), ParseError> {
        let (_positional, flags) = split_flags(payload, &[], "workdir", line)?;
        let mut prefix = "shellflow".to_string();
        for (flag, value) in &flags {
            match flag.as_str() {
                "--prefix" => {
                    let raw = flag_value(value, flag, "workdir", line)?;
                    if raw.is_empty() ||
                        !raw.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                    {
                        return Err(ParseError::InvalidDirective {
                            line,
                            directive: "workdir".to_string(),
                            reason: format!("invalid workdir prefix `{raw}`"),
                        });
                    }
                    prefix = raw.to_string();
                }
                other => {
                    return Err(unknown_flag("workdir", other, line));
                }
            }
        }
        if self.plan.workdir.is_some() {
            return Err(ParseError::InvalidDirective {
                line,
                directive: "workdir".to_string(),
                reason: "the workdir is already declared".to_string(),
            });
        }
        self.plan.workdir = Some(Workdir { prefix });
        Ok(())
    }
}

/// The positional arguments and the flags of one directive payload.
type SplitPayload = (Vec<String>, Vec<(String, Option<String>)>);

/// Split a directive payload into positional arguments and flags.
///
/// `bools` names the flags that take no value; every other `--flag` takes
/// the next token as its value. A flag that stands alone at the end of the
/// payload keeps `None` as its value: only the directive knows which flags
/// exist, so only it can tell "unknown flag" from "flag without a value".
///
/// The positional arguments keep their order, so a directive can read them
/// positionally (`<unit> @<target>`) or take the last one as the target
/// (`<path>… @<target>`).
fn split_flags(
    payload: &str,
    bools: &[&str],
    directive: &str,
    line: usize,
) -> Result<SplitPayload, ParseError> {
    let mut positional: Vec<String> = Vec::new();
    let mut flags: Vec<(String, Option<String>)> = Vec::new();
    let mut tokens = split_words(payload).into_iter().peekable();
    while let Some(token) = tokens.next() {
        if !token.starts_with("--") {
            positional.push(token);
            continue;
        }
        // `--flag=value` carries its value inline, so a value that itself
        // looks like a flag (`--version-flag=--version`) still parses.
        if let Some((flag, inline)) = token.split_once('=') {
            if bools.contains(&flag) {
                return Err(ParseError::InvalidDirective {
                    line,
                    directive: directive.to_string(),
                    reason: format!("`{flag}` takes no value"),
                });
            }
            flags.push((flag.to_string(), Some(inline.to_string())));
            continue;
        }
        if bools.contains(&token.as_str()) {
            flags.push((token, None));
            continue;
        }
        // A flag takes the next token as its value. A value that looks like a
        // flag is not consumed: `# @backup /p @t --dir --seal` means a missing
        // `--dir` value, not a directory named `--seal`. The missing value is
        // kept as `None` so the directive can report `unknown flag` for
        // unknown flags and `expects a value` for known ones.
        let value = match tokens.peek() {
            Some(next) if !next.starts_with("--") => tokens.next(),
            _ => None,
        };
        flags.push((token, value));
    }
    Ok((positional, flags))
}

/// Split a directive payload into whitespace-separated words, honouring
/// single and double quotes (a quoted region never splits, and the quotes
/// themselves are removed). A backslash escapes the next character. An
/// unterminated quote runs to the end of the payload.
///
/// Multi-word flag values (`--build 'cargo build --release'`) depend on
/// this: without quote awareness the value would be truncated to its first
/// word and the rest misread as positionals.
fn split_words(payload: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = payload.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == '\\' && q == '"' {
                // Inside double quotes a backslash is special only before
                // `$`, `` ` ``, `"`, `\`, or newline; otherwise it stays
                // literal (Bash keeps `\n` as two characters).
                if let Some(n) = chars.next() {
                    if matches!(n, '$' | '`' | '"' | '\\') {
                        cur.push(n);
                    } else if n == '\n' {
                        // Line continuation: both characters disappear.
                    } else {
                        cur.push('\\');
                        cur.push(n);
                    }
                } else {
                    cur.push('\\');
                }
            } else {
                cur.push(c);
            }
            in_word = true;
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            in_word = true;
        } else if c.is_whitespace() {
            if in_word {
                words.push(std::mem::take(&mut cur));
                in_word = false;
            }
        } else if c == '\\' {
            // Outside quotes a backslash escapes the next char, so
            // `a\ b` stays one word.
            if let Some(n) = chars.next() {
                cur.push(n);
                in_word = true;
            }
        } else {
            cur.push(c);
            in_word = true;
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// The value of a flag, or a readable error when the flag stands alone.
fn flag_value<'a>(
    value: &'a Option<String>,
    flag: &str,
    directive: &str,
    line: usize,
) -> Result<&'a str, ParseError> {
    value.as_deref().ok_or_else(|| ParseError::InvalidDirective {
        line,
        directive: directive.to_string(),
        reason: format!("`{flag}` expects a value"),
    })
}

/// The error every directive reports for a flag it does not define.
///
/// One constructor rather than fifteen identical literals: the wording is
/// part of what users script against, so it must not drift per directive.
fn unknown_flag(directive: &str, flag: &str, line: usize) -> ParseError {
    ParseError::InvalidDirective {
        line,
        directive: directive.to_string(),
        reason: format!("unknown flag `{flag}`"),
    }
}

/// The target of a mutating directive: the argument is mandatory, because a
/// mutation that lands on the wrong host is not recoverable by re-running it.
fn require_target(raw: &str, directive: &str, line: usize) -> Result<String, ParseError> {
    let target = raw.trim_start_matches('@').trim();
    if target.is_empty() {
        return Err(ParseError::InvalidDirective {
            line,
            directive: directive.to_string(),
            reason: "missing target".to_string(),
        });
    }
    Ok(target.to_string())
}

/// Parse a seconds value: a positive integer.
fn parse_secs(raw: &str, directive: &str, line: usize) -> Result<u64, ParseError> {
    let secs: u64 = raw.parse().map_err(|_| ParseError::InvalidDirective {
        line,
        directive: directive.to_string(),
        reason: format!("invalid seconds `{raw}`"),
    })?;
    if secs == 0 {
        return Err(ParseError::InvalidDirective {
            line,
            directive: directive.to_string(),
            reason: "must be greater than zero".to_string(),
        });
    }
    Ok(secs)
}

/// Parse an octal file mode (`0644`).
fn parse_mode(raw: &str, directive: &str, line: usize) -> Result<u32, ParseError> {
    let trimmed = raw.trim();
    let digits = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    if digits.is_empty() || !digits.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(ParseError::InvalidDirective {
            line,
            directive: directive.to_string(),
            reason: format!("invalid octal mode `{raw}`"),
        });
    }
    u32::from_str_radix(digits, 8).map_err(|_| ParseError::InvalidDirective {
        line,
        directive: directive.to_string(),
        reason: format!("invalid octal mode `{raw}` (out of range for u32)"),
    })
}

/// Parse an owner (`user`, `user:group`, or `:group`).
fn parse_owner(raw: &str, directive: &str, line: usize) -> Result<String, ParseError> {
    let owner = raw.trim();
    let parts: Vec<&str> = owner.split(':').collect();
    let valid_part = |part: &str| {
        !part.is_empty() &&
            part.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    // `(!u.e || !g.e)` and `!(u.e && g.e)` are the same clause by De Morgan,
    // so it appears once. `parts.len() <= 2` and the non-empty owner need no
    // conjunct either: the `_` arm already rejects any other arity, and a
    // matching arm always names a non-empty part.
    let ok = match parts.as_slice() {
        [user] => valid_part(user),
        [user, group] => {
            // `user:group` requires a user; `:group` requires a group.
            (user.is_empty() || valid_part(user)) &&
                (group.is_empty() || valid_part(group)) &&
                !(user.is_empty() && group.is_empty())
        }
        _ => false,
    };
    if !ok {
        return Err(ParseError::InvalidDirective {
            line,
            directive: directive.to_string(),
            reason: format!("invalid owner `{raw}` (want `user` or `user:group`)"),
        });
    }
    Ok(owner.to_string())
}

/// Whether a status pattern is an exact code (`200`) or a class (`2xx`).
fn is_status_pattern(pattern: &str) -> bool {
    if pattern.len() == 3 && pattern.ends_with("xx") {
        return pattern.starts_with(|c: char| c.is_ascii_digit());
    }
    pattern.parse::<u16>().is_ok_and(|code| (100..600).contains(&code))
}

/// Whether a server/group alias is syntactically valid.
fn is_valid_alias_name(name: &str) -> bool {
    !name.is_empty() &&
        name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Whether a toolchain name is known to the `@toolchain` step.
fn is_known_tool(name: &str) -> bool {
    matches!(
        name,
        "os" | "aur" |
            "rustup" |
            "cargo" |
            "go" |
            "npm" |
            "pipx" |
            "uv" |
            "foundry" |
            "proto" |
            "gh"
    )
}

/// Reject `@only_if` on steps that carry no script context.
fn reject_guard(has_guard: bool, directive: &str, line: usize) -> Result<(), ParseError> {
    if has_guard {
        return Err(ParseError::InvalidDirective {
            line,
            directive: directive.to_string(),
            reason: format!("`@only_if` is not supported on `@{directive}`"),
        });
    }
    Ok(())
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
            state.heredocs.open_in(line, line_no);
            state.pending.push(line.to_string());
        }
    }

    // An unterminated here-document swallowed every following line as data,
    // directives included. That produces a plan that looks valid but is
    // silently missing steps, so it is an error rather than a plan.
    if let Some((line, heredoc)) = state.heredocs.unterminated() {
        return Err(ParseError::UnterminatedHeredoc { line, delimiter: heredoc.tag.clone() });
    }

    state.flush();

    for (group, members) in &state.plan.groups {
        // The key is always inserted when the group is declared, so the
        // lookup cannot miss; `copied` keeps the invariant cheap to uphold
        // rather than trusting it unguarded.
        let line = state.group_lines.get(group).copied().unwrap_or_default();
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

    use super::{directive, is_valid_alias_name, parse_script, split_words};
    use crate::{
        error::ParseError,
        plan::{
            ActiveState, AssertStep, Assertion, CopyStep, EnabledState, EnvEntry, ExportVar,
            LocalStep, RemoteStep, Step, WaitStep,
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

    fn as_service(step: &Step) -> Result<&crate::plan::ServiceStep, String> {
        match step {
            Step::Service(s) => Ok(s),
            other => Err(format!("expected service step, got {other:?}")),
        }
    }

    fn as_install(step: &Step) -> Result<&crate::plan::InstallStep, String> {
        match step {
            Step::Install(s) => Ok(s),
            other => Err(format!("expected install step, got {other:?}")),
        }
    }

    fn as_backup(step: &Step) -> Result<&crate::plan::BackupStep, String> {
        match step {
            Step::Backup(s) => Ok(s),
            other => Err(format!("expected backup step, got {other:?}")),
        }
    }

    fn as_credstore(step: &Step) -> Result<&crate::plan::CredstoreStep, String> {
        match step {
            Step::Credstore(s) => Ok(s),
            other => Err(format!("expected credstore step, got {other:?}")),
        }
    }

    fn as_helper(step: &Step) -> Result<&crate::plan::HelperStep, String> {
        match step {
            Step::Helper(s) => Ok(s),
            other => Err(format!("expected helper step, got {other:?}")),
        }
    }

    fn as_release(step: &Step) -> Result<&crate::plan::ReleaseStep, String> {
        match step {
            Step::Release(s) => Ok(s),
            other => Err(format!("expected release step, got {other:?}")),
        }
    }

    fn as_build(step: &Step) -> Result<&crate::plan::BuildStep, String> {
        match step {
            Step::Build(s) => Ok(s),
            other => Err(format!("expected build step, got {other:?}")),
        }
    }

    fn as_toolchain(step: &Step) -> Result<&crate::plan::ToolchainStep, String> {
        match step {
            Step::Toolchain(s) => Ok(s),
            other => Err(format!("expected toolchain step, got {other:?}")),
        }
    }

    fn as_image(step: &Step) -> Result<&crate::plan::ImageStep, String> {
        match step {
            Step::Image(s) => Ok(s),
            other => Err(format!("expected image step, got {other:?}")),
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
                state: ActiveState::Active,
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
                state: ActiveState::Failed,
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
            assert!(parse(script).is_err(), "expected an error for:\n{script}");
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
    fn copy_exclude_quotes_are_stripped_and_quote_aware() -> Result<(), String> {
        // `@copy` shares the workspace flag parser (`split_flags`), so
        // matching quotes are stripped and a quoted glob may contain spaces —
        // the same word rules every other directive's flag values follow.
        let plan = parse(
            "# @copy a -> /srv/b @web --exclude \"*.log\" --exclude '*.tmp' \
             --exclude 'my *.log'\n",
        )?;
        let copy = as_copy(&plan.steps[0])?;
        assert_eq!(copy.excludes, vec!["*.log", "*.tmp", "my *.log"]);
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
        assert_eq!(export, &vec![ExportVar { name: "VERSION".to_string(), public: false }]);
        Ok(())
    }

    #[test]
    fn the_plan_accessors_expose_what_the_parser_built() -> Result<(), String> {
        // The plan's fields are private: every consumer reads it through these
        // accessors, so an accessor that returned nothing would silently blank
        // out a preview or a secrets resolution.
        let plan = parse(
            "# @server web1 web@h1\n\
             # @secrets s.env.age\n\
             # @workdir --prefix sf\n\
             # @local\n\
             echo hi\n",
        )?;
        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.servers().len(), 1);
        assert!(plan.groups().is_empty());
        assert!(plan.env().is_empty());
        assert_eq!(plan.secrets().len(), 1);
        assert_eq!(plan.secrets()[0].file, "s.env.age");
        assert_eq!(plan.workdir().map(|workdir| workdir.prefix.as_str()), Some("sf"));
        Ok(())
    }

    #[test]
    fn export_is_masked_unless_it_says_public() -> Result<(), String> {
        // The masking decision belongs to the playbook, not to the variable
        // name: a credential exported from a vault is routinely called
        // `DATABASE_URL`, so a name heuristic is not a safety property.
        let masked = parse("# @local\nDATABASE_URL=postgres://x\n# @export DATABASE_URL\n")?;
        assert!(!as_local(&masked.steps[0])?.export[0].public, "default must be masked");

        let public = parse("# @local\nVERSION=1\n# @export VERSION --public\n")?;
        assert!(as_local(&public.steps[0])?.export[0].public, "`--public` must opt out");

        // The flag covers the whole line, so a comma-separated list is one
        // decision rather than a per-name suffix nobody can read.
        let list = parse("# @local\nA=1\nB=2\n# @export A,B --public\n")?;
        assert!(as_local(&list.steps[0])?.export.iter().all(|var| var.public));
        Ok(())
    }

    #[test]
    fn export_rejects_an_unknown_flag() {
        let err = parse_script("# @local\nV=1\n# @export V --quiet\n").expect_err("must fail");
        assert!(err.to_string().contains("unknown flag `--quiet`"), "unexpected error: {err}");
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
        assert_eq!(export, &vec![ExportVar { name: "VERSION".to_string(), public: false }]);
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
        assert_eq!(
            as_local(&plan.steps[0])?.export,
            vec![ExportVar { name: "VERSION".to_string(), public: false }]
        );
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
        // so the directive before the real terminator stays inside the block.
        let plan = parse("# @local\ncat <<-EOF\nbody\n  EOF\n# @remote web\n\tEOF\necho done\n")?;
        assert_eq!(plan.steps.len(), 1);
        assert!(as_local(&plan.steps[0])?.script.contains("# @remote web"));
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
            ("# @copy a -> /dst @web --exclude\n", "copy", "`--exclude` expects a value"),
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
    fn unterminated_heredoc_is_rejected() {
        // An unterminated body swallows every following line, so the plan it
        // yields looks valid but is silently missing steps. Reporting the
        // opener line is the only way the user can find the missing terminator
        // without diffing the plan against the script.
        let err = parse("# @local\ncat <<EOF\n# @remote web\n").expect_err("must fail");
        assert!(
            err.contains("line 2: unterminated here-document `EOF`"),
            "the opener line and delimiter are both reported: {err}"
        );
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
            host in "[a-z][a-z0-9.-]{0,39}",
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

    // === the lifecycle and host-operation primitives ===

    #[test]
    fn service_parses_unit_target_and_flags() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @service dufs @api --enable --restart --wait --verify\n",
        )?;
        let step = as_service(&plan.steps[0])?;
        assert_eq!(step.unit, "dufs.service");
        assert_eq!(step.target.text, "api");
        assert!(step.enable);
        assert!(step.restart);
        assert!(step.wait);
        assert!(step.verify);
        assert!(!step.reload);
        assert!(!step.force_start);
        Ok(())
    }

    #[test]
    fn service_accepts_a_bare_unit_name() -> Result<(), String> {
        let plan = parse("# @server api api\n# @service dufs.service @api\n")?;
        assert_eq!(as_service(&plan.steps[0])?.unit, "dufs.service");
        Ok(())
    }

    #[test]
    fn service_requires_a_target() {
        let err = parse("# @server api api\n# @service dufs\n").unwrap_err();
        assert!(err.contains("expected `<unit> @<target>"), "{err}");
    }

    #[test]
    fn service_rejects_an_unknown_flag() {
        let err = parse("# @server api api\n# @service dufs @api --nope\n").unwrap_err();
        assert!(err.contains("unknown flag `--nope`"), "{err}");
    }

    #[test]
    fn service_rejects_only_if() {
        let err = parse("# @server api api\n# @only_if true\n# @service dufs @api\n").unwrap_err();
        assert!(err.contains("`@only_if` is not supported on `@service`"), "{err}");
    }

    #[test]
    fn install_parses_paths_and_options() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @install /tmp/x/dufs.service -> /etc/systemd/system/dufs.service @api \
             --mode 0644 --owner root:root --dir-mode 0755\n",
        )?;
        let step = as_install(&plan.steps[0])?;
        assert_eq!(step.src, "/tmp/x/dufs.service");
        assert_eq!(step.dst, "/etc/systemd/system/dufs.service");
        assert_eq!(step.mode, Some(0o644));
        assert_eq!(step.owner.as_deref(), Some("root:root"));
        assert_eq!(step.dir_mode, Some(0o755));
        Ok(())
    }

    #[test]
    fn install_requires_an_absolute_destination() {
        let err = parse("# @server api api\n# @install /a -> b @api\n").unwrap_err();
        assert!(err.contains("the destination must be absolute"), "{err}");
    }

    #[test]
    fn install_requires_the_arrow() {
        let err = parse("# @server api api\n# @install /a /b @api\n").unwrap_err();
        assert!(err.contains("expected `src -> dst @target"), "{err}");
    }

    #[test]
    fn backup_parses_paths_keep_and_seal() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @backup /etc/systemd/system/dufs.service /opt/dufs/etc/config.toml @api \
             --keep 5 --seal\n",
        )?;
        let step = as_backup(&plan.steps[0])?;
        assert_eq!(
            step.paths,
            vec!["/etc/systemd/system/dufs.service", "/opt/dufs/etc/config.toml"]
        );
        assert_eq!(step.target.text, "api");
        assert_eq!(step.keep, Some(5));
        assert!(step.seal);
        Ok(())
    }

    #[test]
    fn backup_rejects_a_relative_path() {
        let err = parse("# @server api api\n# @backup etc/dufs.service @api\n").unwrap_err();
        assert!(err.contains("the path must be absolute"), "{err}");
    }

    #[test]
    fn backup_rejects_a_zero_keep() {
        let err =
            parse("# @server api api\n# @backup /etc/dufs.service @api --keep 0\n").unwrap_err();
        assert!(err.contains("must be greater than zero"), "{err}");
    }

    #[test]
    fn credstore_parses_service_and_required_keys() -> Result<(), String> {
        let plan = parse("# @server api api\n# @credstore dufs @api --require TOKEN,API_KEY\n")?;
        let step = as_credstore(&plan.steps[0])?;
        assert_eq!(step.service, "dufs");
        assert_eq!(step.target.text, "api");
        assert_eq!(step.require, vec!["TOKEN".to_string(), "API_KEY".to_string()]);
        Ok(())
    }

    #[test]
    fn helper_parses_source_and_triple() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @helper @api --source /src/shellflow --triple x86_64-unknown-linux-musl\n",
        )?;
        let step = as_helper(&plan.steps[0])?;
        assert_eq!(step.target.text, "api");
        assert_eq!(step.source.as_deref(), Some("/src/shellflow"));
        assert_eq!(step.triple.as_deref(), Some("x86_64-unknown-linux-musl"));
        assert_eq!(step.install_path, "/usr/local/bin/shellflow");
        Ok(())
    }

    #[test]
    fn helper_inherits_the_previous_target() -> Result<(), String> {
        let plan = parse("# @server api api\n# @copy a -> b @api\n# @helper\n")?;
        assert_eq!(as_helper(&plan.steps[1])?.target.text, "api");
        Ok(())
    }

    #[test]
    fn assert_no_leak_parses_unit_and_lines() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_no_leak dufs @api --lines 500\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::NoLeak { unit: "dufs.service".to_string(), lines: Some(500) }]
        );
        Ok(())
    }

    #[test]
    fn assert_digest_parses_path_and_expected_hash() -> Result<(), String> {
        let hash = "a".repeat(64);
        let plan = parse(&format!(
            "# @server api api\n# @assert_digest /opt/dufs/etc/config.toml @api --sha256 {hash}\n"
        ))?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::Digest {
                path: "/opt/dufs/etc/config.toml".to_string(),
                sha256: Some(hash),
                local: None,
            }]
        );
        Ok(())
    }

    #[test]
    fn assert_digest_rejects_a_short_hash() {
        let err = parse("# @server api api\n# @assert_digest /a @api --sha256 abc\n").unwrap_err();
        assert!(err.contains("64 hex characters"), "{err}");
    }

    #[test]
    fn assert_credstore_parses_the_service() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_credstore dufs @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(step.checks, vec![Assertion::Credstore { service: "dufs".to_string() }]);
        Ok(())
    }

    #[test]
    fn new_assertions_merge_into_one_step() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @assert_no_leak dufs @api\n\
             # @assert_credstore dufs @api\n",
        )?;
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(as_assert(&plan.steps[0])?.checks.len(), 2);
        Ok(())
    }

    #[test]
    fn unit_inventory_inherits_the_target() -> Result<(), String> {
        let plan = parse("# @server api api\n# @copy a -> b @api\n# @unit_inventory\n")?;
        match &plan.steps[1] {
            Step::UnitInventory(s) => assert_eq!(s.target.text, "api"),
            other => return Err(format!("expected unit_inventory step, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn workdir_declares_the_managed_directory() -> Result<(), String> {
        let plan = parse("# @workdir --prefix deploy\necho hi\n")?;
        let workdir = plan.workdir.clone().ok_or("no workdir declared")?;
        assert_eq!(workdir.prefix, "deploy");
        Ok(())
    }

    #[test]
    fn workdir_cannot_be_declared_twice() {
        let err = parse("# @workdir\n# @workdir\n").unwrap_err();
        assert!(err.contains("already declared"), "{err}");
    }

    #[test]
    fn workdir_rejects_an_unsafe_prefix() {
        let err = parse("# @workdir --prefix ../evil\n").unwrap_err();
        assert!(err.contains("invalid workdir prefix"), "{err}");
    }

    // === the validation rules of the directives ===

    #[test]
    fn two_copies_with_different_options_do_not_merge() -> Result<(), String> {
        // The merge condition is "same target AND same options": a copy
        // that asked for `--delete` must not be folded into one that did not.
        let plan = parse(
            "# @server api api\n\
             # @copy a -> b @api\n\
             # @copy c -> d @api --delete\n",
        )?;
        let copies: Vec<&CopyStep> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                Step::Copy(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(copies.len(), 2, "{copies:?}");
        assert!(!copies[0].delete);
        assert!(copies[1].delete);
        Ok(())
    }

    #[test]
    fn a_state_must_be_one_systemd_actually_prints() {
        // The charset check used to accept anything alphanumeric, so
        // `@assert foo banana` parsed and then failed on the target — after
        // the deploy had run. The legal set is `systemctl is-active`'s, and it
        // is the same set `@assert_enabled` validates against.
        let err = parse("# @server api api\n# @assert dufs @api not-running\n").unwrap_err();
        assert!(err.contains("invalid state `not-running`"), "{err}");
        assert!(err.contains("active, reloading, inactive"), "{err}");
    }

    #[test]
    fn a_state_with_an_unsafe_character_is_rejected() {
        let err = parse("# @server api api\n# @assert dufs @api bad;state\n").unwrap_err();
        assert!(err.contains("invalid state `bad;state`"), "{err}");
    }

    #[test]
    fn a_health_check_accepts_a_method_and_a_header() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @assert_health http://x/ @api --method POST --header Content-Type:application/json\n",
        )?;
        let step = as_assert(&plan.steps[0])?;
        let Assertion::Health { method, headers, .. } = &step.checks[0] else {
            return Err("not a health check".to_string());
        };
        assert_eq!(method.as_deref(), Some("POST"));
        assert_eq!(headers, &vec!["Content-Type:application/json".to_string()]);
        Ok(())
    }

    #[test]
    fn a_quoted_flag_value_survives_the_shared_tokenizer() -> Result<(), String> {
        // Every directive tokenizes with `split_words`, so a quoted value is
        // one word everywhere. `@assert_health … --body 'hello world'` used
        // to split into three tokens and fail with "duplicate URL".
        let plan = parse(
            "# @server api api\n\
             # @assert_health http://x/ @api --method POST --body 'hello world' --header 'X-Test: a b'\n",
        )?;
        let step = as_assert(&plan.steps[0])?;
        let Assertion::Health { body, headers, .. } = &step.checks[0] else {
            return Err("not a health check".to_string());
        };
        assert_eq!(body.as_deref(), Some("hello world"));
        assert_eq!(headers, &vec!["X-Test: a b".to_string()]);
        Ok(())
    }

    #[test]
    fn export_takes_public_as_a_flag_anywhere() -> Result<(), String> {
        // `--public` used to be a trailing-suffix special case, so the same
        // flag in any other position was reported as an unknown flag.
        let plan = parse("# @local\nV=1\n# @export --public VERSION,COMMIT\n")?;
        let exported = &as_local(&plan.steps[0])?.export;
        assert_eq!(exported.len(), 2);
        assert!(exported.iter().all(|var| var.public), "all are public: {exported:?}");
        Ok(())
    }

    #[test]
    fn a_health_check_rejects_a_non_alphabetic_method() {
        let err =
            parse("# @server api api\n# @assert_health http://x/ @api --method G3T\n").unwrap_err();
        assert!(err.contains("invalid HTTP method"), "{err}");
    }

    #[test]
    fn a_health_check_rejects_a_header_without_a_colon() {
        let err = parse("# @server api api\n# @assert_health http://x/ @api --header nope\n")
            .unwrap_err();
        assert!(err.contains("invalid header"), "{err}");
    }

    #[test]
    fn a_health_check_rejects_an_unknown_flag() {
        let err =
            parse("# @server api api\n# @assert_health http://x/ @api --bogus\n").unwrap_err();
        assert!(err.contains("unknown flag `--bogus`"), "{err}");
    }

    #[test]
    fn a_health_check_rejects_a_url_with_a_control_character() {
        // A URL cannot carry a space (the payload is split on whitespace),
        // but a control character reaches the check and must be rejected.
        let err = parse("# @server api api\n# @assert_health http://x/a\u{1}b @api\n").unwrap_err();
        assert!(err.contains("must not contain whitespace"), "{err}");
    }

    #[test]
    fn a_reload_accepts_a_wait_flag() -> Result<(), String> {
        let plan = parse("# @server api api\n# @reload dufs @api --wait\n")?;
        let Step::Reload(reload) = &plan.steps[0] else {
            return Err("not a reload step".to_string());
        };
        assert!(reload.wait);
        assert!(reload.signal.is_none());
        Ok(())
    }

    #[test]
    fn a_reload_rejects_a_flag_without_a_value() {
        let err = parse("# @server api api\n# @reload dufs @api --timeout\n").unwrap_err();
        assert!(err.contains("`--timeout` expects a value"), "{err}");
    }

    #[test]
    fn a_reload_rejects_an_unsafe_signal() {
        let err = parse("# @server api api\n# @reload dufs @api --signal 'SIG;rm'\n").unwrap_err();
        assert!(err.contains("invalid signal"), "{err}");
    }

    #[test]
    fn a_reload_rejects_a_non_numeric_timeout() {
        let err = parse("# @server api api\n# @reload dufs @api --timeout soon\n").unwrap_err();
        assert!(err.contains("invalid seconds"), "{err}");
    }

    #[test]
    fn a_reload_rejects_an_unsafe_unit_name() {
        for unit in ["a..b", ".foo", "..foo", "a;b"] {
            let err = parse(&format!("# @server api api\n# @reload {unit} @api\n")).unwrap_err();
            assert!(err.contains("unsafe unit name"), "{unit}: {err}");
        }
    }

    #[test]
    fn template_units_are_accepted_by_every_unit_directive() {
        // systemd template units (`getty@tty1.service`) are legitimate names,
        // so `@` and `:` are part of the single shared unit charset —
        // `@service` accepts them exactly like `@reload`/`@wait_active`.
        let plan = parse("# @server api api\n# @service getty@tty1 @api\n").unwrap();
        let Step::Service(step) = &plan.steps[0] else {
            panic!("expected a service step");
        };
        assert_eq!(step.unit, "getty@tty1.service");

        let plan = parse("# @server api api\n# @reload getty@tty1 @api\n").unwrap();
        let Step::Reload(step) = &plan.steps[0] else {
            panic!("expected a reload step");
        };
        assert_eq!(step.unit, "getty@tty1.service");

        let plan = parse("# @server api api\n# @wait_active getty@tty1 @api\n").unwrap();
        let Step::Wait(step) = &plan.steps[0] else {
            panic!("expected a wait step");
        };
        assert_eq!(step.unit, "getty@tty1.service");
    }

    #[test]
    fn reload_flags_parse_in_any_position() {
        // The flag vocabulary is `split_flags`, so flags may appear anywhere
        // after `<unit> @<target>` and quoted values are honoured.
        let plan =
            parse("# @server api api\n# @reload dufs @api --wait --signal SIGUSR1 --timeout 30\n")
                .unwrap();
        let Step::Reload(step) = &plan.steps[0] else {
            panic!("expected a reload step");
        };
        assert!(step.wait);
        assert_eq!(step.signal.as_deref(), Some("SIGUSR1"));
        assert_eq!(step.timeout, Some(30));
    }

    #[test]
    fn a_backup_rejects_an_unsafe_service_name() {
        let err = parse("# @server api api\n# @backup /etc/x @api --service 'a b'\n").unwrap_err();
        assert!(err.contains("unsafe service name"), "{err}");
    }

    #[test]
    fn a_backup_rejects_a_relative_snapshot_directory() {
        let err = parse("# @server api api\n# @backup /etc/x @api --dir relative\n").unwrap_err();
        assert!(err.contains("must be absolute"), "{err}");
    }

    #[test]
    fn a_helper_rejects_a_relative_install_path() {
        let err = parse("# @server api api\n# @helper @api --install-path relative/shellflow\n")
            .unwrap_err();
        assert!(err.contains("must be absolute"), "{err}");
    }

    #[test]
    fn a_timeout_of_zero_is_rejected() {
        let err = parse("# @server api api\n# @service dufs @api --timeout 0\n").unwrap_err();
        assert!(err.contains("greater than zero"), "{err}");
    }

    #[test]
    fn a_non_numeric_timeout_is_rejected() {
        let err = parse("# @server api api\n# @service dufs @api --timeout soon\n").unwrap_err();
        assert!(err.contains("invalid seconds"), "{err}");
    }

    #[test]
    fn a_mode_with_a_non_octal_digit_is_rejected() {
        let err = parse("# @server api api\n# @install /a -> /b @api --mode 0999\n").unwrap_err();
        assert!(err.contains("invalid octal mode"), "{err}");
        // The digit check fires first: an out-of-range radix error would mean
        // the octal validation was skipped.
        assert!(!err.contains("out of range"), "{err}");
    }

    #[test]
    fn a_mode_without_digits_is_rejected() {
        let err = parse("# @server api api\n# @install /a -> /b @api --mode 0o\n").unwrap_err();
        assert!(err.contains("invalid octal mode"), "{err}");
    }

    #[test]
    fn an_owner_with_an_unsafe_character_is_rejected() {
        let err =
            parse("# @server api api\n# @install /a -> /b @api --owner 'bad/owner'\n").unwrap_err();
        assert!(err.contains("invalid owner"), "{err}");
    }

    #[test]
    fn an_alias_with_a_blank_or_a_slash_is_invalid() {
        assert!(is_valid_alias_name("api"));
        assert!(is_valid_alias_name("a-b_c.d9"));
        assert!(!is_valid_alias_name(""));
        assert!(!is_valid_alias_name("a b"));
        assert!(!is_valid_alias_name("a/b"));
    }

    #[test]
    fn an_owner_accepts_user_group_and_either_side_empty() -> Result<(), String> {
        for owner in ["u", "u:g", "u:", ":g", "a-b_c.d"] {
            let plan =
                parse(&format!("# @server api api\n# @install /a -> /b @api --owner {owner}\n"))
                    .map_err(|e| format!("{owner}: {e}"))?;
            let step = as_install(&plan.steps[0])?;
            assert_eq!(step.owner.as_deref(), Some(owner));
        }
        Ok(())
    }

    #[test]
    fn an_owner_rejects_empty_and_extra_parts() {
        // Empty and multi-part owners never reach a valid user:group shape.
        // `--owner ''` keeps its quotes in the raw value, which is itself
        // not a valid owner character.
        for flag in ["--owner ''", "--owner :", "--owner u:g:x", "--owner 'u g'"] {
            let err = parse(&format!("# @server api api\n# @install /a -> /b @api {flag}\n"))
                .unwrap_err();
            assert!(err.contains("invalid owner"), "{flag}: {err}");
        }
    }

    #[test]
    fn an_owner_rejects_either_side_invalid() {
        // Each `&&` in the pair clause is load-bearing: an invalid user fails
        // even with a valid group, and vice versa.
        for flag in ["--owner u!:g", "--owner u:g!"] {
            let err = parse(&format!("# @server api api\n# @install /a -> /b @api {flag}\n"))
                .unwrap_err();
            assert!(err.contains("invalid owner"), "{flag}: {err}");
        }
    }

    #[test]
    fn a_status_class_is_accepted_and_a_broken_one_is_not() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_health http://x/ @api --expect 2xx\n")?;
        let step = as_assert(&plan.steps[0])?;
        let Assertion::Health { expect, .. } = &step.checks[0] else {
            return Err("not a health check".to_string());
        };
        assert_eq!(expect, &vec!["2xx".to_string()]);
        let err = parse("# @server api api\n# @assert_health http://x/ @api --expect 2xxx\n")
            .unwrap_err();
        assert!(err.contains("invalid status code"), "{err}");
        Ok(())
    }

    #[test]
    fn an_unsafe_unit_name_is_rejected_everywhere() {
        for unit in [".foo", "..foo", "a..b", "a..;b", "a;b"] {
            let err = parse(&format!("# @server api api\n# @assert {unit} @api\n")).unwrap_err();
            assert!(err.contains("unsafe unit name"), "{unit}: {err}");
        }
    }

    #[test]
    fn quoted_flag_values_survive_as_one_word() {
        // `split_words` is what lets `--build 'cargo build --release'`
        // arrive intact; without quote awareness the value would truncate
        // to `cargo` and the rest would become bogus positionals.
        assert_eq!(split_words("a 'b c' d"), vec!["a", "b c", "d"]);
        assert_eq!(
            split_words("--build 'cargo build --release'"),
            vec!["--build", "cargo build --release"]
        );
    }

    #[test]
    fn split_words_handles_quotes_backslashes_and_edges() {
        // Double quotes process backslash escapes; single quotes do not.
        assert_eq!(split_words("\"a\\\"b\""), vec!["a\"b"]);
        assert_eq!(split_words("'a\\b'"), vec!["a\\b"]);
        // Outside quotes a backslash escapes the next char, keeping `a b` whole.
        assert_eq!(split_words("a\\ b c"), vec!["a b", "c"]);
        // An unterminated quote runs to the end; empty quotes are one empty word.
        assert_eq!(split_words("'abc"), vec!["abc"]);
        assert_eq!(split_words("''"), vec![""]);
        // Plain splitting is unchanged (multiple spaces, tabs).
        assert_eq!(split_words("  a\tb  "), vec!["a", "b"]);
        assert!(split_words("   ").is_empty());
    }

    #[test]
    fn inline_flag_values_support_dashed_values() -> Result<(), String> {
        let plan = parse("# @server api api\n# @service app @api --enable --timeout=60\n")?;
        match &plan.steps[0] {
            Step::Service(s) => assert_eq!(s.timeout, Some(60)),
            other => return Err(format!("expected service step, got {other:?}")),
        }
        let err = parse("# @server api api\n# @service app @api --enable=x\n").unwrap_err();
        assert!(err.contains("takes no value"), "{err}");
        Ok(())
    }

    #[test]
    fn a_value_flag_never_swallows_the_next_flag() {
        // `split_flags` must not consume a following `--flag` as the value:
        // `# @backup /p @t --dir --seal` is a missing `--dir` value, not a
        // directory named `--seal`.
        let err = parse("# @server api api\n# @backup /p @t --dir --seal\n").unwrap_err();
        assert!(err.contains("`--dir` expects a value"), "{err}");
    }

    #[test]
    fn a_flag_without_a_value_is_rejected() {
        let err = parse("# @server api api\n# @install /a -> /b @api --mode\n").unwrap_err();
        assert!(err.contains("`--mode` expects a value"), "{err}");
    }

    #[test]
    fn release_parses_repo_target_and_options() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @release sigoden/dufs @api --installed-cmd /opt/dufs/bin/dufs --asset dufs-{tag}-x86_64-unknown-linux-musl.tar.gz --to /opt/dufs/bin\n",
        )?;
        let step = as_release(&plan.steps[0])?;
        assert_eq!(step.repo, "sigoden/dufs");
        assert_eq!(step.target.text, "api");
        assert_eq!(step.installed_cmd, "/opt/dufs/bin/dufs");
        assert_eq!(step.asset, "dufs-{tag}-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(step.to_dir, "/opt/dufs/bin");
        assert_eq!(step.base_url, None);
        Ok(())
    }

    #[test]
    fn release_parses_a_vendor_download_host() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @release o/r @api --installed-cmd x --asset y --to /tmp --base-url https://cdn.example.com/rel\n",
        )?;
        let step = as_release(&plan.steps[0])?;
        assert_eq!(step.base_url.as_deref(), Some("https://cdn.example.com/rel"));
        Ok(())
    }

    #[test]
    fn release_rejects_a_non_http_base_url() {
        let err = parse(
            "# @server api api\n# @release o/r @api --installed-cmd x --asset y --to /tmp --base-url ftp://x\n",
        )
        .unwrap_err();
        assert!(err.contains("http"), "{err}");
    }

    #[test]
    fn release_rejects_a_non_repo_first_arg() {
        let err = parse(
            "# @server api api\n# @release not-a-repo @api --installed-cmd x --asset y --to /tmp\n",
        )
        .unwrap_err();
        assert!(err.contains("owner/name"), "{err}");
    }

    #[test]
    fn release_rejects_absolute_and_spaced_repos() {
        // `/or` (one slash) kills the leading-`||` mutants; `/o/r` and
        // `o/r/extra` kill the arity clause. A spaced repo never reaches the
        // check — whitespace splits it into extra positionals.
        for repo in ["/or", "/o/r", "o/r/extra"] {
            let err = parse(&format!(
                "# @server api api\n# @release {repo} @api --installed-cmd x --asset y --to /tmp\n"
            ))
            .unwrap_err();
            assert!(err.contains("owner/name") || err.contains("expected"), "{repo}: {err}");
        }
    }

    #[test]
    fn release_requires_all_options() {
        let err =
            parse("# @server api api\n# @release o/r @api --asset y --to /tmp\n").unwrap_err();
        assert!(err.contains("--installed-cmd"), "{err}");
    }

    #[test]
    fn build_parses_manifest_fields() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @build https://github.com/x/y.git @api --ref abc123 --build cargo --artifacts target/release/app --install-dirs /opt/app/bin --units app.service --version-flag=--version --min-free-gb 20\n",
        )?;
        let step = as_build(&plan.steps[0])?;
        assert_eq!(step.repo, "https://github.com/x/y.git");
        assert_eq!(step.git_ref, "abc123");
        assert_eq!(step.build_cmd, "cargo");
        assert_eq!(step.artifacts, vec!["target/release/app".to_string()]);
        assert_eq!(step.install_dirs, vec!["/opt/app/bin".to_string()]);
        assert_eq!(step.units, vec!["app.service".to_string()]);
        assert_eq!(step.version_flag, "--version");
        assert_eq!(step.min_free_gb, 20);
        assert_eq!(step.prep_cmd, None);
        Ok(())
    }

    #[test]
    fn build_accepts_an_absolute_workdir() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @build https://github.com/x/y.git @api --ref r --build b --artifacts a --install-dirs /opt/a --workdir /home/u/src/x\n",
        )?;
        let step = as_build(&plan.steps[0])?;
        assert_eq!(step.workdir.as_deref(), Some("/home/u/src/x"));
        Ok(())
    }

    #[test]
    fn build_rejects_a_relative_workdir() {
        let err = parse(
            "# @server api api\n# @build https://github.com/x/y.git @api --ref r --build b --artifacts a --install-dirs /opt/a --workdir rel/path\n",
        )
        .unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn build_rejects_a_relative_install_dir() {
        let err = parse(
            "# @server api api\n\
             # @build https://github.com/x/y.git @api --ref r --build b --artifacts a --install-dirs rel/path\n",
        )
        .unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn build_parses_an_optional_prep_command() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @build https://github.com/x/y.git @api --ref r --build b --artifacts a --install-dirs /opt/a --prep 'git submodule update --init'\n",
        )?;
        let step = as_build(&plan.steps[0])?;
        assert_eq!(step.prep_cmd.as_deref(), Some("git submodule update --init"));
        Ok(())
    }

    #[test]
    fn toolchain_parses_tool_list_and_target() -> Result<(), String> {
        let plan = parse("# @server api api\n# @toolchain rustup,cargo,uv @api\n")?;
        let step = as_toolchain(&plan.steps[0])?;
        assert_eq!(step.tools, vec!["rustup", "cargo", "uv"]);
        assert_eq!(step.target.text, "api");
        Ok(())
    }

    #[test]
    fn toolchain_rejects_unknown_tools() {
        let err = parse("# @server api api\n# @toolchain rustup,brew @api\n").unwrap_err();
        assert!(err.contains("unknown tool `brew`"), "{err}");
    }

    #[test]
    fn toolchain_deduplicates_tools() -> Result<(), String> {
        let plan = parse("# @server api api\n# @toolchain uv,uv @api\n")?;
        let step = as_toolchain(&plan.steps[0])?;
        assert_eq!(step.tools, vec!["uv".to_string()]);
        Ok(())
    }

    #[test]
    fn image_parses_images_and_prune() -> Result<(), String> {
        let plan =
            parse("# @server api api\n# @image searxng:latest rsshub:latest @api --prune\n")?;
        let step = as_image(&plan.steps[0])?;
        assert_eq!(step.images, vec!["searxng:latest", "rsshub:latest"]);
        assert!(step.prune);
        Ok(())
    }

    #[test]
    fn image_requires_an_image() {
        let err = parse("# @server api api\n# @image @api\n").unwrap_err();
        assert!(err.contains("missing image"), "{err}");
    }

    #[test]
    fn assert_enabled_parses_unit_state_and_target() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_enabled smg disabled @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(
            step.checks,
            vec![Assertion::Enabled {
                unit: "smg.service".to_string(),
                state: EnabledState::Disabled,
            }]
        );
        Ok(())
    }

    #[test]
    fn assert_enabled_rejects_unknown_states() {
        let err = parse("# @server api api\n# @assert_enabled smg off @api\n").unwrap_err();
        assert!(err.contains("invalid state"), "{err}");
    }

    #[test]
    fn assert_port_free_parses_ports_and_target() -> Result<(), String> {
        let plan = parse("# @server api api\n# @assert_port_free 3000,3001 @api\n")?;
        let step = as_assert(&plan.steps[0])?;
        assert_eq!(step.checks, vec![Assertion::PortFree { ports: vec![3000, 3001] }]);
        Ok(())
    }

    #[test]
    fn assert_port_free_rejects_port_zero() {
        let err = parse("# @server api api\n# @assert_port_free 0 @api\n").unwrap_err();
        assert!(err.contains("port 0"), "{err}");
    }

    #[test]
    fn new_steps_expose_names_kinds_and_targets() -> Result<(), String> {
        let plan = parse(
            "# @server api api\n\
             # @name rel\n\
             # @release o/r @api --installed-cmd x --asset y --to /tmp\n\
             # @name b\n\
             # @build https://github.com/x/y.git @api --ref r --build b --artifacts a --install-dirs /opt/a\n",
        )?;
        assert_eq!(plan.steps[0].name(), Some("rel"));
        assert_eq!(plan.steps[0].kind(), "release");
        assert_eq!(plan.steps[0].target_text(), Some("api"));
        assert_eq!(plan.steps[1].kind(), "build");
        Ok(())
    }
}
