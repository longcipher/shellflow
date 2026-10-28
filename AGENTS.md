# shellflow Agent Instructions

## Non-negotiables

- Surgical edits only: every changed line must trace to the request. No drive-by refactors, no reformatting untouched code, no deleting pre-existing dead code (mention it instead).
- Fix root causes. Never silence a warning, weaken a check, or patch a symptom to make a gate pass.
- Never report completion while any `just` gate below fails. Report the failure verbatim and stop.
- Stop and ask when a request is ambiguous, conflicts with existing conventions, or requires credentials, publishing, or destructive operations.
- When a correction reveals a missing rule, add one specific rule here ("always X for Y", never "be careful with Y"); delete rules that never catch real errors.

## Scope

- `shellflow` is a shell-native, agentless automation CLI: it drives a plain Bash script whose blocks are delimited by `# @` comment directives, over the system `ssh`/`rsync`/`scp`/`bash`. Targets need only `bash`; there is no agent, no SSH library and no YAML.
- `crates/shellflow-dsl` owns the directive scanner and the plan model, `crates/shellflow-core` the templating and exported-variable handling, `crates/shellflow-secrets` the `age`-encrypted secret store (the only crate that touches `age`), `crates/shellflow-muxy` the optional native transport, `crates/shellflow-text` the shared shell-text rules (the zero-dependency leaf), and `bin/shellflow` the CLI, executors and service management.
- `examples/env-app` and `examples/secret-app` are `publish = false` demo targets; `playbooks/deploy.sh` exercises every DSL feature against the `trade`/`api` hosts from `~/.ssh/config`; `SKILL.md` is the agent-facing skill; `docs/design.md` holds the architecture (Part I DSL/engine, Part II `S1`-`S12` secrets).
- English only in code, comments, docs, and commit messages.

## Execution

- Parallelize aggressively: dispatch subagents for independent research, exploration, and implementation.
- NEVER run two `cargo` commands concurrently, and never overlap file edits with a running `cargo` command (`target/` file lock): finish edits, wait, then run.
- NEVER use `git worktree`. Edit the current branch in place.
- TDD for behavior changes: failing test first, smallest change to pass, then run `just mutation` and fix surviving mutants.

## Verification loop

After each feature or bug fix, in order; any failure means the task is not done:

```bash
just format
just lint
just test
just mutation
```

`just lint` is the CI gate: `typos`, `rumdl`, `cargo sort --check`, `cargo +nightly fmt --check`, `cargo +nightly clippy -D warnings`, `cargo shear`. `just fuzz-check` type-checks the fuzz targets; `just fuzz SECS=60` runs them.

## Rust workspace rules

- Edition 2024, resolver 3. Members are `crates/*`, `bin/*` and `examples/*`; the fuzz crates under `crates/*/fuzz` are detached workspaces and are excluded from the root workspace on purpose.
- Because the fuzz crates are detached, `cargo fmt --all` skips them: `just format` formats their `fuzz_targets/*.rs` explicitly with `rustfmt --edition 2024`. Keep it that way when a fuzz target is added.
- `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `print_stdout`, `print_stderr` and `allow_attributes` are `deny`. The only escape hatch is `#[expect(lint, reason = "...")]`.
- Test modules opt out of the test-only lints through one `#![cfg_attr(test, allow(...))]` per crate root (`panic`, `unwrap_used`, `expect_used`, `pedantic`, `nursery`); that is the only place a bare `allow` appears, and it never applies to production code.
- `print_stdout` has **no** module-level exemption: every line the tool prints goes through `ui` (`Ui` on the run path, `ui::report!` for report subcommands). A `println!` in any other module fails the lint.
- `.cargo/config.toml` sets `rustc-wrapper = "kache"`; clippy invocations must clear it (`RUSTC_WRAPPER=`) exactly as the Justfile does.
- There is no `rust-toolchain.toml`: CI installs nightly, so use `cargo +nightly fmt` and `cargo +nightly clippy` exactly as the Justfile does.
- `.cargo/mutants.toml` excludes only `bin/shellflow/src/main.rs`, `bin/shellflow/src/executor/process.rs`, and `examples/*/src/**`: every other `bin` module carries unit tests that kill mutants, so they stay in mutation scope. The orchestration paths that need a live process tree are covered by `bin/shellflow/tests/integration.rs` instead.
- Never hand-type dependency versions. Shared crates go into root `[workspace.dependencies]` and members reference them with `workspace = true`.

## Dependency choices

- The DSL is Bash, not a parser library: `shellflow-dsl` scans `# @` directives itself. Do not introduce a YAML/TOML script format.
- Remote execution shells out to the system `ssh`/`rsync`/`scp` through `tokio::process::Command`; never add an SSH client crate.
- Secrets use `age` for encryption and `zeroize` for in-memory wiping. Secret values are masked in every preview, including local blocks.
- `nix` covers process/signal/user/fs handling, `sd-notify` the systemd readiness protocol, `zbus` the optional D-Bus path, `tokio` (`full`) the async runtime, `clap` (derive) the CLI, `colored` the output. There is no logging framework: `ui` is the one output path (streaming, masking, audit log).
- The muxy transport is tested against an in-crate fake peer (`crates/shellflow-muxy/src/harness.rs`, `#[cfg(test)]`) that speaks the real wire protocol over a socket pair. `muxy-server` is **not** a usable dev-dependency (its `muxy-terminal` builds ghostty's VT with `zig` and a network fetch); do not re-add it.
- Errors: `thiserror` in the library crates, `eyre` in `bin/shellflow`. Concrete error types through `?`; never string errors.
- Forbidden here: `anyhow`, `log`, `reqwest`, `dashmap`.

## Code conventions

- A deploy script must stay 100% valid Bash: `bash deploy.sh` has to run it unchanged. Never emit syntax that only the shellflow parser accepts.
- Directives are defined in `docs/design.md` section 4.1 (`shellflow-dsl` owns the scanner); add new ones to `shellflow-dsl` with a parse test, never ad hoc in the executors.
- Multi-host fan-out goes through `JoinSet` plus a semaphore; never spawn one task per host without the bound.
- The `dbus` feature (systemd unit state over D-Bus) is off by default so the standard build stays a single static binary; the CLI polls instead. Keep D-Bus code behind the feature.
- Do not introduce `unsafe` except where a libc-level API leaves no alternative, and then only with a `// SAFETY:` comment stating the invariant. Today there are 18 such blocks: `nix::sys::signal::signal` for the `systemd` helper's signal forwarding and for the CLI's test-only `set_var`/environment locks, plus `shellflow-secrets`' `O_NOFOLLOW` open and fchmod calls. If `std::env::set_var` is needed in tests, hold the crate's `ENV_LOCK` and carry the `// SAFETY:` comment.
- `proptest` properties live next to the crate logic they exercise and run in the ordinary `cargo test` loop; the fuzz targets cover the hostile-input parsers (`fuzz_parse_script`, `fuzz_interpolate`, `fuzz_parse_ssh_spec`, `fuzz_parse_env_file`).
- Directive parsing lives only in `shellflow-dsl`: never hand-roll a `strip_prefix("# @…")` scanner elsewhere (the whole-word rule, spec validation, and here-document awareness live in the grammar). A status/verify subcommand reads a playbook through `parse_script`.
- The `run` path prints only through the `ui` module (masked, audited); report subcommands print through the `ui::report!` / `ui::report_part!` macros, which route to the same sink. `main.rs` keeps one scoped `#[expect(clippy::print_stderr, …)]` for the fatal-error and interrupt banners, which must reach a possibly-broken stderr. A bare `println!` anywhere else fails the lint.
