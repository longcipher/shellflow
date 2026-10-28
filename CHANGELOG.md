# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The Muxy transport dropped the tail of every step.** `LineAssembler::finish`
  existed but was only called from tests, so the rows still on screen when a
  session ended were never flushed: a step whose output was shorter than one
  screen (the default is 50 rows) streamed nothing at all. The end of a session
  now flushes first, and cancellation collects the same flush before it drops
  the channel.
- **An unterminated here-document silently truncated the plan.** Every later
  `# @` directive was swallowed as body text, producing a plan that looked
  valid and was missing steps. Parsing now fails with
  `line N: unterminated here-document `TAG`` pointing at the opening line.
- **A helper timeout was classified as a script failure on the `@service` path**
  while `@wait_active` called it a timeout — two ladders, two answers. Both use
  `executor::classify_helper_exit`, so a slow host exits 5 (retry) and a broken
  deploy exits 4 (roll back) on every path.
- **`--body 'hello world'` did not parse.** Seven directives tokenized their
  payload with `split_whitespace` while the other twenty-six were
  quote-aware. All 33 now share `split_words`/`split_flags`.
- **`@assert foo banana` parsed and failed on the target.** `@assert` accepted
  any `[A-Za-z0-9-]` state while `@assert_enabled` enforced four legal values.
  Both now use closed enums (`ActiveState`, `EnabledState`).
- **Blocking `systemd` verbs ran on a tokio worker.** `wait`, `reload`,
  `exec` and `watchdog` poll with `std::thread::sleep`; they are now dispatched
  through `spawn_blocking`.
- **A UTF-8 BOM hid the first key of an env file**, so a store edited on
  Windows looked corrupt.
- **The identity directory was created with the umask's permissions**; it is
  now `0700` like the key file it holds.
- **An uninstalled signal handler was ignored** in `systemd exec`: a supervisor
  that cannot forward `SIGTERM` now fails instead of silently never stopping.
- **A failed wait left the batch watchdog spinning** for the full timeout, and
  a probe's stdout reader was detached instead of aborted.

### Changed

- **`host.rs` is a module family, not a god module.** 1450 lines became a
  dispatch table (259 lines) plus `host/{probe,lifecycle,install,backup,
  credstore,privileged}.rs`, and `HostError` became an enum keyed on the reason
  (`Usage`/`Internal`/`Failed`/`TimedOut`/`Delegated`) instead of a
  `{ message, code }` pair. The eight hand-rolled `sudo` invocations now go
  through one constructor, so `sudo -n` cannot be forgotten at a new call site.
- **The `muxy` feature no longer forks the executors' shape.**
  `executor::Native` carries the connection cache and plan index in every
  build, which removed 18 of the 31 `#[cfg(feature = "muxy")]` attributes from
  the step dispatch; what remains is the single transport decision and the
  attempt it guards.
- **The target-side host verbs are tested.** `@service`'s policy (restart
  only a running unit, wait only for a unit that exists, skip `enable` for a
  generated unit), the digest gate, the credential-store agreement check and
  the leak comparison are now pure functions with unit tests, which is what
  mutation testing needed: `host.rs`, `host/lifecycle.rs` and
  `host/install.rs` are now at 0 surviving mutants.
- **Every line the tool prints goes through `ui`.** Report subcommands used
  `println!` directly, which skipped the masker and needed a per-module
  `print_stdout` exemption; they now use `ui::report!` and the exemption is
  gone, so a bare `println!` outside `ui`/`main` fails the lint again.
- **The `muxy` pump queue is bounded** (256 messages) with backpressure, so a
  slow consumer cannot grow memory without limit.
- **Secrets no longer appear in `Debug` output**: `SecretMasker`, `StepParams`
  and `PumpMsg` hand-write `Debug` and show counts instead of values.
- **`scp` takes its connection policy from `transport::SshPolicy`** instead of
  spelling `BatchMode`/`ConnectTimeout=15` itself.
- **One `systemctl` invocation path** (`src/systemctl.rs`) and one unit-name
  rule set (`shellflow-text`) replace the copies in `host` and `systemd`.
- **`--export` accepts `--public` in any position**; it was a trailing-suffix
  special case.
- **Bracketed IPv6 destinations** (`deploy@[2001:db8::1]:2222`) parse and
  round-trip into `ssh`/`rsync` argv.

### Added

- `@assert` accepts the full `systemctl is-active` set: `active`, `reloading`,
  `inactive`, `failed`, `activating`, `deactivating`.
- `just ci` runs `fuzz-check` and `check-cn`; a nightly CI job runs `just
  mutation`, and mutation testing now covers `bin/shellflow` except the two
  modules whose behaviour lives in the integration suite.

## [0.5.2] — 2026-10-26

Version-only release: the `0.5.0` index entry on crates.io is broken and cannot
be published over, so `0.5.1`/`0.5.2` re-cut the same tree. The transport,
exit-code and masking seams converged in this release (`e8110c2`).

## [0.4.0] — 2026-10-22

The release that moves the deployment logic out of the playbooks and into the
tool: a set of new DSL primitives, a target-side helper that owns their
semantics, and the systemd integration that makes "the unit is active" mean
"the service can serve traffic".

### Added

- **New DSL primitives.** `@service`, `@install`, `@backup`, `@credstore`,
  `@assert_no_leak`, `@assert_digest`, `@assert_credstore`, `@unit_inventory`,
  `@helper` and `@workdir`. Each one replaces a hand-written block that every
  playbook spelled slightly differently — and that every playbook spelled
  *wrongly* in the same way.
- **Target-side host helpers.** `shellflow host <service|install|backup|
  credstore|assert-no-leak|assert-digest|assert-credstore|inventory>` runs on
  the target and owns the correctness of the operation: the install is
  **atomic** (write beside the destination, then rename), the backup asserts
  on the files *it* wrote rather than re-globbing a directory through a
  pipeline that cannot fail, and the leak check compares the **real
  credential values** instead of a per-service regular expression.
- **The systemd readiness supervisor.** `shellflow systemd exec` starts a
  command, waits for a declared readiness condition (a port, a URL, a file),
  sends `READY=1`, forwards `SIGTERM`, and exits with the child's status. A
  `Type=simple` unit's `active` means "the process was forked"; with the
  supervisor it means "the service can serve traffic".
- **The watchdog keepalive.** `shellflow systemd watchdog` keeps a unit's
  `WatchdogSec=` alive, so a hung-but-alive process is no longer invisible.
- **The service manifest.** `services/<svc>/<unit>.service.toml` states a
  unit's host, binary, credential store and keys, render templates, ports,
  health URL, user and runtime directory **once**. `shellflow unit render`
  derives the unit's drop-in from it — the credential wiring, the render line,
  the version status line — so those are generated rather than copied, and
  they cannot drift apart. `service status --all` reads the fleet map from the
  manifests instead of parsing playbook text.
- **The repository consistency check.** `shellflow unit verify` answers
  statically whether the generated drop-ins are up to date, whether every
  `@install` names a file the playbook actually stages, whether every
  service's drop-in is installed, whether the shared hardening reaches
  every service that takes it, and whether every backup runs **before** the
  install it protects — a snapshot taken after the overwrite restores what
  was just deployed, not what was there.
- **`service check --all`.** Every service of a host is audited in **one** SSH
  round trip instead of one per service.

### Changed

- **The `@only_if` guard runs inside the payload.** A guarded step costs one
  SSH round trip instead of two. A failing guard still skips the block (the
  block reports `SKIPPED` through a dedicated exit code).
- **`--ssh-reuse` is on by default.** A playbook is a sequence of steps
  against the same hosts; every step used to pay a full TCP connect plus key
  exchange. `ControlMaster=auto` is safe by construction — OpenSSH replaces a
  dead control socket rather than failing on it. `--no-ssh-reuse` turns it
  off.
- **`service status` queries the fleet concurrently** instead of one
  handshake after another.
- **The batch transport streams.** The answers are parsed as they arrive, so
  the response is never held twice, and the connection closes as soon as the
  last expected answer is in.
- **`service check` audits the unit invariants.** It now flags a **shared
  `RuntimeDirectory=`** (systemd recreates it on every start, so two units
  sharing one destroy each other's files), a notify unit without
  `TimeoutStartSec=`, a restart policy without `StartLimitBurst=`, a unit
  with no hardening at all, and a `ProtectHome=`/`ReadWritePaths=` conflict.

### Fixed

- The assertion primitives reject an unsafe unit name, a state with an
  unsafe character, a non-alphabetic HTTP method, a header without a colon,
  an unknown flag, a URL with a control character, a non-octal file mode, an
  unsafe owner, and a timeout of zero.

[0.4.0]: https://github.com/longcipher/shellflow/releases/tag/v0.4.0
