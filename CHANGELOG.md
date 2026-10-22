# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
