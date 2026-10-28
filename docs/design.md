# shellflow — Design Document

> Part I covers the DSL and execution engine; **Part II** (sections `S1`–`S12`)
> covers the embedded `age` integration (`keys`/`secret`), the `@secrets`
> directive, `--local` mode, and the target-side `cred-env` helpers. The
> optional native transport (`shellflow-muxy`, the `muxy` feature) is
> documented in `docs/muxy-transport.md`.

## 1. Executive Summary

`shellflow` is a minimal, modern, single-binary Rust CLI for shell-native
deployment. It combines the best ideas of:

| Tool | Idea absorbed |
|---|---|
| **Mina** | A single SSH connection per remote block: the Bash script is piped over `ssh host "bash -s"` via stdin, eliminating per-command round trips. |
| **Envoy** | Pure-Bash developer experience: the "DSL" is just a Bash script with comment directives. No YAML, no new language, full editor highlighting. |
| **Deployer** | The canonical pipeline: `local build -> copy (rsync) -> remote deploy`, with multi-host fan-out. |
| **pyinfra** | Realtime debugging (`-v/-vv/-vvv`) and idempotent dry-run/diff previews — without Python or a fact-collector engine. |

Design constraints:

- **Zero YAML, zero Python.** The input is 100% valid Bash. `bash deploy.sh` runs
  the file as a plain script; `shellflow` interprets `# @` comment directives to
  drive local/remote execution.
- **Zero embedded SSH protocol.** We shell out to the system `ssh` and `rsync`
  via `tokio::process::Command`. This inherits `~/.ssh/config`, `ssh-agent`,
  keys, jump hosts, and hardware tokens for free.
- **Leverage the shell, do not reimplement it.** `set -ex` replaces a debugger,
  `rsync --dry-run -i` replaces a diff engine, `bash -n` replaces remote syntax
  checking.
- **Production-safe by default.** Timeouts, Ctrl-C/SIGTERM cleanup, preflight
  checks, and exit codes CI can distinguish — no orphan processes.

## 2. Goals & Non-Goals

### Goals

- A single static binary (few MB, LTO-fat release profile) that runs anywhere
  `ssh`/`rsync`/`bash` exist — local, CI (GitHub Actions, GitLab CI), laptop.
- Concurrent multi-host execution with live, host-prefixed, color-coded output.
- `-v / -vv / -vvv` realtime debugging with zero extra architecture.
- `--dry-run` / `--diff` idempotent previews before any change.
- Lean, auditable codebase: the library crates `shellflow-text` (shared
  shell-text rules, the zero-dependency leaf), `shellflow-dsl`, `shellflow-core`,
  `shellflow-secrets`, `shellflow-muxy` (the optional native transport, behind
  the `muxy` feature) plus the `bin/shellflow` CLI, of which about a third is
  tests. The target is clarity and test coverage, not line-count
  gymnastics — "lightweight" means a single static binary with no runtime
  dependencies, not minimal source lines.- Production-safe lifecycle: global and per-step timeouts, Ctrl-C/SIGTERM
  handling that never leaves orphan processes, and a friendly preflight check.
- TDD with unit tests + `proptest` in the normal `cargo test` loop, plus
  `cargo-mutants` for mutation coverage (`just mutation`).

### Non-Goals

- No server-side agent, daemon, or push/pull protocol.
- No configuration-state database or fact-collector engine (pyinfra-style
  "facts"). Idempotency is achieved through `@only_if` guards and transport
  semantics (`rsync` delta), not a state model.
- No reimplementation of SSH, SCP, or rsync.
- No Windows support in v1 (Bash-dependent; WSL is an acceptable host).
- No interactive credential handling. Scripts run with the SSH user's
  privileges; interactive password prompts are explicitly unsupported (see
  §9).

## 3. Related Work & Absorbed Ideas

### 3.1 Mina — script streaming over a single SSH connection

Mina's core trick: concatenate the whole remote task into one script and feed it
once via stdin. We do exactly this:

```text
shellflow                     ssh -T user@host bash -l -s     remote host
┌─────────────┐   stdin    ┌──────────────────────────────┐   ┌─────────┐
│  payload    │ ─────────> │ set -eu + env(PATH) + block  │ ─>│ bash    │
│  (memory)   │            │  (env precedes set -x, §7.2)  │   │ stdout  │
└─────────────┘            └──────────────────────────────┘   │ stderr  │
        ▲                                                      │         │
        └──────────────────── streamed lines ─────────────────┘         │
```

One TCP/SSH setup per host per remote block — no per-command overhead.

### 3.2 Envoy — pure Bash DX

Envoy's insight is that the deployment description should *be* a script.
Comment directives keep the file executable as plain Bash while giving the tool
structured boundaries.

### 3.3 pyinfra — realtime debugging + idempotent preview, without the engine

pyinfra's two most loved features are:

1. **Realtime debugging** — see exactly what runs on which host, when.
2. **Idempotent dry-run/diff** — prove the change before making it.

pyinfra implements these with a heavy Facts → State → Operations engine. We
reproduce both features with three shell primitives (see §8), keeping the total
complexity at a fraction of pyinfra's.

## 4. The DSL: Pure Bash + Comment Directives

### 4.1 Directive grammar

A directive is a Bash comment line whose first non-whitespace token is `# @`.
All other lines (including plain comments) belong to the current block.

| Directive | Syntax | Semantics |
|---|---|---|
| `@server` | `# @server <name> <ssh-spec>` | Declare a server alias. `<ssh-spec>` = `[user@]host[:port]` |
| `@group` | `# @group <name> <member>[,<member>…]` | Declare a group of server aliases |
| `@env` | `# @env <KEY>` / `# @env <KEY>=<value>` | Inject an env var into subsequent blocks. No `=value` → copy from shellflow's own environment. Values never appear in argv and are masked in previews/traces (§7.2, §9) |
| `@local` | `# @local` | Following lines run on the local machine (default at start) |
| `@remote` | `# @remote <target>` | Following lines stream to `<target>` (alias, group, or raw ssh-spec; `@`-prefix optional) |
| `@copy` | `# @copy <src> -> <dst> @<target> [--delete] [--exclude <glob>]` | Sync a local file/dir to `<dst>` on all hosts in `<target>`. `--delete` mirrors removal of remote extras; in `--local` mode it swaps a staged copy into place so a failed copy cannot empty the destination. `--exclude` (repeatable) is honored by the rsync path and warned as ignored on the scp fallback and in `--local` mode. `src`/`dst` support `$VAR`/`${VAR}` interpolation from `@export`ed state (§4.4) |
| `@secrets` | `# @secrets <file.env.age> [--identity <path>]` | Decrypt an age-encrypted `KEY=VALUE` file into the environment of all subsequent blocks (Part II §S5). `--identity` overrides the run-wide `-i` for this entry only. |
| `@export` | `# @export <VAR>[,<VAR>…] [--public]` | After the preceding local block, capture the named variables into run state; later `@copy` paths interpolate them and later blocks receive them as env vars (§7.6). A captured value is **masked by default** — the value is unknown at parse time and a playbook routinely exports a credential it just fetched; `--public` is the explicit, reviewable opt-out for a value that is meant to be read (`VERSION`, `COMMIT`) |
| `@timeout` | `# @timeout <seconds>` | Cap the next block per host; on expiry the child is SIGTERM'd, then SIGKILL'd after a grace period (§7.5) |
| `@name` | `# @name <label>` | Label the next block (for `--only`/`--skip` filtering and reporting) |
| `@only_if` | `# @only_if <command>` | Guard: run next block only where `<command>` succeeds (exit 0); otherwise report `SKIPPED` |
| `@wait_active` | `# @wait_active <unit> @<target> [--timeout SECS]` | Poll `systemctl is-active <unit>` on every target host until it reports active or the budget expires (default 300s). Replaces the hand-rolled `for`/`sleep`/`ss` poll loops that differ in every playbook. A host that never reports active is `FAILED` (script class); an unreachable host is a transport failure (§6) |
| `@assert` | `# @assert <unit> [@<target>] [<state>]` | Assert the unit's `ActiveState` on the target (default `active`). The target is inherited from the previous step when it is not given. A failed assertion fails the step (script class) |
| `@assert_health` | `# @assert_health <url> [@<target>] [--expect CODES] [--method M] [--body D] [--header H]` | Assert that the URL answers with an accepted HTTP status (any 2xx/3xx by default; `--expect` takes exact codes and classes such as `2xx`). `--method`/`--body`/`--header` cover endpoints that only answer POST. The probe waits (up to the step's timeout) on the target, so a service that was just started is not failed for the wrong reason. The target is inherited from the previous step |
| `@assert_port` | `# @assert_port <port>[,<port>…] [@<target>] [--udp]` | Assert that the ports are listening, waiting up to the step's timeout (in one round trip, not one per poll). `--udp` checks the UDP sockets. The target is inherited from the previous step |
| `@assert_port_free` | `# @assert_port_free <port>[,<port>…] [@<target>]` | Assert that the ports have no listener. A conflict names the occupant (the listening process, `nft` DNAT rules, container publish mappings) instead of just "address in use" |
| `@assert_enabled` | `# @assert_enabled <unit> <enabled\|disabled\|static\|masked> [@<target>]` | Assert the unit's boot state. The expected state is declared next to the unit, so enablement drift fails the deploy instead of waiting for a reboot surprise |
| `@assert_rendered` | `# @assert_rendered <path> [@<target>]` | Assert that the file exists and holds no unexpanded `${…}` placeholder. The target is inherited from the previous step |
| `@assert_no_leak` | `# @assert_no_leak <unit> [@<target>] [--lines N]` | Assert that no credential **value** of the unit's store appears in its journal, its command line, or its environment. The check is value-based: the target-side helper decrypts the store and compares, so a playbook needs no per-service regular expression and the plaintext never reaches the script, the command line, or the log |
| `@assert_digest` | `# @assert_digest <path> [@<target>] [--sha256 HEX] [--local PATH]` | Assert that the file matches a digest (`--sha256`) or the controller's copy of it (`--local`). A real drift gate: the hand-written `md5sum` printed a digest that nothing compared |
| `@assert_credstore` | `# @assert_credstore <service> [@<target>]` | Assert that the service's credential store exists, is `0700`/`0600`, and holds exactly the keys the unit declares. A key in one and not the other is a unit that fails to start with a cryptic systemd error; this makes it a readable failure |
| `@workdir` | `# @workdir [--prefix NAME]` | Declare the run's **remote** staging directory, published to the run state as `WORKDIR`. The controller never creates it, so a run leaves nothing behind on the machine that drives the deployment; the target's copy is removed when the run ends |
| `@helper` | `# @helper [@<target>] [--source DIR] [--triple T] [--install-path PATH]` | Build, cache, ship, and atomically install the target-side helper. The build is the expensive part of a deploy, so the artifact is cached by source revision and target triple: the second service reuses the first one's build |
| `@backup` | `# @backup <path>… @<target> [--keep N] [--seal] [--dir PATH] [--service S]` | Snapshot the paths for rollback, keep the newest `N`, and shred the rest. `--seal` encrypts the snapshot with the host key, so no plaintext lands on disk. The "no plaintext left behind" guarantee is **structural**: the helper checks the files *it* wrote, not a directory re-globbed through a pipeline that cannot fail |
| `@install` | `# @install <src> -> <dst> @<target> [--mode M] [--owner U:G] [--dir-mode M]` | Install a file on the target **atomically**: the data is written to a temporary name in the destination directory and renamed into place, so a reader (systemd, `systemctl cat`, a concurrent `daemon-reload`) never observes a half-written unit file, config, or binary |
| `@credstore` | `# @credstore <service> @<target> [--require KEY,…]` | Seal the service's credential store and check it against the keys the unit declares |
| `@service` | `# @service <unit> @<target> [--enable] [--restart] [--reload] [--wait] [--verify] [--force-start]` | Drive the unit's lifecycle: verify the installed unit, reload the manager, enable it, restart it, wait for it to be ready. `--restart` restarts a unit that was **running** and leaves a unit that was not running alone — restarting an inactive unit *starts* it, which is the opposite of what an operator who keeps a unit stopped wants. `--force-start` overrides that deliberately |
| `@reload` | `# @reload <unit> @<target> [--signal SIG] [--wait] [--timeout SECS]` | Reload a unit through its own `ExecReload=` (or an explicit `--signal`); `--wait` waits for readiness. A reload that cannot be performed fails instead of degrading into a restart |
| `@unit_inventory` | `# @unit_inventory [@<target>]` | List the units installed on the target. A **report**, not a gate: a pre-existing finding must never block an unrelated deploy |
| `@release` | `# @release <owner/repo> @<target> --installed-cmd CMD --asset PATTERN --to DIR [--base-url URL]` | Track a GitHub release: resolve the newest tag (via the `releases/latest` redirect, falling back to the API), compare against the installed binary, and download the matching asset only on drift. `{tag}`/`{version}` expand to the `v`-prefixed/bare tag; the install is atomic; an unresolvable release skips instead of failing. `--base-url` overrides the download host for vendor CDNs |
| `@build` | `# @build <repo-url> @<target> --ref REF --build CMD --artifacts A… --install-dirs D… [--prep CMD] [--workdir DIR] [--units U…] [--version-flag F] [--min-free-gb N]` | Build a pinned ref from source on the target: fetch and detached-checkout, native build, disk guard, fresh-binary preflight (declared flag first, then the flag chain), backup, atomic install, restart-only-running units, auto-rollback (old binary restored, unit re-started) on restart failure. Artifacts support `path=name` renames. `--prep` runs at the repo root after checkout (e.g. submodule init). `--workdir` builds inside an existing checkout instead of cloning (for cross-repo path deps); checkout there is never forced |
| `@toolchain` | `# @toolchain <tool,…> @<target>` | Update language toolchains (`os`, `aur`, `rustup`, `cargo`, `go`, `npm`, `pipx`, `uv`, `foundry`, `proto`, `gh`). Each missing tool reports SKIP; any failed update fails the step. The per-tool quirks (AUR never under sudo, `uv tool upgrade --all`, foundry skipped while `anvil` runs) are owned by the runner |
| `@image` | `# @image <image…> @<target> [--prune]` | Pull container images (podman, then docker), compare digests before/after, report MOVED/SAME/FAIL per image |

**Assertion steps.** Consecutive assertions that share a target are merged
into **one** step: the whole group travels in a single SSH round trip, and the
operator sees which condition failed. A *named* assertion is its own step, so
it can be selected on its own with `--only`. An assertion's path or URL may
name a captured variable (`/run/${SVC}/config.toml`); it is resolved from
the run state, like a `@copy` path. The target may be
omitted, in which case it is inherited from the previous step — the common
case is therefore a single short line. An assertion step replaces the
hand-written `systemctl is-active && curl -f` tail that every playbook used
to end with, and that every playbook spelled differently.

**Rules:**

1. Every `# @` directive flushes the pending block. Directives may appear in any
   order and may be interleaved with blocks.
2. A block that contains no executable statement (only comments/blank lines) is
   dropped.
3. Blocks default to `local` until an explicit `@remote`/`@copy`/`@local`.
   `@copy` is a self-contained step that carries its own target, and it returns
   the block mode to `local` — the lines that follow are not streamed to the
   copy's remote target. Other self-contained steps (`@wait_active`,
   `@reload`, `@assert*`, `@service`, `@install`, `@backup`, `@credstore`,
   `@helper`, `@workdir`, `@unit_inventory`, `@release`, `@build`,
   `@toolchain`, `@image`) leave the ambient mode unchanged:
   lines after `# @service …` still run where the previous `@remote`/`@local`
   put them.
4. `@env`, `@only_if`, `@timeout`, and `@name` apply to the *next* block that
   contains statements. `@export` applies to the *preceding* local block and is
   an error after a remote block (remote variables cannot be captured). Because
   every directive flushes the pending block, the preceding local block may
   already have been emitted when `@export` is read; `@export` therefore binds
   to the last emitted local step, not only to the pending one.
5. The shebang `#!/usr/bin/env shellflow` is a comment like any other: a
   comment-only block is dropped, but a block that also holds code keeps its
   lines verbatim (harmless under `bash`, which treats it as a comment).
6. CRLF line endings are tolerated (`\r` stripped).
7. Lines are included verbatim in the payload, preserving fidelity.
8. A here-document body is opaque: `<<TAG` / `<<-TAG` openers are tracked
   lexically and every line up to the exact terminator is script content,
   exempt from directive detection. Bodies are consumed FIFO because one
   line may open several here-documents.
9. A directive keyword must be a whole word: `# @server-web x` is an unknown
   directive, not `@server` with the name `-web`.

### 4.2 Reference example

```bash
#!/usr/bin/env shellflow

# === Servers and groups ===
# @server web1 deploy@10.0.0.1
# @server web2 deploy@10.0.0.2:2222
# @group  web  web1,web2

# === Build locally, capture the git revision ===
# @name build
# @local
set -eu
echo "==> building release binary"
cargo build --release --locked
VERSION=$(git rev-parse --short HEAD)

# === Capture VERSION into run state (see §4.4, §7.6) ===
# @export VERSION --public

# === Ship the artifact ($VERSION is interpolated by shellflow, not Bash) ===
# @name ship
# @copy target/release/myapp-$VERSION -> /tmp/shellflow/myapp-$VERSION @web --delete

# === Restart, but only where the service exists ===
# @name restart
# @remote web
# @only_if systemctl list-unit-files --type service | grep -q myapp
set -eu
echo "==> restarting myapp-$VERSION on $(hostname)"
sudo systemctl restart myapp
```

### 4.3 Parsing model

The parser is a single-pass line scanner (no regex, no PEG engine — see
Decision Record D-3). It produces an `ExecutionPlan`:

```rust
/// A parsed `[user@]host[:port]` destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshSpec {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// Target of a remote/copy step: a server alias, a group, or a literal spec.
///
/// The raw text is kept verbatim and classified lazily in `resolve_hosts`, so
/// a step may target a group that is declared later in the script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    /// The raw target text from the script (`web`, `deploy@host`…).
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct LocalStep {
    pub name: Option<String>,
    pub script: String,
    pub guard: Option<String>,
    pub timeout: Option<u64>,
    /// Variables captured into run state after this step (`@export`).
    pub export: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RemoteStep {
    pub name: Option<String>,
    pub target: Target,
    pub script: String,
    pub guard: Option<String>,
    pub timeout: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct CopyStep {
    pub name: Option<String>,
    /// Consecutive copies to the same target travel in one transfer.
    pub entries: Vec<CopyEntry>,
    pub target: Target,
    pub delete: bool,
    /// `--exclude <glob>` patterns (repeatable); honored by the rsync path,
    /// warned as ignored on the scp fallback and in `--local` mode.
    pub excludes: Vec<String>,
    /// `@only_if` is **not supported on `@copy`** — the parser rejects it and
    /// this field stays `None` in valid plans (retained for struct symmetry).
    pub guard: Option<String>,
    /// Per-step timeout in seconds (`@timeout`); bounds the rsync/scp transfer.
    pub timeout: Option<u64>,
    /// `@env` snapshot in effect when the copy was declared.
    pub env: std::sync::Arc<Vec<EnvEntry>>,
}

#[derive(Clone, Debug)]
pub enum Step {
    Local(LocalStep),
    Remote(RemoteStep),
    Copy(CopyStep),
    Wait(WaitStep),
    Reload(ReloadStep),
    Assert(AssertStep),
    Service(ServiceStep),
    Install(InstallStep),
    Backup(BackupStep),
    Credstore(CredstoreStep),
    UnitInventory(UnitInventoryStep),
    Helper(HelperStep),
    // Added after this section was written; see §4.1 for the directives.
    Build(BuildStep),
    Release(ReleaseStep),
    Toolchain(ToolchainStep),
    Image(ImageStep),
}

/// A wait-for-active step (`@wait_active`).
#[derive(Clone, Debug)]
pub struct WaitStep {
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// systemd unit name (`foo` or `foo.service`).
    pub unit: String,
    /// Wait budget in seconds (`@timeout` or `--timeout N`, else 300).
    pub timeout: Option<u64>,
    /// Poll interval in seconds (fixed at 5: kind to systemd, not a knob).
    pub interval_secs: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionPlan {
    /// Deterministic ordering (BTreeMap) for stable plan summaries.
    pub servers: BTreeMap<String, SshSpec>,
    pub groups: BTreeMap<String, Vec<String>>,
    /// All `@env` entries, in declaration order.
    ///
    /// Copy-on-write behind an `Arc`: every step holds an `Arc` clone of the
    /// snapshot that was current when it was declared, so snapshotting the
    /// environment into every step costs one pointer copy rather than a deep
    /// copy of every key/value pair.
    pub env: Arc<Vec<EnvEntry>>,
    /// All `@secrets` file references, in declaration order.
    pub secrets: Vec<SecretEntry>,
    /// The run's remote staging directory (`@workdir`), if declared.
    pub workdir: Option<Workdir>,
    pub steps: Vec<Step>,
}

/// Captured cross-step state (`@export`): interpolated into later `@copy`
/// paths and injected as env vars into later local/remote blocks.
#[derive(Clone, Debug, Default)]
pub struct RunState {
    pub vars: BTreeMap<String, String>,
}

/// Pure resolution: alias/group/raw -> concrete hosts, honoring a CLI
/// `--target` restriction. Kept in the core crate so it is unit-testable.
pub fn resolve_hosts(
    plan: &ExecutionPlan,
    target: &Target,
    restrict: &[String],
) -> Result<Vec<ResolvedHost>, ParseError>;
```

`ResolvedHost { alias: String, spec: SshSpec }` carries the display alias
(`web1`) for log prefixes and the concrete spec for `ssh`/`rsync` argv.

### 4.4 Known limitations (documented)

- Directive detection is lexical. A `# @foo` line inside a **here-document
  body** is recognized as body data, not a directive, so generated content
  (systemd units, templates, YAML) can never rewrite block boundaries. A
  `# @foo` line inside a multi-line *string* that is not a here-document is
  still treated as a directive, because a lexical scanner cannot see
  multi-line string spans. Deploy scripts should keep directives at the top
  level.
- A here-document whose delimiter the shell expands (`<<$TAG`,
  `` <<`gen_tag` ``) cannot be tracked statically, so its body keeps the
  untracked behavior. Quoted (`<<'TAG'`, `<<"TAG"`) and backslash-escaped
  (`<<\TAG`) delimiters are literal and are tracked exactly. See
  `crates/shellflow-dsl/src/heredoc.rs`.
- An **unterminated** here-document is a parse error naming the line that
  opened it. Bash only warns and treats end-of-file as the terminator; matching
  that would let a missing terminator silently swallow every later directive,
  producing a plan that looks valid and is missing steps. The strictness is
  deliberate and is the one place the grammar is stricter than Bash.
- Directive payloads are tokenized with the same quote-aware rule everywhere
  (`'a b'` is one value), so a quoted `--body`/`--header`/path behaves the same
  in all 33 directives.
- No conditional/loop constructs in the DSL itself. Script authors use plain
  Bash (`if`, `for`, `command -v`, `[ -f ] || …`) for control flow, and
  `@only_if` for host-level preconditions.
- **`@copy` paths are parsed by shellflow, not Bash.** `src`/`dst` are literal
  strings extracted from the comment, so a bare `$VERSION` there is *not*
  expanded by Bash and would silently reach `rsync` verbatim. Use `@export` to
  capture values and let shellflow interpolate `$VAR`/`${VAR}` from run state.
  An unresolved variable is an error at execution time, never a silent no-op.
  `@env KEY= value` keeps the space, like a shell assignment with a quoted
  value would need quoting to preserve.
- `@copy` delimiters are fixed: `src`/`dst` must not contain the literal `->`,
  the target is the final whitespace-separated token (an `@` prefix is
  optional and stripped). A `dst` with spaces is joined from the middle tokens;
  a leading `@` in a path is ambiguous with the target marker and unsupported.

## 5. Architecture

### 5.1 Workspace layout

Per `AGENTS.md`: `bin/` holds CLI crates, `crates/` holds reusable libraries.

```text
shellflow/
├── Cargo.toml                 # workspace deps & lints
├── Justfile                   # format/lint/test/mutation/build
├── AGENTS.md                  # the non-negotiables an agent must follow
├── docs/
│   ├── design.md              # this document (Part I: engine, Part II: secrets)
│   ├── muxy-transport.md      # the optional native transport
│   ├── infra-integration-roadmap.md # the production-adoption roadmap
│   └── example-app.md         # worked examples: secret-app + env-app
├── bin/
│   └── shellflow/             # CLI + execution engine (I/O boundary)
│       ├── Cargo.toml
│       ├── assets/            # embedded bash helper + scaffolding templates
│       │   ├── cred-env.sh    # the bash fallback for `cred-env`
│       │   └── service-*.tmpl # `service init` / `unit render` templates
│       ├── src/
│       │   ├── main.rs        # clap entry, run loop, signals, final exit code
│       │   ├── cli.rs         # clap derive: every subcommand and flag
│       │   ├── exit.rs        # the CLI and target-helper exit-code protocols
│       │   ├── ui.rs          # the one output sink: streaming, masking, audit
│       │   ├── fsx.rs         # atomic 0600/0755 writes (helper assets)
│       │   ├── executor/      # the execution engine
│       │   │   ├── mod.rs       # shared types, fan-out slot, capture-file guard
│       │   │   ├── error.rs     # RunError / RunOutcome (the crate taxonomy)
│       │   │   ├── remote.rs    # step dispatch, ssh streaming, login-shell probe
│       │   │   ├── local.rs     # bash -c, guard, @export capture
│       │   │   ├── copy.rs      # rsync + scp fallback, staged --delete swap
│       │   │   ├── host.rs      # @service/@install/@backup/@credstore/@helper
│       │   │   ├── helper.rs    # the systemd helper protocol (wait/reload)
│       │   │   ├── assert_step.rs # @assert and the --check probe
│       │   │   ├── build.rs     # @build
│       │   │   ├── release.rs   # @release
│       │   │   ├── toolchain.rs # @toolchain
│       │   │   ├── image.rs     # @image
│       │   │   ├── muxy.rs      # the muxy adapter (same payload shape)
│       │   │   ├── transport.rs # the one ssh argv / rsync `-e` builder
│       │   │   ├── cancel.rs    # cooperative cancellation for the interrupt path
│       │   │   ├── process.rs   # process groups, terminate, GroupGuard
│       │   │   └── stream.rs    # piped-output forwarding, timeout, drain
│       │   ├── secrets.rs     # @secrets resolution -> run-state env + masks
│       │   ├── secret.rs      # `secret encrypt|decrypt|edit|creds|keys-check|find-duplicates`
│       │   ├── keys.rs        # `keys generate|public`
│       │   ├── template.rs    # `template check|render`
│       │   ├── cred_env.rs    # `cred-env` (target-side helpers)
│       │   ├── host.rs        # `host` (target-side helpers)
│       │   ├── systemd.rs     # `systemd` (target-side helpers)
│       │   ├── systemd_dbus.rs # the optional D-Bus unit-state path
│       │   ├── service.rs     # `service init`
│       │   ├── service_check/ # `service check` (audit + remote batch)
│       │   ├── service_diff.rs    # `service diff`
│       │   ├── service_manifest.rs # `service manifest`
│       │   ├── service_status.rs   # `service status`
│       │   ├── manifest.rs    # the `services/<svc>/<unit>.service.toml` model
│       │   ├── unit.rs        # drop-in rendering
│       │   ├── unit_cmd.rs    # `unit render|manifest|verify`
│       │   ├── unit_verify.rs # the repository consistency check
│       │   ├── rbatch.rs      # one round trip, many questions
│       │   ├── audit.rs       # the secret-shaped-plaintext gate
│       │   ├── lint.rs        # `--check` shell-hygiene warnings
│       │   ├── diffutil.rs    # unified-diff rendering
│       │   ├── emit.rs        # emit the embedded bash helper
│       │   └── preflight.rs   # required-tool preflight
│       └── tests/
│           ├── integration.rs # end-to-end with mock ssh/rsync shims
│           ├── cred_env.rs    # cred-env / emit / template
│           ├── service_init.rs # service init + secret keys-check
│           ├── no_panic_in_production.rs # the lint-gate guarantee
│           └── mockbin/       # fake ssh/rsync/scp (Bash shims recording argv)
└── crates/
    ├── shellflow-text/        # the shared shell-text rules (zero-dependency leaf)
    │   └── src/lib.rs
    ├── shellflow-dsl/         # the grammar + the plan model (pure, no I/O)
    │   └── src/{lib,parser,plan,heredoc,ssh_spec,error}.rs
    ├── shellflow-core/        # runtime helpers: env, capture, templating, masking
    │   └── src/{lib,env,template,error}.rs
    ├── shellflow-muxy/        # the optional native transport
    │   └── src/{lib,conn,lines,session,payload,policy,outcome,error,harness}.rs
    └── shellflow-secrets/     # age wrapper (the only crate that links `age`)
        └── src/{lib,identity,crypto,recipients,env,fsx,error}.rs
```

### 5.2 Crate responsibilities

**`shellflow-text`** — the shared shell-text rules, the zero-dependency leaf.

- Owns `shell_quote_single`, `strip_surrounding_quotes`, and the
  shell-identifier rule. The DSL (which reads directive payloads), the
  runtime (which renders payload headers), and the secrets crate (which
  reads sealed env files) all depend on it, so the rules cannot drift apart
  — and the secrets crate can share them without dragging in the plan model.

**`shellflow-dsl`** — the grammar, pure, synchronous, dependency-light.

- Owns the deploy-script language: the scanner, the plan model, the target
  resolution, the ssh-destination model, and the errors the scanner reports.
  It depends only on `shellflow-text` and `thiserror`, so the grammar can be
  read, tested and fuzzed without the runtime — and the runtime cannot grow
  a second opinion about what a script means.
- `shellflow-core` re-exports its public API, so a consumer of the runtime
  helpers does not have to know which crate owns which half of the language.

**`shellflow-core`** — pure, synchronous, dependency-light.

- Re-exports the DSL plan model (`ExecutionPlan`, `Target`, `resolve_hosts`,
  `SshSpec`, `interpolate`); the grammar itself lives in `shellflow-dsl`.
- Renders the payload env header (escaping + `set -x` ordering), parses the
  NUL-delimited `@export` capture records (with an allow-list-checked variant
  for the executor), and masks known secret values — all
  pure string logic, unit- and proptest-able.
- Re-exports the workspace-wide shell-text rules (`is_valid_var_name`,
  `strip_surrounding_quotes`) for its own consumers, but **owns none of them**:
  they live in `shellflow-text`, which `shellflow-dsl` and `shellflow-secrets`
  depend on directly. There is one definition of each rule, one authoritative
  import path (`shellflow_text`), and `shellflow-core` is a façade, not a
  second home. (Keeping a re-export here is what lets a consumer of the runtime
  helpers avoid knowing which crate owns which half of the language — it must
  not become the place a rule is *edited*.)
- Exposes `ParseError` / `InterpolateError` / `CaptureError` / `RenderEnvError`
  (with line numbers where applicable) via `thiserror`.
- No tokio, no stdio, no network, **no filesystem access**. `ExecutionPlan.env`
  is copy-on-write (`Arc<Vec<_>>`), so snapshotting the env into every step
  does not make plan construction quadratic. Everything is unit- and
  proptest-able.

**`shellflow-secrets`** — age wrapper.

- Wraps the `age` crate (X25519 identities) for identity loading and
  generation, file encrypt/decrypt, and recipient read-back.
- Resolves the identity path (`-i` / `$SHELLFLOW_AGE_IDENTITY` /
  `~/.config/age/keys.txt`). An empty or unset `$HOME` is treated as *absent*
  rather than as the current directory: the default location is then
  undefined, and resolving it to a *relative* path would adopt a planted
  `./.config/age/keys.txt` as the operator's identity. The resolver fails
  closed with a clear message instead. A whitespace-only
  `$SHELLFLOW_AGE_IDENTITY` is treated as unset.
- Parses `KEY=VALUE` env files (blank lines and full-line `#` comments ignored;
  first `=` splits the key; a repeated key keeps its last value and appears once,
  matching `source` semantics; single-space `export` prefix tolerated).
- Library-only: no `tokio`, no `std::process`. It does perform its own file
  I/O (identity load, env-file read), which is exactly its stated job (§S7);
  it has no network or subprocess surface. `nix` is used for two facts the
  identity loader cannot get from `std` on stable Rust: the effective uid
  (ownership is checked, not only the mode) and `O_NOFOLLOW` (a symlink planted
  at the identity path is refused rather than followed). `fsx` owns the
  atomic-write primitives (staged temp file + rename for `write_atomic`,
  hard-link for `write_new_file`, parent-directory `fsync` for both) that every
  secret-bearing file uses.
- `shellflow-core` stays free of async, I/O, and crypto.

**`shellflow-muxy`** — the optional native transport (the `muxy` feature).

- One connection per host: ssh carries the muxy bridge, a pump thread is the
  only consumer of the client's events, and a step's output streams as
  complete lines over the session. Documented in `docs/muxy-transport.md`;
  the ssh transport covers every step when the feature is off.

**`bin/shellflow`** — the I/O boundary.

- clap parsing and script loading.
- The execution engine: spawns `bash`, `ssh`, `rsync` via
  `tokio::process::Command`; fans out to hosts with `tokio::task::JoinSet`;
  streams prefixed output.
- `executor::transport` is the one builder for every `ssh` invocation and for
  the `-e` transport string `rsync` gets: `BatchMode=yes`, `-T`, the connect
  bound and `ControlMaster` are decided once, instead of at each of the eight
  call sites (which is how two of them lost `-T` and three used three different
  timeouts).
- `exit.rs` owns both exit-code protocols: the CLI's own (§6) and the
  target-side helper's (the `systemd`/`host` verbs, which report on a unit or a
  file and are a wire contract with the payloads).
- `eyre` for application errors. There is no logging framework: the `run`
  path owns one output path (`ui`), which streams user-facing lines, applies
  masking, and writes the audit log. The report subcommands render terminal
  output directly, and each printing module declares that with a scoped
  `#[expect(clippy::print_stdout, …, reason = "…")]` in `main.rs`, so a new
  print outside those modules fails the lint instead of bypassing the
  masker.

### 5.3 Dependencies

Added via `cargo add` only (never hand-edited into `Cargo.toml`):

```bash
# workspace level
cargo add eyre tokio --workspace                       # already present
cargo add colored --workspace                          # ANSI UI in bin
cargo add age tempfile --workspace                     # secrets crate

# bin/shellflow
cargo add clap tokio eyre colored -p shellflow --workspace
cargo add shellflow-core shellflow-secrets -p shellflow --path crates/...

# crates/shellflow-core
cargo add thiserror -p shellflow-core --workspace
cargo add proptest -p shellflow-core --workspace --dev

# crates/shellflow-secrets
cargo add age -p shellflow-secrets --workspace
cargo add thiserror -p shellflow-secrets --workspace
cargo add proptest -p shellflow-secrets --workspace --dev
cargo add tempfile -p shellflow-secrets --workspace --dev
```

| Crate | Where | Why |
|---|---|---|
| `clap` (derive) | bin | CLI parsing |
| `tokio` | bin | async process supervision, `JoinSet` |
| `eyre` | bin | application error handling (per AGENTS.md) |
| `thiserror` | text/dsl/core/secrets/muxy | library error types (per AGENTS.md) |
| `colored` | bin | host-prefix and step-header ANSI styling |
| `age` | secrets | embedded X25519 encryption (no `rage` binary) |
| `zeroize` | bin, secrets | in-memory scrubbing of plaintext secrets |
| `nix` | bin | process groups, signals, user/fs handling |
| `sd-notify` | bin | the systemd readiness protocol (`Type=notify` supervision) |
| `sha2` | bin | credential-store fingerprints (`cred-env`) |
| `serde_json` | bin | structured outputs (state lines, summaries) |
| `toml_edit` | bin | service manifests and rendered TOML templates |
| `shellflow-text` | dsl/core/secrets | the shared shell-text rules (the zero-dependency leaf) |
| `shellflow-dsl` | bin, core | local path dependency (the grammar + the plan model) |
| `shellflow-core` | bin, secrets | local path dependency (runtime helpers; re-exports the DSL) |
| `shellflow-secrets` | bin | local path dependency (crypto + env parser + recipients) |
| `shellflow-muxy` | bin (`muxy` feature) | local path dependency (optional native transport; see `muxy-transport.md`) |
| `muxy-client` / `muxy-protocol` | muxy (`muxy` feature) | third-party beta, pinned to an exact rev (the supply-chain boundary) |
| `zbus` (optional) | bin (`dbus` feature) | event-driven systemd unit state over D-Bus; the CLI polls without it |
| `proptest` (dev) | dsl/core/secrets | property tests in the normal test loop |
| `tempfile` (dev) | secrets, bin | temp-file fixtures in tests |

Explicitly **not** used: `anyhow` (forbidden), `russh`/`libssh2`/`ssh2` (we wrap
system `ssh`), `futures` (unnecessary — `JoinSet` covers fan-out), `scc`
(no shared concurrent maps in this design), `winnow`/`pest` (see D-3),
`reqwest`/`dashmap` (forbidden by AGENTS.md).

#### The target-side helper modules

`bin/shellflow/src/host.rs` is a dispatch table plus the shared vocabulary
(`HostError`, path/unit/digest helpers); the verbs live in submodules, one
responsibility each:

| Module | Responsibility |
|---|---|
| `host/probe.rs` | read-only state: `systemd-analyze verify`, `systemctl show` parsing, the readiness verdict, the unit inventory |
| `host/lifecycle.rs` | verify → reload → enable → restart → wait, in that order |
| `host/install.rs` | the atomic install (write beside, then rename) and digest assertions |
| `host/backup.rs` | snapshots: write, seal, prune, shred |
| `host/credstore.rs` | the credential store layout, its keys, the value-based leak check |
| `host/privileged.rs` | `sudo -n` and the elevated filesystem/`systemctl` primitives |

`HostError` is an enum keyed on the *reason* (`Usage`, `Internal`, `Failed`,
`TimedOut`, `Delegated`) rather than a `{ message, code }` pair, so a caller can
tell "the operator asked for something impossible" from "the condition did not
hold" without parsing text. `exit_code()` is the wire contract with the
controller (1 / 1 / 3 / 4 / the delegated code).

#### The transport seam

`executor::Native` is the **only** place the `muxy` feature forks the
executors. Every step struct carries a `Native` unconditionally — the probed
login environment, the per-host connection cache and the plan index — so the
*shape* of a step does not depend on the build. What remains behind
`#[cfg(feature = "muxy")]` is the decision itself
(`transport::should_use_muxy`, one function) and the attempt it guards; a
build without the feature answers `false` for every class and carries an empty
`Native`. `--transport muxy` then fails closed at the CLI with exit 3 instead
of silently falling back.

## 6. CLI Interface

```text
USAGE: shellflow [OPTIONS] [SCRIPT]

ARGS:
  <SCRIPT>  Deploy script path [default: deploy.sh]

OPTIONS:
  -v, --verbose...            Increase verbosity (-v, -vv, -vvv)  [see §8.1]
  -n, --dry-run               Simulate; no writes. Syntax-checks payloads.
  -d, --diff                  Show itemized file changes; implies no writes.
  -t, --target <TARGET>       Restrict to these servers/groups (comma-separated)
  -o, --only <STEP>           Run only matching blocks (by name or 1-based index)
  -s, --skip <STEP>           Skip matching blocks (repeatable)
  -p, --parallel <N>          Max concurrent hosts per step [default: 16; 0 = all]
  -c, --continue-on-error     Continue after a failed host/step; print summary
  -k, --check                 Syntax-check only: local `bash -n`, remote
                              `ssh host bash -n -s`; no execution
      --timeout <SECS>        Per-step timeout for all steps [default: none;
                              @timeout overrides it per step]
      --output <MODE>         stream (default) | grouped — print each host's
                              logs as one block when that host finishes
      --mask-min-len <N>      Minimum @secrets value length that is masked;
                              defaults to $SHELLFLOW_MASK_MIN_LEN, else 6
  -l, --log-file <PATH>       Append every streamed line (tagged host+stream)
                              to a file for audit (run path only)
      --no-color              Disable ANSI colors
      --local                 Run remote blocks/copies on the controller
                               (debugging; no network or sudo required)
  -i, --identity <PATH>       age identity for `@secrets` decryption
      --no-ssh-reuse          Do not reuse SSH connections within a run
                               (every step opens its own connection)
  -h, --help                  Print help
  -V, --version               Print version

SUBCOMMANDS (the bare positional `shellflow deploy.sh` == `shellflow run`):
  run [SCRIPT] [flags]                   run a deploy script (the default)
  keys generate | public                 manage age identities
  secret encrypt|decrypt|edit|creds|keys-check|find-duplicates
  template check <tmpl> <file.env.age>   cross-check ${KEY} against a sealed env
  template render <tmpl> <file.env.age> [--format toml|json|none]
  emit cred-env [-o PATH]                print the bash helper (fallback targets;
                                         covers exec/render only)
  cred-env exec|render|credstore-install target-side helpers (see §S12)
  host service|install|backup|credstore|assert-no-leak|assert-digest|
       assert-credstore|inventory         target-side host helpers (§S12.1)
  systemd notify|wait|reload|status|watch|transient|exec|watchdog
  unit render|manifest|verify             service manifest and drop-in gates
  service init|check|diff|manifest|status repository scaffolding and fleet gates
  audit [PATH]                           scan the repo for secret-shaped plaintext
  unit render <svc> <unit> [--repo PATH]  generate the unit's drop-in from
       [--output PATH] [--check]          its manifest
  unit manifest <svc> <unit> [--repo PATH]  print the manifest
  unit verify [--repo PATH]                check the repository's consistency
  systemd notify|wait|reload|status|watch|transient|exec|watchdog
                                      target-side systemd helpers (§S12.1)
  service init <svc> [--host <alias>]    repository scaffolding (see §S12.2)

EXIT CODES:
  0   success (skipped blocks and dry-runs with no errors)
  1   plan/parse error (bad script, unresolved @export variable, an
      unresolvable target, a syntax error found by a dry-run/check)
  2   CLI usage error (clap)
  3   transport/setup failure (missing ssh/rsync/bash, ssh exit 255, a broken
      payload pipe, rsync I/O error)
  4   script execution failure (a local/remote step exited non-zero)
  5   a step exceeded --timeout/@timeout (any class: remote, local, copy,
      guard, or the target helper's own budget)
  130 interrupted by SIGINT/SIGTERM (see §7.5)

4 versus 5 matters to a CI retry policy: "the deploy broke" is a rollback,
"the box was slow" is a retry. 1 versus 4 keeps "the playbook is wrong, nothing
was attempted" separate from "the deployment failed". `exit.rs` is the single
definition of these values.

42 is reserved inside a guarded remote payload as the guard's "skip"
channel; it never becomes the process exit code. The payload installs an
`EXIT` trap that remaps a block's own `exit 42` to 1, and the guard disables
the trap before it exits 42. A block without a guard is never interpreted as
a skip.

`--log-file` belongs to `run`, not to the global option set: the maintenance
subcommands produce no streamed lines and now reject the flag instead of
accepting it and silently writing nothing.

The distinction between 1 and 4 is deliberate: 1 means "the playbook is
wrong" (nothing was attempted), 4 means "the deployment failed". A CI gate
can therefore tell the two apart without parsing the output.

**Two protocols, deliberately separate.** The `systemd` and `host` subcommands
run *on the target* and report on a unit or a file, so their codes are a wire
contract with the payloads that call them (`remote::wait_command`,
`remote::reload_command`, `executor::host`): there, `3` means "the condition
did not hold" and `5` means "the unit does not exist". They are not the CLI's
codes, and `exit.rs` keeps them in a separate module so a literal cannot drift
between the two.

The subcommands use the same classes: a failure that means "the request could
not even be attempted" — a missing `ssh` in `service check`, an unreachable
host — is a transport/setup failure (3), and everything else is 1. `service
check` therefore agrees with the `run` path about the same missing tool
instead of reporting it as a generic error.
```

Example invocations:

```bash
shellflow deploy.sh                      # real run
shellflow -vv deploy.sh                  # show every command + payload
shellflow -vvv deploy.sh                 # set -ex + ssh -v live trace
shellflow --dry-run --diff deploy.sh     # preview changes, change nothing
shellflow -t web1 deploy.sh              # deploy one host from group `web`
shellflow -k deploy.sh                   # syntax-check everything
```

### 6.1 The service manifest and the unit generator

A deploy repository repeats the same facts in three places: the systemd unit,
the playbook, and the operator's memory. The unit declares the credential
keys, the render template, and the binary; the playbook repeats the service
name and the host.

The **service manifest** (`services/<svc>/<unit>.service.toml`) states them
once:

```toml
host = "api"
unit = "dufs.service"
binary = "/opt/dufs/bin/dufs"
secret_file = "services/dufs/{host}.env.age"
credentials = ["DUFS_AUTH_PASSWORD"]
ports = [5000]
user = "akagi201"
runtime_dir = "dufs"

[[render]]
template = "/opt/dufs/etc/config.yaml.tmpl"
target = "/run/dufs/config.yaml"
```

`shellflow unit render <svc> <unit>` derives the unit's drop-in from it: the
`LoadCredentialEncrypted=` wiring, the `ExecStartPre=… cred-env render …`
line, and the `ExecStartPost=… systemd-notify --status=…` line are identical
in shape across a repository, so they are **generated** rather than copied —
and the shared hardening drop-in rides along, which makes the hardening a
default rather than an opt-in.

The manifest is also the fleet map: `shellflow service status --all` reads the
host of every service from the manifests instead of parsing playbook text, and
`service check` uses the same source of truth.

`service verify` (`unit_verify`) is the repository-side checker: it reads the
manifests, drop-ins, and playbook facts and reports what would not match the
target. It is a sibling of `service check` (which probes a live host).

### 6.2 The repository consistency check

A deploy repository has parts that are **generated** (the unit drop-ins) and
parts that are **written** (the playbooks, the manifests). The generated parts
drift away from the sources they come from, and the drift is silent.

`shellflow unit verify` answers, statically:

1. **Is every generated drop-in up to date?** The drop-in is re-rendered from
   the manifest and compared with the file on disk.
2. **Does every `@install` source exist?** The install steps are read out of
   the playbook **with the tool's own parser**, so the check sees exactly what
   a deploy would do, and every source is looked up in the repository.
3. **Is every generated drop-in installed?** A service whose drop-in is never
   installed would run with the unit's own (stale) wiring.
4. **Does the shared hardening reach every service that takes it?** The
   hardening is a default, not an opt-in; a unit that cannot take it says so
   in its manifest (`hardening = false`).
5. **Does every backup run before the install it protects?** The directives
   execute in source order, so a `# @backup` line that sits below the
   `# @install` lines snapshots the **new** file: the rollback copy would
   restore what was just deployed. The check compares the plan's own step
   order.

The check is deliberately offline. When it cannot read a sealed credential
file (no identity is available), the affected drop-in is reported as
**skipped** in both the per-check output and the summary, and the summary
never calls the repository consistent without naming the skipped count. A
skipped check is not a pass.

## 7. Execution Engine

### 7.1 Step lifecycle

```text
for each step (sequentially):
    resolve hosts (respecting --target restriction)
    print header  [STEP n/m] <name> <kind> -> <target>
        # n is the step's 1-based index in the unfiltered plan (the number
        # --only/--skip accept); m is that plan's step count, even when a
        # filter runs only some of them
    if payload display requested (-vv, dry-run, diff): print script preview
    match step:
        Local  -> run_local(step)
        Copy   -> fan_out(run_copy, hosts, --parallel)
        Remote -> fan_out(run_remote, hosts, --parallel)
    if fail-fast and any host failed: abort remaining steps (exit 3/4)
print summary (elapsed per step, per-host status)
```

### 7.2 Remote streaming (Mina-style)

```rust
// Simplified: real implementation uses two reader tasks + one channel (see 7.4).
let mut child = Command::new("ssh")
    .args(spec.to_ssh_args())          // ["-p", "2222", "deploy@10.0.0.2"]
    .arg("-T")
    .arg("-v")                         // only when verbose >= 3
    .arg(if syntax_only { "bash -n -s" } else { env.shell.invoke(false) })
    //                                     ^ real runs use the host's login
    //                                       shell, e.g. `bash -l -s` / `zsh -l -s`
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?;

// Payload layout — env lines always precede tracing so exports are never
// traced:
//   set -eu
//   export PATH='***'         <- probed login PATH (from the rc file)
//   export KEY='***'          <- env block (from @env/@export state)
//   set -x                    <- only at -vvv, AFTER the env block
//   <user script>
let payload = format!(
    "set -eu\n{env_lines}{trace_line}{script}",
    env_lines = render_env(&env_with_login_path), // single-quote-escaped values
    trace_line = if verbose >= 3 { "set -x\n" } else { "" },
);
// 1. Write payload, then DROP stdin so remote bash/zsh sees EOF.
child.stdin.take().unwrap().write_all(payload.as_bytes()).await?;
// 2. Concurrently read stdout (white) and stderr (red / yellow at -vvv),
//    prefixing every line with [host]; known env values are masked (see §9).
// 3. wait(); map non-zero exit to eyre error with host context. ssh exit 255
//    is classified as a transport error (exit 3), other non-zero as script
//    failure (exit 4) — see §6.
```

Key points:

- **One connection per host per remote block** — the payload is streamed from
  memory, not from a temp file. This is the Mina win.
- **Login-shell parity**: before the first remote block of a run, each host is
  probed once (cached per run) with a script that prints the login shell
  (`$SHELL`) and the PATH an interactive login would see — the rc file
  (`.zshrc`/`.bashrc`) is sourced *inside the probe shell only*, where
  toolchain managers (proto/nvm/rustup/mise) export their PATH entries.
  Payloads then stream over `<shell> -l -s` (`bash -l -s` / `zsh -l -s`) with
  that PATH injected into the env block. The rc file is **never sourced inside
  the payload**: interactive configs (oh-my-zsh hooks, aliases, prompts) break
  `set -eu` in scripts. Unsupported shells (fish/nushell), unreachable hosts,
  and probe failures fall back to plain `bash -l -s` with no injected PATH, and
  `--check`/`--dry-run` stay on `bash -n -s` (no probe, no login env). An
  explicit `@env PATH=…`/`@export PATH` always wins over the probe.
  > The probe's **completion marker**, not its exit status, is the success
  > criterion. The probe also reports whether the target has `rsync`, and a
  > host without `rsync` makes that check fail — so if the exit status were
  > the criterion, the whole probe result (the login shell *and* the
  > rc-extended PATH) would be discarded on exactly the minimal hosts that
  > need it most. Each field degrades independently instead.
- `set -eu` by default (crash on unset vars and errors); `-vvv` upgrades to
  `set -ex` for live tracing.
- `@env`/captured variables are injected as a `export KEY='value';` block at
  the top of the payload (single-quote-escaped), always *before* any `set -x`
  tracing, and the values are masked in previews, trace output, and log files
  (§9). Local steps receive them via `Command::env()` instead of text
  injection.
- **Fail-fast by default**: a non-zero remote exit aborts the remaining steps.
  `--continue-on-error` collects per-host results and prints a final table.

### 7.3 Copy (rsync delta)

```rust
let mut cmd = Command::new("rsync");
cmd.args(["-a", "-z"]);                        // archive + compress
if delete { cmd.arg("--delete"); }             // optional flag: @copy … --delete
if dry_run || diff { cmd.args(["--dry-run", "-i"]); }
if let Some(port) = spec.port { cmd.args(["-e", &format!("ssh -p {port}")]); }
cmd.arg(src).arg(format!("{}:{dst}", spec.to_dest())); // user@host:path
```

`rsync --dry-run -i` computes the real local↔remote delta and itemizes it
(`>f++++++++` new file, `f..t......` timestamp-only, `*deleting` removal) —
this *is* our diff engine (pyinfra feature #2).

**Target directory creation & no-rsync fallback.** Whether the target has
`rsync` is discovered **once per host per run** during the login-environment
probe (a single `ssh` round trip that also yields the login shell and PATH;
see §7.2). The result is cached in the per-run `ShellCache` and reused for
every copy step — no extra probe connection. When `rsync` is present on the
target, the transfer runs under `--rsync-path "mkdir -p <parent-dir> &&
rsync"` so a file-style destination's parent directory is created
automatically (matching rsync's own `dir/` semantics). When rsync is missing
on the target, `@copy` falls back to `ssh mkdir -p <parent-dir>` + `scp src
host:<parent-dir>/`, keeping the design promise that targets only need `bash`
(§9). This preserves the delta/idempotency properties in the common case and
degrades gracefully to a plain copy on minimal hosts.

The fallback **cannot** mirror deletions or filter files, so a copy step that
asked for `--delete` or `--exclude` fails closed on such a host (exit 1)
instead of performing a materially different transfer than the playbook
requested — an excluded file would land on the target and stale files would
survive, while the step reported success. `--allow-unfiltered-copy` is the
explicit opt-out; the downgrade is then reported in the step output.

**Dry-run still probes the target — deliberately.** §7.2's "no probe, no login
env" rule governs *remote blocks*: in `--check`/`--dry-run` they stay on
`bash -n -s` and never open a second connection. A copy step is different: the
whole point of `rsync --dry-run -i` is to compute the *real* local↔remote
delta, so the target must be reached anyway, and the `rsync`-or-`scp` decision
has to be made before the transfer starts. The probe is therefore the
mechanism that answers that question (§7.3), and it is cached per host per
run, so a playbook with several copy steps still opens one connection per
host. `--check` is the mode that stays entirely offline: it skips the copy
step altogether rather than touching the target.

### 7.4 Concurrency & output integrity

- Each step fans out over hosts with `tokio::task::JoinSet`, bounded by
  `--parallel N` via `tokio::sync::Semaphore` (default: 16; `0` = unbounded).
- **Correctness fix over the naive sketch:** the common `tokio::select!` over two
  infinite read-loops is wrong — when one stream hits EOF the `select!` returns
  and the other reader is dropped, silently truncating stderr/stdout. Instead,
  per host we spawn two reader tasks (stdout, stderr) that push lines into a
  small `mpsc`, and a single consumer prints `[host] line` in order. Both
  streams are drained to EOF.
- Output is line-buffered and flushed immediately; `--no-color` strips ANSI.
- **Output modes** (`--output`): `stream` (default) renders every line as it
  arrives; `grouped` buffers each host's lines and prints them as a single
  `[host]` block when that host finishes, keeping high-fanout logs readable.
- **Audit trail** (`--log-file`): every streamed line (tagged `[host]` plus
  stream marker) is appended regardless of UI mode; masking applies to the file
  too (§9).
- `-vv` prints the exact argv of every spawned process (via `Debug`), so users
  can copy-paste the command to reproduce issues.

### 7.5 Lifecycle: preflight, timeouts, signals

- **Preflight.** Before running anything, shellflow verifies that `bash`,
  `ssh`, `rsync`, and `scp` exist on `PATH` *and are executable*, and fails
  with a friendly message (exit 3) if any is missing — no mid-run
  `Command::new` surprise. (`scp` is required because `@copy` falls back to it
  on rsync-less targets; see §7.3.) Each probe is bounded, so a PATH-shadowed
  wrapper that never exits cannot hang the CLI before the timeout machinery
  exists.
- **Process groups.** Every child is spawned with `process_group(0)`, so it
  leads a fresh process group. Signalling only the *direct child* is not
  enough: a block runs `bash -c`, whose own descendants (`cargo` -> `rustc`, a
  `sleep 300 &`) would survive. Two mechanisms cover the whole tree:
  - `terminate()` — on a timeout or transport failure: `SIGTERM` the group,
    wait up to a 5s grace period for the direct child, then `SIGKILL` the
    group unconditionally (a grandchild that traps `SIGTERM` must not outlive
    the step just because its parent exited promptly).
  - `GroupGuard` — an RAII guard dropped on *every* exit path, including the
    task cancellation caused by SIGINT, which `SIGKILL`s the group unless it
    was disarmed after a clean reap.
  Killing the group also closes the inherited stdout/stderr pipe ends, so an
  orphan can no longer keep the log stream open after a step has finished.
- **Timeouts.** `--timeout <secs>` applies globally; `@timeout` overrides per
  step. Each host task wraps `child.wait()` in `tokio::time::timeout`; on
  expiry it tears the group down as above and records the host as `TIMEOUT` (a
  failure: abort or continue per `--continue-on-error`).
- **Signals.** `tokio::signal` installs SIGINT/SIGTERM handlers. On receipt,
  the run is cancelled **cooperatively**: every in-flight host task observes
  the signal, terminates its own process group (`SIGTERM`, a grace period,
  then `SIGKILL`), and returns normally; the executor is then awaited to
  completion before the process exits. shellflow prints a summary of
  completed/failed/pending steps and exits 130. **No orphan processes
  survive.**
  > Cancelling by *dropping* the executor's future is not enough: the host
  > tasks are aborted asynchronously, so their process-group guards may never
  > run before the process exits — which is how an orphaned `ssh` survives a
  > Ctrl-C. Cooperative cancellation makes the teardown a precondition of
  > the exit, not a race against it.
- **Preflight probes are isolated too.** The preflight probe leads its own
  process group like every other child, so a PATH-shadowed wrapper that
  backgrounds helpers cannot leave them behind when the probe is killed.
- **A backgrounded descendant cannot hang a step.** A block that backgrounds
  a process (`nohup svc &`) leaves the descendant holding the step's output
  pipe. The drain of the reader tasks is therefore bounded: a group that
  still holds the pipe past the grace period is killed rather than hanging
  the run, and `--timeout` stays a real bound on the step.

### 7.6 Cross-step state (`@export`)

Local steps run as separate processes, so `cd` and shell variables do not
survive a step boundary (remote blocks are fresh SSH sessions by design).
Rather than a long-lived interactive shell — which silently breaks step
isolation and error semantics — state is passed *explicitly* (Decision Record
D-7):

1. When a local step declares `@export VAR`, shellflow appends a capture line
   that writes the values to a private temp file as **NUL-delimited** records
   (`NAME=VALUE\0`); the temp path is passed via `Command::env`, so it never
   appears on stdout. NUL is used because a shell value may legally contain a
   newline: a newline-delimited format would let one exported value forge
   another and would silently truncate a legitimately multi-line value. The
   reader is the pure `shellflow_core::parse_capture_records`.
2. After the step, shellflow reads the file into `RunState`. Scripts that call
   `exit` before the capture line cannot export — documented, acceptable. The
   capture file is owned by an RAII guard, so it is deleted on **every** exit
   path, including a failed step: it holds plaintext and must not outlive the
   step, least of all on a shared CI runner.
3. Later `@copy` `src`/`dst` strings are interpolated from `RunState`
   (`$VAR`/`${VAR}`); unresolved names are a plan-build error.
4. Later local steps receive the values via `Command::env()`; later remote
   blocks receive them in the env header (masked, §9).
5. **Every captured value joins the mask registry** unless the playbook
   declared it `--public`. The decision is a property of the declaration and of
   the value's length (`--mask-min-len`), never of the variable's *name*: the
   ordinary name for a credential a block just fetched from a vault is
   `DATABASE_URL`, so a name heuristic ("looks secret") reads as a safety
   property while being a guess. `--public` is the explicit opt-out for a value
   that is meant to be read, and it is visible in the playbook next to the
   declaration, where a reviewer sees it.

This makes versioned artifact paths work end-to-end:

```bash
# @local
VERSION=$(git rev-parse --short HEAD)
# @export VERSION --public
# @copy target/release/myapp-$VERSION -> /srv/myapp-$VERSION @web
```

## 8. DX Features

### 8.1 Realtime debugging: `-v`, `-vv`, `-vvv`

| Level | Shows |
|---|---|
| default | Step headers (`[STEP 1/4] build · local`), live `[web1] …` prefixed output, per-step elapsed time, final summary |
| `-v` | Plan preview (servers, groups, step list), rsync transfer lines, host status per step |
| `-vv` | Exact `ssh`/`rsync`/`bash` argv, full payload script previews, guard (`@only_if`) evaluations |
| `-vvv` | Everything above **plus** `set -ex` injected into every payload and `ssh -v` on the wire; Bash trace lines (`+ echo …`) arrive on stderr colored yellow — an OS-level realtime stdin/stdout/stderr trace with zero extra machinery |

Sample `-vvv` output:

```text
[STEP 3/4] restart · remote -> web
  |--- Remote Payload (web) ---
  | set -eu
  | echo "==> restarting myapp on $(hostname)"
  | sudo systemctl restart myapp
  |-----------------------------
[web1] + echo '==> restarting myapp on web1'
[web1] ==> restarting myapp on web1
[web1] + sudo systemctl restart myapp
[web2] + echo '==> restarting myapp on web2'
[web2] ==> restarting myapp on web2
[web2] + sudo systemctl restart myapp
✔ Step 3/4 done in 1.24s (web1 ✓, web2 ✓)
```

### 8.2 Idempotent dry-run & diff

| Mode | Local blocks | Remote blocks | Copy steps |
|---|---|---|---|
| `--dry-run` | print payload; run `bash -n` locally | print payload; run `ssh host bash -n -s` (syntax only) | `rsync -avzn --delete -i` — real delta, nothing written |
| `--diff` | same as dry-run | same as dry-run | dry-run itemize filtered to **changed** items only, color-coded by symbol |

Nothing is written in either mode; both exit `1` if any `bash -n` finds a
syntax error. This is the pyinfra "prove it before you change it" loop, achieved
entirely with `rsync`/`bash` primitives (see D-4).

**A copy that cannot be previewed is skipped, never performed.** `rsync
--dry-run` is what produces the delta; the `scp` fallback (a target without
`rsync`, §7.3) and the local `cp` have no dry-run mode at all — previewing
them would mean performing them. So on such a host the copy step is skipped
with a warning and the run reports the host as `SKIPPED`: a "dry run" that
wrote to the target would be the most dangerous flag in the tool. The
`--delete`/`--exclude` fail-closed rule (§7.3) applies to dry-runs too, so a
playbook that asks for a filtered copy still refuses to run against a target
that cannot honour it.

**State in dry-run.** Local steps are *not* executed in dry-run, so
`@export`ed variables are unknown there. A `@copy` path referencing an
unresolved variable prints a warning and is skipped for itemization instead of
guessing a path.

**Guards are not evaluated in dry-run.** An `@only_if` guard is a command
like any other, and it runs with the block's environment — so evaluating it
could change the target. In `--dry-run`/`--check` the guard is *reported*
rather than run. The same rule applies to a remote block resolved on the
controller with `--local`.

### 8.3 Idempotency strategy

Three cooperating layers, deliberately *not* a state engine:

1. **Transport idempotency** — `rsync` transfers only deltas; re-running a copy
   step is a no-op when content matches.
2. **Guard idempotency** — `@only_if` blocks are skipped where the precondition
   already holds; skipped blocks print `SKIPPED (guard)` and count as success,
   so repeated runs converge. The skip travels through exit code 42, which is
   reserved *inside a guarded payload only*: the guard clears the payload's
   `EXIT` trap before using it, and the trap remaps a block's own `exit 42`
   to 1. A remote block without a guard therefore cannot be mistaken for a
   skip.
3. **Author idempotency** — plain Bash (`[ -f ] ||`, `command -v`,
   `systemctl is-active`) for everything the tool can't infer. `set -eu` and
   pre-run `bash -n` make partial failures from typos impossible.

## 9. Security & Operational Notes

- **Inherit the user's SSH trust**: keys, `~/.ssh/config`, `ssh-agent`, jump
  hosts, YubiKey — all handled by the system `ssh`. We never touch credentials.
- **No interactive prompts**: we use `ssh -T` (no TTY) **and**
  `-o BatchMode=yes` on every ssh invocation the tool makes. A transfer tool
  that starts its own ssh is given the same options (rsync through `-e`, scp
  directly), so a copy cannot stop at a password or host-key prompt in the
  middle of a run. The secrets payload travels over that channel, so an
  unknown host key or a missing key must fail closed rather than raise a
  prompt an operator may approve for a rogue key. Host-key *policy* stays
  with the user's `~/.ssh/config` — the
  tool does not add `accept-new` or `no`, which would auto-trust an unseen
  key. Provision a first connection explicitly:
  `ssh-keyscan <host> >> ~/.ssh/known_hosts`. `sudo` in scripts
  requires passwordless sudo or a pre-provisioned key. This is documented
  behavior, not a bug.
- **Remote requirement**: only `bash` on the target; `rsync`/`ssh` needed only
  on the controller. Remote blocks additionally run under the host's login
  shell (`$SHELL` probed once per run, `bash`/`zsh` supported; anything else
  falls back to bash) with the rc-extended login PATH injected into each
  payload, mirroring a manual `ssh host` — see §7.2.
- **Secrets in `@env`/`@export`.** Values never appear in any process argv. For
  local steps they are passed via `Command::env()`; for remote steps they exist
  only inside the payload streamed over stdin, placed *before* any `set -x` so
  the export lines themselves are never traced (§7.2). Known values are masked
  (`***`) in payload previews, trace output, and `--log-file`. The audit log is
  created `0600` (and re-tightened when an existing file is appended to); a log
  that cannot be opened is a **hard error**, not a warning — a run that was
  asked to keep an audit trail and silently keeps none is worse than a run that
  refuses to start.
  > **Masking is applied by the sink *and* by the call site.** The sink
  > (`print_line` for control lines, `Ui::emit_host_line` for host output) is
  > the guarantee: every byte that reaches the terminal or the audit log passes
  > through the redactor, so a secret cannot leak because a call site forgot to
  > ask for masking — and a render function that forgets cannot reintroduce the
  > gap the way `plan_preview`'s step line once did. The call sites also redact,
  > *before* they add ANSI colour: a below-threshold value is only redacted
  > where it stands alone as a token, and an escape sequence next to it would
  > look like an identifier character and hide the value from the narrow rules.
  > The two passes cannot unmask anything. The process-wide mask registry is
  > what lets the free render functions — which have no `Ui` handle — redact
  > exactly like the `Ui` methods do.
  >
  > Redaction is **stateful across output lines**: a value that a target
  > program split across two lines (`fold`, a pager, a progress bar) is
  > redacted as a whole, because the two fragments would otherwise reassemble
  > into the original in the scrollback or in the audit trail. The payload
  > preview uses the same stateful masker, so a value split across two lines
  > of a block body is redacted there too. A prefix at the tail of a line is
  > *always* remembered as a pending continuation, even when another range
  > already covers those bytes, so the rest of the value cannot slip through
  > on the next line. Every occurrence of a value is masked — a value that
  > overlaps itself is masked whole, exactly like the stateless path. Values
  > below the masking threshold
  > cannot use a global substring replace (it would shred unrelated output),
  > so they are redacted only where they stand alone as a token or appear as
  > `KEY=value`; the run names the affected keys so the exemption is never
  > silent. Residual caveat: redaction is a plaintext match, so a base64/hex
  > rendering of a value is never redacted.
- **Decrypted values in memory.** The plaintext buffer is zeroized when it is
  dropped, and the resolved values are scrubbed when the run ends. The
  residual is explicit: the values are also cloned into the run-state env map,
  the mask registry, and the **child process environment**, where the same
  UID can read them through `/proc/<pid>/environ`; they are not `mlock`'d and
  may reach swap. A same-UID or root attacker on the controller can read the
  `0600` age identity directly and decrypt every sealed file anyway, so this
  is a defense-in-depth property, not a boundary.
- **The age identity must be owner-only.** `keys generate` writes `0600`, and
  the loader enforces it: a group- or world-readable identity is refused
  (the identity opens every sealed env file the operator owns).
  `SHELLFLOW_ALLOW_UNSAFE_IDENTITY=1` is the explicit opt-out.
- **Trust boundary**: the deploy script is code with the controller user's
  privileges. Users should review scripts as they would any shell code.
- No `unsafe` anywhere; `unwrap_used`/`expect_used`/`panic` are denied by the
  workspace lints.

## 10. Testing Strategy

### 10.1 `shellflow-core` (unit + property)

Example-based unit tests (colocated `#[cfg(test)]`):

- directive recognition incl. whitespace tolerance and CRLF stripping;
- `@server`/`@group`/`@env`/`@copy` payload parsing (incl. `rsplit_once('@')`
  for copy targets and port-bearing specs);
- block flushing and mode switching; dropping comment-only blocks;
- `@only_if`, `@timeout`, and `@name` attachment to the following block;
- `@export` attachment to the preceding local block; error after a remote block;
- `@copy --delete` parsing and `$VAR`/`${VAR}` interpolation from `RunState`;
  unresolved variables are errors, not silent literals;
- the NUL-delimited `@export` capture protocol: a value containing a newline
  or `=` round-trips intact and can never be read as a second record;
- env-block rendering: single-quote escaping, ordering before `set -x`,
  masking of known values; mask ordering is normalized once per run
  (`prepare_masks`), not once per output line;
- the stateful masker: a value split across lines is redacted as a whole (two
  and three lines, a split at a line end, a split at the first character), the
  text around a masked value survives, every occurrence in a line is masked
  (a value that overlaps itself is masked whole, like the stateless path),
  and the longest secret wins a tie — the mask set is ordered longest-first
  and then by value, so the ordering (and every tie it breaks) is the same on
  every run and on every host;
- `resolve_hosts`: alias / group / raw spec / `--target` restriction;
- `SshSpec`: `user@host:port` → `["-p", "2222", "user@host"]` and rsync dest;
- here-documents: quoted/escaped/plain/`<<-` delimiters, `<<<` here-strings,
  quoted regions and trailing comments not opening one, multiple openers on
  one line drained FIFO, tab-only terminator indentation, CRLF, unterminated
  bodies, and the property that a body line never splits the plan.

`proptest` properties (in the ordinary `cargo test` path):

- **Reparse idempotence**: any non-directive script body, when wrapped in a
  generated sequence of directives, re-parses to the same step payloads
  (modulo trailing newline);
- **Block separation**: generated directive/boundary sequences never produce a
  step whose content bleeds across a `@copy`/`@remote` boundary;
- **Determinism**: `resolve_hosts` ordering is stable for a fixed plan.

### 10.2 `bin/shellflow` (integration)

End-to-end tests with **mock `ssh`/`rsync` shims** placed earlier on `PATH`
(`tests/mockbin/`), which record argv to a log file and behave deterministically:

- execution order and per-host fan-out (parallelism observable in logs);
- payload integrity: the exact script sent over stdin (mock `ssh` writes stdin
  to a file);
- `-vvv` injects `set -ex` and adds `ssh -v`;
- `--dry-run` sends `bash -n -s` and `rsync --dry-run -i`; nothing written —
  including through the `scp` fallback, which has no dry-run mode and is
  therefore skipped rather than performed;
- fail-fast aborts remaining steps vs `--continue-on-error` summary;
- `--target`, `--only`, `--skip`, exit codes, `--no-color`;
- timeout: a sleeping mock `ssh` is SIGTERM'd and reported `TIMEOUT`;
- SIGINT: an in-flight mock `ssh` is killed and shellflow exits 130, and the
  interrupt summary is recorded in the `--log-file` audit trail;
- `--output grouped` emits per-host blocks; `--log-file` contains tagged lines;
- the plan preview and the step headers share one numbering space (the
  unfiltered plan index, which is also what `--only`/`--skip` accept), also
  when a filter runs only some of the plan;
- preflight: PATH without `ssh` fails fast with exit 3 and a friendly message;
  the `service check` subcommand reports the same failure class the same way;
- `-vvv` with an `@env` secret: the mock's echoed payload shows the value
  masked as `***`, including in the local `bash -c` preview;
- a `# @remote` line inside a here-document body: no `ssh` invocation at all,
  while a directive after the terminator still runs;
- `@secrets --identity` decrypts with the pinned key and no run-wide `-i`;
- `SHELLFLOW_MASK_MIN_LEN` and `--mask-min-len` both gate short-value masking;
- preflight fails when `scp` is missing even though `bash`/`ssh`/`rsync` exist;
- a step with no hosts renders `—`, and `--only` keeps header and summary
  numbering in sync;
- process-group teardown: a background grandchild of a timed-out local block
  is gone afterwards, and a child that traps `SIGTERM` is `SIGKILL`ed.
- **failure-path hygiene**: a failed `@export` step leaves no capture file
  behind; an exported value cannot forge a sibling variable; a broken ssh
  payload pipe is classified as a transport error (exit 3), never a timeout;
  a failed `--local --delete` copy leaves the previous destination intact and
  cleans up its staging directory.

These tests require local `bash`, `ssh`-less (mock shims), and no network.

### 10.3 Tooling gates

```bash
just format
just lint        # typos, rumdl, cargo sort, fmt, clippy -D warnings, cargo shear
just test        # cargo test --all-features (incl. proptest)
just mutation    # cargo-mutants; fix survivors
just check-cn    # no CJK in code/comments (docs/comments are English-only)
```

`just lint` runs `clippy --workspace --all-targets --all-features`, so test
code is linted too. The `deny` lints (`panic`, `unwrap_used`, `expect_used`)
and the `pedantic`/`nursery` groups are scoped to production code with an
explicit `cfg_attr(test, allow(...))` at each crate root: the constraint is
stated where it holds instead of being satisfied by silently skipping test
targets.

Fuzz (`cargo-fuzz`) and Criterion benchmarks: **N/A** for v1 — the grammar is a
fixed line scanner and the workload is I/O-bound. Revisit if the DSL grows
expression evaluation or a documented latency SLA appears.

## 11. Performance

- Parser is a single O(n) scan; plan construction is negligible.
- Mina-style single-connection streaming avoids per-command SSH overhead.
- `rsync` delta minimizes bytes on the wire.
- `JoinSet` + semaphore give bounded, real multi-host concurrency.
- Release profile (`lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`)
  yields a small static binary with no runtime dependencies.
- `kache` rustc wrapper (already in `.cargo/config.toml`) keeps incremental
  rebuilds fast.

### Round trips

The engine spends SSH round trips, so they are counted explicitly:

| Operation | Round trips |
|---|---|
| Remote block | 1 |
| Remote block with `@only_if` | **1** — the guard is folded into the payload and reports "skip" through a dedicated exit code, instead of costing a second connection |
| Copy | 1 probe per host per run (cached) + 1 rsync per transfer group |
| `@assert` group | 1 (one framed batch) |
| `@service`, `@install`, `@backup`, `@credstore`, `@unit_inventory` | 1 each |
| `@wait_active` | 1 (the whole poll loop runs on the target) |
| `service check` | 1 (eight queries batched) |
| `service status` | 1 per host, **concurrently** |

### Connection reuse

`--ssh-reuse` is **on by default** (`--no-ssh-reuse` turns it off). A
playbook is a sequence of steps against the same hosts, and every step used
to pay a full TCP connect plus key exchange. `ControlMaster=auto` is safe by
construction: OpenSSH reuses the master when it is alive and creates a new
one when it is not, so a stale control socket is detected and replaced rather
than breaking a deploy.

### The batch transport

A batch asks many questions in one round trip. Its answers are parsed **as
they arrive**: the response is never buffered whole and then copied into a
second set of strings, so the peak memory is one answer plus the answers
already collected. The transport also knows when the batch is **complete** —
every expected answer has arrived — and closes the connection then, instead
of waiting for a trailing query that may be slow.

### The helper build

The target-side helper is built once per **source revision and target
triple** and cached under `~/.cache/shellflow/`. The build is the single
most expensive part of a deploy — a cross-compile takes minutes — and the
cache turns it into a one-off: the second service that needs the helper
reuses the first one's artifact.

## 12. Decision Records

### D-1. Wrap system `ssh`/`rsync` instead of a Rust SSH library

`russh`/`libssh2` would reimplement auth, key handling, `~/.ssh/config`, agent,
and jump-host semantics. Wrapping the battle-tested system binaries is simpler,
more secure, and matches the project's zero-redundancy ethos.

### D-2. Comment directives instead of YAML

The file is valid Bash (highlighting, `bash -n`, and execution all work), the
grammar is ~6 directives, and there is no second parser for users to learn.

### D-3. Line scanner instead of `winnow`/`pest`

AGENTS.md prefers `winnow`/`pest` for *ad-hoc manual parsing*. Here the grammar
is line-oriented with fixed prefixes and `space`/`,`/`->`/`@`-delimited
payloads: one `match` arm per directive, a shared quote-aware tokenizer
(`split_words`/`split_flags`), and a here-document state machine. The scanner
is now ~2,700 lines for **33** directives (plus ~2,000 lines of tests), which
is large but flat — each directive is independent, and none of it needs a
combinator grammar's backtracking. If the DSL ever grows nested expressions,
switching the payload parsing to `winnow` is a contained change.

### D-4. Shell primitives replace the fact engine

`rsync --dry-run -i` ≙ diff engine; `bash -n` ≙ remote syntax validation;
`set -ex` ≙ debugger; `@only_if` ≙ pyinfra's `when` conditions. This is how we
absorb pyinfra's DX without its complexity.

### D-5. `JoinSet` + per-host reader tasks instead of `futures::try_join_all` + `select!`

`JoinSet` gives natural bounded fan-out and per-task error collection. A naive
`select!` over stdout/stderr loops drops the remaining stream at the first EOF
(see §7.4); dedicated reader tasks + a line channel drain both streams fully.

### D-6. `eyre`/`thiserror`, not `anyhow`

Per AGENTS.md: `eyre` at the application boundary (bin), `thiserror` in the
library (core). `anyhow` is forbidden in this workspace.

### D-7. Explicit `@export` state passing instead of a long-lived shell

A persistent interactive `bash` would preserve `cd`/variables across local
steps, but it breaks step isolation, muddies `set -e` failure semantics, and
complicates timeouts and cancellation. An explicit `@export` capture (temp-file,
NUL-delimited) keeps every step a clean, killable process and makes cross-step
data visible in the plan — at the cost of one documented limitation (`exit`
prevents capture).

### D-8. Env injection & redaction, not argv or `set -a` tricks

Local env is passed via `Command::env()` (never in argv). Remote env goes in a
payload header *before* `set -x` and is masked by shellflow in every output
path. We deliberately avoid the `set -a; . /dev/stdin; set +a` pattern (it does
not stop xtrace leakage either) and `ssh host 'KEY=val bash -s'` (puts the
secret in `ssh`'s argv, visible to `ps` and to `-vv` argv printing).

## 13. AGENTS.md Compliance Checklist

| Requirement | How the design satisfies it |
|---|---|
| `bin/` CLI + `crates/` libs | `bin/shellflow` + `crates/shellflow-core` + `crates/shellflow-secrets` |
| `cargo add` only; `workspace = true` | §5.3 |
| `eyre` app / `thiserror` lib | §5.2, D-6 |
| One output path | no logging framework; `ui` streams user-facing lines, masks secrets, and writes the audit log (`#![allow(clippy::print_stdout)]`) |
| No `anyhow`/`log`/`reqwest`/`dashmap` | none used |
| No `unsafe`, no `unwrap`/`expect`/`panic` | workspace lints deny; code uses `?` + `eyre` context |
| Pedantic/nursery clippy, `missing_docs` | all public items documented |
| proptest in normal test loop | §10.1 |
| Mutation testing | `just mutation` gate |
| Fuzz/benchmark conditional | marked N/A with justification (§10.3) |
| English-only docs/comments | this document and all code comments are English |
| Sequential cargo commands | per AGENTS.md, builds never run in parallel |

## 14. Implementation Milestones

1. **M1 — Core parser (TDD).** `crates/shellflow-core`: data model, scanner,
   `SshSpec`, `resolve_hosts`, `@export`/`@timeout`/`@copy --delete`, env
   rendering + masking, unit + proptest suite. Ends with a versioned
   build-and-deploy fixture (git-rev captured via `@export`, interpolated into
   `@copy`) driving the parser tests. `just test` green.
2. **M2 — Minimal executor.** `bin/shellflow`: clap CLI, preflight check, and
   local, remote, and copy execution (single-host, streaming with prefix).
   Manual smoke test with a real script.
3. **M3 — Concurrency & lifecycle.** `JoinSet` fan-out, `--parallel`, fail-fast
   vs `--continue-on-error`, per-step/global timeouts, SIGINT/SIGTERM handling,
   summary output, exit-code classification (3 vs 4).
4. **M4 — DX features.** `-v/-vv/-vvv` (incl. `set -ex` placement, `ssh -v`,
   secret masking), `--dry-run`, `--diff`, `--target`, `--only`/`--skip`,
   `--check`, `--output grouped`, `--log-file`, `@name`, `@only_if`, `@env`,
   `@export` end-to-end.
5. **M5 — Integration tests.** mock `ssh`/`rsync` shims; full matrix in §10.2
   (incl. timeout, SIGINT, masking, preflight).
6. **M6 — Polish.** `README.md` rewrite, `examples/deploy.sh`, docs, final
   `just format && just lint && just test && just mutation` run, git history in
   focused commits.

Each milestone ends with `just lint && just test && just mutation` green before
proceeding.

## 15. Sample outputs

### `shellflow --dry-run --diff deploy.sh`

```text
>>> [DRY RUN] no changes will be made <<<

[STEP 1/3] build · local
  |--- Local Payload ---
  | set -eu
  | echo "==> building release binary"
  | cargo build --release --locked
  | VERSION=$(git rev-parse --short HEAD)
  |----------------------
  ↳ local syntax check (bash -n): OK
  ↳ (state capture skipped in dry-run: VERSION unknown)

[STEP 2/3] ship · copy -> web  [--delete]
  ! VERSION unresolved in dry-run — itemization skipped (would sync
  ! target/release/myapp-$VERSION -> /tmp/shellflow/myapp-$VERSION)

[STEP 3/3] restart · remote -> web
  |--- Remote Payload (web) ---
  | set -eu
  | echo "==> restarting myapp-$VERSION on $(hostname)"
  | sudo systemctl restart myapp
  |-----------------------------
  ↳ remote syntax check (bash -n) on web1: OK
  ↳ remote syntax check (bash -n) on web2: OK
  [web1] SKIPPED (guard: systemctl list-unit-files … | grep -q myapp)
  [web2] SKIPPED (guard: …)

✔ Dry run complete — no changes made. Run without --dry-run to capture VERSION.
```

---

## Part II — Secrets & Credentials

> Formerly `docs/design-secrets.md` (kept as a separate design until the
> docs consolidation). Sections are numbered `S1`–`S12` to stay distinct from
> Part I; in-text references use the `§S<n>` form.

### S1. Motivation & Goals

Today `shellflow` is a deployment engine, but it has no first-class story for
**encrypted configuration**. Projects that need it end up with ad-hoc glue:

- an external `age`/`rage` CLI to generate identities and encrypt/decrypt files;
- a render script that decrypts secrets, base64-encodes them, and injects them
  as literal `# @env KEY=<value>` lines so they are masked by shellflow;
- a template renderer (`sed`) to substitute paths into `@copy` directives;
- hand-maintained systemd unit `ImportCredential=` lists that must stay in
  sync with the encrypted env files.

All of this knowledge lives in per-project scripts and READMEs instead of in
the tool. The result is a fragmented, hard-to-audit workflow where the
controller needs several external binaries and every project reinvents the
same pipeline.

#### Goals

1. **Single controller tool.** After this change the controller needs only
   `shellflow` (plus the `ssh`/`rsync`/`bash` it already wraps). No `age`,
   `rage`, `base64`, or render scripts.
2. **Static playbooks.** Playbooks reference encrypted files directly
   (`# @secrets conf/prod.env.age`) instead of generated ones containing
   base64 literals.
3. **Uniform secret hygiene.** Secrets are masked in previews, traces, and
   audit logs; never appear in any argv; never touch disk on the controller or
   the targets.
4. **Zero target-side crypto.** Targets only need `bash` and systemd ≥ 254.

#### Non-goals

- **Not a replacement for systemd.** Credential storage on targets stays
  systemd-native (`systemd-creds`, `LoadCredentialEncrypted=` /
  `ImportCredential=`). `shellflow` decrypts on the controller and lets the
  target's systemd re-seal per host.
- **Not a Vault/KMS.** Single-operator asymmetric encryption of whole files,
  consistent with the existing shell-native, minimal-toolchain philosophy.
- **No new deployment language.** `@secrets` builds on the existing
  directive DSL and `ExecutionPlan`; playbooks remain 100% valid Bash.

### S2. Design Overview

```text
controller (only shellflow + ssh/rsync/bash)              targets (bash + systemd >= 254)
┌───────────────────────────────────────────────┐        ┌──────────────────────────────────┐
│ keys generate / public          identity      │        │                                  │
│ secret encrypt / decrypt / edit               │        │                                  │
│ @secrets file.env.age  ──decrypt──> env vars │  ssh   │   remote bash blocks receive the  │
│   (masked everywhere, never in argv)         │───────>│   decrypted env (masked) over the  │
│                                              │        │   encrypted channel; targets need │
│                                              │        │   only bash (+ systemd-creds)     │
└───────────────────────────────────────────────┘        └──────────────────────────────────┘
```

Key pieces:

1. **`crates/shellflow-secrets`** — a new library crate wrapping the Rust
   `age` crate (the reference Rust implementation that `rage` itself wraps).
   Handles identity loading, file encrypt/decrypt, recipient read-back, and
   `KEY=VALUE` env parsing. No I/O leaks into `shellflow-core`.
2. **CLI subcommands** — `keys`, `secret`; the bare positional form
   (`shellflow deploy.sh`) keeps working as `run`.
3. **`@secrets` directive** — decrypts an age file at execution time, injects
   the keys as environment variables into subsequent blocks, exports a
   `LT_SECRET_KEYS` list, and registers every value for masking.

### S3. `age` Integration

`shellflow` embeds the Rust `age` crate. `rage` is itself a thin CLI over
this crate, so encrypted files are interoperable: files created by
`shellflow secret encrypt` decrypt with `rage`, and vice versa.

#### S3.1 Identity resolution

Identity (private key) is resolved in this order:

1. `-i` / `--identity` flag (any subcommand that needs it);
2. `$SHELLFLOW_AGE_IDENTITY`;
3. `~/.config/age/keys.txt` (the age convention).

Identity files are the standard age format (X25519 private key). Existing
`rage`/`age` identities work unchanged.

#### S3.2 Recipients

Recipients (public keys) are passed as repeatable `-r age1…` arguments or
read from a directory of `*.pub` files via `--recipients-dir` (one key per
file). This mirrors how projects conventionally store operator public keys.

> The age format is **anonymous**: the header stores the ephemeral share, not
> the recipients, so recipients cannot be recovered from an encrypted file.
> `secret edit` therefore **requires** `-r`/`--recipients-dir` and fails
> fast if none are given — re-encrypting without them would silently drop
> operators.

### S4. CLI Surface

```text
shellflow run [SCRIPT] [flags]        # current behavior; also the default
shellflow keys generate [-o PATH]     # write a new identity
shellflow keys public [-i PATH]       # print the public key
shellflow secret encrypt [-r age1…]... [-o OUT] FILE
shellflow secret decrypt [-i KEY] [FILE]
shellflow secret edit [-i KEY] FILE   # decrypt -> $EDITOR -> re-encrypt
shellflow secret creds FILE           # print ImportCredential=KEY lines
```

`run` keeps accepting the positional script so `shellflow deploy.sh` remains
backward compatible; all existing flags (`-v/-n/-d/-t/-o/-s/-p/-c/-k`, etc.)
apply to `run`.

### S5. `@secrets` Directive

#### S5.1 Syntax & semantics

```bash
#!/usr/bin/env shellflow

# @server web-1 deploy@10.0.0.11
# @server web-2 deploy@10.0.0.12
# @group  web  web-1,web-2

# @secrets services/myapp/env/prod.env.age
# @remote web
set -eu
# LT_SECRET_KEYS is exported automatically. Per-service store: one
# sub-directory per service keeps deploys from wiping another service's
# credentials (ImportCredential= only reads the flat store).
sudo install -d -m 0700 /etc/credstore.encrypted/myapp
# Use `tr + read + printenv`, NOT `for key in $LT_SECRET_KEYS` + `${!key}`:
# word splitting and indirect expansion are bash-only, and the remote login
# shell may be zsh (both silently misbehave there).
printf '%s\n' "$LT_SECRET_KEYS" | tr ' ' '\n' | while read -r key; do
  [ -n "$key" ] || continue
  printf '%s' "$(printenv "$key")" | sudo systemd-creds encrypt \
    --with-key=host --name="$key" - "/etc/credstore.encrypted/myapp/${key}"
done
```

> Credential filenames equal the key names (no `.cred` suffix):
> `systemd-creds` embeds the output filename into the ciphertext, and
> `ImportCredential=KEY` looks up the store by exact name — mismatches are
> refused. With `--local`, this block runs on the controller instead of over
> SSH, which is useful for debugging.

- `@secrets <file.age>` behaves like a batch of `@env KEY=VALUE` entries
  applied to all **subsequent** blocks, but the values are resolved at
  execution time from the encrypted file.
- The directive is a comment, so the playbook remains 100% valid Bash.
- Repeatable: multiple `@secrets` lines merge in order; later files win on
  key conflicts (matching shell `source` semantics).
- The decrypted keys are **also** exported as the space-separated list
  variable `LT_SECRET_KEYS`, so remote blocks can iterate them without
  knowing the key names ahead of time.

#### S5.2 Execution-time resolution

The parser records only the file path (keeping `shellflow-core` pure and
I/O-free):

```rust
pub struct SecretEntry {
    pub file: String,
    pub identity: Option<String>,
}
// ExecutionPlan gains: pub secrets: Vec<SecretEntry>
```

The executor resolves all `SecretEntry` values once, before the first step:

1. resolve the identity — **most specific wins**: the `@secrets` line's own
   `--identity`, then the run-wide `-i` flag, then `$SHELLFLOW_AGE_IDENTITY`,
   then `~/.config/age/keys.txt`. Identities are loaded lazily and cached per
   run, so a playbook whose files each pin their own identity never touches
   the default path, and a repeated path is read once. A missing or invalid
   identity is a hard error (never a silent skip);
2. decrypt the file. Later files win on key conflicts (matching `source`
   semantics) and the key list is deduplicated in first-seen order;
3. parse `KEY=VALUE` lines (blank lines and `#` comments ignored; the first
   `=` splits the key);
4. insert every key into run-state env (same layer as `@export`, so explicit
   `@env` still wins on conflicts);
5. register every value in the `Ui` mask set (see §S5.3);
6. export `LT_SECRET_KEYS` into run-state env — **only when there are shared
   keys**. The variable is a *set* of key names; an empty value would be
   indistinguishable from "this service has no credentials", which
   `cred-env credstore-install` acts on by clearing the credential store. A
   playbook whose every entry is per-host therefore exports no variable at
   all, and the store is left untouched; the per-host key names are added by
   the executor, for the host it is about to talk to.

#### S5.3 Masking

`Ui::mask_line` currently performs a global `str::replace` for every known
secret. Short values (e.g. `1`, `on`) would corrupt output, so `@secrets`
masking applies only to values of length ≥ a threshold. The threshold
defaults to `6` and is configurable via `$SHELLFLOW_MASK_MIN_LEN` (or
`--mask-min-len` on `run`, which takes precedence). An unparsable or negative
`$SHELLFLOW_MASK_MIN_LEN` falls back to `6` rather than failing the run.
Explicit `@env KEY=value` literals keep their unconditional masking, and a
value captured by `@export` is masked the same way unless the playbook says
`--public` (§7.6). Nothing about masking depends on the variable's name.

Masking covers host lines, payload previews, and `--log-file` output through
the existing `Ui` path; secrets never appear in any spawned argv. Every path
that renders *user content* must route through the mask, not only the payload
previews: the `-vv` local `bash -c` echo goes through `Ui::masked_note` for
exactly this reason, since a literal secret embedded in a block body would
otherwise be printed unmasked two lines below a preview showing `***`.

#### S5.4 Precedence & errors

- Precedence for a key present in several sources:
  `@env KEY=value` (step) > `@secrets`/`@export` (run state) > passthrough.
- Missing identity, undecryptable file, or malformed env content is a hard
  error before any step runs (never a silent skip).

#### S5.5 Per-host secrets via the `{host}` placeholder

A `@secrets` path may contain `{host}`, which expands to the **target alias**
of each host the selected steps actually reach (after `--target` restriction):

```bash
# @server web-1 deploy@10.0.0.11
# @server web-2 deploy@10.0.0.12
# @group  web  web-1,web-2

# @secrets services/myapp/{host}.env.age
# @remote web
echo "this is $API_KEY"        # different per host
```

Semantics:

1. Expansion uses the set of aliases the **selected** steps target. A host no
   selected step touches never requires a file, so `-t web-1` with
   `--only fetch` does not need `web-2.env.age`.
2. A targeted host whose file is missing is a **hard error** (fail closed).
   Guessing a path or silently skipping a host would deploy a host with the
   wrong credentials.
3. Per-host pairs are layered onto that host's payload env only; one host
   never sees another host's values. `LT_SECRET_KEYS` is extended with that
   host's keys.
4. Every value is registered for masking exactly like a shared value.
5. `--local` resolves remote blocks on the controller, so a `{host}` playbook
   is ambiguous there: it requires a single host (`-t <host>`) and errors
   otherwise, rather than picking one arbitrarily.
6. Remote syntax checks (`--check`/`--dry-run`) do not need per-host values:
   they never execute the block.

### S7. Crate & Module Impact

| Area | Change |
|---|---|
| `crates/shellflow-secrets` (new) | `age` wrapper: identity load, encrypt/decrypt, recipient read-back, env-file parser. Library-only; unit + proptest. |
| `crates/shellflow-core` | `ExecutionPlan.secrets: Vec<SecretEntry>`; parser recognizes `@secrets` (path only, no I/O). |
| `bin/shellflow` | clap subcommands (`run` default); executor resolves secrets into run-state env + mask list; `Ui` gains a min-length mask threshold. |
| `bin/shellflow/src/preflight.rs` | unchanged (`age` is embedded; `bash`/`ssh`/`rsync` remain the only required tools). |

Dependency additions (via `cargo add`, workspace-managed): `age`,
`age-core`, `clap` (already present), `tempfile` (dev). `shellflow-core`
stays free of async, I/O, and crypto.

### S8. Security Properties

- **Controller-only secrets**: encrypted files travel to the controller,
  decrypted in memory, injected into remote payloads over the (already
  encrypted) SSH channel. Targets never hold the age identity.
- **No argv / no disk**: secret values never appear in process argv. Every
  file that holds plaintext or ciphertext — `secret decrypt -o`, `secret
  edit`, `cred-env render` — is written `0600` through a same-directory
  temporary file and an atomic rename, so a partial or failed write never
  truncates the previous contents and the mode is corrected even when
  re-writing an existing file. The `@export` capture file is owned by an RAII
  guard and deleted on every exit path, including a failed step.
- **Masked everywhere**: previews, `-vv/-vvv` traces, and `--log-file` redact
  every `@secrets` value (subject to the min-length guard). The redaction is
  applied by the output sink, so every render path is covered by
  construction — including error messages, `bash -n` diagnostics, and the
  audit trail.
- **Fail fast**: missing identity, decrypt failure, or malformed env aborts
  before any step executes.
- **Recipient safety**: `secret edit` requires explicit `-r`/`--recipients-dir`
  and fails fast otherwise — age is anonymous, so re-encrypting without the
  full recipient list would silently drop operators. The check runs *before*
  the ciphertext is read, so a rejected invocation never stages plaintext.

### S9. Testing Strategy

- **Unit (TDD)** — `shellflow-secrets`: identity load/paths, encrypt→decrypt
  round-trip with an ephemeral generated identity, recipient read-back,
  env-file parsing (blank/comment/`=`-in-value edge cases).
- **Property** — env-file parser invariants via `proptest` (e.g. parse
  round-trip stability), masking threshold behavior.
- **Parser** — `@secrets` directive recognition, ordering, and
  `LT_SECRET_KEYS` export using the existing `shellflow-core` test style.
- **Resolver** — a per-entry `--identity` beats the run-wide `-i`; a playbook
  whose every entry pins an identity succeeds even when the default identity
  path does not exist; a missing identity is a hard error naming the path;
  later files win on key conflicts and `LT_SECRET_KEYS` is deduplicated; the
  threshold gates which values are registered for masking.
- **Integration** — extend `bin/shellflow/tests/` with mock `ssh`/`rsync`
  shims (existing pattern): a playbook with `@secrets` must (a) not leak the
  value into captured argv or payload previews, (b) run the remote block with
  the env injected, (c) fail fast without an identity, (d) decrypt through a
  per-entry `--identity` with no run-wide `-i`, and (e) honor
  `SHELLFLOW_MASK_MIN_LEN` for short values.
- **Mutation** — `just mutation` over the new crate and parser changes.
- **Fuzz** — conditional: the env-file parser is the only parser-like surface;
  add `cargo-fuzz` only if it grows into a general config format.

### S10. Milestones

1. **M1 — `shellflow-secrets` crate.** `age` wrapper + env parser + tests.
2. **M2 — `keys` / `secret` subcommands.** `generate`, `public`, `encrypt`,
   `decrypt`, `edit`, `creds`.
3. **M3 — `@secrets` directive.** Parser entry, executor resolution, masking
   threshold, `LT_SECRET_KEYS`.
4. **M4 — Docs & examples.** Update `README.md`, `docs/design.md`, add an
   end-to-end example playbook.

Each milestone ends with `just format && just lint && just test &&
just mutation` green.

### S11. Decision Records

#### D-1. Embed the Rust `age` crate instead of shelling out to `rage`

`rage` is a CLI wrapper over the same crate; embedding it removes a PATH
dependency, keeps behavior identical, and matches the tool's zero-runtime
philosophy. The Go `age` implementation is not used.

#### D-2. `@secrets` directive instead of generated base64 `@env` glue

The directive keeps playbooks static and valid Bash, moves decryption into
the tool (where masking already lives), and eliminates render scripts and
temporary files.

#### D-4. Masking with a min-length threshold

`mask_line` does global replacement; protecting short values from being
over-masked requires a threshold, which is exposed as configuration rather
than hard-coded.

### S12. Target-side helpers: `cred-env`, templates, `emit`, `template check`

#### S12.1 Motivation

Every third-party service used to ship its own `bin/<svc>-start` launcher: a
credential→env export loop plus, when the app only reads a config file, a
heredoc that renders the config into tmpfs. Both parts were copied verbatim
into every service and were bash/zsh-fragile in different ways.

#### S12.2 Design

The helpers are **subcommands of the shellflow binary itself**; the playbook
installs that binary once per target host (static musl cross-build via
`cargo zigbuild`, ~3 MB, idempotent, version upgrades ship with each deploy)
and every unit references it:

- **`shellflow cred-env exec <cmd> [args…]`** — exports every
  `$CREDENTIALS_DIRECTORY/*` as an env var (filename = variable name, exact
  `[A-Za-z_][A-Za-z0-9_]*` check matching the Rust env parser) and execs the
  command (`CommandExt::exec`, so systemd's main PID and signals apply to the
  real program). Unset `$CREDENTIALS_DIRECTORY` fails closed — a unit that
  declares no credentials should not run through `cred-env`. Replaces the
  per-service export loop.
- **`shellflow cred-env render <tmpl> <out>`** — substitutes `${KEY}`
  placeholders from the credentials into a template and writes `<out>` (0600,
  same-directory temp file + atomic rename). Substitution is literal;
  `shellflow_core::render_template` fails with the sorted list of missing keys
  before anything is written. Replaces the per-service heredoc.
- **`shellflow cred-env credstore-install <svc> [--store-dir PATH]`** —
  clears `/etc/credstore.encrypted/<svc>/` and re-seals every key listed in
  `$LT_SECRET_KEYS` (exported by `@secrets`) via
  `sudo systemd-creds encrypt --with-key=host --name=<KEY>`, value on stdin.
  Unset `$LT_SECRET_KEYS` aborts (the store must not be wiped for nothing);
  set-but-empty is an explicit "no credentials" and clears the store. The new
  store is built in a staging directory and swapped in only once every key
  sealed successfully, so a mid-way failure leaves the previous store intact
  rather than empty or half-written. Replaces the hand-written install loop
  (and its zsh/bash portability class).
- **Templates** are plaintext files with `${KEY}` placeholders, committed next
  to the service. They contain no secrets, so they may live on persistent
  disk; only the rendered output (tmpfs) ever holds values.
- **`shellflow template check <tmpl> <file.env.age>`** extracts the
  template's `${KEY}` references (`shellflow_core::template_keys`) and
  cross-checks them against the encrypted env file on the controller: missing
  keys are fatal (they would abort the unit at start), unreferenced keys are
  reported as notes.
- **Controller-side replacements for the infra repo's bash scripts**:
  `shellflow secret keys-check <dir>` verifies all `<host>.env.age` files in a
  service directory share one key set (was `scripts/check-env-keys.sh`);
  `shellflow service init <svc> [--host …]` scaffolds the flat layout + unit +
  playbook skeleton (was `scripts/new-service.sh`).
- **Fallback**: `shellflow emit cred-env [-o PATH]` still prints a pure-bash
  asset (`bin/shellflow/assets/cred-env.sh`, embedded with `include_str!`)
  implementing `exec`/`render` with the same semantics, for targets that
  cannot host the binary. Both implementations are exercised by parallel
  integration suites over one shared fixture set.

#### S12.3 Correctness constraints discovered while testing

- **Literal substitution cannot use `${line//needle/val}`**: in the
  replacement string, `&` expands to the matched text on some bash versions
  (sed-like semantics), so a password containing `&` would corrupt the render.
  The bash fallback builds the result with `${text%%"$needle"*}` /
  `${text#*"$needle"}` instead, which is literal on every bash; the Rust
  `render_template` splices spans from the original text (also making
  self-referential values safe).
- **Variable-name validation cannot use a `case` glob**: in
  `case $key in [A-Za-z_][A-Za-z0-9_]*)`, the trailing `*` matches *any*
  string, so `BAD-NAME` passes and the subsequent `export` fails. Both
  implementations use the exact regex equivalent
  (`[[ =~ ]]` in bash, a char-based check in Rust), matching the Rust env
  parser.
- **`ExecStart=` performs no command substitution**: `$(cat …)` is passed
  literally, and the `sh -c` workaround would expose the secret in argv
  (`ps`). Apps must read `$CREDENTIALS_DIRECTORY/<KEY>` themselves, use
  `cred-env exec`, or consume a `cred-env render`-produced config file.
- **The encrypted path form needs `LoadCredentialEncrypted=ID:PATH`**:
  `LoadCredential=` expects a plaintext source and `ImportCredential=` only
  searches the flat credential-store directories (systemd.io/CREDENTIALS,
  systemd.exec(5)).

#### S12.4 Testing

- `crates/shellflow-core/src/template.rs`: unit + proptest coverage of the
  placeholder scanner and `render_template` (boundaries, malformed forms,
  multi-byte, adjacent placeholders, literal values, missing-key fail-closed).
  30 of 31 mutants caught (1 unviable).
- `bin/shellflow/tests/cred_env.rs`: two parallel suites over shared fixtures —
  (a) the bash fallback asset under `bash`, (b) the real `shellflow cred-env`
  binary (`CARGO_BIN_EXE_shellflow`) with a fake `$CREDENTIALS_DIRECTORY` and
  a stub `sudo`/`systemd-creds` on `PATH`: `exec` export semantics (including
  invalid names and fail-closed without the directory), flag passthrough, exit
  code propagation, `render` literal substitution (values with `&|$\\'"`),
  non-UTF-8 rejection, 0600 output, no temp-file leftovers, and
  `credstore-install` happy path (argv hygiene: values never in argv), stale
  key clearing, and fail-closed on empty/missing/invalid keys and unsafe
  service names.
- `bin/shellflow/tests/service_init.rs`: `service init` scaffolding (file
  set, executable bit, overwrite refusal, name validation, generated playbook
  passes `-k` end-to-end with a real encrypted env) and `secret keys-check`
  (match/mismatch/no-files cases).
