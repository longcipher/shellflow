# shellflow — Design Document

> Part I covers the DSL and execution engine; **Part II** (sections `S1`–`S12`)
> covers the embedded `age` integration (`keys`/`secret`), the `@secrets`
> directive, `--local` mode, and the target-side `cred-env` helpers.

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
- Lean, auditable codebase: 2 crates, on the order of 1500–2000 lines. The
  target is clarity and test coverage, not line-count gymnastics — "lightweight"
  means a single static binary with no runtime dependencies, not minimal source
  lines.
- Production-safe lifecycle: global and per-step timeouts, Ctrl-C/SIGTERM
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
| `@copy` | `# @copy <src> -> <dst> @<target> [--delete]` | Sync a local file/dir to `<dst>` on all hosts in `<target>`. `--delete` mirrors removal of remote extras. `src`/`dst` support `$VAR`/`${VAR}` interpolation from `@export`ed state (§4.4) |
| `@export` | `# @export <VAR>[,<VAR>…]` | After the preceding local block, capture the named variables into run state; later `@copy` paths interpolate them and later blocks receive them as env vars (§7.6) |
| `@timeout` | `# @timeout <seconds>` | Cap the next block per host; on expiry the child is SIGTERM'd, then SIGKILL'd after a grace period (§7.5) |
| `@name` | `# @name <label>` | Label the next block (for `--only`/`--skip` filtering and reporting) |
| `@only_if` | `# @only_if <command>` | Guard: run next block only where `<command>` succeeds (exit 0); otherwise report `SKIPPED` |

**Rules:**

1. Every `# @` directive flushes the pending block. Directives may appear in any
   order and may be interleaved with blocks.
2. A block that contains no executable statement (only comments/blank lines) is
   dropped.
3. Blocks default to `local` until an explicit `@remote`/`@copy`/`@local`.
4. `@env`, `@only_if`, `@timeout`, and `@name` apply to the *next* block that
   contains statements. `@export` applies to the *preceding* local block and is
   an error after a remote block (remote variables cannot be captured).
5. The shebang `#!/usr/bin/env shellflow` is ignored, as is any line before the
   first directive that only contains comments/blank lines.
6. CRLF line endings are tolerated (`\r` stripped).
7. Lines are included verbatim in the payload, preserving fidelity.
8. A here-document body is opaque: `<<TAG` / `<<-TAG` openers are tracked
   lexically and every line up to the exact terminator is script content,
   exempt from directive detection. Bodies are consumed FIFO because one
   line may open several here-documents.

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
# @export VERSION

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
    Alias(String),
    Raw(String),
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
    pub src: String,
    pub dst: String,
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
    pub env: Vec<EnvEntry>,
}

#[derive(Clone, Debug)]
pub enum Step {
    Local(LocalStep),
    Remote(RemoteStep),
    Copy(CopyStep),
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionPlan {
    /// Deterministic ordering (BTreeMap) for stable plan summaries.
    pub servers: BTreeMap<String, SshSpec>,
    pub groups: BTreeMap<String, Vec<String>>,
    pub env: Vec<(String, String)>, // from @env directives, in order
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
) -> Vec<ResolvedHost>;
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
  `crates/shellflow-core/src/heredoc.rs`.
- No conditional/loop constructs in the DSL itself. Script authors use plain
  Bash (`if`, `for`, `command -v`, `[ -f ] || …`) for control flow, and
  `@only_if` for host-level preconditions.
- **`@copy` paths are parsed by shellflow, not Bash.** `src`/`dst` are literal
  strings extracted from the comment, so a bare `$VERSION` there is *not*
  expanded by Bash and would silently reach `rsync` verbatim. Use `@export` to
  capture values and let shellflow interpolate `$VAR`/`${VAR}` from run state.
  An unresolved variable is an error at plan-build time, never a silent no-op.
- `@copy` delimiters are fixed: `src`/`dst` must not contain the literal `->`,
  the target is the final whitespace-separated token (an `@` prefix is
  recommended), and paths containing spaces or a leading `@` are unsupported.

## 5. Architecture

### 5.1 Workspace layout

Per `AGENTS.md`: `bin/` holds CLI crates, `crates/` holds reusable libraries.

```text
shellflow/
├── Cargo.toml                 # workspace deps & lints (already configured)
├── Justfile                   # format/lint/test/mutation/build (already configured)
├── docs/
│   ├── design.md              # this document (Part I: engine, Part II: secrets)
│   └── example-app.md         # worked examples: secret-app + env-app
├── bin/
│   └── shellflow/             # CLI + execution engine (I/O boundary)
│       ├── Cargo.toml
│       ├── src/
│       │   ├── main.rs        # clap entry, tracing init, orchestration
│       │   ├── cli.rs         # Args (clap derive)
│       │   ├── ui.rs          # colored streaming output, plan summary, masking
│       │   ├── executor.rs    # run_local / run_remote / run_copy, fan-out
│       │   ├── secrets.rs     # @secrets resolution -> run-state env + mask list
│       │   ├── secret.rs      # `secret` subcommand (encrypt/decrypt/edit/creds)
│       │   ├── keys.rs        # `keys` subcommand (generate/public)
│       │   └── preflight.rs   # required-tool preflight check
│       └── tests/
│           ├── integration.rs # end-to-end with mock ssh/rsync shims
│           └── mockbin/       # fake ssh/rsync/scp (Bash shims recording argv)
└── crates/
    ├── shellflow-core/        # parser + plan types (pure, no I/O)
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── plan.rs        # data model (§4.3)
    │       ├── env.rs         # env rendering + masking (pure string logic)
    │       ├── parser.rs      # line scanner -> ExecutionPlan
    │       └── ssh_spec.rs    # SshSpec parse / to_args / rsync dest
    └── shellflow-secrets/     # age wrapper (encrypt/decrypt, env parser)
        ├── Cargo.toml
        └── src/
            └── lib.rs         # identity load, crypto, KEY=VALUE env parsing
```

### 5.2 Crate responsibilities

**`shellflow-core`** — pure, synchronous, dependency-light.

- Parses scripts into `ExecutionPlan`.
- Resolves targets to host lists (`resolve_hosts`).
- Builds `ssh`/`rsync` argv strings from `SshSpec` (including `-p` for ports and
  `-e 'ssh -p N'` for rsync).
- Renders the payload env header (escaping + `set -x` ordering) and masks known
  secret values — pure string logic, unit-testable.
- Exposes `ParseError` (with line numbers) via `thiserror`.
- No tokio, no stdio, no network. Everything is unit- and proptest-able.

**`shellflow-secrets`** — pure crypto/parsing wrapper, no I/O at the crate
boundary beyond what `age` requires.

- Wraps the `age` crate (X25519 identities) for identity loading, file
  encrypt/decrypt, and recipient read-back.
- Parses `KEY=VALUE` env files (blank lines and `#` comments ignored; first
  `=` splits the key) for `@secrets` resolution.
- Library-only: no `tokio`, no `std::process`. Unit- and proptest-tested.
- `shellflow-core` stays free of async, I/O, and crypto.

**`bin/shellflow`** — the I/O boundary.

- clap parsing, `tracing_subscriber` init, script loading.
- The execution engine: spawns `bash`, `ssh`, `rsync` via
  `tokio::process::Command`; fans out to hosts with `tokio::task::JoinSet`;
  streams prefixed output.
- `eyre` for application errors; `tracing` for logs; `println!`/`eprintln!`
  only for user-facing streaming UI (with `#![allow(clippy::print_stdout)]`,
  as permitted for CLI crates in the workspace lint config).

### 5.3 Dependencies

Added via `cargo add` only (never hand-edited into `Cargo.toml`):

```bash
# workspace level
cargo add eyre tokio tracing-subscriber --workspace   # already present
cargo add colored --workspace                          # ANSI UI in bin
cargo add age tempfile --workspace                     # secrets crate

# bin/shellflow
cargo add clap tokio eyre colored tracing-subscriber -p shellflow --workspace
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
| `thiserror` | core/secrets | library error types (per AGENTS.md) |
| `tracing-subscriber` | bin | env-filtered logging init |
| `colored` | bin | host-prefix and step-header ANSI styling |
| `age` | secrets | embedded X25519 encryption (no `rage` binary) |
| `shellflow-core` | bin | local path dependency (parser + plan) |
| `shellflow-secrets` | bin | local path dependency (crypto + env parser) |
| `proptest` (dev) | core/secrets | property tests in the normal test loop |
| `tempfile` (dev) | secrets | temp-file fixtures in tests |

Explicitly **not** used: `anyhow` (forbidden), `russh`/`libssh2`/`ssh2` (we wrap
system `ssh`), `futures` (unnecessary — `JoinSet` covers fan-out), `scc`
(no shared concurrent maps in this design), `winnow`/`pest` (see D-3),
`reqwest`/`dashmap` (forbidden by AGENTS.md).

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
  -p, --parallel <N>          Max concurrent hosts per step [default: all]
  -c, --continue-on-error     Continue after a failed host/step; print summary
  -k, --check                 Syntax-check only: local `bash -n`, remote
                              `ssh host bash -n -s`; no execution
      --timeout <SECS>        Per-step timeout for all steps [default: none]
      --output <MODE>         stream (default) | grouped — print each host's
                              logs as one block when that host finishes
      --mask-min-len <N>      Minimum @secrets value length that is masked;
                              defaults to $SHELLFLOW_MASK_MIN_LEN, else 6
  -l, --log-file <PATH>       Append every streamed line (tagged host+stream)
                              to a file for audit
      --no-color              Disable ANSI colors
  -h, --help                  Print help
  -V, --version               Print version

EXIT CODES:
  0   success (skipped blocks and dry-runs with no errors)
  1   plan/parse error (bad script, unresolved @export variable)
  2   CLI usage error (clap)
  3   transport/setup failure (missing ssh/rsync/bash, ssh exit 255, rsync I/O error)
  4   script execution failure (a local/remote step exited non-zero)
  130 interrupted by SIGINT/SIGTERM (see §7.5)
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

## 7. Execution Engine

### 7.1 Step lifecycle

```text
for each step (sequentially):
    resolve hosts (respecting --target restriction)
    print step header  [STEP n/m] <name> <kind> -> <target>
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

### 7.4 Concurrency & output integrity

- Each step fans out over hosts with `tokio::task::JoinSet`, bounded by
  `--parallel N` via `tokio::sync::Semaphore` (default: unbounded).
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
  `ssh`, and `rsync` exist on `PATH` and fails with a friendly message (exit 3)
  if any is missing — no mid-run `Command::new` surprise.
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
  shellflow cancels all in-flight host tasks, the `GroupGuard`s tear down every
  process group, shellflow prints a summary of completed/failed/pending steps,
  and exits 130. No orphan processes survive.

### 7.6 Cross-step state (`@export`)

Local steps run as separate processes, so `cd` and shell variables do not
survive a step boundary (remote blocks are fresh SSH sessions by design).
Rather than a long-lived interactive shell — which silently breaks step
isolation and error semantics — state is passed *explicitly* (Decision Record
D-7):

1. When a local step declares `@export VAR`, shellflow appends a capture line
   that writes the values to a private temp file as NUL-delimited records (the
   temp path is passed via `Command::env`, so it never appears on stdout).
2. After the step, shellflow reads the file into `RunState`. Scripts that call
   `exit` before the capture line cannot export — documented, acceptable.
3. Later `@copy` `src`/`dst` strings are interpolated from `RunState`
   (`$VAR`/`${VAR}`); unresolved names are a plan-build error.
4. Later local steps receive the values via `Command::env()`; later remote
   blocks receive them in the env header (masked, §9).

This makes versioned artifact paths work end-to-end:

```bash
# @local
VERSION=$(git rev-parse --short HEAD)
# @export VERSION
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

**State in dry-run.** Local steps are *not* executed in dry-run, so
`@export`ed variables are unknown there. A `@copy` path referencing an
unresolved variable prints a warning and is skipped for itemization instead of
guessing a path.

### 8.3 Idempotency strategy

Three cooperating layers, deliberately *not* a state engine:

1. **Transport idempotency** — `rsync` transfers only deltas; re-running a copy
   step is a no-op when content matches.
2. **Guard idempotency** — `@only_if` blocks are skipped where the precondition
   already holds; skipped blocks print `SKIPPED (guard)` and count as success,
   so repeated runs converge.
3. **Author idempotency** — plain Bash (`[ -f ] ||`, `command -v`,
   `systemctl is-active`) for everything the tool can't infer. `set -eu` and
   pre-run `bash -n` make partial failures from typos impossible.

## 9. Security & Operational Notes

- **Inherit the user's SSH trust**: keys, `~/.ssh/config`, `ssh-agent`, jump
  hosts, YubiKey — all handled by the system `ssh`. We never touch credentials.
- **No interactive prompts**: we use `ssh -T` (no TTY). `sudo` in scripts
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
  (`***`) in payload previews, trace output, and `--log-file`. Residual caveat:
  if the *user's own script* echoes a secret, that is the script's doing —
  treat `-vvv` as a debug tool and prefer `@env KEY` passthrough from CI over
  literal values in the deploy file.
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
- env-block rendering: single-quote escaping, ordering before `set -x`,
  masking of known values;
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
- `--dry-run` sends `bash -n -s` and `rsync --dry-run -i`; nothing written;
- fail-fast aborts remaining steps vs `--continue-on-error` summary;
- `--target`, `--only`, `--skip`, exit codes, `--no-color`;
- timeout: a sleeping mock `ssh` is SIGTERM'd and reported `TIMEOUT`;
- SIGINT: an in-flight mock `ssh` is killed and shellflow exits 130;
- `--output grouped` emits per-host blocks; `--log-file` contains tagged lines;
- preflight: PATH without `ssh` fails fast with exit 3 and a friendly message;
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

These tests require local `bash`, `ssh`-less (mock shims), and no network.

### 10.3 Tooling gates

```bash
just format
just lint        # typos, rumdl, cargo sort, fmt, clippy -D warnings, cargo shear
just test        # cargo test --all-features (incl. proptest)
just mutation    # cargo-mutants; fix survivors
just check-cn    # no CJK in code/comments (docs/comments are English-only)
```

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
is line-oriented with fixed prefixes and trivial `space`/`,`/`->`/`@`-delimited
payloads — a deterministic ~120-line scanner is more readable and more
testable than a combinator grammar for this shape, and keeps the dependency
tree minimal. If the DSL ever grows nested expressions, switching the payload
parsing to `winnow` is a contained change.

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
| `tracing` for logs | bin initializes `tracing_subscriber`; `println!` reserved for streaming UI with the documented `#![allow(clippy::print_stdout)]` |
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
6. export `LT_SECRET_KEYS` into run-state env.

#### S5.3 Masking

`Ui::mask_line` currently performs a global `str::replace` for every known
secret. Short values (e.g. `1`, `on`) would corrupt output, so `@secrets`
masking applies only to values of length ≥ a threshold. The threshold
defaults to `6` and is configurable via `$SHELLFLOW_MASK_MIN_LEN` (or
`--mask-min-len` on `run`, which takes precedence). An unparsable or negative
`$SHELLFLOW_MASK_MIN_LEN` falls back to `6` rather than failing the run.
Explicit `@env KEY=value` literals keep their current unconditional masking.

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
- **No argv / no disk**: secret values never appear in process argv; the
  temporary plaintext lives only in shellflow's memory and is dropped after
  the run.
- **Masked everywhere**: previews, `-vv/-vvv` traces, and `--log-file` redact
  every `@secrets` value (subject to the min-length guard).
- **Fail fast**: missing identity, decrypt failure, or malformed env aborts
  before any step executes.
- **Recipient safety**: `secret edit` requires explicit `-r`/`--recipients-dir`
  and fails fast otherwise — age is anonymous, so re-encrypting without the
  full recipient list would silently drop operators.

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
  set-but-empty is an explicit "no credentials" and clears the store. Replaces
  the hand-written install loop (and its zsh/bash portability class).
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
