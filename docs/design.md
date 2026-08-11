# shellflow — Design Document

> Related design: [`design-secrets.md`](design-secrets.md) covers the embedded
> `age` integration (`keys`/`secret`), the `@secrets` directive, the `deploy`
> subcommand, and `--local` mode.

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
shellflow                     ssh -T user@host bash -s          remote host
┌─────────────┐   stdin    ┌──────────────────────────────┐   ┌─────────┐
│  payload    │ ─────────> │  set -eu + env + remote block │ ─>│ bash    │
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

- Directive detection is lexical. A `# @foo` line inside a heredoc body or a
  multi-line string is not recognized as a directive (it would be treated as
  script content — which is safe, just not a directive). Deploy scripts must
  keep directives at the top level.
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
│   └── design.md              # this document
├── bin/
│   └── shellflow/             # CLI + execution engine (I/O boundary)
│       ├── Cargo.toml
│       ├── src/
│       │   ├── main.rs        # clap entry, tracing init, orchestration
│       │   ├── cli.rs         # Args (clap derive)
│       │   ├── ui.rs          # colored streaming output, plan summary
│       │   └── executor.rs    # run_local / run_remote / run_copy
│       └── tests/
│           ├── integration.rs # end-to-end with mock ssh/rsync shims
│           ├── fixtures/      # sample deploy scripts
│           └── mockbin/       # fake ssh/rsync (Bash shims recording argv)
└── crates/
    └── shellflow-core/        # parser + plan types (pure, no I/O)
        ├── Cargo.toml
        └── src/
            ├── lib.rs
            ├── plan.rs        # data model (§4.3)
            ├── directive.rs   # directive recognition + payload parsing
            ├── parser.rs      # line scanner -> ExecutionPlan
            └── ssh_spec.rs    # SshSpec parse / to_args / rsync dest
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

# bin/shellflow
cargo add clap tokio eyre colored tracing-subscriber -p shellflow --workspace
cargo add shellflow-core -p shellflow --path crates/shellflow-core

# crates/shellflow-core
cargo add thiserror -p shellflow-core --workspace
cargo add proptest -p shellflow-core --workspace --dev
```

| Crate | Where | Why |
|---|---|---|
| `clap` (derive) | bin | CLI parsing |
| `tokio` | bin | async process supervision, `JoinSet` |
| `eyre` | bin | application error handling (per AGENTS.md) |
| `thiserror` | core | library error types (per AGENTS.md) |
| `tracing-subscriber` | bin | env-filtered logging init (`tracing` macros unused in v1) |
| `colored` | bin | host-prefix and step-header ANSI styling |
| `shellflow-core` | bin | local path dependency |
| `proptest` (dev) | core | property tests in the normal test loop |

Explicitly **not** used: `anyhow` (forbidden), `russh`/`libssh2`/`ssh2` (we wrap
system `ssh`), `futures` (unnecessary — `JoinSet` covers fan-out), `scc`
(no shared concurrent maps in this design), `winnow`/`pest` (see D-3).

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
    .arg(if dry_run { "bash -s -n" } else { "bash -s" })
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?;

// Payload layout — env lines always precede tracing so exports are never traced:
//   set -eu
//   export KEY='***'          <- env block (from @env/@export state)
//   set -x                    <- only at -vvv, AFTER the env block
//   <user script>
let payload = format!(
    "set -eu\n{env_lines}{trace_line}{script}",
    env_lines = render_env(&state),        // single-quote-escaped values
    trace_line = if verbose >= 3 { "set -x\n" } else { "" },
);
// 1. Write payload, then DROP stdin so remote `bash -s` sees EOF.
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
(`>f+++++++++` new file, `f..t......` timestamp-only, `*deleting` removal) —
this *is* our diff engine (pyinfra feature #2).

**Target directory creation & no-rsync fallback.** Every copy probes the
remote for `rsync` (`ssh host command -v rsync`). When present, the transfer
runs under `--rsync-path "mkdir -p <parent-dir> && rsync"` so a file-style
destination's parent directory is created automatically (matching rsync's
own `dir/` semantics). When rsync is missing on the target, `@copy` falls
back to `ssh mkdir -p <parent-dir>` + `scp src host:<parent-dir>/`, keeping
the design promise that targets only need `bash` (§9). This preserves the
delta/idempotency properties in the common case and degrades gracefully to a
plain copy on minimal hosts.

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
- **Timeouts.** `--timeout <secs>` applies globally; `@timeout` overrides per
  step. Each host task wraps `child.wait()` in `tokio::time::timeout`; on expiry
  it SIGTERMs the child, waits a 5s grace period, then SIGKILLs it and records
  the host as `TIMEOUT` (a failure: abort or continue per
  `--continue-on-error`).
- **Signals.** `tokio::signal` installs SIGINT/SIGTERM handlers. On receipt,
  shellflow cancels all in-flight host tasks, SIGTERM→SIGKILLs every tracked
  child, prints a summary of completed/failed/pending steps, and exits 130. No
  orphan processes survive.

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
  on the controller.
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
- `SshSpec`: `user@host:port` → `["-p", "2222", "user@host"]` and rsync dest.

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
  masked as `***`.

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
| `bin/` CLI + `crates/` libs | `bin/shellflow` + `crates/shellflow-core` |
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
