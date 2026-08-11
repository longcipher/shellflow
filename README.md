# shellflow

shellflow is a shell-native, agentless automation tool that runs commands over
ssh - concurrently, idempotently and 10x faster than ansible.

A deploy run is a **plain Bash script** annotated with `# @` comment
directives. `shellflow` interprets the directives and drives the blocks
locally, across hosts, and through file copies — wrapping the system
`ssh`/`rsync`/`scp`/`bash`. No Python, no YAML, no agent, no SSH library, no
target-side daemon.

```bash
#!/usr/bin/env shellflow

# @server trade    trade
# @server api      api
# @group  all      trade,api

# @local
VERSION=$(git rev-parse --short HEAD)

# @export VERSION

# @copy target/release/myapp-$VERSION -> /tmp/shellflow/myapp-$VERSION @all

# @remote all
# @only_if test -f /etc/shellflow/myapp
sudo systemctl restart myapp
```

Because directives are comments, the file is **100% valid Bash** — `bash
deploy.sh` runs it unchanged, and your editor highlights it perfectly.

## Features

- **Agentless & shell-native** — zero install on targets: they only need
  `bash`. `shellflow` connects with your system `ssh`, so `~/.ssh/config`,
  keys, `ssh-agent`, jump hosts, and YubiKeys just work.
- **Mina-style streaming** — each remote block is streamed to every host over a
  single `ssh host bash -s` connection from memory. No per-command round trips.
- **Deployer-style pipeline** — `@local` build → `@copy` → `@remote` deploy,
  with concurrent multi-host fan-out (`JoinSet` + semaphore, `--parallel`
  defaults to all hosts).
- **Detailed debugging** — `-v` / `-vv` / `-vvv`:
  - `-v`: plan preview + per-step timing.
  - `-vv`: exact `ssh`/`rsync`/`scp` argv and full payload previews.
  - `-vvv`: injects `set -x` into every payload and `ssh -v` on the wire, so you
    watch Bash trace lines live (stderr shown yellow, per-host prefixed).
- **Idempotent dry-run & diff** — `--dry-run` / `--diff` syntax-check payloads
  (`bash -n`, remote `bash -n -s`) and itemize file changes via
  `rsync --dry-run -i`. Nothing is written; `--diff` hides status prose and
  shows only the change list.
- **State passing** — `@export VAR` captures a variable from a local block and
  injects it into later `@copy` paths, `@remote` blocks, and `@only_if` guards
  as `$VAR` / `${VAR}` / env.
- **Graceful file copies** — `@copy` uses rsync when the target has it (with a
  `mkdir -p` remote wrapper), and automatically falls back to
  `ssh mkdir -p` + `scp` on hosts without rsync. Destination directories are
  always created.
- **Guards & timeouts** — `@only_if <cmd>` skips a block where the
  precondition fails; `--timeout SECS` / `@timeout SECS` kills hung hosts
  (guards included).
- **Lifecycle safety** — Ctrl-C/SIGTERM terminates in-flight children (no
  orphans), prints a summary of completed steps, and exits 130; a preflight
  check fails fast if `bash`/`ssh`/`rsync`/`scp` are missing.
- **Output modes** — `--output grouped` prints each host's logs as one block;
  `--log-file PATH` appends every streamed line (tagged host+stream) for audit.
- **Secrets** — literal `@env KEY=VALUE` values are masked (`***`) in previews,
  trace output, and log files, and never appear in any argv. The `@env KEY`
  passthrough form inherits from shellflow's own environment and is not
  redacted.
- **Encrypted config (`@secrets`)** — `# @secrets file.env.age` decrypts an
  `age`-encrypted env file on the controller, injects every key into the
  block environment, exports the space-separated key list as
  `LT_SECRET_KEYS`, and masks all values in previews/traces/logs. Targets
  never see the decryption identity.
- **Embedded age tooling** — `keys` (generate/public) and `secret`
  (encrypt/decrypt/edit/creds) subcommands manage identities and encrypted env
  files; no `age`/`rage` CLI required on the controller.
- **`deploy` subcommand** — standardized multi-host service deployment from a
  conventional layout (`hosts/inventory.sh`, `services/<svc>/env|units|configs`),
  including per-key `systemd-creds` credential generation on each target.
- **`--local` mode** — run remote blocks and copies on the controller instead
  of over SSH, so playbooks are debuggable without network access or target
  sudo. Output is still streamed through the UI (masked, auditable).

## Install

```bash
cargo install --path bin/shellflow
# or build from the workspace
cargo build --release -p shellflow
```

Requires `bash` on the controller and targets, plus `ssh`/`rsync`/`scp` on the
controller (system tools — your `~/.ssh/config`, keys, agent, and jump hosts
just work). Targets only need `bash`.

## The DSL

A directive is a comment whose first non-whitespace token is `# @`. All other
lines belong to the current block.

| Directive | Syntax | Semantics |
|---|---|---|
| `@server` | `# @server <name> <ssh-spec>` | Alias a host. `<ssh-spec>` = `[user@]host[:port]`, or a `~/.ssh/config` host alias |
| `@group` | `# @group <name> <member>[,<member>…]` | Alias a group of servers |
| `@env` | `# @env <KEY>` / `# @env <KEY>=<value>` | Inject an env var into later blocks; no `=value` copies from shellflow's environment. Literal values are masked in output |
| `@secrets` | `# @secrets <file.env.age> [--identity <PATH>]` | Decrypt an age-encrypted env file at run time; inject keys into later blocks, export the key list as `LT_SECRET_KEYS`, and mask all values. Resolution is a hard error without a usable identity |
| `@local` | `# @local` | Following lines run locally (default) |
| `@remote` | `# @remote <target>` | Following lines stream to the target (alias, group, or raw spec) |
| `@copy` | `# @copy <src> -> <dst> @<target> [--delete]` | Copy a local path to the target (rsync, or scp fallback); creates the destination directory; supports `$VAR` interpolation |
| `@export` | `# @export <VAR>[,<VAR>…]` | Capture variables from the preceding local block into run state |
| `@timeout` | `# @timeout <seconds>` | Per-step timeout for the next block |
| `@name` | `# @name <label>` | Name the next block (for `--only`/`--skip` and reporting) |
| `@only_if` | `# @only_if <command>` | Skip the next block where `<command>` fails |

Key rules:

- Every directive flushes the pending block; blocks with no executable
  statement are dropped.
- Local and remote blocks run with `set -eu` injected (`set -eux` at `-vvv`),
  so a failing command stops the block.
- `@copy` paths are parsed by shellflow, not Bash — use `@export` to capture
  values and reference them as `$VAR`. An unresolved variable is a hard error
  in a real run (and a warning + skip in dry-run/check).
- `@copy` paths must not contain the literal `->`; the target is the last
  whitespace-separated token; paths with spaces are unsupported.
- `@only_if` guards run on each host with the same env as the block.
- Lines inside heredocs are not interpreted as directives.

## CLI

```text
USAGE: shellflow [OPTIONS] [SCRIPT]
       shellflow <COMMAND>

COMMANDS:
  run     Run a deploy script (default; `shellflow deploy.sh` still works)
  keys    Manage age identities (generate, public)
  secret  Encrypt, decrypt, and edit age-encrypted env files
  deploy  Standardized multi-host service deployment

ARGS:
  <SCRIPT>  Deploy script path [default: deploy.sh]

OPTIONS:
  -v, --verbose...            -v info, -vv show commands + payloads,
                              -vvv inject set -x tracing and ssh -v
  -n, --dry-run               Simulate; no writes. Syntax-checks payloads.
  -d, --diff                  Show itemized file changes; implies no writes.
  -t, --target <TARGET>       Restrict to these servers/groups (comma-separated)
  -o, --only <STEP>           Run only matching blocks (by name or 1-based index)
  -s, --skip <STEP>           Skip matching blocks (repeatable)
  -p, --parallel <N>          Max concurrent hosts per step [default: all]
  -c, --continue-on-error     Continue after a failed host/step; print summary
  -k, --check                 Syntax-check only: local bash -n, remote bash -n -s
      --timeout <SECS>        Per-step timeout for all steps
      --output <MODE>         stream (default) | grouped
  -l, --log-file <PATH>       Append streamed lines (tagged host+stream)
      --no-color              Disable ANSI colors
  -i, --identity <PATH>       Age identity for @secrets/deploy decryption
      --mask-min-len <N>      Minimum value length to mask for @secrets [default: 6]
      --local                 Run remote blocks/copies locally (debugging)
  -h, --help                  Print help
  -V, --version               Print version
```

Subcommand details:

```text
shellflow keys generate [-o PATH]         write a new identity (never overwrites)
shellflow keys public [-i PATH]           print the age1... public key
shellflow secret encrypt -r age1... [-o OUT] [FILE]
shellflow secret decrypt [-i PATH] [-o OUT] [FILE]
shellflow secret edit [-i PATH] -r age1... FILE    decrypt -> $EDITOR -> re-encrypt
shellflow secret creds [-i PATH] FILE              print ImportCredential=KEY lines
shellflow deploy <service> [flags]                 deploy one service to a group
```

`deploy <service>` reads a conventional layout (overridable by flags):
`hosts/inventory.sh` for `@server`/`@group`, `services/<service>/env/*.env.age`
(merged lexically), `services/<service>/units/*.service`, and
`services/<service>/configs/*`. It ships binary/units/configs, installs the
`cred-wrap` credential→env wrapper (lets third-party apps that read env vars
run with zero code changes), writes one host-key-bound `systemd-creds`
credential per env key (`/etc/credstore.encrypted/<KEY>`), and reloads/restarts
the units. Shared keys with conflicting values across services are rejected.

Exit codes: `0` success · `1` plan/parse/config error · `2` CLI usage · `3`
transport/setup failure · `4` script execution failure · `130` interrupted.

## Examples

```bash
shellflow playbooks/deploy.sh             # real run against trade + api
shellflow -vv playbooks/deploy.sh         # show every command + payload
shellflow -vvv playbooks/deploy.sh        # set -x + ssh -v live trace
shellflow --dry-run --diff playbooks/deploy.sh  # preview changes, change nothing
shellflow -t api playbooks/deploy.sh      # deploy to a single host
shellflow --only facts playbooks/deploy.sh     # run just one named block
shellflow -k playbooks/deploy.sh          # syntax-check everything
shellflow -c --only ship-marker playbooks/deploy.sh  # copy step, keep going
shellflow --local deploy.sh            # run remote blocks locally for debugging

# Secrets (embedded age; no age/rage CLI needed)
shellflow keys generate -o ~/.config/age/keys.txt
shellflow secret encrypt -r "$(shellflow keys public)" -o prod.env.age < prod.env
shellflow secret edit -r "$(shellflow keys public)" prod.env.age
shellflow secret creds prod.env.age     # -> ImportCredential=KEY lines
shellflow run -i ~/.config/age/keys.txt --local playbook-with-secrets.sh

# Standardized deployment
shellflow deploy web --local --dry-run --diff
shellflow deploy web                    # ship + install + restart (all hosts)
shellflow deploy web -t web-1           # canary a single host
```

[`playbooks/deploy.sh`](playbooks/deploy.sh) is a runnable playbook that
exercises every DSL feature against real `~/.ssh/config` hosts (`trade` and
`api`) — read-only system facts and `/tmp`-confined changes, with parallel
fan-out, guards, timeouts, env passthrough, and secret masking. See
[`docs/design.md`](docs/design.md) for the full design.

## Development

```bash
just setup        # install dev tools (cargo-mutants, shear, sort, typos, rumdl)
just format
just lint         # typos, rumdl, cargo sort, fmt, clippy -D warnings, shear
just test         # cargo test --all-features (unit + proptest + integration)
just mutation     # cargo-mutants — kill surviving mutants
just check-cn     # no CJK in code/comments
```

The integration suite (`bin/shellflow/tests/`) runs the real binary against
mock `ssh`/`rsync`/`scp` shims, so no network is required.

## License

Apache-2.0
