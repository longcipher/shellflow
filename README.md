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
  single `ssh host <login-shell> -s` connection from memory. No per-command
  round trips.
- **Login-shell parity** — remote blocks run under the host's login shell
  (`bash -l -s` / `zsh -l -s`, bash fallback) with the PATH that an
  interactive login would see (rc file `.zshrc`/`.bashrc` probed once per host
  per run, PATH injected into the payload env) — so toolchains installed by
  managers (proto/nvm/rustup/mise) resolve exactly as in a manual `ssh host`,
  without loading interactive rc side effects into scripts.
  `--check`/`--dry-run` stay on plain `bash -n -s`.
- **Deployer-style pipeline** — `@local` build → `@copy` → `@remote` deploy,
  with concurrent multi-host fan-out (`JoinSet` + semaphore, `--parallel`
  defaults to all hosts).
- **Detailed debugging** — `-v` / `-vv` / `-vvv`:
  - `-v`: plan preview + per-step timing.
  - `-vv`: exact `ssh`/`rsync`/`scp` argv, full payload previews, and
    `@only_if` guard evaluations. Every preview is secret-masked, local
    blocks included.
  - `-vvv`: injects `set -x` into every payload and `ssh -v` on the wire, so you
    watch Bash trace lines live (stderr shown yellow, per-host prefixed).
- **Idempotent dry-run & diff** — `--dry-run` / `--diff` syntax-check payloads
  (`bash -n`, remote `bash -n -s`) and itemize file changes via
  `rsync --dry-run -i`. Nothing is written; `--diff` hides status prose and
  shows only the change list. A copy that *cannot* be previewed — the `scp`
  fallback on a host without rsync, or a local `cp` — is skipped with a
  warning instead of being performed: a dry run never writes to a target.
- **State passing** — `@export VAR` captures a variable from a local block and
  injects it into later `@copy` paths, `@remote` blocks, and `@only_if` guards
  as `$VAR` / `${VAR}` / env.
- **Graceful file copies** — `@copy` uses rsync when the target has it (with a
  `mkdir -p` remote wrapper), and automatically falls back to
  `ssh mkdir -p` + `scp` on hosts without rsync. Destination directories are
  always created. `scp` cannot mirror deletions or filter files, so a copy
  step that asked for `--delete` or `--exclude` **fails closed** on such a
  host rather than performing a different transfer than the playbook
  requested. `--allow-unfiltered-copy` accepts the downgrade explicitly (the
  step then warns that the options were dropped). The `scp` fallback has no
  dry-run mode, so under `--dry-run`/`--diff` it is skipped with a warning
  rather than performed.
- **Guards & timeouts** — `@only_if <cmd>` skips a block where the
  precondition fails; `--timeout SECS` / `@timeout SECS` kills hung hosts
  (guards included).
- **Lifecycle safety** — Ctrl-C/SIGTERM terminates in-flight children (no
  orphans), prints a summary of completed steps, and exits 130; a preflight
  check fails fast if `bash`/`ssh`/`rsync`/`scp` are missing.
  Every child runs in its own process group and is torn down with
  `SIGTERM` -> `SIGKILL` after a grace period, so a block's whole process
  tree (`cargo` -> `rustc`, `sleep 300 &`) dies with the step instead of
  lingering as an orphan holding the log pipes open.
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
  never see the decryption identity. Values shorter than the masking
  threshold are not redacted by a global substring replace (that would shred
  unrelated output); instead they are redacted only where they stand alone
  as a token or appear as `KEY=value`, and the run names the affected keys so
  the exemption is never silent. The threshold is `--mask-min-len`, else
  `$SHELLFLOW_MASK_MIN_LEN`, else `6`.
  Redaction is stateful across output lines, so a value that a target program
  split across two lines (`fold`, a pager, a progress bar) is redacted as a
  whole instead of leaking two fragments that reassemble into the original.
  Two residuals are documented rather than implied: redaction is a plaintext
  match, so a base64/hex rendering of a value is never redacted; and the
  decrypted values live in the controller's and the child process's memory
  (visible to the same UID through `/proc/<pid>/environ`, and not
  `mlock`'d) until the run ends.
- **Embedded age tooling** — `keys` (generate/public) and `secret`
  (encrypt/decrypt/edit/creds) subcommands manage identities and encrypted env
  files; no `age`/`rage` CLI required on the controller.
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
| `@secrets` | `# @secrets <file.env.age> [--identity <PATH>]` | Decrypt an age-encrypted env file at run time; inject keys into later blocks, export the key list as `LT_SECRET_KEYS`, and mask all values. Identity precedence is most-specific-wins: the directive's `--identity`, then the run-wide `-i`, then `$SHELLFLOW_AGE_IDENTITY`, then `~/.config/age/keys.txt`. Resolution is a hard error without a usable identity |
| `@local` | `# @local` | Following lines run locally (default) |
| `@remote` | `# @remote <target>` | Following lines stream to the target (alias, group, or raw spec) |
| `@copy` | `# @copy <src> -> <dst> @<target> [--delete] [--exclude <glob>]` | Copy a local path to the target (rsync, or scp fallback); a directory source is flattened into `dst` (contents semantics, identical on GNU rsync and macOS openrsync); supports `$VAR` interpolation; `--exclude` is repeatable and honored by rsync (warned as ignored on the scp fallback and in `--local` mode) |
| `@export` | `# @export <VAR>[,<VAR>…]` | Capture variables from the preceding local block into run state |
| `@timeout` | `# @timeout <seconds>` | Per-step timeout for the next block |
| `@name` | `# @name <label>` | Name the next block (for `--only`/`--skip` and reporting) |
| `@only_if` | `# @only_if <command>` | Skip the next block where `<command>` fails |
| `@wait_active` | `# @wait_active <unit> @<target> [--timeout SECS]` | Poll `systemctl is-active <unit>` until the unit reports active or the budget expires (default 300s). Replaces hand-rolled `for/sleep/ss` loops; a timeout is a script-class failure |
| `@assert` | `# @assert <unit> [@<target>] [<state>]` | Assert the unit's `ActiveState` on the target (default state `active`). The target is inherited from the previous step when it is not given. A failed assertion fails the step |
| `@assert_health` | `# @assert_health <url> [@<target>] [--expect CODES] [--method M] [--body D] [--header H]` | Assert that the URL answers with an accepted HTTP status (any 2xx/3xx by default; `--expect 200,204` or `--expect 2xx,3xx,4xx` to narrow). `--method`/`--body`/`--header` cover endpoints that only answer POST. The probe **waits** (up to the step's timeout) — a service that was just started needs a moment. The target is inherited from the previous step |
| `@assert_port` | `# @assert_port <port>[,<port>…] [@<target>] [--udp]` | Assert that the ports are listening on the target, waiting up to the step's timeout. Replaces the hand-rolled `for i in $(seq 1 12); do ss … ; sleep 5; done` loops. `--udp` checks the UDP sockets |
| `@assert_rendered` | `# @assert_rendered <path> [@<target>]` | Assert that the file exists and holds no unexpanded `${…}` placeholder — a rendered config that still carries a placeholder was never rendered |
| `@assert_no_leak` | `# @assert_no_leak <unit> [@<target>] [--lines N]` | Assert that no credential **value** of the unit's store appears in its journal, its command line, or its environment. Value-based: the target-side helper decrypts the store and compares, so no per-service regular expression is needed and the plaintext never reaches the script or the log |
| `@assert_digest` | `# @assert_digest <path> [@<target>] [--sha256 HEX] [--local PATH]` | Assert that the file matches a digest or the controller's copy of it — a real drift gate |
| `@assert_credstore` | `# @assert_credstore <service> [@<target>]` | Assert that the credential store exists, is `0700`/`0600`, and holds exactly the keys the unit declares |
| `@workdir` | `# @workdir [--prefix NAME]` | Declare the run's remote staging directory (`$WORKDIR`). The controller never creates it, and the target's copy is removed when the run ends |
| `@helper` | `# @helper [@<target>] [--source DIR] [--triple T] [--install-path PATH]` | Build, cache, ship, and atomically install the target-side helper. The build is cached by source revision and target triple, so the second service reuses the first one's build |
| `@backup` | `# @backup <path>… @<target> [--keep N] [--seal] [--dir PATH] [--service S]` | Snapshot the paths for rollback, keep the newest `N`, shred the rest. `--seal` encrypts the snapshot with the host key. The "no plaintext left behind" guarantee is structural — the helper checks the files it wrote |
| `@install` | `# @install <src> -> <dst> @<target> [--mode M] [--owner U:G] [--dir-mode M]` | Install a file on the target **atomically** (write beside the destination, then rename), so a reader never sees a half-written unit file |
| `@credstore` | `# @credstore <service> @<target> [--require KEY,…]` | Seal the service's credential store and check it against the keys the unit declares |
| `@service` | `# @service <unit> @<target> [--enable] [--restart] [--reload] [--wait] [--verify] [--force-start]` | Drive the unit's lifecycle. `--restart` restarts a unit that was **running** and leaves a unit that was not running alone (restarting an inactive unit *starts* it) |
| `@unit_inventory` | `# @unit_inventory [@<target>]` | List the units installed on the target. A report, not a gate |

Consecutive assertions that share a target are **one** step: the whole group
travels in a single SSH round trip, and the operator sees which condition
failed. A *named* assertion (`@name`) is its own step, so it can be selected
on its own with `--only`.

The path/URL of an assertion may name a captured variable
(`/run/${SVC}/config.toml`): it is resolved from the run state, exactly like
a `@copy` path.

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
- `@copy` returns the block mode to `local`: it is a self-contained step, so
  the lines that follow are not streamed to the copy's remote target.
- `@export` binds to the **preceding** local block, even when another
  directive sits between the block and the `@export` line.
- `@only_if` is never evaluated in `--dry-run`/`--check`: the guard is
  reported instead of run, so a preview changes nothing.
- `@only_if` guards run on each host with the same env as the block.
- Lines inside a here-document body are **data, never directives**: a `# @…`
  line inside `cat <<EOF … EOF` is passed through to the block verbatim, so
  generating a unit file or a template can never redirect a block to another
  host. Quoted (`<<'EOF'`, `<<"EOF"`) and backslash-escaped (`<<\EOF`)
  delimiters are tracked exactly; a delimiter the shell expands (`<<$TAG`)
  is not statically knowable and is not tracked. `<<<` is a here-string and
  has no body, so the next line is a directive again.

## CLI

```text
USAGE: shellflow [OPTIONS] [SCRIPT]
       shellflow <COMMAND>

COMMANDS:
  run     Run a deploy script (default; `shellflow deploy.sh` still works)
  keys    Manage age identities (generate, public)
  secret  Encrypt, decrypt, and edit age-encrypted env files

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
  -p, --parallel <N>          Max concurrent hosts per step [default: 16; 0 = all]
  -c, --continue-on-error     Continue after a failed host/step; print summary
  -k, --check                 Syntax-check only: local bash -n, remote bash -n -s
      --timeout <SECS>        Per-step timeout for all steps
      --output <MODE>         stream (default) | grouped
  -l, --log-file <PATH>       Append streamed lines (tagged host+stream)
      --no-color              Disable ANSI colors
  -i, --identity <PATH>       Age identity for @secrets decryption
      --mask-min-len <N>      Minimum value length to mask for @secrets
      --allow-unfiltered-copy Accept the scp fallback dropping --delete/--exclude
      --local                 Run remote blocks/copies locally (debugging)
      --no-ssh-reuse          Do not reuse SSH connections within a run
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
shellflow secret creds [-i PATH] [--store-dir PATH] FILE   print ImportCredential=KEY lines
                                             (--store-dir prints per-service
                                              LoadCredentialEncrypted=KEY:PATH lines)
shellflow template check [-i PATH] <tmpl> <file.env.age>   every ${KEY} in the
                                             template must exist in the env file
shellflow emit cred-env [-o PATH]          print the target-side `cred-env`
                                             bash fallback (export creds /
                                             render templates)
shellflow cred-env exec <cmd> [args…]      [target] export credentials as env
                                             vars, then exec the command
shellflow cred-env render <tmpl> <out>     [target] substitute ${KEY} credential
                                             values into a template (0600)
shellflow cred-env credstore-install <svc> [--store-dir PATH]
                                           [target] clear + re-seal the
                                             per-service credential store
shellflow secret keys-check [-i PATH] <dir>  all <host>.env.age in <dir> must
                                             share the same key set
shellflow unit render <svc> <unit> [--repo PATH] [--output PATH] [--check]
                                          generate the unit's drop-in (the
                                          credential wiring, the render line,
                                          the version status line, and the
                                          shared hardening) from the service
                                          manifest
shellflow unit manifest <svc> <unit> [--repo PATH]
                                          print the service manifest
shellflow unit verify [--repo PATH]      check the repository: the generated
                                          drop-ins are up to date, every
                                          install names a staged file, the
                                          shared hardening reaches every
                                          service that takes it, every
                                          backup runs before the install it
                                          protects
shellflow service init <svc> [--host H]…   scaffold services/<svc>/ +
                                             playbooks/deploy-<svc>.sh (flat
                                             layout, shared-helper unit)
shellflow service check <svc> --host H     read-only audit of a deployed unit
                                             (one ssh round trip): state,
                                             argv/env secrets, credential
                                             wiring, referenced paths,
                                             journal leak scan
shellflow service diff [<svc>] --host H    compare the repository's unit with
        [--local P --remote P]…            the deployed one; exits non-zero on
                                             drift and prints a unified diff
shellflow service manifest --host H       print the sha256 manifest of a
        --path P [--output F]              deployed tree
shellflow service verify --host H         verify a deployed tree against a
        --manifest F                       saved manifest; exits non-zero on
                                             drift
shellflow service status --all           the fleet view: every service of
        [--host H]… [--service S]…        every host the repository
                                             declares, in one table
```

Exit codes: `0` success · `1` plan/parse/config error · `2` CLI usage · `3`
transport/setup failure · `4` script execution failure · `130` interrupted.

## Complete secrets workflow

This section walks through the full lifecycle: from initializing encryption
keys, to encrypting secrets, to deploying them to remote servers.

### 1. Generate an age identity

The first step is to create an age identity (private key). This key lives only
on the controller machine — targets never need it.

```bash
# Generate a new identity (default path: ~/.config/age/keys.txt)
shellflow keys generate

# Or specify a custom output path
shellflow keys generate -o ~/.config/age/my-project-keys.txt

# View the public key (needed for encryption)
shellflow keys public
# -> age1abc123def456...
```

The identity is the master key for every sealed env file the operator owns:
anyone who can read it can decrypt all of them. `keys generate` writes the
file `0600`, and **the loader enforces that too** — a group- or
world-readable identity is refused with an error naming the fix:

```bash
chmod 600 ~/.config/age/keys.txt
```

If a lax mode is deliberate (a key on a shared build agent, for instance),
`SHELLFLOW_ALLOW_UNSAFE_IDENTITY=1` accepts it explicitly.

### 2. Create an encrypted env file

Write your secrets to a plaintext file (one `KEY=VALUE` per line), then encrypt
it with the public key. The plaintext file should never be committed to git.

```bash
# Create a plaintext env file (FOR ILLUSTRATION ONLY — delete after encrypting)
cat > prod.env <<'EOF'
API_KEY=sk-prod-abcdef1234567890
API_SECRET=ss-prod-xyz7890123456789
DB_PASSWORD=db-pass-s3cur3-2024!
LOG_LEVEL=info
EOF

# Encrypt with the public key
shellflow secret encrypt \
  -r "$(shellflow keys public)" \
  -o services/myapp/env/prod.env.age \
  prod.env

# Verify the file is encrypted (binary, unreadable)
head -c 80 services/myapp/env/prod.env.age
# -> age-encrypted...garbage

# Securely delete the plaintext
shred -u prod.env
```

### 3. Debug and inspect encrypted values

View which keys are in an encrypted file without decrypting to disk:

```bash
# Print the ImportCredential=KEY lines (for systemd unit files)
shellflow secret creds services/myapp/env/prod.env.age
# -> ImportCredential=API_KEY
# -> ImportCredential=API_SECRET
# -> ImportCredential=DB_PASSWORD

# Per-service credential store (one sub-directory per service, so deploying
# one service never wipes another service's host-key-bound credentials):
# prints LoadCredentialEncrypted=KEY:/etc/credstore.encrypted/<svc>/KEY lines
shellflow secret creds --store-dir /etc/credstore.encrypted/myapp \
  services/myapp/env/prod.env.age
# -> LoadCredentialEncrypted=API_KEY:/etc/credstore.encrypted/myapp/API_KEY
# -> LoadCredentialEncrypted=API_SECRET:/etc/credstore.encrypted/myapp/API_SECRET
# -> LoadCredentialEncrypted=DB_PASSWORD:/etc/credstore.encrypted/myapp/DB_PASSWORD

# Decrypt to stdout for a quick peek
shellflow secret decrypt services/myapp/env/prod.env.age
# -> API_KEY=sk-prod-abcdef1234567890
# -> API_SECRET=ss-prod-xyz7890123456789
# -> ...

# Edit a value in-place (decrypts, opens $EDITOR, re-encrypts)
# NOTE: --recipients is required to re-encrypt (age is anonymous)
shellflow secret edit \
  -i ~/.config/age/keys.txt \
  -r "$(shellflow keys public)" \
  services/myapp/env/prod.env.age
```

### 4. Use `@secrets` in a playbook

Reference the encrypted file in a playbook with the `@secrets` directive.
shellflow decrypts it at runtime, injects the keys as environment variables,
and masks all values in output.

```bash
#!/usr/bin/env shellflow
# @server trade    trade
# @server api      api
# @group  all      trade,api

# Decrypt and inject secrets (masked in output)
# @secrets services/myapp/env/prod.env.age

# @remote all
# @timeout 120
set -eu
# LT_SECRET_KEYS is automatically exported by @secrets.
# Per-service store: one sub-directory per service keeps deploys from wiping
# another service's credentials (ImportCredential= only reads the flat store).
sudo install -d -m 0700 /etc/credstore.encrypted/myapp
# NOTE: use `tr + read + printenv`, not `for key in $LT_SECRET_KEYS` +
# `${!key}` — the latter are bash-only features and the remote login shell
# may be zsh (word splitting and indirect expansion silently misbehave).
printf '%s\n' "$LT_SECRET_KEYS" | tr ' ' '\n' | while read -r key; do
  [ -n "$key" ] || continue
  printf '%s' "$(printenv "$key")" | sudo systemd-creds encrypt \
    --with-key=host --name="$key" - "/etc/credstore.encrypted/myapp/${key}"
done
sudo systemctl daemon-reload
sudo systemctl restart myapp
```

Run it:

```bash
# Local dry-run to verify
shellflow --dry-run --diff --local -i ~/.config/age/keys.txt playbook.sh

# Real run against all hosts
shellflow -i ~/.config/age/keys.txt playbook.sh

# Single host canary
shellflow -t trade -i ~/.config/age/keys.txt playbook.sh
```

### 5. End-to-end: deploy the secret-app example

The repository includes a complete working example:
[`examples/secret-app/deploy.sh`](examples/secret-app/deploy.sh) deploys the
`secret-app` binary to `api` and `trade` servers (configured in
`~/.ssh/config`).

The demo uses the **cred-env** approach: the shellflow binary installed on the
target (`shellflow cred-env exec`) exports systemd host-key-bound credentials
as environment variables before exec'ing the app. No application code changes
and no per-service starter script — works with any third-party or closed-source
project that reads env vars.

```bash
# 1. Preview the deployment
shellflow --dry-run --diff examples/secret-app/deploy.sh

# 2. Real deployment
shellflow examples/secret-app/deploy.sh

# 3. Verify on a remote host
ssh trade "sudo journalctl -u secret-app.service --no-pager -n 20"
```

Expected output on the target:

```
--- secret-app ---
LOG_LEVEL=info

  API_KEY=sk-p...7890 (len=24)
  API_SECRET=ss-p...6789 (len=24)
  DB_PASSWORD=db-p...024! (len=20)

All secrets present. App is ready.
```

See [`docs/example-app.md`](docs/example-app.md) for
the full detailed walkthrough.

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

# Secrets workflow
shellflow keys generate -o ~/.config/age/keys.txt
shellflow secret encrypt -r "$(shellflow keys public)" -o prod.env.age < prod.env
shellflow secret edit -r "$(shellflow keys public)" prod.env.age
shellflow secret creds prod.env.age
shellflow secret creds --store-dir /etc/credstore.encrypted/myapp prod.env.age
shellflow template check -i ~/.config/age/keys.txt svc.json5.tmpl prod.env.age
shellflow -i ~/.config/age/keys.txt --local playbook-with-secrets.sh

# Full deployment
shellflow examples/secret-app/deploy.sh
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
