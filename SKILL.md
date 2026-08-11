---
name: shellflow
description: >-
  Shell-native, agentless remote automation over ssh — concurrently,
  idempotently, and much faster than Ansible. Use when the user wants to run
  commands or deploy files across one or more servers from a plain Bash
  script annotated with `# @` comment directives, without installing any
  agent on targets. Triggers: "deploy", "run on servers", "run this across
  hosts", "ssh automation", "remote exec", "copy files to servers".
---

# shellflow — shell-native remote automation

shellflow is a shell-native, agentless automation tool that runs commands over
ssh - concurrently, idempotently and 10x faster than ansible.

The input is a **plain Bash script** whose blocks are delimited by `# @`
comment directives. `bash deploy.sh` runs the file unchanged; `shellflow`
drives the blocks: local execution, rsync/scp file copies, and concurrent
remote execution over `ssh host bash -s`. Targets only need `bash`.

## When to use

Reach for `shellflow` (instead of hand-rolling parallel ssh loops, or pulling
in Ansible) when the task is:

- running the same read-only or confined command across several hosts
  (`uname`, `df`, `date`, service status, …),
- shipping a file/artifact to hosts and then acting on it,
- a deploy pipeline: local build → copy artifact → remote restart,
- anything that fits a linear sequence of local/remote/copy blocks.

It does **not** manage persistent config state (no facts/state engine), does
not install agents, and is not a CMDB. Use plain Bash (`if`, `for`,
`[ -f ] ||`, `command -v`) for control flow inside blocks.

## Quick start

```bash
# Build the binary once
cargo build --release -p shellflow
BIN=target/release/shellflow

# Real run, plan preview, live trace, dry-run
$BIN playbooks/deploy.sh
$BIN -v playbooks/deploy.sh
$BIN -vvv playbooks/deploy.sh
$BIN --dry-run --diff playbooks/deploy.sh

# Restrict hosts / steps
$BIN -t api playbooks/deploy.sh
$BIN --only facts playbooks/deploy.sh
$BIN -c --only ship-marker playbooks/deploy.sh
```

## DSL reference

A directive is a comment whose first non-whitespace token is `# @`. All other
lines belong to the current block.

| Directive | Syntax | Semantics |
|---|---|---|
| `@server` | `# @server <name> <ssh-spec>` | Alias a host; `<ssh-spec>` = `[user@]host[:port]` or a `~/.ssh/config` host alias |
| `@group` | `# @group <name> <member>[,<member>…]` | Alias a group of servers |
| `@env` | `# @env <KEY>` / `# @env <KEY>=<value>` | Inject env into later blocks; literal values are masked in output |
| `@secrets` | `# @secrets <file.env.age> [--identity <PATH>]` | Decrypt an age-encrypted env file at run time; inject every key into the block environment, export the space-separated key list as `LT_SECRET_KEYS`, and mask all values. Resolution is a hard error without a usable identity |
| `@local` | `# @local` | Following lines run locally (default) |
| `@remote` | `# @remote <target>` | Following lines stream to the target (alias, group, raw spec) |
| `@copy` | `# @copy <src> -> <dst> @<target> [--delete]` | Copy a local path (rsync, or scp fallback); creates the destination dir; `$VAR` interpolated |
| `@export` | `# @export <VAR>[,<VAR>…]` | Capture variables from the preceding local block into run state |
| `@timeout` | `# @timeout <seconds>` | Per-step timeout for the next block |
| `@name` | `# @name <label>` | Name the next block (for `--only`/`--skip`/reporting) |
| `@only_if` | `# @only_if <command>` | Skip the next block where `<command>` fails |

Behavioral rules to remember:

- Every directive flushes the pending block; comment/blank-only blocks are
  dropped.
- Local and remote blocks get `set -eu` injected (`set -eux` at `-vvv`):
  a failing command stops the block.
- `@copy` paths are parsed by shellflow, not Bash. Capture values with
  `@export` and reference them as `$VAR` / `${VAR}`. Unresolved variables are
  a hard error in a real run, and a warning + skip in `--dry-run`/`--check`.
- `@only_if` guards run per host with the same env as the block; a failed
  guard reports `SKIPPED`.
- `@copy` `src`/`dst` must not contain `->`; the target is the last
  whitespace-separated token; spaces in paths are unsupported.
- Lines inside heredocs are not interpreted as directives.

## Authoring a playbook

Follow the shape of [`playbooks/deploy.sh`](playbooks/deploy.sh): declare
servers/groups, capture a stamp locally with `@export`, ship a marker with
`@copy` (proving interpolation), run read-only facts on every host in
parallel, then use `@only_if`-guarded blocks for checks. Keep remote
mutations confined to `/tmp` unless the user explicitly asks otherwise.

```bash
#!/usr/bin/env shellflow
# @server trade    trade
# @server api      api
# @group  all      trade,api
# @env DEMO_SECRET=shellflow-topsecret   # literal value is masked in output
# @env HOME                              # passthrough from the environment

# @local
STAMP="sf-$(date +%s)"
WORKDIR="/tmp/${STAMP}"
mkdir -p "${WORKDIR}"
# @export STAMP,WORKDIR

# @copy ./playbooks/marker.txt -> $WORKDIR/marker.txt @all

# @remote all
# @timeout 60
set -eu
echo "==> $(uname -a)"
echo "==> ${STAMP} ${WORKDIR}"

# @remote all
# @only_if test -f "$WORKDIR/marker.txt"
cat "${WORKDIR}/marker.txt"
```

## Running safely

- Always run `--dry-run --diff` first on a new playbook.
- Restrict blast radius with `-t <host>` / `--only <step>`.
- Prefer read-only commands (`uname`, `df`, `date`) or `/tmp`-confined
  changes unless the user explicitly requests system mutation.
- Literal `@env KEY=value` values are redacted (`***`) in previews, traces,
  and `--log-file`; use the `@env KEY` passthrough form for values already in
  the environment.
- A hanging host is bounded by `--timeout SECS` / `@timeout SECS` (guards
  included). Ctrl-C/SIGTERM kills in-flight children (no orphans) and exits
  130.

## Troubleshooting

- `exit 3` → transport/setup failure (missing tool, ssh exit 255, copy I/O).
- `exit 4` → a local/remote script failed (see per-host `FAILED` in the
  summary).
- `SKIPPED` → `@only_if` guard failed on that host (check the guard command
  and whether `@export`ed variables are referenced).
- A copy step on a minimal host silently uses the `scp` fallback; `-vv` shows
  which path was taken (`remote rsync: present|missing`).
- Payload previews are masked with `***` where secrets appear — that is
  expected.

## CLI reference

```text
USAGE: shellflow [OPTIONS] [SCRIPT]
       shellflow <COMMAND>

COMMANDS:
  run     Run a deploy script (default)
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
  -p, --parallel <N>          Max concurrent hosts per step [default: all]
  -c, --continue-on-error     Continue after a failed host/step; print summary
  -k, --check                 Syntax-check only: local bash -n, remote bash -n -s
      --timeout <SECS>        Per-step timeout for all steps
      --output <MODE>         stream (default) | grouped
  -l, --log-file <PATH>       Append streamed lines (tagged host+stream)
      --no-color              Disable ANSI colors
  -i, --identity <PATH>       Age identity for @secrets decryption
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
```

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
# LT_SECRET_KEYS is automatically exported by @secrets
for key in $LT_SECRET_KEYS; do
  printf '%s' "${!key}" | sudo systemd-creds encrypt \
    --with-key=host --name="$key" - "/etc/credstore.encrypted/${key}"
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

### 5. End-to-end: deploy demo-secret-app

The repository includes a complete working example:
[`playbooks/deploy-demo.sh`](playbooks/deploy-demo.sh) deploys the
`demo-secret-app` binary to `trade` and `api` servers (configured in
`~/.ssh/config`).

The demo uses the **cred-wrap** approach: systemd host-key-bound credentials
are exported as environment variables by the `cred-wrap` wrapper before
exec'ing the app. No application code changes needed — works with any
third-party or closed-source project that reads env vars.

```bash
# 1. Preview the deployment
shellflow --dry-run --diff playbooks/deploy-demo.sh

# 2. Real deployment
shellflow playbooks/deploy-demo.sh

# 3. Verify on a remote host
ssh trade "sudo journalctl -u demo-secret-app.service --no-pager -n 20"
```

Expected output on the target:

```
--- demo-secret-app ---
LOG_LEVEL=info

  API_KEY=sk-p...7890 (len=24)
  API_SECRET=ss-p...6789 (len=24)
  DB_PASSWORD=db-p...024! (len=20)

All secrets present. App is ready.
```

### 6. Using `@env` for simpler cases

For quick prototyping or when the identity file is not yet set up, use
`@env` with literal values directly in the playbook:

```bash
#!/usr/bin/env shellflow
# @server trade    trade
# @group  all      trade

# Literal values are masked (***) in all output
# @env DEMO_API_KEY=sk-prod-abcdef1234567890
# @env DEMO_API_SECRET=ss-prod-xyz7890123456789

# @remote all
set -eu
printf '%s' "${DEMO_API_KEY}" | sudo systemd-creds encrypt \
  --with-key=host --name=API_KEY - /etc/credstore.encrypted/API_KEY
```

This is simpler but less secure than `@secrets` — the plaintext values are
still visible to anyone who can read the playbook file. Use `@secrets` for
production.

### 7. Security comparison

| Method | Plaintext at rest | Who can read | Best for |
|--------|-------------------|--------------|----------|
| `@env KEY=value` in playbook | In the playbook file | Anyone with file read | Quick prototyping |
| `@secrets file.env.age` | Encrypted with age key | Only identity holder | Production |
| `systemd-creds encrypt --with-key=host` | Bound to host TPM/TPM | Only that host | Runtime secrets |
