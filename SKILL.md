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
remote execution over the host's login shell (`ssh host bash -l -s` /
`zsh -l -s`, probed once per run, with the rc-extended login PATH injected
into each payload so toolchain PATHs resolve as in a manual `ssh host`).
Targets only need `bash`.

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
| `@secrets` | `# @secrets <file.env.age> [--identity <PATH>]` | Decrypt an age-encrypted env file at run time; inject every key into the block environment, export the space-separated key list as `LT_SECRET_KEYS`, and mask all values. Identity precedence: the directive's `--identity`, then run-wide `-i`, then `$SHELLFLOW_AGE_IDENTITY`, then `~/.config/age/keys.txt`. Resolution is a hard error without a usable identity |
| `@local` | `# @local` | Following lines run locally (default) |
| `@remote` | `# @remote <target>` | Following lines stream to the target (alias, group, raw spec) |
| `@copy` | `# @copy <src> -> <dst> @<target> [--delete] [--exclude <glob>]` | Copy a local path (rsync, or scp fallback); creates the destination dir; `$VAR` interpolated; `--exclude` is repeatable and honored by rsync. On a host without rsync the scp fallback cannot filter or mirror, so a step that asked for `--delete`/`--exclude` **fails closed** unless `--allow-unfiltered-copy` accepts the downgrade |
| `@export` | `# @export <VAR>[,<VAR>…]` | Capture variables from the preceding local block into run state |
| `@timeout` | `# @timeout <seconds>` | Per-step timeout for the next block |
| `@name` | `# @name <label>` | Name the next block (for `--only`/`--skip`/reporting) |
| `@only_if` | `# @only_if <command>` | Skip the next block where `<command>` fails |
| `@wait_active` | `# @wait_active <unit> @<target> [--timeout SECS]` | Poll `systemctl is-active` until active or budget expires (default 300s). Replaces hand-rolled `for/sleep/ss` loops; a timeout is a script-class failure |
| `@assert` | `# @assert <unit> [@<target>] [<state>]` | Assert the unit's `ActiveState` (default `active`); the target is inherited from the previous step |
| `@assert_health` | `# @assert_health <url> [@<target>] [--expect CODES] [--method M] [--body D] [--header H]` | Assert the URL answers with an accepted status (any 2xx/3xx by default). The probe **waits** (up to the step's timeout) |
| `@assert_port` | `# @assert_port <port>[,<port>…] [@<target>] [--udp]` | Assert the ports are listening, waiting up to the step's timeout |
| `@assert_port_free` | `# @assert_port_free <port>[,<port>…] [@<target>]` | Assert the ports have no listener. A conflict names the occupant: the listening process, `nft` DNAT rules, and container publish mappings |
| `@assert_enabled` | `# @assert_enabled <unit> <enabled\|disabled\|static\|masked> [@<target>]` | Assert the unit's boot state (`systemctl is-enabled`). Declares the expected state next to the unit so enablement drift fails the deploy |
| `@assert_rendered` | `# @assert_rendered <path> [@<target>]` | Assert the file exists and holds no unexpanded `${…}` placeholder |
| `@assert_no_leak` | `# @assert_no_leak <unit> [@<target>] [--lines N]` | Assert no credential **value** of the unit's store appears in its journal, command line, or environment. Value-based: the helper decrypts the store and compares |
| `@assert_digest` | `# @assert_digest <path> [@<target>] [--sha256 HEX] [--local PATH]` | Assert the file matches a digest or the controller's copy — a real drift gate |
| `@assert_credstore` | `# @assert_credstore <service> [@<target>]` | Assert the credential store is `0700`/`0600` and holds exactly the keys the unit declares |
| `@workdir` | `# @workdir [--prefix NAME]` | Declare the run's remote staging directory (`$WORKDIR`). The controller never creates it; the target's copy is removed when the run ends |
| `@helper` | `# @helper [@<target>] [--source DIR] [--triple T] [--install-path PATH]` | Build, cache, ship, and atomically install the target-side helper. The build is cached by source revision and target triple |
| `@backup` | `# @backup <path>… @<target> [--keep N] [--seal] [--dir PATH] [--service S]` | Snapshot for rollback, keep the newest `N`, shred the rest. `--seal` encrypts with the host key. The "no plaintext left behind" guarantee is structural |
| `@install` | `# @install <src> -> <dst> @<target> [--mode M] [--owner U:G] [--dir-mode M]` | Install on the target **atomically** (write beside the destination, then rename) |
| `@credstore` | `# @credstore <service> @<target> [--require KEY,…]` | Seal the credential store and check it against the unit's declared keys |
| `@service` | `# @service <unit> @<target> [--enable] [--restart] [--reload] [--wait] [--verify] [--force-start]` | Drive the unit's lifecycle. `--restart` restarts a unit that was **running** and leaves a stopped unit alone |
| `@unit_inventory` | `# @unit_inventory [@<target>]` | List the units installed on the target. A report, not a gate |
| `@release` | `# @release <owner/repo> @<target> --installed-cmd CMD --asset PATTERN --to DIR [--base-url URL]` | Track a GitHub release: resolve the newest tag, download the matching asset only on drift, install atomically. `{tag}` = `v`-prefixed tag, `{version}` = tag without `v`. A bare-binary `CMD` is probed with the version-flag chain. `--base-url` overrides the download host for vendor CDNs |
| `@build` | `# @build <repo-url> @<target> --ref REF --build CMD --artifacts A… --install-dirs D… [--prep CMD] [--workdir DIR] [--units U…] [--version-flag F] [--min-free-gb N]` | Build a pinned ref from source on the target: fetch, build natively, probe the fresh binary, back up, install atomically, restart only running units, roll back on restart failure. Artifacts support `path=name` renames. `--workdir` builds inside an existing checkout instead of a fresh clone (for workspaces with cross-repo path deps); no `--force` there |
| `@toolchain` | `# @toolchain <tool,…> @<target>` | Update language toolchains (`os`, `aur`, `rustup`, `cargo`, `go`, `npm`, `pipx`, `uv`, `foundry`, `proto`, `gh`). Per-tool quirks (no-sudo AUR, `uv --all`, anvil-aware foundry) are owned by the runner |
| `@image` | `# @image <image…> @<target> [--prune]` | Pull container images, compare digests, report MOVED/SAME/FAIL. Runtime auto-detected (podman, then docker) |

Behavioral rules to remember:

- Every directive flushes the pending block; comment/blank-only blocks are
  dropped.
- Local and remote blocks get `set -eu` injected (`set -eux` at `-vvv`):
  a failing command stops the block.
- Remote blocks run under the target's login shell, which may be `zsh`.
  `-k` / `--dry-run` lint every block for zsh-unsafe constructs (`for x in
  $VAR` without word splitting, `${!name}`, `${}` literals, assigning to the
  read-only `status`, `local` outside any function, `read` without `-r`) and
  print `zsh-risk`/`shell-risk` warnings next to the `bash -n` result. `bash
  -n` alone cannot catch these — treat warnings as errors before deploying
  to zsh hosts.
- `@copy` paths are parsed by shellflow, not Bash. Capture values with
  `@export` and reference them as `$VAR` / `${VAR}`. Unresolved variables are
  a hard error in a real run, and a warning + skip in `--dry-run`/`--check`.
- `@only_if` guards run per host with the same env as the block; a failed
  guard reports `SKIPPED`.
- `@copy` `src`/`dst` must not contain `->`; the target is the last
  whitespace-separated token; spaces in paths are unsupported.
- Lines inside a here-document body are data, never directives: a `# @…`
  line inside `cat <<EOF … EOF` is passed through verbatim. Quoted/escaped
  delimiters are tracked exactly; an expanded delimiter (`<<$TAG`) is not.
  `<<<` is a here-string with no body, so the next line is a directive.

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
  130. Each child runs in its own process group, torn down `SIGTERM` ->
  `SIGKILL`, so background jobs a block spawned die with the step.

## Troubleshooting

- `exit 3` → transport/setup failure (missing tool, ssh exit 255, copy I/O).
- `exit 4` → a local/remote script failed (see per-host `FAILED` in the
  summary).
- `SKIPPED` → `@only_if` guard failed on that host (check the guard command
  and whether `@export`ed variables are referenced).
- A copy step on a minimal host uses the `scp` fallback; `-vv` shows
  which path was taken (`remote rsync: present|missing`). If the step asked
  for `--delete` or `--exclude`, the fallback **cannot** honour it and the
  step fails (exit 1) rather than shipping excluded files or leaving stale
  ones; install rsync on the target, or pass `--allow-unfiltered-copy` to
  accept the downgrade explicitly. Under `--dry-run`/`--diff` the fallback is
  skipped with a warning — `scp` has no dry-run mode, and a dry run must
  never write to a target.
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
shellflow template render [-i PATH] [--format toml|json|none] <tmpl> <file.env.age>
                                            decrypt + substitute in memory and
                                            validate the output (never prints
                                            values; catches joined lines etc.)
shellflow emit cred-env [-o PATH]         print the target-side `cred-env`
                                            bash fallback (export creds /
                                            render templates)
shellflow cred-env exec <cmd> [args…]     [target] export credentials as env
                                            vars, then exec the command
shellflow cred-env render <tmpl> <out>    [target] substitute ${KEY} credential
                                            values into a template (0600)
shellflow cred-env credstore-install <svc> [--store-dir PATH]
                                          [target] clear + re-seal the
                                            per-service credential store
                                            (self-elevates: call as plain
                                            `sudo …`, never `sudo -E`)
shellflow secret keys-check [-i PATH] <dir>   all <host>.env.age in <dir> must
                                            share the same key set
shellflow secret find-duplicates [-i PATH] [dir]   identical values shared
                                            across files (rotation linkage)
shellflow host service <unit> [--enable] [--restart] [--reload] [--wait]
                             [--verify] [--force-start] [--timeout N]
                                          [target] drive the unit's lifecycle;
                                          a restart never *starts* a unit that
                                          was not running
shellflow host install <src> <dst> [--mode M] [--owner U:G] [--dir-mode M]
                                          [target] atomic install (write beside
                                          the destination, then rename)
shellflow host backup <path>… [--keep N] [--seal] [--dir PATH] [--service S]
                                          [target] snapshot for rollback
shellflow host credstore <svc> [--require KEY,…]
                                          [target] seal the store, check the
                                          key set against the unit
shellflow host assert-no-leak <unit> [--lines N]
                                          [target] value-based leak check
shellflow host assert-digest <path> [--sha256 HEX] [--local PATH]
                                          [target] digest drift gate
shellflow host assert-credstore <svc>
                                          [target] store permissions + key set
shellflow host inventory                [target] list the installed units
shellflow systemd exec --ready-port N [--ready-url U] [--ready-file F]
                         [--timeout N] [--watchdog] [--status TEXT] -- CMD…
                                          [target] supervise a command under a
                                          readiness contract (Type=notify)
shellflow systemd watchdog [--interval N] [--timeout N]
                                          [target] keep the unit's watchdog
                                          alive
shellflow unit render <svc> <unit> [--repo PATH] [--output PATH] [--check]
                                          generate the unit's drop-in from the
                                          service manifest (credential wiring,
                                          render line, version status, shared
                                          hardening); `--check` exits non-zero
                                          when the drop-in is out of date
shellflow unit manifest <svc> <unit> [--repo PATH]
                                          print the service manifest
shellflow unit verify [--repo PATH]      check the repository: the generated
                                          drop-ins are up to date, every
                                          install names a staged file, the
                                          shared hardening reaches every
                                          service that takes it, every
                                          backup runs before the install it
                                          protects
shellflow service init <svc> [--host H]… [--pattern full|exec|no-secret|container|oneshot|no-start|notify|socket] [--timer SCHEDULE]
                                            scaffold services/<svc>/ +
                                            playbooks/deploy-<svc>.sh (flat
                                            layout, shared-helper unit)
shellflow service check <svc> --host H [--journal-lines N]   read-only audit
                                            of the deployed unit (argv/env
                                            leaks, wiring, journal shapes)
shellflow audit [PATH]                  scan the repo for secret-shaped
                                            plaintext (pre-commit gate)
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

The identity is the master key for every sealed env file the operator owns:
anyone who can read it can decrypt all of them. `keys generate` writes the
file `0600`, and the loader enforces that too — a group- or
world-readable identity is refused with an error naming the fix:

```bash
chmod 600 ~/.config/age/keys.txt
```

If a lax mode is deliberate, `SHELLFLOW_ALLOW_UNSAFE_IDENTITY=1` accepts it
explicitly.

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

The block above is the *manual* form: the playbook owns the credential
installation. The recommended form delegates both sides to the shellflow
binary itself — see §4.1.

### 4.1 Target-side helpers: `shellflow cred-env` (no per-service starter scripts)

Third-party apps that only read env vars or config files used to need a
hand-written `bin/<svc>-start` launcher per service. Instead, the deploy
playbook installs the shellflow binary itself on the target once (static musl
build, ~3 MB, idempotent) and every unit references its `cred-env` subcommands
— no service ever ships its own starter, and no shell participates in
credential handling at runtime:

```bash
# Controller, in the playbook's fetch step (cross-compiled for the target):
cargo zigbuild --release -p shellflow --target x86_64-unknown-linux-musl
# …ship target/x86_64-unknown-linux-musl/release/shellflow via @copy, then:
sudo install -m 0755 /tmp/<stamp>/shellflow /usr/local/bin/shellflow

# In the playbook's remote install step — seal the per-service store.
# Call it WITHOUT sudo: the helper probes store writability and re-executes
# itself under `sudo --preserve-env=<exact keys>` only when elevation is
# actually needed (never `sudo -E`).
/usr/local/bin/shellflow cred-env credstore-install <svc>
```

```ini
# services/<svc>/<svc>.service
[Service]
RuntimeDirectory=<svc>
LoadCredentialEncrypted=ZENOH_PASSWORD:/etc/credstore.encrypted/<svc>/ZENOH_PASSWORD

# App needs a config file: render a plaintext template (placeholders only,
# committed to the repo) into tmpfs at start — values never touch disk.
ExecStartPre=/usr/local/bin/shellflow cred-env render \
    /etc/<svc>/<svc>.json5.tmpl /run/<svc>/<svc>.json5

# App reads env vars: export credentials, then exec. No wrapper per service.
ExecStart=/usr/local/bin/shellflow cred-env exec /usr/local/bin/<svc> -c /run/<svc>/<svc>.json5
```

- `cred-env exec <cmd>…` exports every `$CREDENTIALS_DIRECTORY/*` as an env
  var (filename = variable name; invalid names skipped) and execs the command
  (process replacement, so systemd supervision applies to the real program).
  Missing `$CREDENTIALS_DIRECTORY` fails the unit (fail closed).
- `cred-env render <tmpl> <out>` substitutes `${KEY}` placeholders with
  credential values into `<out>` (0600, atomic rename). Substitution is
  literal — values containing `&`, `|`, `$`, quotes or backslashes are
  inserted verbatim. A `${KEY}` without a matching credential aborts the unit
  before anything is written (fail closed).
- `cred-env credstore-install <svc>` clears
  `/etc/credstore.encrypted/<svc>/` and re-seals every key from the
  environment via `systemd-creds encrypt --with-key=host` (replaces the
  hand-written install loop; unset `$LT_SECRET_KEYS` aborts).
- Validate a template against its encrypted env before deploying:
  `shellflow template check -i <identity> services/<svc>/<svc>.json5.tmpl services/<svc>/<host>.env.age`
  (missing keys fail; env keys the template never references are reported as
  notes).
- Render-check it too (catches structural accidents `check` cannot see):
  `shellflow template render -i <identity> --format toml <tmpl> <env.age>`
  (decrypts + substitutes in memory, validates TOML/JSON, prints no values).
- For DB/KV/RPC credentials, verify the candidate against the live backend
  before sealing (`psql … SELECT 1`, RESP `AUTH`+`PING`, authed API probe):
  `systemctl show` proves what is configured, never what works. Seal only
  verified values.
- After deploying, audit the live unit:
  `shellflow service check <svc> --host <alias>`
  (argv/env leaks, credential wiring, journal value shapes).
- Before committing, scan the repo: `shellflow audit .`
  (URL-embedded creds, live assignments, token shapes, PEM blocks).

`shellflow emit cred-env` still prints a pure-bash equivalent of `exec`/`render`
for targets that cannot host the binary — a documented fallback for those two
verbs only (`credstore-install` needs the binary). The fallback fails closed
like the Rust helper on missing keys and non-UTF8 values; error texts differ,
so do not grep for them.

Self-built apps can skip `cred-env` entirely: read
`$CREDENTIALS_DIRECTORY/<KEY>` early in the process (about 10 lines) and point
`ExecStart` straight at the binary.

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

The demo uses the **cred-env** approach: the generic `cred-env` helper
(`shellflow emit cred-env`) exports systemd host-key-bound credentials as
environment variables before exec'ing the app. No application code changes
needed — works with any third-party or closed-source project that reads env
vars, and no per-service starter script to maintain.

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
| `systemd-creds encrypt --with-key=host` | Bound to the host key (`/var/lib/systemd/credential.secret`, root-only; TPM2 optional via `host:tpm2`) | Only that host | Runtime secrets |
