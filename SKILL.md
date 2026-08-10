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
