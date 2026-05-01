---
name: shellflow
description: Use when writing or reviewing Shellflow playbooks, especially when mixing # @LOCAL and # @REMOTE blocks, declaring # @option parameters, freezing shared prelude values, using # @TASK/# @MACRO targets, lifecycle hooks, parallel groups, or agent-facing JSON/JSONL output.
---

# Shellflow Playbook Authoring

## Overview

Shellflow playbooks are normal shell scripts with comment markers. The script remains valid shell for humans, while Shellflow uses markers to split execution into isolated local and remote blocks, pass explicit context between blocks, and emit structured results for agents.

Generate ordinary shell first. Then apply Shellflow rules for block boundaries, prelude freezing, remote host resolution, dynamic options, task selection, lifecycle hooks, and agent-safe output.

## When to Use

Use this skill when:

- Writing a new Shellflow playbook.
- Refactoring a shell script into `# @LOCAL` and `# @REMOTE` blocks.
- Reviewing Shellflow parser compatibility.
- Explaining block isolation, prelude behavior, exports, tasks, hooks, or parallel execution.
- Preparing a script for `shellflow run --json`, `--jsonl`, or `agent-run`.

Do not use this skill for:

- Generic bash unrelated to Shellflow.
- Arbitrary SSH orchestration syntaxes that Shellflow does not parse.
- Comma-expanded multi-host syntax inside one `# @REMOTE` marker.
- Embedded workflow logic that belongs in the outer agent.

## Core Rules

### 1. Write normal shell

- Use a regular `.sh` file.
- Keep a shebang when helpful, for example `#!/bin/bash`.
- Put shell safety flags such as `set -euo pipefail` in the prelude only if every block should inherit them.
- Prefer clear, self-contained commands over clever shell state.

### 2. Use supported markers

Top-level markers:

- `# @LOCAL`
- `# @REMOTE <ssh-host>`
- `# @SERVER <name>`
- `# @option <name>[=<default>]`
- `# @TASK <name>`
- `# @MACRO <name> ...` / `# @ENDMACRO`
- `# @HELPER <name>` / `# @ENDHELPER`
- `# @HOOK <type>` / `# @ENDHOOK`

Block directives must appear immediately after `# @LOCAL` or `# @REMOTE <host>`, before command lines:

- `# @TIMEOUT <seconds>`
- `# @RETRY <count>`
- `# @EXPORT NAME=stdout|stderr|output|exit_code`
- `# @SHELL bash|zsh|sh`
- `# @PARALLEL [group]`

Write marker names uppercase even though the parser accepts them case-insensitively.

### 3. Keep block boundaries explicit

Good:

```bash
# @LOCAL
echo "build locally"

# @REMOTE staging
uname -a
```

Bad:

```bash
echo "# @LOCAL"
# marker text inside an echo is just shell output, not a block marker
```

`# @REMOTE <ssh-host>` takes one host alias. Do not write `# @REMOTE web-1,web-2`; create separate remote blocks and mark them `# @PARALLEL` if they should run together.

### 4. Treat each block as a fresh shell

Each block is isolated. Do not rely on these persisting across blocks:

- `cd`
- shell variables
- shell functions defined inside a block
- aliases
- `export` values
- shell options set inside a block

Use `SHELLFLOW_LAST_OUTPUT` or `# @EXPORT` for explicit handoff.

Good:

```bash
# @LOCAL
# @EXPORT ARTIFACT=stdout
mktemp

# @LOCAL
test -n "$ARTIFACT"
printf 'ready\n' > "$ARTIFACT"
```

Bad:

```bash
# @LOCAL
artifact=$(mktemp)

# @LOCAL
printf 'ready\n' > "$artifact"
```

## Shared Prelude and Frozen Values

Lines before the first block marker are the shared prelude. Shellflow prepends non-assignment prelude lines to every executable block.

Uppercase assignments in the prelude are special: Shellflow evaluates them once locally and exports the frozen values into every block.

Good:

```bash
#!/bin/bash
set -euo pipefail

BUILD_ID=$(date +%s)

log() {
  printf '[deploy] %s\n' "$*"
}

# @LOCAL
echo "$BUILD_ID"

# @REMOTE staging
echo "$BUILD_ID"
```

Both blocks receive the same `BUILD_ID`.

Avoid one-time side effects in the prelude, especially if uppercase assignments are present and prelude evaluation will run locally:

```bash
cd /srv/app       # bad in prelude
rm -rf tmp/cache  # bad in prelude
```

Put one-time operations in explicit blocks instead.

## Dynamic Options

Use `# @option` to declare parameters a human or agent must fill.

```bash
# @option staging
# @option branch=main
# @option release-name=
```

Semantics:

- `# @option staging` is boolean. `--staging` sets `STAGING=1`; absent means the variable is unset.
- `# @option branch=main` has a default. `--branch develop` sets `BRANCH=develop`.
- `# @option release-name=` is required. Provide `--release-name v1` or environment variable `RELEASE_NAME`.
- Option names become uppercase environment variables with dashes converted to underscores.
- Unknown dynamic CLI options are parse errors.

CLI:

```bash
shellflow run deploy.sh --branch develop --release-name v2026.05.01 --staging
```

Agent input:

```json
{
  "script": "# @option release-name=\n# @LOCAL\necho \"$RELEASE_NAME\"\n",
  "options": {"release-name": "v2026.05.01"},
  "dry_run": false
}
```

## Tasks and Macros

Use `# @TASK <name>` to label the following block.

```bash
# @TASK build
# @LOCAL
echo "build"

# @TASK deploy
# @REMOTE staging
echo "deploy"
```

Run one task:

```bash
shellflow run deploy.sh --task build
```

Use a single-line macro to define a task flow:

```bash
# @MACRO release build deploy smoke-test
```

Then run:

```bash
shellflow run deploy.sh --task release
```

Rules:

- A `--task` target can be either a task name or a macro name.
- A macro used as a task flow must reference existing task names.
- Unknown task targets must fail parse rather than silently running the whole script.

Macros can also expand command snippets inside blocks:

```bash
# @MACRO print_env
#   env | sort
# @ENDMACRO

# @LOCAL
print_env
```

## Helpers

Helpers are reusable command snippets. They expand when a block line is exactly the helper name.

```bash
# @HELPER backup_db
#   pg_dump "$DATABASE_URL" > backup.sql
# @ENDHELPER

# @LOCAL
backup_db
```

Use helpers for local command reuse. Keep them simple and predictable.

## Lifecycle Hooks

Hooks run locally and share Shellflow context:

- `PRE` runs once before main blocks.
- `BEFORE` runs before each main block.
- `AFTER` runs after each main block.
- `SUCCESS` runs after all main blocks succeed.
- `ERROR` runs after a hook or main block fails.
- `FINISHED` runs at the end for success or failure.

Aliases:

- `POST` means `AFTER`.
- `FINALLY` means `FINISHED`.

Example:

```bash
# @HOOK PRE
#   echo "prepare"
# @ENDHOOK

# @HOOK ERROR
#   echo "collect diagnostics"
# @ENDHOOK

# @HOOK FINISHED
#   echo "cleanup"
# @ENDHOOK
```

Use hooks for setup, cleanup, and diagnostics. Do not hide primary deployment logic in hooks.

## Parallel Execution

`# @PARALLEL` applies only to the next block, or to the current block when used as a block directive.

Mark every block that should be in the parallel group:

```bash
# @PARALLEL web
# @REMOTE web-1
systemctl restart nginx

# @PARALLEL web
# @REMOTE web-2
systemctl restart nginx

# @LOCAL
echo "after the parallel group"
```

Run with:

```bash
shellflow run restart.sh --mode parallel
```

Without `--mode parallel`, annotated blocks still run sequentially. Consecutive parallel blocks form one group. A non-parallel block ends the group.

Parallel blocks receive a copied context. Do not rely on exports produced by one parallel block being available to another parallel block in the same group.

## Remote Hosts

Remote hosts can come from inline `# @SERVER` definitions:

```bash
# @SERVER staging
#   host: 192.168.1.100
#   user: deploy
#   port: 22
#   key: ~/.ssh/id_ed25519

# @REMOTE staging
hostname
```

Or from SSH config:

```sshconfig
Host staging
    HostName 192.168.1.100
    User deploy
    Port 22
    IdentityFile ~/.ssh/id_ed25519
```

Rules:

- `@SERVER` requires a `host` field.
- Inline `key` maps to SSH identity file.
- `# @REMOTE <host>` must resolve before execution.
- Unknown remote hosts fail early.
- Use `--ssh-config <path>` to override `~/.ssh/config`.

## Shells and Remote Tracing

Use `# @SHELL zsh` or `# @SHELL bash` immediately after a remote block marker when the target needs a specific shell.

```bash
# @REMOTE zsh-server
# @SHELL zsh
reload
compdef
```

Shellflow starts remote shells in login mode and quietly bootstraps `~/.zshrc` or `~/.bashrc` for zsh/bash blocks.

Remote command tracing uses a shell `DEBUG` trap and executes the whole block as one native script. This preserves multi-line shell structures:

```bash
# @REMOTE staging
if test -f /srv/app/current; then
  echo "exists"
else
  echo "missing"
fi
```

Do not split multi-line shell syntax into separate blocks.

## Agent-Facing CLI

Useful commands:

```bash
shellflow run script.sh
shellflow run script.sh --json
shellflow run script.sh --jsonl
shellflow run script.sh --no-input
shellflow run script.sh --dry-run
shellflow run script.sh --mode parallel
shellflow run script.sh --task release
shellflow run script.sh --audit-log audit.jsonl --jsonl
shellflow agent-run --json-input '{"script":"# @LOCAL\necho hi\n"}'
shellflow doctor script.sh
```

Use:

- `--json` for one final report.
- `--jsonl` for ordered run/block events.
- `--no-input` for CI and agent runs.
- `--dry-run` to inspect the execution plan.
- `--audit-log` to write redacted JSONL events.
- `doctor [script]` to check install/config status and parse an optional script.

Exit codes:

- `0`: success
- `1`: execution failure
- `2`: parse failure
- `3`: SSH config failure
- `4`: timeout failure

## Authoring Checklist

Before returning a Shellflow playbook, verify:

- It is valid shell plus supported comment markers.
- Block directives appear immediately after the block marker.
- Every block can run independently in a fresh shell.
- Shared prelude has no accidental one-time side effects.
- Uppercase prelude assignments are intended to be frozen once locally.
- Required `# @option name=` values are provided by CLI, env, or agent input.
- Cross-block data uses `SHELLFLOW_LAST_OUTPUT` or `# @EXPORT`.
- Remote targets resolve through `# @SERVER` or SSH config.
- Multi-host work uses separate blocks, not comma hosts.
- Each parallel block is explicitly marked and run with `--mode parallel`.
- Hooks are only for setup, cleanup, success, and failure side effects.
- Agent runs use `--json`, `--jsonl`, or `agent-run` instead of scraping human output.

## Reference Example

```bash
#!/bin/bash
set -euo pipefail

# @option release-name=
# @option branch=main

BUILD_ID=$(date +%Y%m%d%H%M%S)

log() {
  printf '[deploy] %s\n' "$*"
}

# @SERVER staging
#   host: staging.example.com
#   user: deploy

# @HOOK ERROR
#   log "deployment failed for $RELEASE_NAME"
# @ENDHOOK

# @HOOK FINISHED
#   log "finished $RELEASE_NAME"
# @ENDHOOK

# @MACRO release build deploy smoke

# @TASK build
# @LOCAL
# @EXPORT ARTIFACT=stdout
log "building $RELEASE_NAME from $BRANCH"
printf '/tmp/%s-%s.tar.gz\n' "$RELEASE_NAME" "$BUILD_ID"

# @TASK deploy
# @REMOTE staging
# @TIMEOUT 120
log "deploying $ARTIFACT"
test -n "$ARTIFACT"

# @TASK smoke
# @LOCAL
log "smoke test complete for $RELEASE_NAME"
```

Run it:

```bash
shellflow run deploy.sh --task release --release-name v2026.05.01 --branch main --jsonl --no-input
```

## Common Mistakes

- Putting `cd`, `rm`, or deployment commands in the prelude.
- Expecting shell variables from one block to exist in the next block.
- Forgetting required dynamic options.
- Using `# @PARALLEL` once and expecting it to apply to every later block.
- Running parallel annotations without `--mode parallel`.
- Using `# @REMOTE web-1,web-2` instead of separate remote blocks.
- Placing `@TIMEOUT`, `@RETRY`, `@EXPORT`, `@SHELL`, or `@PARALLEL` after commands.
- Using invalid export sources.
- Treating hook commands as remote cleanup; hooks currently run locally.
- Printing noisy output from a block whose stdout is exported into later blocks.
- Forgetting to quote `"$SHELLFLOW_LAST_OUTPUT"` and exported variables.
