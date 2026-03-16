---
name: shellflow
description: Use when writing or reviewing bash scripts for Shellflow, especially when mixing # @LOCAL and # @REMOTE markers, relying on a shared prelude, passing data through SHELLFLOW_LAST_OUTPUT, or targeting remote hosts resolved from SSH config.
---

# Shellflow Playbook Authoring

## Overview

Shellflow playbooks are standard bash scripts with comment markers that split execution into sequential local and remote blocks.

The agent should generate normal shell code first, then apply Shellflow-specific rules for block boundaries, shared prelude handling, remote host selection, and cross-block data passing.

## When to Use

Use this skill when:

- Writing a new Shellflow playbook.
- Refactoring an existing bash script into `# @LOCAL` and `# @REMOTE` blocks.
- Reviewing whether a script actually matches Shellflow's parser and execution model.
- Explaining why a Shellflow script behaves differently from a single long-running shell session.

Do not use this skill for:

- Generic bash scripting unrelated to Shellflow.
- Arbitrary SSH orchestration syntax that Shellflow does not parse.
- Multi-host fan-out or non-bash execution models.

## Core Rules

### 1. Write a normal bash script

- Use a regular `.sh` file.
- Keep the shebang at the top when it helps editors and humans, for example `#!/bin/bash`.
- Put shell options such as `set -euo pipefail` near the top if every block should inherit them.

### 2. Use only supported block markers

Shellflow recognizes these standalone marker lines:

- `# @LOCAL`
- `# @REMOTE <ssh-host>`

Rules:

- Markers must appear on their own line as comments.
- `@REMOTE` must include exactly one host argument.
- Marker names are uppercase in current Shellflow usage.
- Unknown markers fail parsing.

Good:

```bash
# @LOCAL
echo "build locally"

# @REMOTE staging
uname -a
```

Bad:

```bash
# @remote staging
uname -a

echo "# @LOCAL"
```

## 3. Treat everything before the first marker as shared prelude

Lines before the first marker are prepended to every executable block.

This area is appropriate for:

- Shebangs
- Shell safety flags such as `set -euo pipefail`
- Small helper functions
- Shared constants that should exist in every block

This area is not appropriate for one-time side effects, because they will run once per block:

- `cd some/dir`
- `echo "starting deployment"`
- `export BUILD_ID=$(date +%s)` when you expect a single shared value
- Any command that should happen only once

Good:

```bash
#!/bin/bash
set -euo pipefail

log() {
  printf '[shellflow] %s\n' "$*"
}

# @LOCAL
log "building"
```

Bad:

```bash
#!/bin/bash
cd /srv/app

# @LOCAL
pwd

# @REMOTE staging
pwd
```

Why it is bad: the `cd /srv/app` line becomes part of every block, including remote blocks.

## 4. Use block directives for timeout, retry, and exports

Block directives must appear immediately after the `# @LOCAL` or `# @REMOTE <host>` marker, before any command lines. They configure execution behavior for that specific block.

### Timeout Directive

`# @TIMEOUT <seconds>` - Abort the block if it exceeds the specified duration.

```bash
# @LOCAL
# @TIMEOUT 30
sleep 60
```

### Retry Directive

`# @RETRY <count>` - Retry the block up to N times on failure (0 means no retry).

```bash
# @LOCAL
# @RETRY 3
curl -f https://api.example.com/health
```

### Export Directive

`# @EXPORT NAME=source` - Capture a value from the block result and pass it to subsequent blocks as an environment variable.

Valid sources:

- `stdout` - The block's standard output
- `stderr` - The block's standard error
- `output` - Combined stdout and stderr
- `exit_code` - The block's exit code (as string)

```bash
# @LOCAL
# @EXPORT BUILD_ID=stdout
echo "build-$(date +%s)"

# @LOCAL
echo "Building: $BUILD_ID"
```

You can use multiple exports in a single block:

```bash
# @LOCAL
# @EXPORT STATUS_CODE=exit_code
# @EXPORT RESPONSE=stdout
curl -s -w "%{http_code}" -o response.txt https://api.example.com
```

### Shell Directive

`# @SHELL <shell>` - Specify the shell to use for executing this block.

Use this when targeting remote hosts that use a non-bash default shell (e.g., zsh).

```bash
# @REMOTE zsh-server
# @SHELL zsh
# zsh-specific commands now work
reload
compdef
```

Without `@SHELL`, Shellflow defaults to `bash` for all remote blocks.

## 5. Assume every block runs in a fresh shell

Each block is isolated.

Do not assume these persist into the next block:

- Current working directory
- Shell variables
- `export` values
- Aliases
- Functions defined inside a block
- Shell options set inside a block

Write each block so it can run independently.

Good:

```bash
# @LOCAL
cd /tmp
artifact=$(mktemp)
printf 'ready' > "$artifact"
echo "$artifact"

# @LOCAL
artifact="$SHELLFLOW_LAST_OUTPUT"
test -f "$artifact"
cat "$artifact"
```

Bad:

```bash
# @LOCAL
cd /tmp
artifact=$(mktemp)

# @LOCAL
printf 'ready' > "$artifact"
pwd
```

Why it is bad: `artifact` and the working directory do not persist.

## 6. Use SHELLFLOW_LAST_OUTPUT for explicit handoff

Shellflow passes the previous block's combined output into the next block as `SHELLFLOW_LAST_OUTPUT`.

Guidelines:

- Prefer passing a single path, ID, or compact value.
- Quote it when reading: `"$SHELLFLOW_LAST_OUTPUT"`.
- If the previous block prints multiple lines, expect a multi-line string.
- Do not treat it as structured JSON unless you intentionally emitted JSON in the previous block.

Good:

```bash
# @LOCAL
echo "/tmp/release.tar.gz"

# @REMOTE staging
tar -tf "$SHELLFLOW_LAST_OUTPUT" >/dev/null
```

Better for structured data:

```bash
# @LOCAL
python - <<'PY'
import json
print(json.dumps({"release": "2026.03.15"}))
PY

# @LOCAL
python - <<'PY'
import json
import os
payload = json.loads(os.environ["SHELLFLOW_LAST_OUTPUT"])
print(payload["release"])
PY
```

## 7. Use SSH config host aliases, not ad-hoc targets

`# @REMOTE <ssh-host>` should point to a host that resolves through SSH config.

Prefer:

- `# @REMOTE staging`
- `# @REMOTE production-app`

Avoid assuming Shellflow accepts any arbitrary free-form destination unless it is resolvable by the SSH config in use.

If a remote host is unknown, Shellflow fails before execution.

## 8. Keep blocks self-contained and fail-fast

Shellflow runs blocks in order and stops on the first failure.

Write blocks so that:

- Preconditions are checked inside the block that needs them.
- Cleanup is local to the block when necessary.
- Output is intentional and not noisy when later blocks depend on it.

Prefer this:

```bash
# @REMOTE staging
cd /srv/app
test -f docker-compose.yml
docker compose pull
docker compose up -d
```

Over this:

```bash
# @REMOTE staging
cd /srv/app

# @REMOTE staging
docker compose pull
docker compose up -d
```

Why: the second block cannot rely on the first block's `cd`.

## 9. CLI Options and Output Modes

Shellflow provides several CLI options for different use cases:

### Basic Options

```bash
shellflow run script.sh              # Run a script
shellflow run script.sh -v          # Run with verbose output
shellflow run script.sh --dry-run   # Preview execution plan without running
```

### Structured Output

```bash
shellflow run script.sh --json       # Single JSON report
shellflow run script.sh --jsonl       # Streaming JSON Lines events
```

- `--json`: Outputs a single JSON object with the complete run report
- `--jsonl`: Outputs one JSON object per event (run_started, block_started, block_finished, run_finished)

### Execution Control

```bash
shellflow run script.sh --no-input   # Non-interactive mode (stdin closed)
shellflow run script.sh --ssh-config /path/to/config  # Custom SSH config
```

- `--no-input`: Closes stdin before running blocks; useful for automation
- `--ssh-config`: Override the default SSH config path (`~/.ssh/config`)

### Audit Logging

```bash
shellflow run script.sh --audit-log audit.jsonl --jsonl
```

The `--audit-log` option writes redacted JSON Lines events to a file. Secret-like exports (containing TOKEN, SECRET, or PASSWORD in the name) are automatically redacted to `[REDACTED]`.

## 10. Exit Codes

Shellflow returns distinct exit codes for different failure types:

- `0`: Success
- `1`: General execution failure
- `2`: Parse failure (invalid script syntax)
- `3`: SSH config failure (host not found)
- `4`: Timeout failure (block exceeded timeout)

## Authoring Checklist

Before returning a Shellflow playbook, verify that:

- The script is valid bash without custom DSL syntax.
- Only `# @LOCAL`, `# @REMOTE <host>`, and block directives (`# @TIMEOUT`, `# @RETRY`, `# @EXPORT`, `# @SHELL`) are used.
- Block directives appear immediately after the block marker, before any commands.
- Anything before the first marker is safe to repeat for every block.
- Every block can run independently in a fresh shell.
- Cross-block data uses `SHELLFLOW_LAST_OUTPUT` or `@EXPORT` explicitly.
- Remote targets match the intended SSH host aliases.
- Commands that should happen once are not accidentally placed in the shared prelude.
- Export sources are valid (stdout, stderr, output, exit_code).

## Reference Example

```bash
#!/bin/bash
set -euo pipefail

log() {
  printf '[deploy] %s\n' "$*"
}

# @LOCAL
# @EXPORT BUILD_ID=stdout
log "building artifact"
build_id="build-$(date +%Y%m%d%H%M%S)"
echo "$build_id"

# @LOCAL
# @TIMEOUT 60
# @RETRY 2
log "deploying to staging"
echo "Deploying $BUILD_ID to staging"

# @REMOTE staging
# @EXPORT DEPLOYED_HOST=stdout
log "receiving deployment"
hostname

# @LOCAL
log "deployed to: $DEPLOYED_HOST"
log "build $BUILD_ID complete"
```

## Common Mistakes

- Putting one-time commands before the first marker, then being surprised when they run for every block.
- Expecting `cd`, `export`, or local shell variables from one block to exist in the next block.
- Using an undefined remote host alias.
- Placing block directives after commands instead of immediately after the marker.
- Using invalid export sources (not stdout, stderr, output, or exit_code).
- Forgetting that `@SHELL` must be specified before any commands in the block.
- Forgetting that `@RETRY 0` means no retry attempts.
- Using `@TIMEOUT` with values too small for normal operation.
- Printing extra debug output from a block whose output is consumed by the next block via `@EXPORT`.
- Forgetting to quote `"$SHELLFLOW_LAST_OUTPUT"`.
- Treating Shellflow as a persistent session instead of sequential isolated shells.
