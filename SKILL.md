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

## 4. Assume every block runs in a fresh shell

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

## 5. Use SHELLFLOW_LAST_OUTPUT for explicit handoff

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

## 6. Use SSH config host aliases, not ad-hoc targets

`# @REMOTE <ssh-host>` should point to a host that resolves through SSH config.

Prefer:

- `# @REMOTE staging`
- `# @REMOTE production-app`

Avoid assuming Shellflow accepts any arbitrary free-form destination unless it is resolvable by the SSH config in use.

If a remote host is unknown, Shellflow fails before execution.

## 7. Keep blocks self-contained and fail-fast

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

## Authoring Checklist

Before returning a Shellflow playbook, verify that:

- The script is valid bash without custom DSL syntax.
- Only `# @LOCAL` and `# @REMOTE <host>` are used.
- Anything before the first marker is safe to repeat for every block.
- Every block can run independently in a fresh shell.
- Cross-block data uses `SHELLFLOW_LAST_OUTPUT` explicitly.
- Remote targets match the intended SSH host aliases.
- Commands that should happen once are not accidentally placed in the shared prelude.

## Reference Example

```bash
#!/bin/bash
set -euo pipefail

log() {
  printf '[deploy] %s\n' "$*"
}

# @LOCAL
log "building artifact"
artifact="$(mktemp /tmp/shellflow-release.XXXXXX)"
printf 'release-%s\n' "$(date +%Y%m%d%H%M%S)" > "$artifact"
echo "$artifact"

# @REMOTE staging
cd /srv/app
artifact_path="$SHELLFLOW_LAST_OUTPUT"
log "receiving artifact path $artifact_path"
test -n "$artifact_path"
uname -a

# @LOCAL
log "remote said: $SHELLFLOW_LAST_OUTPUT"
```

## Common Mistakes

- Putting one-time commands before the first marker, then being surprised when they run for every block.
- Expecting `cd`, `export`, or local shell variables from one block to exist in the next block.
- Using an undefined remote host alias.
- Printing extra debug output from a block whose output is consumed by the next block.
- Forgetting to quote `"$SHELLFLOW_LAST_OUTPUT"`.
- Treating Shellflow as a persistent session instead of sequential isolated shells.
