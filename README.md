# ShellFlow

[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/longcipher/shellflow)
[![Context7](https://img.shields.io/badge/Website-context7.com-blue)](https://context7.com/longcipher/shellflow)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/shellflow.svg)](https://pypi.org/project/shellflow/)

![shellflow](https://socialify.git.ci/longcipher/shellflow/image?font=Source+Code+Pro&language=1&name=1&owner=1&pattern=Circuit+Board&theme=Auto)

ShellFlow is a minimal shell script orchestrator for mixed local and remote execution. You write one shell script, mark execution boundaries with comments, and ShellFlow runs each block in order while resolving remote targets from your SSH configuration.

![shellflow-run](assets/shellflow-run.png)

## What It Does

- Split a shell script into `@LOCAL` and `@REMOTE` execution blocks.
- Run each block fail-fast, in order.
- Reuse the shared prelude before the first marker for every block.
- Pass the previous block output forward as `SHELLFLOW_LAST_OUTPUT`.
- Resolve remote targets from `~/.ssh/config` or a custom SSH config path.

## Quick Start

```bash
uv tool install shellflow

shellflow run playbooks/hello.sh
```

## Installation

### User installation (from PyPI)

```bash
uv tool install shellflow
shellflow --version
```

To upgrade to the latest version:

```bash
uv tool upgrade shellflow
```

### Development checkout

```bash
git clone https://github.com/longcipher/shellflow.git
cd shellflow
uv sync --all-groups # uv sync --refresh --reinstall --no-cache
```

### Install as a local tool (from source)

```bash
uv tool install --force .
shellflow --version
```

### Install into the active environment (from source)

```bash
uv pip install -e .
shellflow --version
```

## Script Format

Shellflow recognizes two markers:

- `# @LOCAL`
- `# @REMOTE <ssh-host>`

`<ssh-host>` must match a `Host` entry in your SSH config. Shellflow then connects using that SSH host definition, which means the actual machine can be resolved through the configured `HostName`, `User`, `Port`, and `IdentityFile` values.

Example:

```bash
#!/bin/bash
set -euo pipefail

# @LOCAL
echo "runs locally"

# @REMOTE sui
uname -a

# @LOCAL
echo "remote output: $SHELLFLOW_LAST_OUTPUT"
```

## SSH Configuration

Example `~/.ssh/config` entry:

```sshconfig
Host sui
    HostName 192.168.1.100
    User deploy
    Port 22
    IdentityFile ~/.ssh/id_ed25519
```

With that config, this block is valid:

```bash
# @REMOTE sui
hostname
```

This is intentional:

- Shellflow accepts configured SSH host names, not arbitrary free-form targets.
- Unknown remote targets fail early with a clear error before spawning `ssh`.
- You can override the default config path with `--ssh-config`.

## Execution Model

Each block runs in a fresh shell.

- Shell options from the prelude are copied into every block.
- Shell state like `cd`, shell variables, aliases, and `export` commands does not persist across blocks.
- Explicit context values are passed forward through environment variables.

Example:

```bash
# @LOCAL
echo "build-123"

# @LOCAL
echo "last output = $SHELLFLOW_LAST_OUTPUT"
```

Lines before the first marker are treated as a shared prelude and prepended to every executable block:

```bash
#!/bin/bash
set -euo pipefail

# @LOCAL
echo "prelude is active"

# @REMOTE sui
echo "prelude is also active here"
```

## CLI

```text
shellflow run <script>
shellflow run <script> --verbose
shellflow run <script> --ssh-config ./ssh_config
shellflow --version
```

Examples:

```bash
shellflow run playbooks/hello.sh
shellflow run playbooks/hello.sh -v
shellflow run playbooks/hello.sh --ssh-config ~/.ssh/config.work
```

## Development

Useful commands:

```bash
just sync
just test
just bdd
just test-all
just typecheck
just build
just publish
```

Direct verification commands:

```bash
uv run pytest -q
uv run behave features
uv run ruff check .
uv run ty check src tests
uv build
```

## Release Process

Shellflow supports both local publishing and GitHub Actions release publishing.

### Local publish

```bash
just publish
```

`uv publish` uses standard `uv` authentication mechanisms such as `UV_PUBLISH_TOKEN`, or PyPI trusted publishing when supported by the environment.

### GitHub Actions publish on tag push

The repository includes:

- `.github/workflows/ci.yml` for lint, type-check, test, and build verification.
- `.github/workflows/release.yml` for publishing to PyPI when a tag like `v0.1.0` is pushed.

Recommended release flow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

To use trusted publishing with PyPI:

1. Create a `pypi` environment in GitHub repository settings.
2. Add this repository as a trusted publisher in the PyPI project settings.
3. Push a `v*` tag.

The release workflow then runs verification, builds distributions with `uv build`, and uploads them with `uv publish`.

## Project Layout

```text
shellflow/
├── src/shellflow.py
├── tests/
├── features/
├── playbooks/
├── pyproject.toml
├── Justfile
└── README.md
```

## License

Apache-2.0
