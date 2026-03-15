# Shellflow

A minimal shell script orchestrator with SSH support. Shellflow allows you to write shell scripts that execute across local and remote environments using simple comment markers.

## Features

- **Block-based execution**: Use comment markers to define local and remote execution blocks
- **SSH support**: Automatically reads SSH configuration from `~/.ssh/config`
- **Fail-fast execution**: Stops on first error with clear error reporting
- **Context passing**: The previous block output is passed via `SHELLFLOW_LAST_OUTPUT`
- **CLI interface**: Simple command-line tool for running scripts

## Installation

```bash
# Install the package and dependencies
uv sync --all-groups

# Install in development mode
uv pip install -e .
```

## Usage

### Writing Scripts

Shellflow scripts use comment markers to define execution blocks:

```bash
# @LOCAL
echo "Running locally"

# @REMOTE myserver
echo "Running on myserver"

# @LOCAL
echo "Back to local"
```

### Running Scripts

```bash
# Run a script
shellflow run script.sh

# Run with verbose output
shellflow run script.sh --verbose
shellflow run script.sh -v

# Use a non-default SSH config file
shellflow run script.sh --ssh-config ./ssh_config
```

### SSH Configuration

Shellflow reads SSH configuration from `~/.ssh/config`. The following options are supported:

```ssh
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/myserver_key
```

If `paramiko` is installed, it will be used for parsing. Otherwise, a basic parser is used as fallback.

### Execution Model

Blocks are intentionally stateless. Shell state such as `cd`, shell variables, and `export` commands do not persist into the next block. If you need to pass data forward, use the previous block output via `SHELLFLOW_LAST_OUTPUT`:

```bash
# @LOCAL
echo "Step 1 output"

# @LOCAL
echo "Previous output was: $SHELLFLOW_LAST_OUTPUT"
```

Lines before the first marker, such as a shebang or shared shell options, are prepended to every block. That lets you define common guardrails once:

```bash
#!/bin/bash
set -euo pipefail

# @LOCAL
echo "runs with the shared prelude"

# @REMOTE myserver
echo "remote block gets the same prelude"
```

## Testing

### Unit Tests (pytest)

Run unit tests with pytest:

```bash
# Run all tests
just test

# Run specific test file
uv run pytest tests/test_shellflow.py

# Run with coverage
uv run pytest --cov=shellflow --cov-report=term-missing
```

### BDD Tests (behave)

Run acceptance tests with behave:

```bash
# Run BDD tests
just bdd

# Or directly
uv run behave
```

### Running All Tests

```bash
# Run format, lint, test, and BDD
just test-all
```

## Development Commands

```bash
just format      # Format code with ruff
just lint        # Lint with ruff
just test        # Run pytest
just bdd         # Run behave BDD tests
just test-all   # Run format, lint, test, and bdd
just typecheck  # Type check with ty
```

## Project Structure

```text
shellflow/
├── src/shellflow.py    # Main module
├── tests/              # Unit tests
├── features/           # BDD feature files
│   ├── parser.feature
│   └── runner.feature
├── pyproject.toml      # Project configuration
└── README.md
```

## CLI Reference

```text
shellflow run <script>    # Run a shellflow script
shellflow run <script> -v # Run with verbose output
shellflow --version       # Show version
```

## License

Apache-2.0
