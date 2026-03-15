# Shellflow Agent Instructions

## Project Overview

Shellflow is a minimal shell script orchestrator with SSH support. It allows users to write shell scripts that execute across local and remote environments using simple comment markers.

## Project Structure

```text
shellflow/
├── src/shellflow.py    # Main module with all functionality
├── tests/               # Unit tests (pytest)
├── features/            # BDD acceptance tests (behave)
│   ├── parser.feature
│   ├── runner.feature
│   ├── steps/shellflow_steps.py
│   └── environment.py
├── behave_runner.py     # Wrapper for running behave
├── pyproject.toml       # Project configuration
├── README.md            # Documentation
└── AGENTS.md           # This file
```

## Core Concepts

### Script Block Markers

- `# @LOCAL` - Start a local execution block
- `# @REMOTE <host>` - Start a remote execution block

### Key Modules

- `Block` - Represents an execution block (local or remote)
- `ExecutionContext` - Passes state between block executions
- `ExecutionResult` - Result of executing a single block
- `RunResult` - Result of running a complete script
- `SSHConfig` - SSH configuration for remote hosts

### CLI Commands

```bash
shellflow run <script>    # Run a shellflow script
shellflow run <script> -v # Run with verbose output
shellflow --version       # Show version
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

## Testing

- Unit tests: `pytest` under `tests/`
- BDD tests: `behave` under `features/`
- Run all: `just test-all`

## Dependencies

- Runtime: `paramiko>=3.0.0`
- Dev: `pytest`, `behave`, `ruff`, `ty`, `hypothesis`
