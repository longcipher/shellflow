"""Shellflow - A minimal shell script orchestrator with SSH support.

This module provides a single-file implementation for parsing and executing
shell scripts with local and remote execution blocks. Scripts use comment
markers to define execution blocks:

    # @LOCAL
    echo "Running locally"

    # @REMOTE server1
    echo "Running on server1"

The module supports SSH configuration from ~/.ssh/config and provides
fail-fast execution with clear error reporting.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any, Protocol

# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class Block:
    """Represents a block of commands to execute."""

    target: str  # "LOCAL" or "REMOTE:<host>"
    commands: list[str] = field(default_factory=list)
    source_line: int = 0
    timeout_seconds: int | None = None
    retry_count: int = 0
    exports: dict[str, str] = field(default_factory=dict)
    shell: str | None = None  # Shell to use for execution (e.g., "zsh", "bash")

    @property
    def is_local(self) -> bool:
        """Check if this block runs locally."""
        return self.target == "LOCAL"

    @property
    def is_remote(self) -> bool:
        """Check if this block runs remotely."""
        return self.target.startswith("REMOTE:")

    @property
    def host(self) -> str | None:
        """Get the remote host if this is a remote block."""
        if self.is_remote:
            return self.target.split(":", 1)[1]
        return None


@dataclass
class ExecutionContext:
    """Context passed between block executions."""

    env: dict[str, str] = field(default_factory=dict)
    last_output: str = ""
    success: bool = True

    def to_shell_env(self) -> dict[str, str]:
        """Convert context to environment variables for shell execution."""
        shell_env = os.environ.copy()
        shell_env.update(self.env)
        shell_env["SHELLFLOW_LAST_OUTPUT"] = self.last_output
        return shell_env


@dataclass
class CommandLog:
    """Structured verbose log for one executed command."""

    command: str
    output: str = ""
    exit_code: int | None = None
    status: str = "completed"

    def to_dict(self) -> dict[str, Any]:
        """Serialize one command log for structured output."""
        return {
            "command": self.command,
            "output": self.output,
            "exit_code": self.exit_code,
            "status": self.status,
        }


@dataclass
class ExecutionResult:
    """Result of executing a single block."""

    success: bool
    output: str
    exit_code: int = 0
    error_message: str = ""
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    attempts: int = 1
    timed_out: bool = False
    timeout_seconds: int | None = None
    failure_kind: str | None = None
    no_input: bool = False
    block_id: str = ""
    block_index: int = 0
    source_line: int = 0
    exported_env: dict[str, str] = field(default_factory=dict)
    command_logs: list[CommandLog] = field(default_factory=list)

    def to_dict(self, *, redact_secret_exports: bool = False) -> dict[str, Any]:
        """Serialize the block result for machine-readable output."""
        payload = {
            "block_id": self.block_id,
            "index": self.block_index,
            "source_line": self.source_line,
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "output": self.output,
            "duration_ms": self.duration_ms,
            "attempts": self.attempts,
            "timed_out": self.timed_out,
            "timeout_seconds": self.timeout_seconds,
            "failure_kind": self.failure_kind,
            "no_input": self.no_input,
            "error_message": self.error_message,
            "exported_env": _serialize_exported_env(self.exported_env, redact_secret_exports=redact_secret_exports),
            "command_logs": [command_log.to_dict() for command_log in self.command_logs],
        }
        if redact_secret_exports:
            return _redact_payload_strings(payload, _collect_secret_values(self.exported_env))
        return payload


@dataclass
class ReportEvent:
    """Structured execution event emitted during a run."""

    event: str
    run_id: str
    schema_version: str
    success: bool | None = None
    exit_code: int | None = None
    block_id: str | None = None
    block_index: int | None = None
    target: str | None = None
    host: str | None = None
    source_line: int | None = None
    blocks_executed: int | None = None
    total_blocks: int | None = None
    attempts: int | None = None
    timeout_seconds: int | None = None
    failure_kind: str | None = None
    no_input: bool | None = None
    block: ExecutionResult | None = None

    def to_dict(self, *, redact_secret_exports: bool = False) -> dict[str, Any]:
        """Serialize the event for JSON Lines output."""
        payload: dict[str, Any] = {
            "event": self.event,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
        }
        if self.success is not None:
            payload["success"] = self.success
        if self.exit_code is not None:
            payload["exit_code"] = self.exit_code
        if self.block_id is not None:
            payload["block_id"] = self.block_id
        if self.block_index is not None:
            payload["index"] = self.block_index
        if self.target is not None:
            payload["target"] = self.target
        if self.host is not None:
            payload["host"] = self.host
        if self.source_line is not None:
            payload["source_line"] = self.source_line
        if self.blocks_executed is not None:
            payload["blocks_executed"] = self.blocks_executed
        if self.total_blocks is not None:
            payload["total_blocks"] = self.total_blocks
        if self.attempts is not None:
            payload["attempts"] = self.attempts
        if self.timeout_seconds is not None:
            payload["timeout_seconds"] = self.timeout_seconds
        if self.failure_kind is not None:
            payload["failure_kind"] = self.failure_kind
        if self.no_input is not None:
            payload["no_input"] = self.no_input
        if self.block is not None:
            payload["block"] = self.block.to_dict(redact_secret_exports=redact_secret_exports)
        return payload


@dataclass
class RunResult:
    """Result of running a complete script."""

    success: bool
    blocks_executed: int = 0
    error_message: str = ""
    block_results: list[ExecutionResult] = field(default_factory=list)
    run_id: str = ""
    schema_version: str = "1.0"
    exit_code: int = 0
    failure_kind: str | None = None
    no_input: bool = False
    events: list[ReportEvent] = field(default_factory=list)

    def to_dict(self, *, redact_secret_exports: bool = False) -> dict[str, Any]:
        """Serialize the run report for machine-readable output."""
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "success": self.success,
            "exit_code": self.exit_code,
            "failure_kind": self.failure_kind,
            "no_input": self.no_input,
            "blocks_executed": self.blocks_executed,
            "error_message": self.error_message,
            "blocks": [
                block_result.to_dict(redact_secret_exports=redact_secret_exports) for block_result in self.block_results
            ],
        }


@dataclass
class SSHConfig:
    """SSH configuration for a remote host."""

    host: str
    hostname: str | None = None
    user: str | None = None
    port: int = 22
    identity_file: str | None = None


# =============================================================================
# Exceptions
# =============================================================================


class ShellflowError(Exception):
    """Base exception for Shellflow errors."""


class ParseError(ShellflowError):
    """Exception raised when parsing fails."""


class ExecutionError(ShellflowError):
    """Exception raised when execution fails."""


PACKAGE_NAME = "shellflow"
DEFAULT_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"
EXIT_SUCCESS = 0
EXIT_EXECUTION_FAILURE = 1
EXIT_PARSE_FAILURE = 2
EXIT_SSH_CONFIG_FAILURE = 3
EXIT_TIMEOUT_FAILURE = 4

# Maximum output lines per command for verbose mode
MAX_OUTPUT_LINES = 20
TRACE_MARKER = "__SHELLFLOW_CMD__:"

FAILURE_PARSE = "parse"
FAILURE_RUNTIME = "runtime"
FAILURE_SSH_CONFIG = "ssh_config"
FAILURE_TIMEOUT = "timeout"
VALID_EXPORT_SOURCES = {"stdout", "stderr", "output", "exit_code"}
SECRET_LIKE_ENV_PATTERNS = ("TOKEN", "SECRET", "PASSWORD")

# ANSI color codes
ANSI_RESET = "\033[0m"
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_DIM = "\033[90m"


def _exit_code_for_failure(failure_kind: str | None) -> int:
    """Map a failure category to the stable CLI exit code."""
    mapping = {
        None: EXIT_SUCCESS,
        FAILURE_RUNTIME: EXIT_EXECUTION_FAILURE,
        FAILURE_PARSE: EXIT_PARSE_FAILURE,
        FAILURE_SSH_CONFIG: EXIT_SSH_CONFIG_FAILURE,
        FAILURE_TIMEOUT: EXIT_TIMEOUT_FAILURE,
    }
    return mapping.get(failure_kind, EXIT_EXECUTION_FAILURE)


def _failure_kind_for_result(result: ExecutionResult) -> str | None:
    """Infer the top-level failure category for a block result."""
    if result.success:
        return None
    if result.timed_out:
        return FAILURE_TIMEOUT
    if result.failure_kind is not None:
        return result.failure_kind
    return FAILURE_RUNTIME


def _stringify_subprocess_stream(value: Any) -> str:
    """Convert subprocess output values to text for reporting."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


# =============================================================================
# SSH Config Parser
# =============================================================================


# Global SSH config resolver


def read_ssh_config(host: str) -> SSHConfig | None:
    """Read SSH configuration for a host from ~/.ssh/config.

    Uses SSHConfigResolver with multiple providers (paramiko, basic parsing).

    Args:
        host: The host alias to look up.

    Returns:
        SSHConfig object if found, None otherwise.
    """
    return _ssh_config_resolver.resolve(host)


def _ssh_config_matches_host(ssh_config: Any, host: str) -> bool:
    """Check whether a host matches any explicit Host rule in the SSH config."""
    get_hostnames = getattr(ssh_config, "get_hostnames", None)
    if not callable(get_hostnames):
        return True

    patterns = {pattern for pattern in get_hostnames() if pattern}
    return any(fnmatch.fnmatch(host, pattern) for pattern in patterns)


def _get_ssh_config_path() -> Path:
    """Resolve the SSH config path, allowing environment override."""
    configured_path = os.environ.get("SHELLFLOW_SSH_CONFIG")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path.home() / ".ssh" / "config"


def _parse_ssh_config_basic(config_path: Path, host: str) -> SSHConfig | None:
    """Basic SSH config parser without paramiko.

    Args:
        config_path: Path to the SSH config file.
        host: The host alias to look up.

    Returns:
        SSHConfig object if found, None otherwise.
    """
    sections: list[tuple[list[str], dict[str, Any]]] = []
    current_patterns: list[str] = []
    current_options: dict[str, Any] = {}

    with config_path.open() as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(maxsplit=1)
            if len(parts) < 2:
                continue

            keyword, value = parts[0].lower(), parts[1]

            if keyword == "host":
                if current_patterns:
                    sections.append((current_patterns, current_options))
                current_patterns = value.split()
                current_options = {}
                continue

            if not current_patterns:
                continue

            if keyword == "hostname":
                current_options["hostname"] = value
            elif keyword == "user":
                current_options["user"] = value
            elif keyword == "port":
                current_options["port"] = int(value)
            elif keyword == "identityfile":
                current_options["identityfile"] = value

    if current_patterns:
        sections.append((current_patterns, current_options))

    config: dict[str, Any] = {"host": host}
    matched = False

    for patterns, options in sections:
        if any(fnmatch.fnmatch(host, pattern) for pattern in patterns):
            matched = True
            config.update(options)

    if not matched:
        return None

    return SSHConfig(
        host=config.get("host", host),
        hostname=config.get("hostname"),
        user=config.get("user"),
        port=config.get("port", 22),
        identity_file=config.get("identityfile"),
    )


# =============================================================================
# Script Parser
# =============================================================================


BLOCK_MARKER_RE = re.compile(r"^\s*#\s*@(?P<marker>[A-Z]+)(?:\s+(?P<argument>\S+))?\s*$")
MARKER_PREFIX_RE = re.compile(r"^\s*#\s*@")


def _parse_block_marker(line: str) -> tuple[str, str | None] | None:
    """Parse a line as a shellflow marker if it matches exactly."""
    match = BLOCK_MARKER_RE.match(line)
    if not match:
        return None
    return match.group("marker"), match.group("argument")


def _build_block_commands(prelude: list[str], body: list[str]) -> list[str]:
    """Combine shared prelude with block-specific commands."""
    cleaned_body = _clean_commands(body)
    if not cleaned_body:
        return []
    return [*prelude, *cleaned_body]


def _parse_positive_int(argument: str | None, *, directive: str, line_no: int) -> int:
    """Parse a positive integer directive argument."""
    if argument is None or not argument.isdigit() or int(argument) <= 0:
        raise ParseError(f"Line {line_no}: @{directive} expects a positive integer")
    return int(argument)


def _parse_non_negative_int(argument: str | None, *, directive: str, line_no: int) -> int:
    """Parse a non-negative integer directive argument."""
    if argument is None or not argument.isdigit():
        raise ParseError(f"Line {line_no}: @{directive} expects a non-negative integer")
    return int(argument)


def _parse_export_directive(argument: str | None, *, line_no: int) -> tuple[str, str]:
    """Parse an @EXPORT NAME=source directive."""
    if not argument or "=" not in argument:
        raise ParseError(f"Line {line_no}: @EXPORT expects NAME=source format")

    name, source = argument.split("=", 1)
    name = name.strip()
    source = source.strip()

    if not _is_valid_env_name(name):
        raise ParseError(f"Line {line_no}: @EXPORT expects a valid environment variable name")

    if source not in VALID_EXPORT_SOURCES:
        valid_sources = ", ".join(sorted(VALID_EXPORT_SOURCES))
        raise ParseError(f"Line {line_no}: @EXPORT source is invalid. Valid sources: {valid_sources}")

    return name, source


def _apply_block_directive(block: Block, marker_name: str, marker_argument: str | None, line_no: int) -> None:
    """Apply block-local directive metadata to a block."""
    if marker_name == "TIMEOUT":
        block.timeout_seconds = _parse_positive_int(marker_argument, directive=marker_name, line_no=line_no)
        return
    if marker_name == "RETRY":
        block.retry_count = _parse_non_negative_int(marker_argument, directive=marker_name, line_no=line_no)
        return
    if marker_name == "EXPORT":
        export_name, export_source = _parse_export_directive(marker_argument, line_no=line_no)
        block.exports[export_name] = export_source
        return
    if marker_name == "SHELL":
        if not marker_argument:
            raise ParseError(f"Line {line_no}: @SHELL requires a shell name (e.g., zsh, bash)")
        block.shell = marker_argument
        return
    raise ParseError(f"Line {line_no}: Unknown marker @{marker_name}")


def parse_script(content: str) -> list[Block]:
    """Parse a shell script into execution blocks.

    Parses scripts with comment markers:
        # @LOCAL        - Start a local execution block
        # @REMOTE <host> - Start a remote execution block

    Args:
        content: The script content to parse.

    Returns:
        List of Block objects.

    Raises:
        ParseError: If the script cannot be parsed.
    """
    blocks: list[Block] = []
    current_block: Block | None = None
    accumulated_lines: list[str] = []
    prelude_lines: list[str] = []
    directive_phase = False

    for line_no, line in enumerate(content.splitlines(), 1):
        marker = _parse_block_marker(line)
        if marker:
            marker_name, marker_argument = marker
            if marker_name in {"LOCAL", "REMOTE"}:
                if current_block is None:
                    prelude_lines = _clean_commands(accumulated_lines)
                else:
                    current_block.commands = _build_block_commands(prelude_lines, accumulated_lines)
                    if current_block.commands:
                        blocks.append(current_block)

                accumulated_lines = []
                directive_phase = True

                if marker_name == "LOCAL":
                    current_block = Block(target="LOCAL", source_line=line_no)
                else:
                    if not marker_argument:
                        raise ParseError(f"Line {line_no}: @REMOTE marker missing host")
                    current_block = Block(target=f"REMOTE:{marker_argument}", source_line=line_no)
                continue

            if current_block is not None and directive_phase:
                _apply_block_directive(current_block, marker_name, marker_argument, line_no)
                continue

            raise ParseError(f"Line {line_no}: Unknown marker @{marker_name}")

        if current_block is not None and directive_phase and MARKER_PREFIX_RE.match(line):
            raise ParseError(f"Line {line_no}: Malformed marker syntax")

        accumulated_lines.append(line)
        if current_block is not None and line.strip():
            directive_phase = False

    # Don't forget the last block
    if current_block:
        current_block.commands = _build_block_commands(prelude_lines, accumulated_lines)
        if current_block.commands:
            blocks.append(current_block)

    return blocks


def _clean_commands(lines: list[str]) -> list[str]:
    """Clean accumulated lines into executable commands.

    Removes leading empty lines and common leading whitespace while
    preserving the relative indentation of the commands.

    Args:
        lines: Raw lines accumulated from the script.

    Returns:
        List of cleaned command lines.
    """
    # Remove empty lines from start and end
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]

    if not lines:
        return []

    # Find common leading whitespace (excluding empty lines)
    non_empty_lines = [line for line in lines if line.strip()]
    if not non_empty_lines:
        return []

    common_indent = min(len(line) - len(line.lstrip()) for line in non_empty_lines)

    # Remove common leading whitespace
    return [line[common_indent:] for line in lines]


# =============================================================================
# Execution
# =============================================================================


def _build_executable_script(
    commands: list[str],
    context: ExecutionContext,
    *,
    include_context_exports: bool,
    shell: str | None = None,
) -> str:
    """Build a shell script payload for local or remote execution."""
    script_lines = ["set -e"]
    if include_context_exports:
        script_lines.extend(_build_context_exports(context))
    script_lines.extend(_build_shell_bootstrap(shell))
    script_lines.extend(commands)
    return "\n".join(script_lines)


def _build_shell_bootstrap(shell: str | None) -> list[str]:
    """Build shell-specific bootstrap lines needed for non-interactive automation."""
    if not shell:
        return []

    shell_name = Path(shell).name
    if shell_name == "zsh":
        return [
            "set +x 2>/dev/null || true",
            "test -f ~/.zshrc && { source ~/.zshrc >/dev/null 2>&1 || true; }",
        ]
    if shell_name == "bash":
        return [
            "set +x 2>/dev/null || true",
            "test -f ~/.bashrc && { set +e; . ~/.bashrc >/dev/null 2>&1; set -e; }",
        ]
    return ["set +x 2>/dev/null || true"]


def _build_context_exports(context: ExecutionContext) -> list[str]:
    """Build export statements for explicit shellflow context values only."""
    exports = [f"export SHELLFLOW_LAST_OUTPUT={_quote_shell_value(context.last_output)}"]
    for key, value in context.env.items():
        if _is_valid_env_name(key):
            exports.append(f"export {key}={_quote_shell_value(value)}")
    return exports


def _extract_export_value(result: ExecutionResult, source: str) -> str:
    """Extract an exportable scalar value from a block result."""
    if source == "stdout":
        return result.stdout
    if source == "stderr":
        return result.stderr
    if source == "output":
        return result.output
    if source == "exit_code":
        return str(result.exit_code)
    return ""


def _is_secret_like_env_name(name: str) -> bool:
    """Return whether an export name is likely to contain a secret."""
    upper_name = name.upper()
    return any(pattern in upper_name for pattern in SECRET_LIKE_ENV_PATTERNS)


def _serialize_exported_env(exported_env: dict[str, str], *, redact_secret_exports: bool) -> dict[str, str]:
    """Serialize exported values, optionally redacting obvious secrets."""
    if not redact_secret_exports:
        return dict(exported_env)
    return {key: "[REDACTED]" if _is_secret_like_env_name(key) else value for key, value in exported_env.items()}


def _collect_secret_values(exported_env: dict[str, str]) -> set[str]:
    """Collect secret-like export values that should be redacted from audit sinks."""
    return {value for key, value in exported_env.items() if _is_secret_like_env_name(key) and value}


def _redact_text_value(value: str, secret_values: set[str]) -> str:
    """Redact known secret values from a string payload."""
    redacted = value
    for secret_value in secret_values:
        redacted = redacted.replace(secret_value, "[REDACTED]")
    return redacted


def _redact_payload_strings(payload: Any, secret_values: set[str]) -> Any:
    """Recursively redact secret values from a serialized payload."""
    if not secret_values:
        return payload
    if isinstance(payload, dict):
        return {key: _redact_payload_strings(value, secret_values) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_redact_payload_strings(value, secret_values) for value in payload]
    if isinstance(payload, str):
        return _redact_text_value(payload, secret_values)
    return payload


def _apply_block_exports(block: Block, result: ExecutionResult, context: ExecutionContext) -> dict[str, str]:
    """Apply explicit block exports to the shared execution context."""
    exported_env: dict[str, str] = {}
    for name, source in block.exports.items():
        value = _extract_export_value(result, source)
        context.env[name] = value
        exported_env[name] = value
    return exported_env


def _is_valid_env_name(name: str) -> bool:
    """Check whether a string is a valid shell environment variable name."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))


def _quote_shell_value(value: str) -> str:
    """Quote a value for use in a shell export statement."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return f'"{escaped}"'


def _combine_output(stdout: str, stderr: str) -> str:
    """Combine stdout and stderr into a single trimmed output string."""
    output = stdout.strip()
    error_output = stderr.strip()
    if output and error_output:
        return f"{output}\n{error_output}"
    return output or error_output


def _strip_trace_markers(output: str) -> str:
    """Remove shellflow trace marker lines from captured output."""
    cleaned_lines: list[str] = []
    for line in output.splitlines():
        if TRACE_MARKER in line:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines).strip()


def _iter_display_commands(commands: list[str]) -> list[str]:
    """Return non-empty, non-comment commands suitable for verbose display."""
    return [command for command in commands if command.strip() and not command.lstrip().startswith("#")]


def _format_env_value(value: str) -> str:
    """Format an environment variable value for readable verbose output."""
    escaped = (
        value.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace('"', '\\"')
    )
    return f'"{escaped}"'


def _iter_display_context(context: ExecutionContext) -> list[str]:
    """Return explicit shellflow context values suitable for verbose display."""
    lines: list[str] = []
    if context.last_output:
        lines.append(f"SHELLFLOW_LAST_OUTPUT={_format_env_value(context.last_output)}")
    for key, value in context.env.items():
        if _is_valid_env_name(key):
            lines.append(f"{key}={_format_env_value(value)}")
    return lines


def _truncate_output_lines(output: str, max_lines: int = MAX_OUTPUT_LINES) -> str:
    """Keep only the last maximum number of lines from output."""
    lines = output.splitlines()
    if len(lines) <= max_lines:
        return output
    truncated = lines[-max_lines:]
    remaining = len(lines) - max_lines
    truncated.insert(0, f"... ({remaining} earlier line{'s' if remaining > 1 else ''} truncated)")
    return "\n".join(truncated)


def _parse_remote_command_logs(  # noqa: PLR0915
    output: str,
    *,
    success: bool,
    exit_code: int,
    interrupted: bool = False,
    trailing_error_output: str = "",
) -> list[CommandLog]:
    """Parse delimiter-separated remote output into one journal entry per command."""
    command_logs: list[CommandLog] = []

    # Find the delimiter from the output
    delim = None
    for line in output.splitlines():
        if line.startswith("__SHELLFLOW_START_") and line.endswith("__"):
            candidate = line[len("__SHELLFLOW_START_") : -2]
            if candidate:
                delim = candidate
                break

    if delim is None:
        # Fallback: no delimiters found, treat entire output as one command
        cleaned = _strip_trace_markers(output)
        combined = _combine_output(cleaned, trailing_error_output) if trailing_error_output else cleaned
        if combined:
            command_logs.append(
                CommandLog(
                    command="<remote-command>",
                    output=combined,
                    exit_code=exit_code,
                    status="completed" if success else "failed",
                )
            )
        return command_logs

    start_marker = f"__SHELLFLOW_START_{delim}__"
    end_marker = f"__SHELLFLOW_END_{delim}__"

    # Split output by start markers
    parts = output.split(start_marker)

    for part in parts[1:]:  # Skip text before the first start marker
        ec = None
        lines = part.split("\n")

        # Find end marker and exit code
        output_lines: list[str] = []
        for line in lines:
            if line.strip() == end_marker.strip():
                continue
            if line.startswith("__SHELLFLOW_EXITCODE__"):
                try:
                    ec = int(line[len("__SHELLFLOW_EXITCODE__") :].strip())
                except ValueError:
                    ec = None
                continue
            if line.startswith("__SHELLFLOW_"):
                continue
            output_lines.append(line)

        cleaned_output = "\n".join(output_lines).strip()
        cleaned_output = _strip_trace_markers(cleaned_output)

        command_logs.append(
            CommandLog(
                command="<remote-command>",
                output=cleaned_output,
                exit_code=ec,
                status="completed",
            )
        )

    # Assign proper commands from the block
    # (callers should set command names after parsing)

    # Set status based on overall result
    if command_logs:
        for cl in command_logs[:-1]:
            if cl.exit_code is None:
                cl.exit_code = 0
            cl.status = "completed" if cl.exit_code == 0 else "failed"

        last = command_logs[-1]
        if success:
            last.status = "completed"
            if last.exit_code is None:
                last.exit_code = 0
        elif interrupted:
            last.status = "interrupted"
            if last.exit_code is None:
                last.exit_code = exit_code
        else:
            last.status = "failed"
            if last.exit_code is None:
                last.exit_code = exit_code

    # Append SSH-level stderr to the last command
    if trailing_error_output.strip():
        if command_logs:
            last = command_logs[-1]
            last.output = _combine_output(last.output, trailing_error_output)
        else:
            command_logs.append(
                CommandLog(
                    command="<remote-command>",
                    output=trailing_error_output.strip(),
                    exit_code=exit_code,
                    status="failed",
                )
            )

    return command_logs


def _build_remote_trace_script(block: Block, context: ExecutionContext, shell: str) -> str:
    """Build a remote script with delimiter-based output separation.

    Each command's combined stdout/stderr is wrapped between unique delimiters
    so that the Python caller can cleanly associate output with commands even
    when shell init files produce xtrace noise.
    """
    delimiter = uuid.uuid4().hex[:16]
    script_lines: list[str] = [
        "set +x 2>/dev/null || true",
        f"__SHELLFLOW_DELIM__={delimiter}",
    ]
    script_lines.extend(_build_context_exports(context))
    script_lines.extend(_build_shell_bootstrap(shell))

    for command in block.commands:
        if not command.strip() or command.lstrip().startswith("#"):
            continue
        script_lines.append('echo "__SHELLFLOW_START_${__SHELLFLOW_DELIM__}__"')
        script_lines.append(f"{{ {command} ; }} 2>&1")
        script_lines.append("__SHELLFLOW_EC__=$?")
        script_lines.append('echo "__SHELLFLOW_END_${__SHELLFLOW_DELIM__}__"')
        script_lines.append('echo "__SHELLFLOW_EXITCODE__${__SHELLFLOW_EC__}"')

    return "\n".join(script_lines)


def _run_remote_subprocess(
    ssh_args: list[str],
    remote_script: str,
    *,
    timeout_seconds: int | None,
) -> tuple[str, str, int, bool, bool]:
    """Run an SSH subprocess and preserve partial output on timeout or interruption."""
    process = subprocess.Popen(
        ssh_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    interrupted = False
    timed_out = False

    try:
        stdout, stderr = process.communicate(remote_script, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate()
    except KeyboardInterrupt:
        interrupted = True
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()

    return (
        stdout or "",
        stderr or "",
        process.returncode if process.returncode is not None else -1,
        interrupted,
        timed_out,
    )


def _print_command_logs(command_logs: list[CommandLog], output_tail_lines: int) -> None:
    """Print grouped verbose logs for each command in execution order."""
    DIM = "\033[90m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    for command_log in command_logs:
        print(f"{DIM}$ {command_log.command}{RESET}")
        if command_log.output:
            print(_truncate_output_lines(command_log.output, output_tail_lines))
        if command_log.status == "failed":
            print(f"{RED}exit {command_log.exit_code}{RESET}")
        elif command_log.status == "interrupted":
            print(f"{YELLOW}! Interrupted while running this command{RESET}")


def _execute_single_command(
    command: str,
    context: ExecutionContext,
    shell: str | None,
    no_input: bool,
    is_remote: bool = False,
    host: str | None = None,
    ssh_config: SSHConfig | None = None,
) -> tuple[str, int, str, str]:
    """Execute a single command and return output, exit code, stdout, stderr.

    Returns:
        Tuple of (combined_output, exit_code, stdout, stderr)
    """
    env = context.to_shell_env()
    script_lines = ["set -e"]

    # Add shell bootstrap for non-interactive shells
    if shell:
        script_lines.extend(_build_shell_bootstrap(shell))

    # Add the single command
    script_lines.append(command)

    script = "\n".join(script_lines)

    run_kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "env": env,
    }

    try:
        if is_remote and host:
            # Remote execution via SSH
            ssh_args = ["ssh"]
            if no_input:
                ssh_args.append("-n")

            if ssh_config:
                if ssh_config.port and ssh_config.port != 22:
                    ssh_args.extend(["-p", str(ssh_config.port)])
                if ssh_config.user:
                    ssh_args.extend(["-l", ssh_config.user])
                if ssh_config.identity_file:
                    ssh_args.extend(["-i", str(Path(ssh_config.identity_file).expanduser())])

            ssh_config_path = _get_ssh_config_path()
            if ssh_config_path.exists():
                ssh_args.extend(["-F", str(ssh_config_path)])

            exec_shell = shell or "bash"
            ssh_args.extend(["-o", "BatchMode=yes", host, exec_shell, "-l", "-s", "-e"])

            result = subprocess.run(
                ssh_args,
                input=script,
                capture_output=True,
                text=True,
            )
        # Local execution
        elif no_input:
            result = subprocess.run(
                ["/bin/bash", "-se", "-c", script],
                stdin=subprocess.DEVNULL,
                **run_kwargs,
            )
        else:
            result = subprocess.run(
                ["/bin/bash", "-se"],
                input=script,
                **run_kwargs,
            )

        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        combined = _combine_output(stdout, stderr)
    except subprocess.TimeoutExpired as e:
        stdout = _stringify_subprocess_stream(e.output).strip()
        stderr = _stringify_subprocess_stream(e.stderr).strip()
        combined = _combine_output(stdout, stderr)
        return combined, -1, stdout, stderr
    except (OSError, subprocess.SubprocessError) as e:
        return str(e), -1, "", str(e)
    else:
        return combined, result.returncode, stdout, stderr


def execute_local(
    block: Block,
    context: ExecutionContext,
    no_input: bool = False,
) -> ExecutionResult:
    """Execute a local block.

    Runs the block's commands in a local subprocess with the given context.

    Args:
        block: The block to execute.
        context: The execution context with environment and state.

    Returns:
        ExecutionResult with success status and output.
    """
    if not block.commands:
        return ExecutionResult(success=True, output="")

    script = _build_executable_script(
        block.commands,
        context,
        include_context_exports=False,
    )
    env = context.to_shell_env()
    run_kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "env": env,
    }
    if block.timeout_seconds is not None:
        run_kwargs["timeout"] = block.timeout_seconds

    try:
        if no_input:
            result = subprocess.run(
                ["/bin/bash", "-se", "-c", script],
                stdin=subprocess.DEVNULL,
                **run_kwargs,
            )
        else:
            result = subprocess.run(
                ["/bin/bash", "-se"],
                input=script,
                **run_kwargs,
            )

        return ExecutionResult(
            success=result.returncode == 0,
            output=_combine_output(result.stdout, result.stderr),
            exit_code=result.returncode,
            error_message="" if result.returncode == 0 else f"Exit code: {result.returncode}",
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            timeout_seconds=block.timeout_seconds,
            failure_kind=None if result.returncode == 0 else FAILURE_RUNTIME,
            no_input=no_input,
        )
    except subprocess.TimeoutExpired as e:
        stdout = _stringify_subprocess_stream(e.output).strip()
        stderr = _stringify_subprocess_stream(e.stderr).strip()
        timeout_value = int(e.timeout) if isinstance(e.timeout, int | float) else e.timeout
        return ExecutionResult(
            success=False,
            output=_combine_output(stdout, stderr),
            exit_code=-1,
            error_message=f"Timed out after {timeout_value} second(s)",
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            timeout_seconds=block.timeout_seconds,
            failure_kind=FAILURE_TIMEOUT,
            no_input=no_input,
        )
    except subprocess.SubprocessError as e:
        return ShellflowExceptionHandler.handle_subprocess_error(e, block, no_input)
    except OSError as e:
        return ShellflowExceptionHandler.handle_os_error(e, block, no_input)


def execute_remote(
    block: Block,
    context: ExecutionContext,
    ssh_config: SSHConfig | None,
    no_input: bool = False,
) -> ExecutionResult:
    """Execute a remote block via SSH.

    Builds an SSH command and executes the block's commands on a remote host.

    Args:
        block: The block to execute.
        context: The execution context with environment and state.
        ssh_config: Optional SSH configuration for the remote host.

    Returns:
        ExecutionResult with success status and output.
    """
    if not block.commands:
        return ExecutionResult(success=True, output="")

    host = block.host
    if not host:
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message="No host specified for remote block",
            stdout="",
            stderr="",
            failure_kind=FAILURE_SSH_CONFIG,
            no_input=no_input,
        )

    if ssh_config is None:
        ssh_config = read_ssh_config(host)

    if ssh_config is None:
        ssh_config_path = _get_ssh_config_path()
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=(f"Remote host '{host}' was not found in SSH config: {ssh_config_path}"),
            stdout="",
            stderr="",
            failure_kind=FAILURE_SSH_CONFIG,
            no_input=no_input,
        )

    ssh_args = ["ssh"]
    if no_input:
        ssh_args.append("-n")

    if ssh_config.port and ssh_config.port != 22:
        ssh_args.extend(["-p", str(ssh_config.port)])
    if ssh_config.user:
        ssh_args.extend(["-l", ssh_config.user])
    if ssh_config.identity_file:
        ssh_args.extend(["-i", str(Path(ssh_config.identity_file).expanduser())])

    ssh_config_path = _get_ssh_config_path()
    if ssh_config_path.exists():
        ssh_args.extend(["-F", str(ssh_config_path)])

    shell = block.shell or "bash"
    # Use --no-rcs for zsh or --norc for bash to prevent sourcing initialization files
    if "zsh" in shell:
        ssh_args.extend(["-o", "BatchMode=yes", host, shell, "--no-rcs", "-s", "-e"])
    else:
        ssh_args.extend(["-o", "BatchMode=yes", host, shell, "--norc", "-s", "-e"])
    remote_script = _build_remote_trace_script(block, context, shell)

    try:
        stdout, stderr, exit_code, interrupted, timed_out = _run_remote_subprocess(
            ssh_args,
            remote_script,
            timeout_seconds=block.timeout_seconds,
        )
        cleaned_stdout = _strip_trace_markers(stdout)
        cleaned_stderr = _strip_trace_markers(stderr)
        command_logs = _parse_remote_command_logs(
            stdout,
            success=exit_code == 0 and not interrupted and not timed_out,
            exit_code=exit_code,
            interrupted=interrupted,
            trailing_error_output=cleaned_stderr,
        )

        success = exit_code == 0 and not interrupted and not timed_out
        failure_kind = None if success else FAILURE_RUNTIME
        result_exit_code = exit_code
        error_message = "" if success else f"SSH exit code: {exit_code}"

        if timed_out:
            result_exit_code = -1
            error_message = f"Timed out after {block.timeout_seconds} second(s)"
            failure_kind = FAILURE_TIMEOUT
        elif interrupted:
            error_message = "Interrupted by user"

        return ExecutionResult(
            success=success,
            output=_combine_output(cleaned_stdout, cleaned_stderr),
            exit_code=result_exit_code,
            error_message=error_message,
            stdout=cleaned_stdout,
            stderr=cleaned_stderr,
            timed_out=timed_out,
            timeout_seconds=block.timeout_seconds,
            failure_kind=failure_kind,
            no_input=no_input,
            command_logs=command_logs,
        )
    except subprocess.SubprocessError as e:
        return ShellflowExceptionHandler.handle_subprocess_error(e, block, no_input)
    except OSError as e:
        return ShellflowExceptionHandler.handle_os_error(e, block, no_input)


def _new_run_id() -> str:
    """Create a stable run identifier for structured output."""
    return f"run-{uuid.uuid4().hex}"


def _make_block_id(index: int) -> str:
    """Create a stable block identifier within a run."""
    return f"block-{index}"


def _make_run_started_event(run_id: str, total_blocks: int, *, no_input: bool = False) -> ReportEvent:
    """Build the run-start event."""
    return ReportEvent(
        event="run_started",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        total_blocks=total_blocks,
        no_input=no_input,
    )


def _make_block_started_event(run_id: str, block_id: str, index: int, block: Block, total_blocks: int) -> ReportEvent:
    """Build the block-start event."""
    return ReportEvent(
        event="block_started",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        block_id=block_id,
        block_index=index,
        target=block.target,
        host=block.host,
        source_line=block.source_line,
        total_blocks=total_blocks,
    )


def _make_block_finished_event(run_id: str, result: ExecutionResult, block: Block, total_blocks: int) -> ReportEvent:
    """Build the block-finished event."""
    return ReportEvent(
        event="block_finished",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        success=result.success,
        exit_code=result.exit_code,
        block_id=result.block_id,
        block_index=result.block_index,
        target=block.target,
        host=block.host,
        source_line=result.source_line,
        total_blocks=total_blocks,
        attempts=result.attempts,
        timeout_seconds=result.timeout_seconds,
        failure_kind=_failure_kind_for_result(result),
        no_input=result.no_input,
        block=result,
    )


def _make_block_retrying_event(
    run_id: str,
    block_id: str,
    index: int,
    block: Block,
    total_blocks: int,
    *,
    attempts: int,
    failure_kind: str | None,
) -> ReportEvent:
    """Build the block-retrying event."""
    return ReportEvent(
        event="block_retrying",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        block_id=block_id,
        block_index=index,
        target=block.target,
        host=block.host,
        source_line=block.source_line,
        total_blocks=total_blocks,
        attempts=attempts,
        timeout_seconds=block.timeout_seconds,
        failure_kind=failure_kind,
        no_input=False,
    )


def _make_run_finished_event(
    run_id: str,
    success: bool,
    exit_code: int,
    blocks_executed: int,
    total_blocks: int,
    *,
    failure_kind: str | None = None,
    no_input: bool = False,
) -> ReportEvent:
    """Build the run-finished event."""
    return ReportEvent(
        event="run_finished",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        success=success,
        exit_code=exit_code,
        blocks_executed=blocks_executed,
        total_blocks=total_blocks,
        failure_kind=failure_kind,
        no_input=no_input,
    )


def _make_dry_run_started_event(run_id: str, total_blocks: int, *, no_input: bool = False) -> ReportEvent:
    """Build the dry-run start event."""
    return ReportEvent(
        event="dry_run_started",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        total_blocks=total_blocks,
        no_input=no_input,
    )


def _make_dry_run_block_event(run_id: str, block_id: str, index: int, block: Block, total_blocks: int) -> ReportEvent:
    """Build a dry-run block-plan event."""
    return ReportEvent(
        event="dry_run_block",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        block_id=block_id,
        block_index=index,
        target=block.target,
        host=block.host,
        source_line=block.source_line,
        total_blocks=total_blocks,
    )


def _make_dry_run_finished_event(run_id: str, total_blocks: int, *, no_input: bool = False) -> ReportEvent:
    """Build the dry-run finished event."""
    return ReportEvent(
        event="dry_run_finished",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        success=True,
        exit_code=EXIT_SUCCESS,
        blocks_executed=0,
        total_blocks=total_blocks,
        no_input=no_input,
    )


def _finalize_block_result(result: ExecutionResult, block: Block, index: int, started_at: float) -> ExecutionResult:
    """Attach reporting metadata to a block result."""
    result.block_id = _make_block_id(index)
    result.block_index = index
    result.source_line = block.source_line
    result.timeout_seconds = block.timeout_seconds
    result.duration_ms = max(int((time.perf_counter() - started_at) * 1000), 0)
    return result


# Global executor factory instance


def _execute_block_once(block: Block, context: ExecutionContext, *, no_input: bool) -> ExecutionResult:
    """Execute one block attempt using the executor abstraction."""
    executor = _executor_factory.get_executor(block)
    return executor.execute(block, context, no_input)


def _emit_structured_output_json(run_result: RunResult) -> None:
    """Print a JSON run report."""
    print(json.dumps(run_result.to_dict()))


def _emit_structured_output_jsonl(run_result: RunResult, *, redact_secret_exports: bool = False) -> None:
    """Print JSON Lines events for a run."""
    for event in run_result.events:
        print(json.dumps(event.to_dict(redact_secret_exports=redact_secret_exports)))


def _write_audit_log(path: Path, run_result: RunResult) -> None:
    """Mirror structured JSONL events to an audit log with redaction applied."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(event.to_dict(redact_secret_exports=True)) for event in run_result.events]
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


# =============================================================================
# SSH Configuration Abstraction
# =============================================================================


class SSHConfigProvider(Protocol):
    """Protocol for SSH configuration providers."""
    
    def get_config(self, host: str) -> SSHConfig | None:
        """Get SSH configuration for a host."""
        ...


class ParamikoSSHConfigProvider:
    """SSH config provider using paramiko."""
    
    def get_config(self, host: str) -> SSHConfig | None:
        """Get SSH config using paramiko."""
        ssh_config_path = _get_ssh_config_path()
        if not ssh_config_path.exists():
            return None
        
        try:
            import paramiko
            
            ssh_config = paramiko.SSHConfig()
            with ssh_config_path.open() as handle:
                ssh_config.parse(handle)
            
            if not _ssh_config_matches_host(ssh_config, host):
                return None
            
            lookup = ssh_config.lookup(host)
            if not lookup:
                return None
            
            return SSHConfig(
                host=host,
                hostname=lookup.get("hostname"),
                user=lookup.get("user"),
                port=int(lookup.get("port", 22)),
                identity_file=lookup.get("identityfile", [None])[0]
                if isinstance(lookup.get("identityfile"), list)
                else lookup.get("identityfile"),
            )
        except (AttributeError, ImportError):
            return None


class BasicSSHConfigProvider:
    """Basic SSH config provider without paramiko."""
    
    def get_config(self, host: str) -> SSHConfig | None:
        """Get SSH config using basic parsing."""
        ssh_config_path = _get_ssh_config_path()
        if not ssh_config_path.exists():
            return None
        
        return _parse_ssh_config_basic(ssh_config_path, host)


class SSHConfigResolver:
    """Resolves SSH configuration using multiple providers."""
    
    def __init__(self, providers: list[SSHConfigProvider] | None = None):
        """Initialize resolver with optional providers."""
        self.providers = providers or [
            ParamikoSSHConfigProvider(),
            BasicSSHConfigProvider(),
        ]
    
    def resolve(self, host: str) -> SSHConfig | None:
        """Resolve SSH config for a host using available providers."""
        for provider in self.providers:
            try:
                config = provider.get_config(host)
                if config:
                    return config
            except Exception:
                continue
        return None


_ssh_config_resolver = SSHConfigResolver()


# =============================================================================
# Unified Exception Handling
# =============================================================================


class ShellflowExceptionHandler:
    """Centralized exception handling for Shellflow operations."""
    
    @staticmethod
    def handle_subprocess_error(error: subprocess.SubprocessError, block: Block, no_input: bool) -> ExecutionResult:
        """Handle subprocess execution errors."""
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=str(error),
            stdout="",
            stderr="",
            timeout_seconds=block.timeout_seconds,
            failure_kind=FAILURE_RUNTIME,
            no_input=no_input,
        )
    
    @staticmethod
    def handle_os_error(error: OSError, block: Block, no_input: bool) -> ExecutionResult:
        """Handle OS-level errors."""
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=str(error),
            stdout="",
            stderr="",
            timeout_seconds=block.timeout_seconds,
            failure_kind=FAILURE_RUNTIME,
            no_input=no_input,
        )
    
    @staticmethod
    def handle_timeout(block: Block, no_input: bool) -> ExecutionResult:
        """Handle timeout errors."""
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=f"Timed out after {block.timeout_seconds} second(s)",
            stdout="",
            stderr="",
            timed_out=True,
            timeout_seconds=block.timeout_seconds,
            failure_kind=FAILURE_TIMEOUT,
            no_input=no_input,
        )
    
    @staticmethod
    def handle_ssh_config_error(host: str, block: Block, no_input: bool) -> ExecutionResult:
        """Handle SSH configuration errors."""
        ssh_config_path = _get_ssh_config_path()
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=(f"Remote host '{host}' was not found in SSH config: {ssh_config_path}"),
            stdout="",
            stderr="",
            failure_kind=FAILURE_SSH_CONFIG,
            no_input=no_input,
            timeout_seconds=block.timeout_seconds,
        )


# =============================================================================
# Execution Abstraction
# =============================================================================


class BlockExecutor(Protocol):
    """Protocol for block execution strategies."""
    
    def execute(
        self,
        block: Block,
        context: ExecutionContext,
        no_input: bool = False,
    ) -> ExecutionResult:
        """Execute a block and return the result."""
        ...


class LocalExecutor:
    """Executor for local block execution."""
    
    def execute(
        self,
        block: Block,
        context: ExecutionContext,
        no_input: bool = False,
    ) -> ExecutionResult:
        """Execute a local block."""
        if no_input:
            return execute_local(block, context, no_input=True)
        return execute_local(block, context)


class RemoteExecutor:
    """Executor for remote block execution via SSH."""
    
    def execute(
        self,
        block: Block,
        context: ExecutionContext,
        no_input: bool = False,
    ) -> ExecutionResult:
        """Execute a remote block."""
        host = block.host
        if not host:
            return ExecutionResult(
                success=False,
                output="",
                exit_code=-1,
                error_message="No host specified for remote block",
                stdout="",
                stderr="",
                failure_kind=FAILURE_SSH_CONFIG,
                no_input=no_input,
                timeout_seconds=block.timeout_seconds,
            )
        
        ssh_config = read_ssh_config(host)
        if ssh_config is None:
            ssh_config_path = _get_ssh_config_path()
            return ExecutionResult(
                success=False,
                output="",
                exit_code=-1,
                error_message=(f"Remote host '{host}' was not found in SSH config: {ssh_config_path}"),
                stdout="",
                stderr="",
                failure_kind=FAILURE_SSH_CONFIG,
                no_input=no_input,
                timeout_seconds=block.timeout_seconds,
            )
        
        return execute_remote(block, context, ssh_config, no_input)


class ExecutorFactory:
    """Factory for creating appropriate executors for blocks."""
    
    def __init__(self):
        """Initialize factory."""
        self.remote_executor = RemoteExecutor()
        self.local_executor = LocalExecutor()
    
    def get_executor(self, block):
        """Get appropriate executor for a block."""
        if block.is_local:
            return self.local_executor
        return self.remote_executor


_executor_factory = ExecutorFactory()


# =============================================================================
# Script Runner
# =============================================================================



def _execute_block_commands_sequential(
    block: Block,
    context: ExecutionContext,
    no_input: bool,
    verbose: bool,
    block_index: int,
    total_blocks: int,
    output_tail_lines: int,
) -> ExecutionResult:
    """Execute block commands sequentially, printing output after each command.

    For local blocks, commands are executed one at a time for verbose output.
    For remote blocks, all commands are executed in a single SSH connection
    to preserve execution state (e.g., working directory) between commands.

    Returns:
        ExecutionResult combining all command outputs.
    """
    if verbose:
        _print_block_header(block, block_index, total_blocks)

    commands_to_execute = _iter_display_commands(block.commands)

    if block.is_remote:
        return _execute_remote_block_sequential(
            block,
            context,
            no_input,
            verbose,
            commands_to_execute,
            output_tail_lines,
        )

    return _execute_local_block_sequential(block, context, no_input, verbose, commands_to_execute, output_tail_lines)


def _print_block_header(block: Block, block_index: int, total_blocks: int) -> None:
    """Print block header for verbose output."""
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    if block.is_local:
        print(f"{BLUE}[{block_index}/{total_blocks}] LOCAL{RESET}")
    else:
        host = block.host or "unknown"
        print(f"{YELLOW}[{block_index}/{total_blocks}] REMOTE: {host}{RESET}")


def _execute_remote_block_sequential(
    block: Block,
    context: ExecutionContext,
    no_input: bool,
    verbose: bool,
    commands_to_execute: list[str],
    output_tail_lines: int,
) -> ExecutionResult:
    """Execute remote block commands in a single SSH connection."""
    RED = "\033[91m"
    DIM = "\033[90m"
    RESET = "\033[0m"

    result = _execute_block_once(block, context, no_input=no_input)

    if verbose:
        # Assign actual command names to parsed logs
        if result.command_logs:
            for i, cl in enumerate(result.command_logs):
                if i < len(commands_to_execute):
                    cl.command = commands_to_execute[i]

        # Print each command with its output
        if result.command_logs:
            _print_command_logs(result.command_logs, output_tail_lines)
        else:
            # Fallback: no command logs, just show commands
            for cmd in commands_to_execute:
                print(f"{DIM}$ {cmd}{RESET}")
            if result.output:
                truncated = _truncate_output_lines(result.output, output_tail_lines)
                print(truncated)

    context.last_output = result.output
    context.success = result.success

    if not result.success and verbose:
        print(f"{RED}✗ Command failed with exit code {result.exit_code}{RESET}\n")

    return result


def _build_local_trace_script(block: Block, context: ExecutionContext, shell: str | None) -> str:
    """Build a local script without tracing for clean output.

    For local execution, we execute all commands in a single script without
    tracing to ensure clean output interleaving. Each command's output
    (stdout and stderr) will be shown in order.
    """
    script_lines = ["set -e"]
    script_lines.extend(_build_context_exports(context))
    script_lines.extend(_build_shell_bootstrap(shell))

    # Add all user commands without tracing
    script_lines.extend(block.commands)

    return "\n".join(script_lines)


def _execute_local_block_sequential(
    block: Block,
    context: ExecutionContext,
    no_input: bool,
    verbose: bool,
    commands_to_execute: list[str],
    output_tail_lines: int,
) -> ExecutionResult:
    """Execute local block as a single script for proper multi-line command handling."""
    RED = "\033[91m"
    DIM = "\033[90m"
    RESET = "\033[0m"

    # Print all commands before executing (for verbose mode)
    if verbose:
        for cmd in commands_to_execute:
            print(f"{DIM}$ {cmd}{RESET}")

    # Execute the entire block as a single script
    result = _execute_block_once(block, context, no_input=no_input)

    # Print output if verbose
    if verbose and result.output:
        truncated = _truncate_output_lines(result.output, output_tail_lines)
        print(truncated)

    # Print exit code if failed
    if not result.success and verbose:
        print(f"{RED}exit {result.exit_code}{RESET}")

    # Update context
    context.last_output = result.output
    context.success = result.success

    return result


def _get_verbose_colors() -> dict[str, str]:
    """Get ANSI color codes for verbose output."""
    return {
        "GREEN": "\033[92m",
        "RED": "\033[91m",
        "BLUE": "\033[94m",
        "YELLOW": "\033[93m",
        "DIM": "\033[90m",
        "RESET": "\033[0m",
    }


def _execute_dry_run(
    blocks: list[Block],
    run_id: str,
    total_blocks: int,
    no_input: bool,
    verbose: bool,
    colors: dict[str, str],
) -> RunResult:
    """Execute dry run - preview execution plan without running commands."""
    events = [_make_dry_run_started_event(run_id, total_blocks, no_input=no_input)]
    
    for i, block in enumerate(blocks, 1):
        block_id = _make_block_id(i)
        events.append(_make_dry_run_block_event(run_id, block_id, i, block, total_blocks))
        if verbose:
            if block.is_local:
                print(f"{colors['BLUE']}[plan {i}/{len(blocks)}] LOCAL{colors['RESET']}")
            else:
                host = block.host or "unknown"
                print(f"{colors['YELLOW']}[plan {i}/{len(blocks)}] REMOTE: {host}{colors['RESET']}")
            for command in _iter_display_commands(block.commands):
                print(f"{colors['DIM']}$ {command}{colors['RESET']}")
    
    events.append(_make_dry_run_finished_event(run_id, total_blocks, no_input=no_input))
    return RunResult(
        success=True,
        blocks_executed=0,
        block_results=[],
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        exit_code=EXIT_SUCCESS,
        no_input=no_input,
        events=events,
    )


def _execute_block_with_sequential_output(
    block: Block,
    context: ExecutionContext,
    no_input: bool,
    verbose: bool,
    block_index: int,
    total_blocks: int,
    output_tail_lines: int,
    colors: dict[str, str],
    events: list[ReportEvent] | None = None,
    run_id: str | None = None,
) -> ExecutionResult:
    """Execute block with sequential per-command output (verbose mode)."""
    # Print context before executing
    for env_line in _iter_display_context(context):
        print(f"{colors['DIM']}@env {env_line}{colors['RESET']}")
    
    # Use sequential execution with per-command output
    attempt_count = 0
    max_attempts = block.retry_count + 1
    result: ExecutionResult | None = None
    
    while True:
        attempt_count += 1
        started_at = time.perf_counter()
        
        result = _execute_block_commands_sequential(
            block,
            context,
            no_input,
            verbose,
            block_index,
            total_blocks,
            output_tail_lines,
        )
        result = _finalize_block_result(result, block, block_index, started_at)
        result.attempts = attempt_count
        
        if result.success or result.timed_out or attempt_count >= max_attempts:
            break
        
        # Emit retry event
        if events is not None and run_id is not None:
            from shellflow import _failure_kind_for_result
            events.append(
                _make_block_retrying_event(
                    run_id,
                    _make_block_id(block_index),
                    block_index,
                    block,
                    total_blocks,
                    attempts=attempt_count,
                    failure_kind=_failure_kind_for_result(result),
                )
            )
        
        if verbose:
            print(f"{colors['YELLOW']}↻ Retrying attempt {attempt_count + 1}/{max_attempts}{colors['RESET']}")
    
    # Print success/failure status
    if result and result.success:
        print(f"{colors['GREEN']}✓ Success{colors['RESET']}\n")
    elif result:
        print(f"{colors['RED']}✗ Failed: {result.error_message}{colors['RESET']}\n")
    
    return result


def _execute_block_standard(
    block: Block,
    context: ExecutionContext,
    no_input: bool,
    verbose: bool,
    block_index: int,
    total_blocks: int,
    output_tail_lines: int,
    colors: dict[str, str],
    events: list[ReportEvent],
    run_id: str,
) -> ExecutionResult:
    """Execute block using standard execution path."""
    # Print block info if verbose
    if verbose:
        if block.is_local:
            print(f"{colors['BLUE']}[{block_index}/{total_blocks}] LOCAL{colors['RESET']}")
        else:
            host = block.host or "unknown"
            print(f"{colors['YELLOW']}[{block_index}/{total_blocks}] REMOTE: {host}{colors['RESET']}")
        for env_line in _iter_display_context(context):
            print(f"{colors['DIM']}@env {env_line}{colors['RESET']}")
        for command in _iter_display_commands(block.commands):
            print(f"{colors['DIM']}$ {command}{colors['RESET']}")
    
    # Execute the block, retrying only bounded runtime failures
    attempt_count = 0
    max_attempts = block.retry_count + 1
    result: ExecutionResult | None = None
    
    while True:
        attempt_count += 1
        started_at = time.perf_counter()
        result = _execute_block_once(block, context, no_input=no_input)
        result = _finalize_block_result(result, block, block_index, started_at)
        result.attempts = attempt_count
        
        if result.success or result.timed_out or attempt_count >= max_attempts:
            break
        
        # Emit retry event
        events.append(
            _make_block_retrying_event(
                run_id,
                _make_block_id(block_index),
                block_index,
                block,
                total_blocks,
                attempts=attempt_count,
                failure_kind=_failure_kind_for_result(result),
            )
        )
        
        if verbose:
            print(f"{colors['YELLOW']}↻ Retrying attempt {attempt_count + 1}/{max_attempts}{colors['RESET']}")
    
    # Print output if verbose
    if verbose:
        if result and result.output:
            truncated = _truncate_output_lines(result.output, output_tail_lines)
            print(truncated)
        if result and result.success:
            print(f"{colors['GREEN']}✓ Success{colors['RESET']}\n")
        elif result:
            print(f"{colors['RED']}✗ Failed: {result.error_message}{colors['RESET']}\n")
    
    return result


def run_script(  # noqa: PLR0915
    blocks: list[Block],
    verbose: bool = False,
    no_input: bool = False,
    dry_run: bool = False,
    sequential_output: bool = True,  # New parameter for sequential output
    output_tail_lines: int = MAX_OUTPUT_LINES,
) -> RunResult:
    """Run a list of blocks sequentially.

    Executes each block in order, updating the execution context between
    blocks. Fails fast on any error.

    Args:
        blocks: List of blocks to execute.
        verbose: Whether to print progress information.
        sequential_output: Whether to print command output sequentially after each command.

    Returns:
        RunResult with success status and execution info.
    """
    context = ExecutionContext()
    blocks_executed = 0
    block_results: list[ExecutionResult] = []
    run_id = _new_run_id()
    total_blocks = len(blocks)
    
    # ANSI color codes for verbose output
    colors = _get_verbose_colors()
    
    if dry_run:
        return _execute_dry_run(
            blocks, run_id, total_blocks, no_input, verbose, colors
        )
    
    events = [_make_run_started_event(run_id, total_blocks, no_input=no_input)]
    
    for i, block in enumerate(blocks, 1):
        block_id = _make_block_id(i)
        events.append(_make_block_started_event(run_id, block_id, i, block, total_blocks))
        
        # Execute the block
        if sequential_output and verbose:
            result = _execute_block_with_sequential_output(
                block, context, no_input, verbose, i, len(blocks), 
                output_tail_lines, colors, events, run_id
            )
        else:
            result = _execute_block_standard(
                block, context, no_input, verbose, i, len(blocks),
                output_tail_lines, colors, events, run_id
            )
        
        result = _finalize_block_result(result, block, i, time.perf_counter())
        blocks_executed += 1
        block_results.append(result)
        events.append(_make_block_finished_event(run_id, result, block, total_blocks))
        
        # Update context
        context.last_output = result.output
        context.success = result.success
        result.exported_env = _apply_block_exports(block, result, context)
        
        # Fail fast on error
        if not result.success:
            failure_kind = _failure_kind_for_result(result)
            exit_code = _exit_code_for_failure(failure_kind)
            events.append(
                _make_run_finished_event(
                    run_id,
                    success=False,
                    exit_code=exit_code,
                    blocks_executed=blocks_executed,
                    total_blocks=total_blocks,
                    failure_kind=failure_kind,
                    no_input=no_input,
                )
            )
            return RunResult(
                success=False,
                blocks_executed=blocks_executed,
                error_message=f"Block {i} failed: {result.error_message}",
                block_results=block_results,
                run_id=run_id,
                schema_version=SCHEMA_VERSION,
                exit_code=exit_code,
                failure_kind=failure_kind,
                no_input=no_input,
                events=events,
            )
    
    events.append(
        _make_run_finished_event(
            run_id,
            success=True,
            exit_code=EXIT_SUCCESS,
            blocks_executed=blocks_executed,
            total_blocks=total_blocks,
            no_input=no_input,
        )
    )
    return RunResult(
        success=True,
        blocks_executed=blocks_executed,
        block_results=block_results,
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        exit_code=EXIT_SUCCESS,
        no_input=no_input,
        events=events,
    )



def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="shellflow",
        description="A minimal shell script orchestrator with SSH support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shellflow run script.sh              # Run a script
  shellflow run script.sh --verbose    # Run with verbose output
    shellflow run script.sh --json       # Emit one machine-readable JSON report
    shellflow run script.sh --jsonl      # Emit streaming JSON Lines events
    shellflow run script.sh --no-input   # Disable interactive stdin consumption
    shellflow run script.sh --dry-run    # Preview the execution plan only
    shellflow run script.sh --audit-log audit.jsonl --jsonl
                                                                            # Mirror redacted events to an audit file
  shellflow --version                  # Show version
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Run command
    run_parser = subparsers.add_parser(
        "run",
        help="Run a shellflow script",
        description="Parse and execute a shellflow script.",
    )
    run_parser.add_argument(
        "script",
        help="Path to the shell script to execute",
    )
    run_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output with colored progress",
    )
    run_parser.add_argument(
        "--output-lines",
        type=int,
        default=MAX_OUTPUT_LINES,
        help="Maximum number of trailing log lines to print per command in verbose mode",
    )
    run_parser.add_argument(
        "--ssh-config",
        help="Path to an SSH config file to use instead of ~/.ssh/config",
    )
    run_parser.add_argument(
        "--no-input",
        action="store_true",
        dest="no_input",
        help="Run without interactive stdin and report non-interactive mode in structured output",
    )
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Preview the execution plan without running any block commands",
    )
    run_parser.add_argument(
        "--audit-log",
        dest="audit_log",
        help="Write a redacted JSON Lines audit log to the given path",
    )
    output_group = run_parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON run report",
    )
    output_group.add_argument(
        "--jsonl",
        action="store_true",
        help="Emit machine-readable JSON Lines events",
    )

    return parser


def main(args: list[str] | None = None) -> int:
    """Main entry point for the CLI.

    Args:
        args: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return EXIT_EXECUTION_FAILURE

    if parsed_args.command == "run":
        return cmd_run(parsed_args)

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Execute the run command.

    Args:
        args: Parsed arguments for the run command.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    script_path = Path(args.script)

    if args.ssh_config:
        os.environ["SHELLFLOW_SSH_CONFIG"] = str(Path(args.ssh_config).expanduser())

    if not script_path.exists():
        sys.stderr.write(f"Error: Script not found: {script_path}\n")
        return EXIT_EXECUTION_FAILURE

    try:
        content = script_path.read_text()
    except OSError as e:
        sys.stderr.write(f"Error: Cannot read script: {e}\n")
        return EXIT_EXECUTION_FAILURE

    try:
        blocks = parse_script(content)
    except ParseError as e:
        sys.stderr.write(f"Parse error: {e}\n")
        return _exit_code_for_failure(FAILURE_PARSE)

    if not blocks:
        empty_result = run_script([], no_input=args.no_input, dry_run=args.dry_run)
        if args.json or args.jsonl:
            if args.json:
                _emit_structured_output_json(empty_result)
            else:
                _emit_structured_output_jsonl(empty_result)
        if args.audit_log:
            _write_audit_log(Path(args.audit_log), empty_result)
        if args.verbose:
            print("No executable blocks found in script.")
        return EXIT_SUCCESS

    machine_mode = args.json or args.jsonl
    result = run_script(
        blocks,
        verbose=args.verbose and not machine_mode,
        no_input=args.no_input,
        dry_run=args.dry_run,
        output_tail_lines=args.output_lines,
    )

    if args.audit_log:
        _write_audit_log(Path(args.audit_log), result)

    if args.json:
        _emit_structured_output_json(result)
    elif args.jsonl:
        _emit_structured_output_jsonl(result)

    if not result.success:
        exit_code = result.exit_code if result.exit_code != EXIT_SUCCESS else EXIT_EXECUTION_FAILURE
        if not machine_mode:
            sys.stderr.write(f"Execution failed: {result.error_message}\n")
        return exit_code

    if args.verbose and not machine_mode:
        print(f"\nCompleted: {result.blocks_executed} block(s) executed successfully.")

    return EXIT_SUCCESS


def _get_version() -> str:
    """Resolve the installed package version, falling back to the source default."""
    try:
        return distribution_version(PACKAGE_NAME)
    except PackageNotFoundError:
        return DEFAULT_VERSION


if __name__ == "__main__":
    sys.exit(main())
