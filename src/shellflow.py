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
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class Block:
    """Represents a block of commands to execute."""

    target: str  # "LOCAL" or "REMOTE:<host>"
    commands: list[str] = field(default_factory=list)

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
class ExecutionResult:
    """Result of executing a single block."""

    success: bool
    output: str
    exit_code: int = 0
    error_message: str = ""


@dataclass
class RunResult:
    """Result of running a complete script."""

    success: bool
    blocks_executed: int = 0
    error_message: str = ""
    block_results: list[ExecutionResult] = field(default_factory=list)


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


# =============================================================================
# SSH Config Parser
# =============================================================================


def read_ssh_config(host: str) -> SSHConfig | None:
    """Read SSH configuration for a host from ~/.ssh/config.

    Uses paramiko.SSHConfig if available, otherwise falls back to basic parsing.

    Args:
        host: The host alias to look up.

    Returns:
        SSHConfig object if found, None otherwise.
    """
    ssh_config_path = _get_ssh_config_path()
    if not ssh_config_path.exists():
        return None

    try:
        # Try to use paramiko if available
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
        # Fall back to basic parsing
        return _parse_ssh_config_basic(ssh_config_path, host)


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

    for line_no, line in enumerate(content.splitlines(), 1):
        marker = _parse_block_marker(line)
        if marker:
            marker_name, marker_argument = marker
            if marker_name not in {"LOCAL", "REMOTE"}:
                raise ParseError(f"Line {line_no}: Unknown marker @{marker_name}")

            if current_block is None:
                prelude_lines = _clean_commands(accumulated_lines)
            else:
                current_block.commands = _build_block_commands(prelude_lines, accumulated_lines)
                if current_block.commands:
                    blocks.append(current_block)

            accumulated_lines = []

            if marker_name == "LOCAL":
                current_block = Block(target="LOCAL")
            else:
                if not marker_argument:
                    raise ParseError(f"Line {line_no}: @REMOTE marker missing host")
                current_block = Block(target=f"REMOTE:{marker_argument}")
            continue

        accumulated_lines.append(line)

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
) -> str:
    """Build a shell script payload for local or remote execution."""
    script_lines = ["set -e"]
    if include_context_exports:
        script_lines.extend(_build_context_exports(context))
    script_lines.extend(commands)
    return "\n".join(script_lines)


def _build_context_exports(context: ExecutionContext) -> list[str]:
    """Build export statements for explicit shellflow context values only."""
    exports = [f"export SHELLFLOW_LAST_OUTPUT={_quote_shell_value(context.last_output)}"]
    for key, value in context.env.items():
        if _is_valid_env_name(key):
            exports.append(f"export {key}={_quote_shell_value(value)}")
    return exports


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


def execute_local(
    block: Block,
    context: ExecutionContext,
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

    try:
        result = subprocess.run(
            ["/bin/bash", "-se"],
            input=script,
            capture_output=True,
            text=True,
            env=env,
        )

        return ExecutionResult(
            success=result.returncode == 0,
            output=_combine_output(result.stdout, result.stderr),
            exit_code=result.returncode,
            error_message="" if result.returncode == 0 else f"Exit code: {result.returncode}",
        )
    except (OSError, subprocess.SubprocessError) as e:
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=str(e),
        )


def execute_remote(
    block: Block,
    context: ExecutionContext,
    ssh_config: SSHConfig | None,
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
        )

    ssh_args = ["ssh"]

    if ssh_config.port and ssh_config.port != 22:
        ssh_args.extend(["-p", str(ssh_config.port)])
    if ssh_config.user:
        ssh_args.extend(["-l", ssh_config.user])
    if ssh_config.identity_file:
        ssh_args.extend(["-i", str(Path(ssh_config.identity_file).expanduser())])

    ssh_config_path = _get_ssh_config_path()
    if ssh_config_path.exists():
        ssh_args.extend(["-F", str(ssh_config_path)])

    ssh_args.extend(["-o", "BatchMode=yes", host, "bash", "-se"])
    remote_script = _build_executable_script(
        block.commands,
        context,
        include_context_exports=True,
    )

    try:
        result = subprocess.run(
            ssh_args,
            input=remote_script,
            capture_output=True,
            text=True,
        )

        return ExecutionResult(
            success=result.returncode == 0,
            output=_combine_output(result.stdout, result.stderr),
            exit_code=result.returncode,
            error_message="" if result.returncode == 0 else f"SSH exit code: {result.returncode}",
        )
    except (OSError, subprocess.SubprocessError) as e:
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=str(e),
        )


# =============================================================================
# Script Runner
# =============================================================================


def run_script(blocks: list[Block], verbose: bool = False) -> RunResult:
    """Run a list of blocks sequentially.

    Executes each block in order, updating the execution context between
    blocks. Fails fast on any error.

    Args:
        blocks: List of blocks to execute.
        verbose: Whether to print progress information.

    Returns:
        RunResult with success status and execution info.
    """
    context = ExecutionContext()
    blocks_executed = 0
    block_results: list[ExecutionResult] = []

    # ANSI color codes for verbose output
    GREEN = "\033[92m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    DIM = "\033[90m"
    RESET = "\033[0m"

    for i, block in enumerate(blocks, 1):
        # Print block info if verbose
        if verbose:
            if block.is_local:
                print(f"{BLUE}[{i}/{len(blocks)}] LOCAL{RESET}")
            else:
                host = block.host or "unknown"
                print(f"{YELLOW}[{i}/{len(blocks)}] REMOTE: {host}{RESET}")
            for env_line in _iter_display_context(context):
                print(f"{DIM}@env {env_line}{RESET}")
            for command in _iter_display_commands(block.commands):
                print(f"{DIM}$ {command}{RESET}")

        # Execute the block
        if block.is_local:
            result = execute_local(block, context)
        else:
            host = block.host
            if not host:
                return RunResult(
                    success=False,
                    blocks_executed=blocks_executed,
                    error_message=f"Block {i}: No host specified for remote block",
                )
            ssh_config = read_ssh_config(host)
            result = execute_remote(block, context, ssh_config)

        # Update context
        context.last_output = result.output
        context.success = result.success
        block_results.append(result)

        if verbose:
            if result.output:
                print(result.output)
            if result.success:
                print(f"{GREEN}✓ Success{RESET}\n")
            else:
                print(f"{RED}✗ Failed: {result.error_message}{RESET}\n")

        blocks_executed += 1

        # Fail fast on error
        if not result.success:
            return RunResult(
                success=False,
                blocks_executed=blocks_executed,
                error_message=f"Block {i} failed: {result.error_message}",
                block_results=block_results,
            )

    return RunResult(
        success=True,
        blocks_executed=blocks_executed,
        block_results=block_results,
    )


# =============================================================================
# CLI
# =============================================================================


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
        "--ssh-config",
        help="Path to an SSH config file to use instead of ~/.ssh/config",
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
        return 1

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
        return 1

    try:
        content = script_path.read_text()
    except OSError as e:
        sys.stderr.write(f"Error: Cannot read script: {e}\n")
        return 1

    try:
        blocks = parse_script(content)
    except ParseError as e:
        sys.stderr.write(f"Parse error: {e}\n")
        return 1

    if not blocks:
        if args.verbose:
            print("No executable blocks found in script.")
        return 0

    result = run_script(blocks, verbose=args.verbose)

    if not result.success:
        sys.stderr.write(f"Execution failed: {result.error_message}\n")
        return 1

    if args.verbose:
        print(f"\nCompleted: {result.blocks_executed} block(s) executed successfully.")

    return 0


def _get_version() -> str:
    """Resolve the installed package version, falling back to the source default."""
    try:
        return distribution_version(PACKAGE_NAME)
    except PackageNotFoundError:
        return DEFAULT_VERSION


if __name__ == "__main__":
    sys.exit(main())
