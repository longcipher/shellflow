"""Data models and type definitions for Shellflow."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .constants import SCHEMA_VERSION

if TYPE_CHECKING:
    from shellflow_models import CommandTrace

from dataclasses import dataclass, field
from typing import Any, Protocol


class BlockExecutor(Protocol):
    """Protocol for block execution strategies."""

    def execute(
        self,
        block: Block,
        context: ExecutionContext,
        no_input: bool = False,
        servers: dict[str, dict[str, str]] | None = None,
    ) -> ExecutionResult:
        """Execute a block and return the result."""
        ...


@dataclass
class Block:
    """Represents a block of commands to execute.

    A block contains a list of shell commands that should be executed
    either locally or on a remote host via SSH.

    Attributes:
        target: Execution target ("LOCAL" or "REMOTE:<host>")
        commands: List of shell commands to execute
        source_line: Line number in source script where block starts
        timeout_seconds: Optional timeout for block execution
        retry_count: Number of retry attempts on failure
        exports: Environment variables to export from block output
        shell: Shell to use for execution (e.g., "bash", "zsh")
        structured_exports: JSON schema-validated exports
        preamble_commands: Shared prelude commands to freeze once at execution time
        preamble_env: Injected environment used while freezing the shared prelude
        display_commands: User-authored commands to show in human-facing output
        annotations: Task and execution metadata
    """

    target: str  # "LOCAL" or "REMOTE:<host>"
    commands: list[str] = field(default_factory=list)
    source_line: int = 0
    timeout_seconds: int | None = None
    retry_count: int = 0
    exports: dict[str, str] = field(default_factory=dict)
    shell: str | None = None
    structured_exports: dict[str, StructuredExport] = field(default_factory=dict)
    preamble_commands: list[str] = field(default_factory=list)
    preamble_env: dict[str, str] = field(default_factory=dict)
    display_commands: list[str] = field(default_factory=list)
    annotations: dict[str, str] = field(default_factory=dict)

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
    """Context passed between block executions.

    Maintains state that persists across block executions, including
    environment variables, previous output, and execution metadata.

    Attributes:
        env: Environment variables shared between blocks
        last_output: Output from the most recently executed block
        success: Success status of the last executed block
        macros: User-defined command macros
        helpers: User-defined helper functions
        variables: User-defined variables
        hooks: Lifecycle hooks (PRE, POST, etc.)
    """

    env: dict[str, str] = field(default_factory=dict)
    last_output: str = ""
    success: bool = True
    macros: dict[str, list[str]] = field(default_factory=dict)
    helpers: dict[str, list[str]] = field(default_factory=dict)
    variables: dict[str, str] = field(default_factory=dict)
    hooks: dict[str, list[str]] = field(default_factory=dict)

    def to_shell_env(self) -> dict[str, str]:
        """Convert context to environment variables for shell execution."""
        shell_env = os.environ.copy()
        shell_env.update(self.env)
        shell_env["SHELLFLOW_LAST_OUTPUT"] = self.last_output
        return shell_env

    def substitute_variables(self, text: str) -> str:
        """Substitute variables in text using $VAR syntax."""
        result = text
        for name, value in self.variables.items():
            result = result.replace(f"${name}", value)
        return result


@dataclass
class CommandLog:
    """Structured verbose log for one executed command.

    Attributes:
        command: The shell command that was executed
        output: Combined stdout and stderr output
        exit_code: Process exit code (None if not yet completed)
        status: Execution status ("completed", "failed", "interrupted")
        success: Whether the command succeeded
    """

    command: str = field()
    output: str = field(default="")
    exit_code: int | None = field(default=None)
    status: str = field(default="completed")
    success: bool = field(default=True)

    def to_dict(self) -> dict[str, Any]:
        """Serialize one command log for structured output."""
        return {
            "command": self.command,
            "output": self.output,
            "exit_code": self.exit_code,
            "status": self.status,
            "success": self.success,
        }


@dataclass
class ExecutionResult:
    """Result of executing a single block.

    Contains the outcome of executing a block of commands, including
    success status, output, timing, and metadata.

    Attributes:
        success: Whether the block executed successfully
        output: Combined stdout and stderr output
        exit_code: Process exit code
        error_message: Human-readable error description
        stdout: Standard output stream
        stderr: Standard error stream
        duration_ms: Execution time in milliseconds
        attempts: Number of execution attempts
        timed_out: Whether execution timed out
        timeout_seconds: Configured timeout duration
        failure_kind: Category of failure ("parse", "runtime", "ssh_config", "timeout")
        no_input: Whether interactive input was disabled
        block_id: Unique identifier for the block
        block_index: Sequential index of the block
        source_line: Source line number where block was defined
        exported_env: Environment variables exported by the block
        command_logs: Detailed logs for individual commands
    """

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
    exported_env: dict[str, Any] = field(default_factory=dict)
    command_logs: list[CommandLog] = field(default_factory=list)

    def to_dict(self, *, redact_secret_exports: bool = False) -> dict[str, Any]:
        """Serialize the block result for machine-readable output."""
        # Handle structured exports (dict objects) vs regular string exports
        serialized_exports = {}
        for key, value in self.exported_env.items():
            if isinstance(value, dict):
                # Structured export - keep as dict for JSON serialization
                serialized_exports[key] = value
            else:
                # Regular string export
                serialized_exports[key] = str(value)

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
            "exported_env": _serialize_exported_env(serialized_exports, redact_secret_exports=redact_secret_exports),
            "command_logs": [command_log.to_dict() for command_log in self.command_logs],
        }
        if redact_secret_exports:
            return _redact_payload_strings(payload, _collect_secret_values(serialized_exports))
        return payload


@dataclass
class ReportEvent:
    """Structured execution event emitted during a run.

    Events provide a stream of execution progress and results for
    monitoring and automation integration.

    Attributes:
        event: Event type ("run_started", "block_started", etc.)
        run_id: Unique identifier for the execution run
        schema_version: Schema version for event format
        success: Success status (when applicable)
        exit_code: Process exit code (when applicable)
        block_id: Block identifier (when applicable)
        block_index: Block sequential index (when applicable)
        target: Execution target (when applicable)
        host: Remote host name (when applicable)
        source_line: Source line number (when applicable)
        blocks_executed: Number of blocks completed (when applicable)
        total_blocks: Total number of blocks in run (when applicable)
        attempts: Number of execution attempts (when applicable)
        timeout_seconds: Configured timeout (when applicable)
        failure_kind: Failure category (when applicable)
        no_input: Whether interactive input was disabled (when applicable)
        block: Complete block execution result (when applicable)
    """

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
    """Result of running a complete script.

    Contains the overall outcome of executing an entire shellflow script,
    including success status, timing, and results for all blocks.

    Attributes:
        success: Whether the entire run succeeded
        blocks_executed: Number of blocks that were executed
        error_message: Human-readable error description
        block_results: Results for each executed block
        run_id: Unique identifier for the execution run
        schema_version: Schema version for result format
        exit_code: Process exit code for the run
        failure_kind: Category of run failure
        no_input: Whether interactive input was disabled
        events: Stream of execution events
    """

    success: bool
    blocks_executed: int = 0
    error_message: str = ""
    block_results: list[ExecutionResult] = field(default_factory=list)
    run_id: str = ""
    schema_version: str = SCHEMA_VERSION
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

    @classmethod
    def from_pydantic(cls, trace: CommandTrace) -> CommandLog:
        """Create a CommandLog from a Pydantic CommandTrace."""
        trace_dict = trace.model_dump()
        return CommandLog(
            command=trace_dict["command"],
            output=trace_dict["stdout_chunk"] + trace_dict["stderr_chunk"],
            exit_code=trace_dict["exit_code"],
            status=trace_dict["status"],
            success=trace_dict["exit_code"] == 0 if trace_dict["exit_code"] is not None else False,
        )


@dataclass
class SSHConfig:
    """SSH configuration for a remote host.

    Defines connection parameters for SSH-based remote execution.

    Attributes:
        host: Host alias or IP address
        hostname: Actual hostname to connect to (may differ from alias)
        user: SSH username
        port: SSH port number
        identity_file: Path to SSH private key file
    """

    host: str
    hostname: str | None = None
    user: str | None = None
    port: int = 22
    identity_file: str | None = None


@dataclass(frozen=True)
class OptionDefinition:
    """A dynamic option declared by a Shellflow script.

    Defines a command-line option that can be declared within a script
    using @option directives.

    Attributes:
        name: Option name (without -- prefix)
        env_name: Environment variable name for the option
        default: Default value if not provided
        is_boolean: Whether this is a boolean flag option
        is_required: Whether this option must be provided
    """

    name: str
    env_name: str
    default: str | None = None
    is_boolean: bool = False
    is_required: bool = False


@dataclass(frozen=True)
class StructuredExport:
    """A JSON schema-validated export from block execution.

    Defines structured data that should be exported from a block's output,
    with validation against a JSON schema.

    Attributes:
        name: Export variable name
        json_schema: JSON schema for validation
        source: Source of the data ("stdout", "stderr", "output", "exit_code")
    """

    name: str
    json_schema: dict[str, Any]
    source: str


# Import here to avoid circular imports
import os  # noqa: E402

from .constants import SECRET_LIKE_ENV_PATTERNS  # noqa: E402


def _serialize_exported_env(exported_env: dict[str, Any], *, redact_secret_exports: bool) -> dict[str, Any]:
    """Serialize exported values, optionally redacting obvious secrets."""
    if not redact_secret_exports:
        return dict(exported_env)
    result = {}
    for key, value in exported_env.items():
        if _is_secret_like_env_name(key):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            # For structured exports, redact secrets within the dict
            result[key] = _redact_dict_secrets(value)
        else:
            result[key] = str(value)
    return result


def _redact_dict_secrets(data: Any) -> Any:
    """Recursively redact secret-like values in a dict structure."""
    if isinstance(data, dict):
        return {k: _redact_dict_secrets(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_redact_dict_secrets(item) for item in data]
    if isinstance(data, str) and any(pattern in data.upper() for pattern in SECRET_LIKE_ENV_PATTERNS):
        return "[REDACTED]"
    return data


def _collect_secret_values(exported_env: dict[str, Any]) -> set[str]:
    """Collect secret-like export values that should be redacted from audit sinks."""
    secrets = set()
    for key, value in exported_env.items():
        if _is_secret_like_env_name(key):
            if isinstance(value, str):
                secrets.add(value)
            elif isinstance(value, dict):
                # Recursively collect secrets from dict values
                secrets.update(_collect_secrets_from_dict(value))
    return secrets


def _collect_secrets_from_dict(data: Any) -> set[str]:
    """Recursively collect string values that might be secrets from a dict."""
    secrets = set()
    if isinstance(data, dict):
        for value in data.values():
            secrets.update(_collect_secrets_from_dict(value))
    elif isinstance(data, list):
        for item in data:
            secrets.update(_collect_secrets_from_dict(item))
    elif isinstance(data, str):
        secrets.add(data)
    return secrets


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


def _is_secret_like_env_name(name: str) -> bool:
    """Return whether an export name is likely to contain a secret."""
    upper_name = name.upper()
    return any(pattern in upper_name for pattern in SECRET_LIKE_ENV_PATTERNS)
