"""Shellflow - A minimal shell script orchestrator with SSH support."""

from __future__ import annotations

from .cli import create_parser
from .config import parse_server_config, parse_variables, read_ssh_config
from .constants import (
    EXIT_EXECUTION_FAILURE,
    EXIT_PARSE_FAILURE,
    EXIT_SSH_CONFIG_FAILURE,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_FAILURE,
    FAILURE_PARSE,
    FAILURE_RUNTIME,
    FAILURE_SSH_CONFIG,
    FAILURE_TIMEOUT,
    MAX_OUTPUT_LINES,
    PACKAGE_NAME,
    SCHEMA_VERSION,
    TRACE_MARKER,
    VALID_EXPORT_SOURCES,
)
from .exceptions import (
    ExecutionError,
    ParseError,
    ShellflowError,
    SSHConfigError,
    TimeoutError,  # noqa: A004
    ValidationError,
)
from .executor import (
    _apply_block_exports,
    _build_executable_script,
    _build_remote_trace_script,
    _is_valid_env_name,
    _parse_debug_trace_command_logs,
    _parse_remote_command_logs,
    _run_remote_subprocess,
    execute_local,
    execute_remote,
)
from .main import main
from .models import (
    Block,
    BlockExecutor,
    CommandLog,
    ExecutionContext,
    ExecutionResult,
    OptionDefinition,
    ReportEvent,
    RunResult,
    SSHConfig,
    StructuredExport,
)
from .parser import _clean_commands, parse_script
from .runner import run_script

__version__ = "0.4.9"

__all__ = [
    "EXIT_EXECUTION_FAILURE",
    "EXIT_PARSE_FAILURE",
    "EXIT_SSH_CONFIG_FAILURE",
    "EXIT_SUCCESS",
    "EXIT_TIMEOUT_FAILURE",
    "FAILURE_PARSE",
    "FAILURE_RUNTIME",
    "FAILURE_SSH_CONFIG",
    "FAILURE_TIMEOUT",
    "MAX_OUTPUT_LINES",
    "PACKAGE_NAME",
    "SCHEMA_VERSION",
    "TRACE_MARKER",
    "VALID_EXPORT_SOURCES",
    "Block",
    "BlockExecutor",
    "CommandLog",
    "ExecutionContext",
    "ExecutionError",
    "ExecutionResult",
    "OptionDefinition",
    "ParseError",
    "ReportEvent",
    "RunResult",
    "SSHConfig",
    "SSHConfigError",
    "ShellflowError",
    "StructuredExport",
    "TimeoutError",
    "ValidationError",
    "_apply_block_exports",
    "_build_executable_script",
    "_build_remote_trace_script",
    "_clean_commands",
    "_is_valid_env_name",
    "_parse_debug_trace_command_logs",
    "_parse_remote_command_logs",
    "_run_remote_subprocess",
    "create_parser",
    "execute_local",
    "execute_remote",
    "main",
    "parse_script",
    "parse_server_config",
    "parse_variables",
    "read_ssh_config",
    "run_script",
]
