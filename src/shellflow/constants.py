"""Shellflow constants and configuration values."""

from __future__ import annotations

# Exit codes
EXIT_SUCCESS = 0
EXIT_EXECUTION_FAILURE = 1
EXIT_PARSE_FAILURE = 2
EXIT_SSH_CONFIG_FAILURE = 3
EXIT_TIMEOUT_FAILURE = 4

# Schema and versioning
PACKAGE_NAME = "shellflow"
DEFAULT_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"

# Failure kinds
FAILURE_PARSE = "parse"
FAILURE_RUNTIME = "runtime"
FAILURE_SSH_CONFIG = "ssh_config"
FAILURE_TIMEOUT = "timeout"

# Output limits
MAX_OUTPUT_LINES = 20
TRACE_MARKER = "__SHELLFLOW_CMD__:"

# Valid export sources
VALID_EXPORT_SOURCES = {"stdout", "stderr", "output", "exit_code"}

# Secret detection patterns
SECRET_LIKE_ENV_PATTERNS = ("TOKEN", "SECRET", "PASSWORD")

# ANSI color codes for terminal output
ANSI_RESET = "\033[0m"
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_DIM = "\033[90m"
