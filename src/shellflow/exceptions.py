"""Shellflow exception hierarchy and error handling utilities."""

from __future__ import annotations


class ShellflowError(Exception):
    """Base exception for all Shellflow errors.

    All Shellflow-specific exceptions inherit from this base class
    to allow for consistent error handling and reporting.
    """


class ParseError(ShellflowError):
    """Exception raised when parsing fails.

    Raised when a shellflow script cannot be parsed due to syntax
    errors, invalid directives, or malformed structure.

    Attributes:
        line: Line number where the error occurred
        content: The problematic content that caused the error
    """

    def __init__(self, message: str, line: int | None = None, content: str | None = None) -> None:
        super().__init__(message)
        self.line = line
        self.content = content


class ExecutionError(ShellflowError):
    """Exception raised when execution fails.

    Raised when a block execution fails due to command errors,
    timeouts, or other runtime issues.

    Attributes:
        block_index: Index of the block that failed
        exit_code: Process exit code
        stderr: Standard error output
    """

    def __init__(
        self,
        message: str,
        block_index: int | None = None,
        exit_code: int | None = None,
        stderr: str | None = None,
    ) -> None:
        super().__init__(message)
        self.block_index = block_index
        self.exit_code = exit_code
        self.stderr = stderr


class SSHConfigError(ShellflowError):
    """Exception raised when SSH configuration is invalid or missing.

    Raised when SSH configuration cannot be loaded or is malformed.

    Attributes:
        host: The host that could not be configured
    """

    def __init__(self, message: str, host: str | None = None) -> None:
        super().__init__(message)
        self.host = host


class TimeoutError(ShellflowError):  # noqa: A001
    """Exception raised when execution times out.

    Raised when a block execution exceeds its configured timeout.

    Attributes:
        timeout_seconds: The configured timeout duration
    """

    def __init__(self, message: str, timeout_seconds: int | None = None) -> None:
        super().__init__(message)
        self.timeout_seconds = timeout_seconds


class ValidationError(ShellflowError):
    """Exception raised when data validation fails.

    Raised when structured exports or other data fail schema validation.
    """
