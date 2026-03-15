"""Behave environment hooks for Shellflow BDD tests."""

from __future__ import annotations

import contextlib
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from behave.runner import Context


def before_all(context: Context) -> None:
    """Set up global test state before all tests."""
    # Store the project root for later use
    context.project_root = Path(__file__).parent.parent


def before_scenario(context: Context, scenario: object) -> None:
    """Reset scenario state before each run.

    Args:
        context: The Behave context object.
        scenario: The current scenario being executed.
    """
    del scenario

    # Reset all shellflow-specific context attributes
    context.script_path = None
    context.script_content = None
    context.parsed_blocks = None
    context.parse_error = None
    context.execution_result = None
    context.stdout = ""
    context.stderr = ""
    context.exit_code = None
    context.verbose = False
    context.test_host = None
    context.ssh_config_path = None
    context.ssh_config_dir = None


def after_scenario(context: Context, scenario: object) -> None:
    """Clean up after each scenario.

    Args:
        context: The Behave context object.
        scenario: The current scenario that was executed.
    """
    del scenario

    # Clean up temporary script file if it exists
    if hasattr(context, "script_path") and context.script_path:
        with contextlib.suppress(OSError):
            Path(context.script_path).unlink(missing_ok=True)
        context.script_path = None

    # Clean up temporary SSH config if it exists
    if hasattr(context, "ssh_config_dir") and context.ssh_config_dir:
        try:
            if Path(context.ssh_config_dir).exists():
                shutil.rmtree(context.ssh_config_dir, ignore_errors=True)
        except OSError:
            pass
        context.ssh_config_dir = None
        context.ssh_config_path = None


def after_all(context: Context) -> None:
    """Clean up global state after all tests."""
    # Nothing to clean up at the global level currently
    del context
