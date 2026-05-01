"""Hook parsing and execution functionality for Shellflow.

Provides functions to parse and execute hook definitions in shell scripts.
Hooks are defined using # @HOOK <type> and executed at different lifecycle points.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.shellflow import ExecutionContext, ExecutionResult


class ParseError(ValueError):
    """Exception raised when hook parsing fails."""


def parse_hooks(content: str) -> dict[str, list[str]]:
    """Parse hook definitions from script content.

    Parses scripts containing hook definitions in the format:
        # @HOOK <type>
        #   <command1>
        #   <command2>
        # @ENDHOOK

    Args:
        content: The script content to parse.

    Returns:
        Dictionary mapping hook types to lists of commands.

    Raises:
        ParseError: If hook syntax is invalid.
    """
    hooks: dict[str, list[str]] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]
        marker = _parse_hook_marker(line)
        if marker:
            marker_name, marker_argument = marker
            if marker_name == "HOOK":
                if not marker_argument:
                    raise ParseError(f"Line {i + 1}: @HOOK requires a hook type")
                hook_type = _normalize_hook_type(marker_argument.strip())
                if hook_type in hooks:
                    raise ParseError(f"Line {i + 1}: Hook '{hook_type}' already defined")

                # Parse hook body until @ENDHOOK
                i += 1
                hook_commands = []
                while i < len(lines):
                    body_line = lines[i]
                    end_marker = _parse_hook_marker(body_line)
                    if end_marker and end_marker[0] == "ENDHOOK":
                        if end_marker[1]:  # @ENDHOOK shouldn't have arguments
                            raise ParseError(f"Line {i + 1}: @ENDHOOK should not have arguments")
                        break
                    hook_commands.append(body_line)
                    i += 1
                else:
                    raise ParseError(f"Line {len(lines)}: Unterminated @HOOK '{hook_type}' - missing @ENDHOOK")

                hooks[hook_type] = _clean_hook_commands(hook_commands)
            else:
                raise ParseError(f"Line {i + 1}: Unexpected hook marker @{marker_name}")
        i += 1

    return hooks


def _parse_hook_marker(line: str) -> tuple[str, str] | None:
    """Parse a line as a hook marker if it matches exactly."""
    match = re.match(r"^\s*#\s*@(?P<marker>HOOK|ENDHOOK)(?:\s+(?P<argument>.*?))?\s*$", line, re.IGNORECASE)
    if not match:
        return None
    return match.group("marker").upper(), match.group("argument") or ""


def _normalize_hook_type(value: str) -> str:
    """Normalize hook names to Shellflow's lifecycle names."""
    hook_type = value.upper()
    aliases = {
        "POST": "AFTER",
        "BEFORE": "BEFORE",
        "PRE": "PRE",
        "AFTER": "AFTER",
        "SUCCESS": "SUCCESS",
        "ERROR": "ERROR",
        "FINISHED": "FINISHED",
        "FINALLY": "FINISHED",
    }
    return aliases.get(hook_type, hook_type)


def _clean_hook_commands(lines: list[str]) -> list[str]:
    """Clean hook command lines by removing leading # and whitespace."""
    # Remove empty lines from start and end
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]

    if not lines:
        return []

    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Remove leading # and any whitespace after it
        if stripped.startswith("#"):
            content = stripped[1:].strip()
            if content:  # Only keep non-empty content
                cleaned_lines.append(content)
        else:
            # Line doesn't start with #, keep as-is (shouldn't happen in well-formed hooks)
            cleaned_lines.append(stripped)

    return cleaned_lines


def execute_hook(
    hook_type: str,
    hooks: dict[str, list[str]],
    context: ExecutionContext,
    no_input: bool = False,
) -> ExecutionResult | None:
    """Execute a hook if it exists.

    Args:
        hook_type: The type of hook to execute (e.g., 'PRE', 'POST')
        hooks: Dictionary of parsed hooks
        context: Current execution context

    Returns:
        ExecutionResult if hook was executed, None if no hook found
    """
    hook_type = _normalize_hook_type(hook_type)
    if hook_type not in hooks:
        return None

    # Create a temporary block for the hook commands
    from shellflow import Block, execute_local

    hook_block = Block(
        target="LOCAL",
        commands=hooks[hook_type],
        source_line=0,  # Hooks don't have a specific source line
    )

    # Execute the hook locally
    return execute_local(hook_block, context, no_input=no_input)
