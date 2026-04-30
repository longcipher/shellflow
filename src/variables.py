"""Variable parsing functionality for Shellflow.

Provides functions to parse and manage variable definitions in shell scripts.
Variables are defined using # @VAR NAME=value markers.
"""

from __future__ import annotations

import re
from typing import Any


def parse_variables(content: str) -> dict[str, str]:
    """Parse script-level variables from content.

    Args:
        content: The script content to parse.

    Returns:
        Dict of variable name to value.

    Raises:
        ParseError: If variable parsing fails.
    """
    variables: dict[str, str] = {}
    lines = content.splitlines()
    for line_no, line in enumerate(lines, 1):
        marker = _parse_block_marker(line)
        if marker and marker[0] == "VAR":
            if not marker[1] or "=" not in marker[1]:
                raise ParseError(f"Line {line_no}: @VAR expects NAME=value format")
            name, value = marker[1].split("=", 1)
            name = name.strip()
            value = value.strip()
            if not _is_valid_env_name(name):
                raise ParseError(f"Line {line_no}: @VAR expects a valid variable name")
            variables[name] = value
    return variables


BLOCK_MARKER_RE = re.compile(r"^\s*#\s*@(?P<marker>[A-Z_]+)(?:\s+(?P<argument>\S+))?\s*$")


def _parse_block_marker(line: str) -> tuple[str, str | None] | None:
    """Parse a line as a shellflow marker if it matches exactly."""
    match = BLOCK_MARKER_RE.match(line)
    if not match:
        return None
    return match.group("marker"), match.group("argument")


def _is_valid_env_name(name: str) -> bool:
    """Check whether a string is a valid shell environment variable name."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))


class ParseError(Exception):
    """Exception raised when variable parsing fails."""
    pass