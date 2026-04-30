"""Macro parsing functionality for Shellflow.

Provides functions to parse and manage macro definitions in shell scripts.
Macros are defined using # @MACRO <name> and # @ENDMACRO markers.
"""

from __future__ import annotations

import re
from typing import Any


def parse_macros(content: str) -> dict[str, list[str]]:
    """Parse macro definitions from script content.

    Parses scripts containing macro definitions in the format:
        # @MACRO <name>
        #   <command1>
        #   <command2>
        # @ENDMACRO

    Args:
        content: The script content to parse.

    Returns:
        Dictionary mapping macro names to lists of commands.

    Raises:
        ParseError: If macro syntax is invalid.
    """
    macros: dict[str, list[str]] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]
        marker = _parse_macro_marker(line)
        if marker:
            marker_name, marker_argument = marker
            if marker_name == "MACRO":
                if not marker_argument:
                    raise ParseError(f"Line {i + 1}: @MACRO requires a macro name")
                macro_name = marker_argument.strip()
                if macro_name in macros:
                    raise ParseError(f"Line {i + 1}: Macro '{macro_name}' already defined")

                # Parse macro body until @ENDMACRO
                i += 1
                macro_commands = []
                while i < len(lines):
                    body_line = lines[i]
                    end_marker = _parse_macro_marker(body_line)
                    if end_marker and end_marker[0] == "ENDMACRO":
                        if end_marker[1]:  # @ENDMACRO shouldn't have arguments
                            raise ParseError(f"Line {i + 1}: @ENDMACRO should not have arguments")
                        break
                    macro_commands.append(body_line)
                    i += 1
                else:
                    raise ParseError(f"Line {len(lines)}: Unterminated @MACRO '{macro_name}' - missing @ENDMACRO")

                macros[macro_name] = _clean_macro_commands(macro_commands)
            else:
                raise ParseError(f"Line {i + 1}: Unexpected macro marker @{marker_name}")
        i += 1

    return macros


def _parse_macro_marker(line: str) -> tuple[str, str] | None:
    """Parse a line as a macro marker if it matches exactly."""
    match = re.match(r"^\s*#\s*@(?P<marker>MACRO|ENDMACRO)(?:\s+(?P<argument>\S+))?\s*$", line)
    if not match:
        return None
    return match.group("marker"), match.group("argument") or ""


def _clean_macro_commands(lines: list[str]) -> list[str]:
    """Clean macro command lines by removing leading whitespace."""
    # Remove empty lines from start and end
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]

    if not lines:
        return []

    # Find common leading whitespace
    non_empty_lines = [line for line in lines if line.strip()]
    if not non_empty_lines:
        return []

    common_indent = min(len(line) - len(line.lstrip()) for line in non_empty_lines)

    # Remove common leading whitespace
    return [line[common_indent:] for line in lines]


class ParseError(Exception):
    """Exception raised when macro parsing fails."""
    pass