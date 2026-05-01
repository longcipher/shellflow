"""Helper parsing functionality for Shellflow.

Provides functions to parse and manage helper definitions in shell scripts.
Helpers are defined using # @HELPER <name> and # @ENDHELPER markers.
"""

from __future__ import annotations

import re


def parse_helpers(content: str) -> dict[str, list[str]]:
    """Parse helper definitions from script content.

    Parses scripts containing helper definitions in the format:
        # @HELPER <name>
        #   <command1>
        #   <command2>
        # @ENDHELPER

    Args:
        content: The script content to parse.

    Returns:
        Dictionary mapping helper names to lists of commands.

    Raises:
        ParseError: If helper syntax is invalid.
    """
    helpers: dict[str, list[str]] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]
        marker = _parse_helper_marker(line)
        if marker:
            marker_name, marker_argument = marker
            if marker_name == "HELPER":
                if not marker_argument:
                    raise ParseError(f"Line {i + 1}: @HELPER requires a helper name")
                helper_name = marker_argument.strip()
                if helper_name in helpers:
                    raise ParseError(f"Line {i + 1}: Helper '{helper_name}' already defined")

                # Parse helper body until @ENDHELPER
                i += 1
                helper_commands = []
                while i < len(lines):
                    body_line = lines[i]
                    end_marker = _parse_helper_marker(body_line)
                    if end_marker and end_marker[0] == "ENDHELPER":
                        if end_marker[1]:  # @ENDHELPER shouldn't have arguments
                            raise ParseError(f"Line {i + 1}: @ENDHELPER should not have arguments")
                        break
                    helper_commands.append(body_line)
                    i += 1
                else:
                    raise ParseError(f"Line {len(lines)}: Unterminated @HELPER '{helper_name}' - missing @ENDHELPER")

                helpers[helper_name] = _clean_helper_commands(helper_commands)
            else:
                raise ParseError(f"Line {i + 1}: Unexpected helper marker @{marker_name}")
        i += 1

    return helpers


def _parse_helper_marker(line: str) -> tuple[str, str] | None:
    """Parse a line as a helper marker if it matches exactly."""
    match = re.match(r"^\s*#\s*@(?P<marker>HELPER|ENDHELPER)(?:\s+(?P<argument>.*?))?\s*$", line, re.IGNORECASE)
    if not match:
        return None
    return match.group("marker").upper(), match.group("argument") or ""


def _clean_helper_commands(lines: list[str]) -> list[str]:
    """Clean helper command lines by removing leading # and whitespace."""
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
            # Line doesn't start with #, keep as-is (shouldn't happen in well-formed helpers)
            cleaned_lines.append(stripped)

    return cleaned_lines


class ParseError(ValueError):
    """Exception raised when helper parsing fails."""
