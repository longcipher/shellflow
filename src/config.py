"""Server definition parsing for Shellflow scripts."""

from __future__ import annotations


def parse_server_config(script: str) -> dict[str, dict[str, str]]:
    """Parse # @SERVER definitions from a Shellflow script."""
    servers: dict[str, dict[str, str]] = {}
    lines = script.splitlines()
    current_server: str | None = None

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line:
            continue

        if line.upper().startswith("# @SERVER"):
            parts = line.split(maxsplit=2)
            if len(parts) < 3 or not parts[2].strip():
                raise ValueError(f"Line {line_num}: Server name cannot be empty")
            current_server = parts[2].strip()
            servers[current_server] = {}
            continue

        if not current_server or not line.startswith("#   "):
            continue

        config_line = line[4:]
        if ": " not in config_line:
            raise ValueError(f"Line {line_num}: Malformed config line '{config_line}'. Expected format: 'key: value'")

        key, value = config_line.split(": ", 1)
        servers[current_server][key.strip()] = value.strip()

    for server_name, config in servers.items():
        if "host" not in config:
            raise ValueError(f"Server '{server_name}': Missing required field 'host'")

    return servers
