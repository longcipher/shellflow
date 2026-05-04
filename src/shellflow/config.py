"""Configuration management for Shellflow."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from .exceptions import ParseError, SSHConfigError
from .models import SSHConfig


def read_ssh_config(host: str, servers: dict[str, dict[str, str]] | None = None) -> SSHConfig | None:
    """Read SSH configuration for a host from ~/.ssh/config or server definitions.

    Uses SSHConfigResolver with multiple providers (paramiko, basic parsing).

    Args:
        host: The host alias to look up.
        servers: Optional server definitions from script.

    Returns:
        SSHConfig object if found, None otherwise.
    """
    # First check server definitions
    if servers and host in servers:
        server_config = servers[host]
        hostname = server_config.get("host")
        if not hostname:
            raise SSHConfigError(f"Server '{host}' is missing required field 'host'", host)

        # Validate and parse port
        port_str = server_config.get("port", "22")
        try:
            port = int(port_str)
        except ValueError as e:
            raise SSHConfigError(f"Invalid port '{port_str}' for server '{host}': {e}", host) from e
        if port < 1 or port > 65535:
            raise SSHConfigError(f"Invalid port '{port_str}' for server '{host}': out of valid range (1-65535)", host)

        return SSHConfig(
            host=host,
            hostname=hostname,
            user=server_config.get("user"),
            port=port,
            identity_file=server_config.get("key"),
        )

    return _ssh_config_resolver.resolve(host)


def _ssh_config_matches_host(ssh_config: Any, host: str) -> bool:
    """Check whether a host matches any explicit Host rule in the SSH config."""
    get_hostnames = getattr(ssh_config, "get_hostnames", None)
    if not callable(get_hostnames):
        return True

    patterns = {pattern for pattern in get_hostnames() if pattern}
    return any(fnmatch.fnmatch(host, pattern) for pattern in patterns)


def _get_ssh_config_path() -> Path:
    """Resolve the SSH config path, allowing environment override."""
    import os

    configured_path = os.environ.get("SHELLFLOW_SSH_CONFIG")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path.home() / ".ssh" / "config"


def _parse_ssh_config_basic(config_path: Path, host: str) -> SSHConfig | None:
    """Basic SSH config parser without paramiko.

    Args:
        config_path: Path to the SSH config file.
        host: The host alias to look up.

    Returns:
        SSHConfig object if found, None otherwise.
    """
    sections: list[tuple[list[str], dict[str, Any]]] = []
    current_patterns: list[str] = []
    current_options: dict[str, Any] = {}

    with config_path.open() as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(maxsplit=1)
            if len(parts) < 2:
                continue

            keyword, value = parts[0].lower(), parts[1]

            if keyword == "host":
                if current_patterns:
                    sections.append((current_patterns, current_options))
                current_patterns = value.split()
                current_options = {}
                continue

            if not current_patterns:
                continue

            if keyword == "hostname":
                current_options["hostname"] = value
            elif keyword == "user":
                current_options["user"] = value
            elif keyword == "port":
                current_options["port"] = int(value)
            elif keyword == "identityfile":
                current_options["identityfile"] = value

    if current_patterns:
        sections.append((current_patterns, current_options))

    config: dict[str, Any] = {"host": host}
    matched = False

    for patterns, options in sections:
        if any(fnmatch.fnmatch(host, pattern) for pattern in patterns):
            matched = True
            config.update(options)

    if not matched:
        return None

    return SSHConfig(
        host=config.get("host", host),
        hostname=config.get("hostname"),
        user=config.get("user"),
        port=config.get("port", 22),
        identity_file=config.get("identityfile"),
    )


class SSHConfigProvider:
    """Protocol for SSH configuration providers."""

    def get_config(self, host: str) -> SSHConfig | None:
        """Get SSH configuration for a host."""


class ParamikoSSHConfigProvider:
    """SSH config provider using paramiko."""

    def get_config(self, host: str) -> SSHConfig | None:
        """Get SSH config using paramiko."""
        ssh_config_path = _get_ssh_config_path()
        if not ssh_config_path.exists():
            return None

        try:
            import paramiko

            ssh_config = paramiko.SSHConfig()
            with ssh_config_path.open() as handle:
                ssh_config.parse(handle)

            if not _ssh_config_matches_host(ssh_config, host):
                return None

            lookup = ssh_config.lookup(host)
            if not lookup:
                return None

            return SSHConfig(
                host=host,
                hostname=lookup.get("hostname"),
                user=lookup.get("user"),
                port=int(lookup.get("port", 22)),
                identity_file=lookup.get("identityfile", [None])[0]
                if isinstance(lookup.get("identityfile"), list)
                else lookup.get("identityfile"),
            )
        except (AttributeError, ImportError):
            return None


class BasicSSHConfigProvider:
    """Basic SSH config provider without paramiko."""

    def get_config(self, host: str) -> SSHConfig | None:
        """Get SSH config using basic parsing."""
        ssh_config_path = _get_ssh_config_path()
        if not ssh_config_path.exists():
            return None

        return _parse_ssh_config_basic(ssh_config_path, host)


class SSHConfigResolver:
    """Resolves SSH configuration using multiple providers."""

    def __init__(self, providers: list[SSHConfigProvider] | None = None) -> None:
        """Initialize resolver with optional providers."""
        self.providers = providers or [
            ParamikoSSHConfigProvider(),
            BasicSSHConfigProvider(),
        ]

    def resolve(self, host: str) -> SSHConfig | None:
        """Resolve SSH config for a host using available providers."""
        for provider in self.providers:
            try:
                config = provider.get_config(host)
                if config:
                    return config
            except Exception:  # noqa: BLE001,S112
                continue
        return None


_ssh_config_resolver = SSHConfigResolver()


def parse_server_config(content: str) -> dict[str, dict[str, str]]:
    """Parse @SERVER definitions from script content."""
    servers: dict[str, dict[str, str]] = {}
    current_server: str | None = None

    for line_no, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue

        if line.upper().startswith("# @SERVER"):
            parts = line.split(maxsplit=2)
            if len(parts) < 3 or not parts[2].strip():
                raise ParseError(f"Line {line_no}: Server name cannot be empty")
            current_server = parts[2].strip()
            servers[current_server] = {}
            continue

        if not current_server or not line.startswith("#   "):
            continue

        config_line = line[4:]
        if ":" not in config_line:
            raise ParseError(f"Line {line_no}: Malformed config line '{config_line}'. Expected format: 'key: value'")

        key, value = config_line.split(":", 1)
        servers[current_server][key.strip()] = value.strip()

    for server_name, config in servers.items():
        if not config.get("host"):
            raise ParseError(f"Server '{server_name}': Missing required field 'host'")

    return servers


def parse_macros(content: str) -> dict[str, list[str]]:
    """Parse @MACRO definitions from script content."""
    macros: dict[str, list[str]] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        marker = _parse_definition_marker(lines[i], "MACRO", "ENDMACRO")
        if not marker:
            i += 1
            continue

        marker_name, marker_argument = marker
        if marker_name != "MACRO":
            raise ParseError(f"Line {i + 1}: Unexpected macro marker @{marker_name}")
        if not marker_argument:
            raise ParseError(f"Line {i + 1}: @MACRO requires a macro name")

        parts = marker_argument.split()
        macro_name = parts[0]
        if macro_name in macros:
            raise ParseError(f"Line {i + 1}: Macro '{macro_name}' already defined")

        if len(parts) > 1:
            macros[macro_name] = parts[1:]
            i += 1
            continue

        macro_commands, i = _parse_definition_body(lines, i + 1, macro_name, "MACRO", "ENDMACRO")
        macros[macro_name] = macro_commands

    return macros


def parse_helpers(content: str) -> dict[str, list[str]]:
    """Parse @HELPER definitions from script content."""
    helpers: dict[str, list[str]] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        marker = _parse_definition_marker(lines[i], "HELPER", "ENDHELPER")
        if not marker:
            i += 1
            continue

        marker_name, marker_argument = marker
        if marker_name != "HELPER":
            raise ParseError(f"Line {i + 1}: Unexpected helper marker @{marker_name}")
        if not marker_argument:
            raise ParseError(f"Line {i + 1}: @HELPER requires a helper name")
        helper_name = marker_argument
        if helper_name in helpers:
            raise ParseError(f"Line {i + 1}: Helper '{helper_name}' already defined")

        helper_commands, i = _parse_definition_body(lines, i + 1, helper_name, "HELPER", "ENDHELPER")
        helpers[helper_name] = helper_commands

    return helpers


def parse_variables(content: str) -> dict[str, str]:
    """Parse @VAR definitions from script content."""
    variables: dict[str, str] = {}
    for line_no, line in enumerate(content.splitlines(), 1):
        marker = _parse_generic_marker(line)
        if not marker or marker[0] != "VAR":
            continue
        if not marker[1] or "=" not in marker[1]:
            raise ParseError(f"Line {line_no}: @VAR expects NAME=value format")
        var_name, var_value = marker[1].split("=", 1)
        var_name = var_name.strip()
        var_value = var_value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", var_name):
            raise ParseError(f"Line {line_no}: @VAR expects a valid variable name")
        variables[var_name] = var_value

    return variables


def parse_hooks(content: str) -> dict[str, list[str]]:
    """Parse @HOOK definitions from script content."""
    hooks: dict[str, list[str]] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        marker = _parse_definition_marker(lines[i], "HOOK", "ENDHOOK")
        if not marker:
            i += 1
            continue

        marker_name, marker_argument = marker
        if marker_name != "HOOK":
            raise ParseError(f"Line {i + 1}: Unexpected hook marker @{marker_name}")
        if not marker_argument:
            raise ParseError(f"Line {i + 1}: @HOOK requires a hook type")

        hook_name = _normalize_hook_name(marker_argument)
        if hook_name in hooks:
            raise ParseError(f"Line {i + 1}: Hook '{hook_name}' already defined")

        hook_commands, i = _parse_definition_body(lines, i + 1, hook_name, "HOOK", "ENDHOOK")
        hooks[hook_name] = hook_commands

    return hooks


def _parse_definition_marker(line: str, start_marker: str, end_marker: str) -> tuple[str, str] | None:
    """Parse a directive block marker with an optional argument."""
    match = re.match(
        rf"^\s*#\s*@(?P<marker>{start_marker}|{end_marker})(?:\s+(?P<argument>.*?))?\s*$",
        line,
        re.IGNORECASE,
    )
    if not match:
        return None
    return match.group("marker").upper(), (match.group("argument") or "").strip()


def _parse_definition_body(
    lines: list[str],
    start_index: int,
    name: str,
    start_marker: str,
    end_marker: str,
) -> tuple[list[str], int]:
    """Parse a directive body until its end marker and return cleaned commands."""
    body_lines: list[str] = []
    i = start_index
    while i < len(lines):
        marker = _parse_definition_marker(lines[i], start_marker, end_marker)
        if marker and marker[0] == end_marker:
            if marker[1]:
                raise ParseError(f"Line {i + 1}: @{end_marker} should not have arguments")
            return _clean_definition_commands(body_lines), i + 1
        body_lines.append(lines[i])
        i += 1
    raise ParseError(f"Line {len(lines)}: Unterminated @{start_marker} '{name}' - missing @{end_marker}")


def _clean_definition_commands(lines: list[str]) -> list[str]:
    """Clean directive body commands by trimming directive comment prefixes."""
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]

    cleaned_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            stripped = stripped[1:].strip()
        if stripped:
            cleaned_lines.append(stripped)
    return cleaned_lines


def _normalize_hook_name(value: str) -> str:
    """Normalize hook aliases to the lifecycle names used by the runner."""
    aliases = {
        "POST": "AFTER",
        "PRE": "PRE",
        "BEFORE": "BEFORE",
        "AFTER": "AFTER",
        "SUCCESS": "SUCCESS",
        "ERROR": "ERROR",
        "FINISHED": "FINISHED",
        "FINALLY": "FINISHED",
    }
    return aliases.get(value.upper(), value.upper())


def _parse_generic_marker(line: str) -> tuple[str, str | None] | None:
    """Parse a generic shellflow marker line with an optional argument."""
    match = re.match(r"^\s*#\s*@(?P<marker>[A-Za-z_]+)(?:\s+(?P<argument>.*?))?\s*$", line)
    if not match:
        return None
    argument = match.group("argument")
    return match.group("marker").upper(), argument.strip() if argument is not None else None
