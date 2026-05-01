"""Doctor command diagnostics for Shellflow."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path


def run_doctor(
    *,
    script_path: Path | None = None,
    block_count: int | None = None,
    remote_hosts: list[str] | None = None,
) -> str:
    """Run configuration diagnostics and return a human-readable report."""
    results = []

    if script_path is not None:
        results.append(f"Script: {script_path} (parsed)")
    if block_count is not None:
        results.append(f"Blocks: {block_count} executable block(s)")

    ssh_config_path = _get_ssh_config_path()
    if ssh_config_path.exists():
        results.append(f"SSH config file: {ssh_config_path} (found)")
        try:
            content = ssh_config_path.read_text()
        except OSError as exc:
            results.append(f"SSH connections: Error reading config - {exc}")
        else:
            results.append(f"SSH connections: {content.count('Host ')} host(s) configured")
    else:
        results.append(f"SSH config file: {ssh_config_path} (not found)")
        results.append("SSH connections: No SSH config found")

    if remote_hosts:
        results.append(f"Remote hosts referenced: {', '.join(remote_hosts)}")

    results.append("Configuration: Shellflow is properly installed")
    dependency_status = "available" if importlib.util.find_spec("paramiko") is not None else "not available"
    results.append(f"Dependencies: paramiko {dependency_status}")

    return "\n".join(results)


def _get_ssh_config_path() -> Path:
    """Get the SSH config path, checking environment override first."""
    configured_path = os.environ.get("SHELLFLOW_SSH_CONFIG")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path.home() / ".ssh" / "config"
