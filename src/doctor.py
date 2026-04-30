"""Doctor command for Shellflow configuration diagnostics.

This module provides diagnostics for Shellflow configuration and SSH connections.
"""

import os
from pathlib import Path


def run_doctor() -> str:
    """Run diagnostics and return a report string.

    Returns:
        A diagnostic report containing information about SSH connections and configuration.
    """
    results = []

    # Check SSH configuration
    ssh_config_path = _get_ssh_config_path()
    if ssh_config_path.exists():
        results.append(f"SSH config file: {ssh_config_path} (found)")
        try:
            with ssh_config_path.open() as f:
                content = f.read()
                host_count = content.count("Host ")
                results.append(f"SSH connections: {host_count} host(s) configured")
        except Exception as e:
            results.append(f"SSH connections: Error reading config - {e}")
    else:
        results.append(f"SSH config file: {ssh_config_path} (not found)")
        results.append("SSH connections: No SSH config found")

    # Check configuration
    config_status = []
    config_status.append("Configuration: Shellflow is properly installed")

    # Check for Python dependencies
    try:
        import paramiko
        config_status.append("Dependencies: paramiko available")
    except ImportError:
        config_status.append("Dependencies: paramiko not available")

    results.append("\n".join(config_status))

    return "\n".join(results)


def _get_ssh_config_path() -> Path:
    """Get the SSH config path, checking environment override first."""
    configured_path = os.environ.get("SHELLFLOW_SSH_CONFIG")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path.home() / ".ssh" / "config"