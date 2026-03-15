#!/usr/bin/env python3
"""Wrapper script to run behave with proper paths for Shellflow.

This script works around issues with `uv run behave` by setting up
paths correctly and invoking behave programmatically.
"""

from __future__ import annotations

import sys
from pathlib import Path


def setup_paths() -> Path:
    """Set up Python paths for imports.

    Returns:
        The project root directory.
    """
    # Get the project root (parent of this script)
    project_root = Path(__file__).parent.resolve()

    # Add src and features to the path
    src_path = project_root / "src"
    features_path = project_root / "features"

    # Insert at the beginning of sys.path
    for path in [str(src_path), str(features_path)]:
        if path not in sys.path:
            sys.path.insert(0, path)

    return project_root


def run_behave() -> int:
    """Run behave with proper configuration.

    Returns:
        Exit code from behave.
    """
    setup_paths()

    # Import behave after setting up paths
    from behave.__main__ import main

    return main()


if __name__ == "__main__":
    sys.exit(run_behave())
