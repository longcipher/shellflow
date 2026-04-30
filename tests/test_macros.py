"""Unit tests for macros module.

Tests for parse_macros function in src/macros.py.
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from macros import parse_macros


def test_parse_macro_groups():
    script = """
# @MACRO deploy
#   echo "deploy step 1"
#   echo "deploy step 2"
# @ENDMACRO
"""
    macros = parse_macros(script)
    assert 'deploy' in macros
    assert len(macros['deploy']) == 2