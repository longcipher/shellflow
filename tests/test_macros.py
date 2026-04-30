"""Unit tests for macros module.

Tests for parse_macros function and macro expansion in src/shellflow.py.
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from macros import parse_macros
from shellflow import parse_script, ParseError


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


def test_macro_expansion():
    script = """
# @MACRO deploy
#   echo "deploy step 1"
#   echo "deploy step 2"
# @ENDMACRO

# @LOCAL
deploy
"""
    macros = parse_macros(script)
    blocks = parse_script(script, macros)
    assert len(blocks) == 1
    assert len(blocks[0].commands) == 2
    assert blocks[0].commands[0] == 'echo "deploy step 1"'
    assert blocks[0].commands[1] == 'echo "deploy step 2"'


def test_macro_expansion_with_regular_commands():
    script = """
# @MACRO setup
#   echo "setup step 1"
#   echo "setup step 2"
# @ENDMACRO

# @LOCAL
echo "before setup"
setup
echo "after setup"
"""
    macros = parse_macros(script)
    blocks = parse_script(script, macros)
    assert len(blocks) == 1
    assert len(blocks[0].commands) == 4
    assert blocks[0].commands[0] == 'echo "before setup"'
    assert blocks[0].commands[1] == 'echo "setup step 1"'
    assert blocks[0].commands[2] == 'echo "setup step 2"'
    assert blocks[0].commands[3] == 'echo "after setup"'


def test_undefined_macro_error():
    script = """
# @LOCAL
undefined_macro
"""
    macros = parse_macros(script)
    blocks = parse_script(script, macros)
    assert len(blocks) == 1
    assert len(blocks[0].commands) == 1
    assert blocks[0].commands[0] == "undefined_macro"


def test_macro_expanded_only_when_standalone():
    script = """
# @MACRO deploy
#   echo "deploy"
# @ENDMACRO

# @LOCAL
echo "deploy command"  # This should not be expanded
deploy
"""
    macros = parse_macros(script)
    blocks = parse_script(script, macros)
    assert len(blocks) == 1
    assert len(blocks[0].commands) == 2
    assert blocks[0].commands[0] == 'echo "deploy command"  # This should not be expanded'
    assert blocks[0].commands[1] == 'echo "deploy"'