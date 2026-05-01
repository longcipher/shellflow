"""Unit tests for helpers module.

Tests for parse_helpers function and helper expansion in src/shellflow.py.
"""

from __future__ import annotations

from helpers import parse_helpers
from shellflow import parse_script, run_script


def test_parse_helper_groups():
    script = """
# @HELPER backup_db
#   mysqldump db > backup.sql
# @ENDHELPER
"""
    helpers = parse_helpers(script)
    assert "backup_db" in helpers
    assert len(helpers["backup_db"]) == 1
    assert helpers["backup_db"][0] == "mysqldump db > backup.sql"


def test_helper_expansion():
    script = """
# @HELPER backup_db
#   mysqldump db > backup.sql
# @ENDHELPER

# @LOCAL
backup_db
"""
    helpers = parse_helpers(script)
    blocks = parse_script(script, None, helpers)
    assert len(blocks) == 1
    assert len(blocks[0].commands) == 1
    assert blocks[0].commands[0] == "mysqldump db > backup.sql"


def test_helper_expansion_with_regular_commands():
    script = """
# @HELPER backup_db
#   mysqldump db > backup.sql
# @ENDHELPER

# @LOCAL
echo "starting backup"
backup_db
echo "backup complete"
"""
    helpers = parse_helpers(script)
    blocks = parse_script(script, None, helpers)
    assert len(blocks) == 1
    assert len(blocks[0].commands) == 3
    assert blocks[0].commands[0] == 'echo "starting backup"'
    assert blocks[0].commands[1] == "mysqldump db > backup.sql"
    assert blocks[0].commands[2] == 'echo "backup complete"'


def test_helper_functionality():
    script = """
# @HELPER backup_db
#   echo "backup completed"
# @ENDHELPER
# @LOCAL
backup_db
"""
    helpers = parse_helpers(script)
    blocks = parse_script(script, None, helpers)
    result = run_script(blocks, helpers=helpers)
    assert result.success
