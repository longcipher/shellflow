"""Unit tests for task annotations feature."""

from __future__ import annotations

from shellflow import parse_script


def test_parse_task_annotations():
    script = """
# @ANNOTATE task1
#   description: Deploy web app
#   timeout: 300
# @LOCAL
echo "deploying"
"""
    blocks = parse_script(script)
    assert blocks[0].annotations['description'] == 'Deploy web app'
    assert blocks[0].annotations['timeout'] == '300'