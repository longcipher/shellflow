"""Tests for hook system."""

from shellflow import parse_script, run_script
from shellflow.config import parse_hooks


def test_pre_execution_hook():
    script = """
# @HOOK PRE
#   echo "preparing"
# @ENDHOOK
# @LOCAL
echo "main task"
"""
    hooks = parse_hooks(script)
    blocks = parse_script(script, hooks=hooks)
    result = run_script(blocks, hooks=hooks)
    # For now, just check that it succeeds - hook output is not captured in RunResult
    assert result.success
