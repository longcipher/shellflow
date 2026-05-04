"""Unit tests for variable functionality."""

from shellflow import parse_script, run_script
from shellflow.config import parse_variables


def test_variable_substitution():
    """Test that variables defined with @VAR are substituted in commands."""
    script = """
# @VAR APP_NAME=myapp
# @LOCAL
echo $APP_NAME
"""
    blocks = parse_script(script)
    variables = parse_variables(script)
    result = run_script(blocks, variables=variables)
    assert result.success
    assert "myapp" in result.block_results[0].output
