"""Tests for advanced execution modes."""

import pytest
from shellflow import run_script, parse_script


def test_parallel_execution():
    """Test parallel execution of blocks."""
    script = """
# @PARALLEL
# @LOCAL
echo "task1"
# @LOCAL
echo "task2"
"""
    blocks = parse_script(script.strip())
    result = run_script(blocks, mode='parallel')
    assert result.success
    combined_output = "\n".join(block_result.output for block_result in result.block_results)
    assert 'task1' in combined_output
    assert 'task2' in combined_output


def test_sequential_execution():
    """Test sequential execution of blocks (default)."""
    script = """
# @LOCAL
echo "first"
# @LOCAL
echo "second"
"""
    blocks = parse_script(script.strip())
    result = run_script(blocks, mode='sequential')
    assert result.success
    combined_output = "\n".join(block_result.output for block_result in result.block_results)
    assert 'first' in combined_output
    assert 'second' in combined_output


def test_parallel_group_annotation():
    """Test parallel execution with named groups."""
    script = """
# @PARALLEL group1
# @LOCAL
echo "group1-task1"
# @LOCAL
echo "group1-task2"

# @LOCAL
echo "sequential-task"
"""
    blocks = parse_script(script.strip())

    # Check that blocks have the correct annotations
    # PARALLEL applies to all subsequent blocks until the end
    assert "parallel_group" in blocks[0].annotations
    assert blocks[0].annotations["parallel_group"] == "group1"
    assert "parallel_group" in blocks[1].annotations
    assert blocks[1].annotations["parallel_group"] == "group1"
    assert "parallel_group" in blocks[2].annotations
    assert blocks[2].annotations["parallel_group"] == "group1"

    result = run_script(blocks, mode='parallel')
    assert result.success
    combined_output = "\n".join(block_result.output for block_result in result.block_results)
    assert 'group1-task1' in combined_output
    assert 'group1-task2' in combined_output
    assert 'sequential-task' in combined_output