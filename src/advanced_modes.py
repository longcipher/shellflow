"""Advanced execution modes for Shellflow.

This module provides advanced execution modes including parallel execution
and dry-run capabilities.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


def run_parallel(
    blocks,
    context,
    servers=None,
    no_input=False,
    verbose=False,
    output_tail_lines=20,
    run_id="",
    total_blocks=0,
):
    """Execute blocks in parallel using a thread pool.

    Args:
        blocks: List of blocks to execute in parallel.
        context: Shared execution context.
        servers: SSH server configurations.
        no_input: Whether to disable interactive input.
        verbose: Whether to enable verbose output.
        output_tail_lines: Maximum output lines to show.
        run_id: Run identifier for events.
        total_blocks: Total number of blocks in the script.

    Returns:
        List of execution results in the order they completed.
    """
    # Import here to avoid circular imports
    from shellflow import (
        ExecutionResult,
        _execute_block_standard,
        _finalize_block_result,
        _apply_block_exports,
        _get_verbose_colors,
    )

    if not blocks:
        return []

    # ANSI color codes for verbose output
    colors = _get_verbose_colors()

    results: list[ExecutionResult] = []
    lock = threading.Lock()

    def execute_block_worker(block: Block, block_index: int) -> ExecutionResult:
        """Execute a single block and return its result."""
        block_id = f"block-{block_index}"
        start_time = time.perf_counter()

        # Execute the block
        result = _execute_block_standard(
            block, context, servers, no_input, verbose, block_index, total_blocks,
            output_tail_lines, colors, [], run_id
        )

        result = _finalize_block_result(result, block, block_index, start_time)
        result.block_id = block_id
        result.block_index = block_index

        # Apply exports to shared context (thread-safe)
        with lock:
            result.exported_env = _apply_block_exports(block, result, context)
            # Update shared context
            context.last_output = result.output
            context.success = result.success

        return result

    # Execute blocks in parallel
    with ThreadPoolExecutor(max_workers=len(blocks)) as executor:
        # Submit all tasks
        future_to_block = {
            executor.submit(execute_block_worker, block, i + 1): (block, i + 1)
            for i, block in enumerate(blocks)
        }

        # Collect results as they complete
        for future in as_completed(future_to_block):
            block, block_index = future_to_block[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                # Handle any exceptions from the worker thread
                error_result = ExecutionResult(
                    success=False,
                    output="",
                    error_message=f"Parallel execution failed: {exc}",
                    block_index=block_index,
                    source_line=block.source_line,
                )
                results.append(error_result)

    # Sort results by block index to maintain order
    results.sort(key=lambda r: r.block_index)

    return results
