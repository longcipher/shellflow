"""Advanced execution modes for Shellflow.

This module provides advanced execution modes including parallel execution
and dry-run capabilities.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shellflow import Block, ExecutionContext, ExecutionResult


def run_parallel(
    blocks: list[Block],
    context: ExecutionContext,
    servers: dict[str, dict[str, str]] | None = None,
    no_input: bool = False,
    verbose: bool = False,
    output_tail_lines: int = 20,
    run_id: str = "",
    total_blocks: int = 0,
) -> list[ExecutionResult]:
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
    from shellflow.models import ExecutionContext, ExecutionResult
    from shellflow.runner import (
        _execute_block_standard,
        _finalize_block_result,
        _get_verbose_colors,
    )

    if not blocks:
        return []

    # ANSI color codes for verbose output
    colors = _get_verbose_colors()

    results: list[ExecutionResult] = []
    print_lock = threading.Lock()

    def execute_block_worker(block: Block, block_index: int) -> ExecutionResult:
        """Execute a single block and return its result."""
        block_id = f"block-{block_index}"
        start_time = time.perf_counter()
        child_context = ExecutionContext(
            env=dict(context.env),
            last_output=context.last_output,
            success=context.success,
            macros=dict(context.macros),
            helpers=dict(context.helpers),
            variables=dict(context.variables),
            hooks=dict(context.hooks),
        )

        # Execute the block
        with print_lock:
            result = _execute_block_standard(
                block,
                child_context,
                servers,
                no_input,
                verbose,
                block_index,
                total_blocks,
                output_tail_lines,
                colors,
                [],
                run_id,
            )

        result = _finalize_block_result(result, block, block_index, start_time)
        result.block_id = block_id
        result.block_index = block_index

        return result

    # Execute blocks in parallel
    with ThreadPoolExecutor(max_workers=len(blocks)) as executor:
        # Submit all tasks
        future_to_block = {
            executor.submit(execute_block_worker, block, i + 1): (block, i + 1) for i, block in enumerate(blocks)
        }

        # Collect results as they complete
        for future in as_completed(future_to_block):
            block, block_index = future_to_block[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:  # noqa: BLE001
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
