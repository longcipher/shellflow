"""Script execution runner for Shellflow."""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from typing import Any

from . import executor as executor_module
from .constants import (
    ANSI_BLUE,
    ANSI_DIM,
    ANSI_GREEN,
    ANSI_RED,
    ANSI_RESET,
    ANSI_YELLOW,
    EXIT_EXECUTION_FAILURE,
    EXIT_SUCCESS,
    FAILURE_RUNTIME,
    MAX_OUTPUT_LINES,
    SCHEMA_VERSION,
)
from .executor import _apply_block_exports, _execute_block_once, execute_local_traced
from .models import Block, ExecutionContext, ExecutionResult, ReportEvent, RunResult
from .parser import _expand_macros_and_helpers_in_commands, _freeze_preamble


def run_script(  # noqa: PLR0911, PLR0913, PLR0915
    blocks: list[Block],
    servers: dict[str, dict[str, str]] | None = None,
    verbose: bool = False,
    no_input: bool = False,
    dry_run: bool = False,
    mode: str = "sequential",  # New parameter for execution mode
    sequential_output: bool = True,  # New parameter for sequential output
    output_tail_lines: int = MAX_OUTPUT_LINES,
    macros: dict[str, list[str]] | None = None,
    helpers: dict[str, list[str]] | None = None,
    variables: dict[str, str] | None = None,
    hooks: dict[str, list[str]] | None = None,
) -> RunResult:
    """Run a list of blocks sequentially.

    Executes each block in order, updating the execution context between
    blocks. Fails fast on any error.

    Args:
        blocks: List of blocks to execute.
        servers: Optional server configuration dictionary.
        verbose: Whether to print progress information.
        no_input: Whether to disable interactive input.
        dry_run: Whether to only preview execution without running.
        mode: Execution mode ("sequential" or "parallel").
        sequential_output: Whether to print command output sequentially.
        output_tail_lines: Maximum lines to show in verbose output.
        macros: Macro definitions for expansion.
        helpers: Helper definitions for expansion.
        variables: Variable definitions.
        hooks: Hook definitions for lifecycle events.

    Returns:
        RunResult with success status and execution info.
    """
    context = ExecutionContext(macros=macros or {}, helpers=helpers or {}, variables=variables or {}, hooks=hooks or {})
    blocks_executed = 0
    block_results: list[ExecutionResult] = []
    run_id = _new_run_id()
    total_blocks = len(blocks)

    # ANSI color codes for verbose output
    colors = _get_verbose_colors()

    if dry_run:
        return _execute_dry_run(blocks, run_id, total_blocks, no_input, verbose, colors)

    blocks = _prepare_blocks_for_execution(blocks, macros or {}, helpers or {})

    events = [_make_run_started_event(run_id, total_blocks, no_input=no_input)]

    # Execute PRE hooks before main blocks
    if "PRE" in context.hooks:
        hook_result = execute_hook("PRE", context.hooks, context, no_input=no_input)
        if hook_result and not hook_result.success:
            execute_hook("ERROR", context.hooks, context, no_input=no_input)
            execute_hook("FINISHED", context.hooks, context, no_input=no_input)
            # PRE hook failed, fail the entire run
            events.append(
                _make_run_finished_event(
                    run_id,
                    success=False,
                    exit_code=hook_result.exit_code,
                    blocks_executed=0,
                    total_blocks=total_blocks,
                    failure_kind="hook_pre",
                    no_input=no_input,
                )
            )
            return RunResult(
                success=False,
                blocks_executed=0,
                error_message=f"PRE hook failed: {hook_result.error_message}",
                block_results=[],
                run_id=run_id,
                schema_version=SCHEMA_VERSION,
                exit_code=hook_result.exit_code,
                failure_kind="hook_pre",
                no_input=no_input,
                events=events,
            )

    # Group blocks for execution based on mode
    if mode == "parallel":
        # Group consecutive blocks with parallel annotations
        execution_groups = _group_blocks_for_parallel_execution(blocks)
    else:
        # Sequential execution - each block is its own group
        execution_groups = [[block] for block in blocks]

    current_block_index = 0

    for group in execution_groups:
        if len(group) == 1:
            # Sequential execution for single blocks
            block = group[0]
            current_block_index += 1
            i = current_block_index
            block_id = _make_block_id(i)
            events.append(_make_block_started_event(run_id, block_id, i, block, total_blocks))

            before_hook = execute_hook("BEFORE", context.hooks, context, no_input=no_input)
            if before_hook and not before_hook.success:
                execute_hook("ERROR", context.hooks, context, no_input=no_input)
                execute_hook("FINISHED", context.hooks, context, no_input=no_input)
                failure_kind = FAILURE_RUNTIME
                exit_code = _exit_code_for_failure(failure_kind)
                events.append(
                    _make_run_finished_event(
                        run_id,
                        success=False,
                        exit_code=exit_code,
                        blocks_executed=blocks_executed,
                        total_blocks=total_blocks,
                        failure_kind="hook_before",
                        no_input=no_input,
                    )
                )
                return RunResult(
                    success=False,
                    blocks_executed=blocks_executed,
                    error_message=f"BEFORE hook failed: {before_hook.error_message}",
                    block_results=block_results,
                    run_id=run_id,
                    schema_version=SCHEMA_VERSION,
                    exit_code=exit_code,
                    failure_kind="hook_before",
                    no_input=no_input,
                    events=events,
                )

            # Execute the block
            if sequential_output and verbose:
                result = _execute_block_with_sequential_output(
                    block,
                    context,
                    servers,
                    no_input,
                    verbose,
                    i,
                    len(blocks),
                    output_tail_lines,
                    colors,
                    events,
                    run_id,
                )
            else:
                result = _execute_block_standard(
                    block,
                    context,
                    servers,
                    no_input,
                    verbose,
                    i,
                    len(blocks),
                    output_tail_lines,
                    colors,
                    events,
                    run_id,
                )

            blocks_executed += 1
            block_results.append(result)

            # Update context
            context.last_output = result.output
            context.success = result.success
            result.exported_env = _apply_block_exports(block, result, context)
            events.append(_make_block_finished_event(run_id, result, block, total_blocks))

            after_hook = execute_hook("AFTER", context.hooks, context, no_input=no_input)
            if after_hook and not after_hook.success and result.success:
                result.success = False
                result.exit_code = after_hook.exit_code
                result.error_message = f"AFTER hook failed: {after_hook.error_message}"
                result.failure_kind = FAILURE_RUNTIME

            # Fail fast on error
            if not result.success:
                failure_kind = _failure_kind_for_result(result)
                exit_code = _exit_code_for_failure(failure_kind)
                execute_hook("ERROR", context.hooks, context, no_input=no_input)
                execute_hook("FINISHED", context.hooks, context, no_input=no_input)
                events.append(
                    _make_run_finished_event(
                        run_id,
                        success=False,
                        exit_code=exit_code,
                        blocks_executed=blocks_executed,
                        total_blocks=total_blocks,
                        failure_kind=failure_kind,
                        no_input=no_input,
                    )
                )
                return RunResult(
                    success=False,
                    blocks_executed=blocks_executed,
                    error_message=f"Block {i} failed: {result.error_message}",
                    block_results=block_results,
                    run_id=run_id,
                    schema_version=SCHEMA_VERSION,
                    exit_code=exit_code,
                    failure_kind=failure_kind,
                    no_input=no_input,
                    events=events,
                )
        else:
            # Parallel execution for multiple blocks
            start_block_index = current_block_index + 1
            current_block_index += len(group)

            for offset, block in enumerate(group):
                i = start_block_index + offset
                events.append(_make_block_started_event(run_id, _make_block_id(i), i, block, total_blocks))

            # Execute blocks in parallel
            parallel_results = run_parallel(
                group, context, servers, no_input, verbose, output_tail_lines, run_id, total_blocks
            )

            for offset, (result, exported_env_values) in enumerate(parallel_results):
                block = group[offset]
                absolute_index = start_block_index + offset
                result.block_index = absolute_index
                result.block_id = _make_block_id(absolute_index)
                result.source_line = block.source_line
                blocks_executed += 1
                block_results.append(result)
                for name, value in exported_env_values.items():
                    context.env[name] = value
                context.last_output = result.output
                context.success = result.success
                events.append(_make_block_finished_event(run_id, result, block, total_blocks))

                # Fail fast on error in parallel execution
                if not result.success:
                    failure_kind = _failure_kind_for_result(result)
                    exit_code = _exit_code_for_failure(failure_kind)
                    execute_hook("ERROR", context.hooks, context, no_input=no_input)
                    execute_hook("FINISHED", context.hooks, context, no_input=no_input)
                    events.append(
                        _make_run_finished_event(
                            run_id,
                            success=False,
                            exit_code=exit_code,
                            blocks_executed=blocks_executed,
                            total_blocks=total_blocks,
                            failure_kind=failure_kind,
                            no_input=no_input,
                        )
                    )
                    return RunResult(
                        success=False,
                        blocks_executed=blocks_executed,
                        error_message=f"Block {result.block_index} failed: {result.error_message}",
                        block_results=block_results,
                        run_id=run_id,
                        schema_version=SCHEMA_VERSION,
                        exit_code=exit_code,
                        failure_kind=failure_kind,
                        no_input=no_input,
                        events=events,
                    )

    success_hook = execute_hook("SUCCESS", context.hooks, context, no_input=no_input)
    if success_hook and not success_hook.success:
        execute_hook("ERROR", context.hooks, context, no_input=no_input)
        execute_hook("FINISHED", context.hooks, context, no_input=no_input)
        events.append(
            _make_run_finished_event(
                run_id,
                success=False,
                exit_code=EXIT_EXECUTION_FAILURE,
                blocks_executed=blocks_executed,
                total_blocks=total_blocks,
                failure_kind="hook_success",
                no_input=no_input,
            )
        )
        return RunResult(
            success=False,
            blocks_executed=blocks_executed,
            error_message=f"SUCCESS hook failed: {success_hook.error_message}",
            block_results=block_results,
            run_id=run_id,
            schema_version=SCHEMA_VERSION,
            exit_code=EXIT_EXECUTION_FAILURE,
            failure_kind="hook_success",
            no_input=no_input,
            events=events,
        )

    finished_hook = execute_hook("FINISHED", context.hooks, context, no_input=no_input)
    if finished_hook and not finished_hook.success:
        events.append(
            _make_run_finished_event(
                run_id,
                success=False,
                exit_code=EXIT_EXECUTION_FAILURE,
                blocks_executed=blocks_executed,
                total_blocks=total_blocks,
                failure_kind="hook_finished",
                no_input=no_input,
            )
        )
        return RunResult(
            success=False,
            blocks_executed=blocks_executed,
            error_message=f"FINISHED hook failed: {finished_hook.error_message}",
            block_results=block_results,
            run_id=run_id,
            schema_version=SCHEMA_VERSION,
            exit_code=EXIT_EXECUTION_FAILURE,
            failure_kind="hook_finished",
            no_input=no_input,
            events=events,
        )

    events.append(
        _make_run_finished_event(
            run_id,
            success=True,
            exit_code=EXIT_SUCCESS,
            blocks_executed=blocks_executed,
            total_blocks=total_blocks,
            no_input=no_input,
        )
    )
    return RunResult(
        success=True,
        blocks_executed=blocks_executed,
        block_results=block_results,
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        exit_code=EXIT_SUCCESS,
        no_input=no_input,
        events=events,
    )


def _new_run_id() -> str:
    """Create a stable run identifier for structured output."""
    return f"run-{uuid.uuid4().hex}"


def _make_block_id(index: int) -> str:
    """Create a stable block identifier within a run."""
    return f"block-{index}"


def _make_run_started_event(run_id: str, total_blocks: int, *, no_input: bool = False) -> ReportEvent:
    """Build the run-start event."""
    return ReportEvent(
        event="run_started",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        total_blocks=total_blocks,
        no_input=no_input,
    )


def _make_block_started_event(run_id: str, block_id: str, index: int, block: Block, total_blocks: int) -> ReportEvent:
    """Build the block-start event."""
    return ReportEvent(
        event="block_started",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        block_id=block_id,
        block_index=index,
        target=block.target,
        host=block.host,
        source_line=block.source_line,
        total_blocks=total_blocks,
    )


def _make_block_finished_event(run_id: str, result: ExecutionResult, block: Block, total_blocks: int) -> ReportEvent:
    """Build the block-finished event."""
    return ReportEvent(
        event="block_finished",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        success=result.success,
        exit_code=result.exit_code,
        block_id=result.block_id,
        block_index=result.block_index,
        target=block.target,
        host=block.host,
        source_line=result.source_line,
        total_blocks=total_blocks,
        attempts=result.attempts,
        timeout_seconds=result.timeout_seconds,
        failure_kind=_failure_kind_for_result(result),
        no_input=result.no_input,
        block=result,
    )


def _make_block_retrying_event(
    run_id: str,
    block_id: str,
    index: int,
    block: Block,
    total_blocks: int,
    *,
    attempts: int,
    failure_kind: str | None,
) -> ReportEvent:
    """Build the block-retrying event."""
    return ReportEvent(
        event="block_retrying",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        block_id=block_id,
        block_index=index,
        target=block.target,
        host=block.host,
        source_line=block.source_line,
        total_blocks=total_blocks,
        attempts=attempts,
        timeout_seconds=block.timeout_seconds,
        failure_kind=failure_kind,
        no_input=False,
    )


def _make_run_finished_event(
    run_id: str,
    success: bool,
    exit_code: int,
    blocks_executed: int,
    total_blocks: int,
    *,
    failure_kind: str | None = None,
    no_input: bool = False,
) -> ReportEvent:
    """Build the run-finished event."""
    return ReportEvent(
        event="run_finished",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        success=success,
        exit_code=exit_code,
        blocks_executed=blocks_executed,
        total_blocks=total_blocks,
        failure_kind=failure_kind,
        no_input=no_input,
    )


def _make_dry_run_started_event(run_id: str, total_blocks: int, *, no_input: bool = False) -> ReportEvent:
    """Build the dry-run start event."""
    return ReportEvent(
        event="dry_run_started",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        total_blocks=total_blocks,
        no_input=no_input,
    )


def _make_dry_run_block_event(run_id: str, block_id: str, index: int, block: Block, total_blocks: int) -> ReportEvent:
    """Build a dry-run block-plan event."""
    return ReportEvent(
        event="dry_run_block",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        block_id=block_id,
        block_index=index,
        target=block.target,
        host=block.host,
        source_line=block.source_line,
        total_blocks=total_blocks,
    )


def _make_dry_run_finished_event(run_id: str, total_blocks: int, *, no_input: bool = False) -> ReportEvent:
    """Build the dry-run finished event."""
    return ReportEvent(
        event="dry_run_finished",
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        success=True,
        exit_code=EXIT_SUCCESS,
        blocks_executed=0,
        total_blocks=total_blocks,
        no_input=no_input,
    )


def _finalize_block_result(result: ExecutionResult, block: Block, index: int, started_at: float) -> ExecutionResult:
    """Attach reporting metadata to a block result."""
    result.block_id = _make_block_id(index)
    result.block_index = index
    result.source_line = block.source_line
    result.timeout_seconds = block.timeout_seconds
    result.duration_ms = max(int((time.perf_counter() - started_at) * 1000), 0)
    return result


def _execute_dry_run(
    blocks: list[Block],
    run_id: str,
    total_blocks: int,
    no_input: bool,
    verbose: bool,
    colors: dict[str, str],
) -> RunResult:
    """Execute dry run - preview execution plan without running commands."""
    events = [_make_dry_run_started_event(run_id, total_blocks, no_input=no_input)]

    for i, block in enumerate(blocks, 1):
        block_id = _make_block_id(i)
        events.append(_make_dry_run_block_event(run_id, block_id, i, block, total_blocks))
        if verbose:
            if block.is_local:
                print(f"{colors['BLUE']}[plan {i}/{len(blocks)}] LOCAL{colors['RESET']}")
            else:
                host = block.host or "unknown"
                print(f"{colors['YELLOW']}[plan {i}/{len(blocks)}] REMOTE: {host}{colors['RESET']}")
            for command in _commands_for_display(block):
                print(f"{colors['DIM']}$ {command}{colors['RESET']}")

    events.append(_make_dry_run_finished_event(run_id, total_blocks, no_input=no_input))
    return RunResult(
        success=True,
        blocks_executed=0,
        block_results=[],
        run_id=run_id,
        schema_version=SCHEMA_VERSION,
        exit_code=EXIT_SUCCESS,
        no_input=no_input,
        events=events,
    )


def _execute_block_with_sequential_output(  # noqa: PLR0913
    block: Block,
    context: ExecutionContext,
    servers: dict[str, dict[str, str]] | None,
    no_input: bool,
    verbose: bool,
    block_index: int,
    total_blocks: int,
    output_tail_lines: int,
    colors: dict[str, str],
    events: list[ReportEvent] | None = None,
    run_id: str | None = None,
) -> ExecutionResult:
    """Execute block with sequential per-command output (verbose mode)."""
    # Print context before executing
    for env_line in _iter_display_context(context):
        print(f"{colors['DIM']}@env {env_line}{colors['RESET']}")

    # Use sequential execution with per-command output
    attempt_count = 0
    max_attempts = block.retry_count + 1
    result: ExecutionResult | None = None

    while True:
        attempt_count += 1
        started_at = time.perf_counter()

        result = _execute_block_commands_sequential(
            block,
            context,
            servers,
            no_input,
            verbose,
            block_index,
            total_blocks,
            output_tail_lines,
        )
        result = _finalize_block_result(result, block, block_index, started_at)
        result.attempts = attempt_count

        if result.success or result.timed_out or attempt_count >= max_attempts:
            break

        # Emit retry event
        if events is not None and run_id is not None:
            events.append(
                _make_block_retrying_event(
                    run_id,
                    _make_block_id(block_index),
                    block_index,
                    block,
                    total_blocks,
                    attempts=attempt_count,
                    failure_kind=_failure_kind_for_result(result),
                )
            )

        if verbose:
            print(f"{colors['YELLOW']}↻ Retrying attempt {attempt_count + 1}/{max_attempts}{colors['RESET']}")

    # Print success/failure status
    if result and result.success:
        print(f"{colors['GREEN']}✓ Success{colors['RESET']}\n")
    elif result:
        print(f"{colors['RED']}✗ Failed: {result.error_message}{colors['RESET']}\n")

    return result


def _execute_block_standard(  # noqa: PLR0913
    block: Block,
    context: ExecutionContext,
    servers: dict[str, dict[str, str]] | None,
    no_input: bool,
    verbose: bool,
    block_index: int,
    total_blocks: int,
    output_tail_lines: int,
    colors: dict[str, str],
    events: list[ReportEvent],
    run_id: str,
) -> ExecutionResult:
    """Execute block using standard execution path."""
    # Print block info if verbose
    if verbose:
        if block.is_local:
            print(f"{colors['BLUE']}[{block_index}/{total_blocks}] LOCAL{colors['RESET']}")
        else:
            host = block.host or "unknown"
            print(f"{colors['YELLOW']}[{block_index}/{total_blocks}] REMOTE: {host}{colors['RESET']}")
        for env_line in _iter_display_context(context):
            print(f"{colors['DIM']}@env {env_line}{colors['RESET']}")
        for command in _commands_for_display(block):
            print(f"{colors['DIM']}$ {command}{colors['RESET']}")

    # Execute the block, retrying only bounded runtime failures
    attempt_count = 0
    max_attempts = block.retry_count + 1
    result: ExecutionResult | None = None

    while True:
        attempt_count += 1
        started_at = time.perf_counter()
        result = _execute_block_once(block, context, no_input=no_input, servers=servers)
        result = _finalize_block_result(result, block, block_index, started_at)
        result.attempts = attempt_count

        if result.success or result.timed_out or attempt_count >= max_attempts:
            break

        # Emit retry event
        events.append(
            _make_block_retrying_event(
                run_id,
                _make_block_id(block_index),
                block_index,
                block,
                total_blocks,
                attempts=attempt_count,
                failure_kind=_failure_kind_for_result(result),
            )
        )

        if verbose:
            print(f"{colors['YELLOW']}↻ Retrying attempt {attempt_count + 1}/{max_attempts}{colors['RESET']}")

    # Print output if verbose
    if verbose:
        if result and result.output:
            truncated = _truncate_output_lines(result.output, output_tail_lines)
            print(truncated)
        if result and result.success:
            print(f"{colors['GREEN']}✓ Success{colors['RESET']}\n")
        elif result:
            print(f"{colors['RED']}✗ Failed: {result.error_message}{colors['RESET']}\n")

    return result


def _get_verbose_colors() -> dict[str, str]:
    """Get ANSI color codes for verbose output."""
    return {
        "RESET": ANSI_RESET,
        "RED": ANSI_RED,
        "GREEN": ANSI_GREEN,
        "YELLOW": ANSI_YELLOW,
        "BLUE": ANSI_BLUE,
        "DIM": ANSI_DIM,
    }


def _prepare_blocks_for_execution(
    blocks: list[Block],
    macros: dict[str, list[str]],
    helpers: dict[str, list[str]],
) -> list[Block]:
    """Freeze shared preambles once at execution time and attach them to blocks."""
    cached_preambles: dict[tuple[tuple[str, ...], tuple[tuple[str, str], ...]], list[str]] = {}
    prepared_blocks: list[Block] = []

    for block in blocks:
        key = (
            tuple(block.preamble_commands),
            tuple(sorted(block.preamble_env.items())),
        )
        if key not in cached_preambles:
            frozen_preamble = _freeze_preamble(block.preamble_commands, block.preamble_env)
            cached_preambles[key] = _expand_macros_and_helpers_in_commands(
                frozen_preamble,
                macros,
                helpers,
                block.source_line,
            )

        prepared_blocks.append(
            replace(
                block,
                commands=[*cached_preambles[key], *block.commands],
                preamble_commands=[],
                preamble_env={},
                display_commands=list(block.commands),
            )
        )

    return prepared_blocks


def _copy_execution_context(context: ExecutionContext) -> ExecutionContext:
    """Clone execution context for isolated parallel block execution."""
    return ExecutionContext(
        env=dict(context.env),
        last_output=context.last_output,
        success=context.success,
        macros=dict(context.macros),
        helpers=dict(context.helpers),
        variables=dict(context.variables),
        hooks=dict(context.hooks),
    )


def _commands_for_display(block: Block) -> list[str]:
    """Return commands to show in dry-run and verbose output."""
    if block.display_commands:
        return list(block.display_commands)
    if block.preamble_commands:
        return [*block.preamble_commands, *block.commands]
    return list(block.commands)


def _iter_display_context(context: ExecutionContext) -> list[str]:
    """Render the explicit shared context in a readable shell-style format."""
    entries = [f"SHELLFLOW_LAST_OUTPUT={_quote_display_value(context.last_output)}"]
    entries.extend(f"{key}={_quote_display_value(context.env[key])}" for key in sorted(context.env))
    return entries


def _quote_display_value(value: str) -> str:
    """Quote a context value for human-readable output."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return f'"{escaped}"'


def _truncate_output_lines(output: str, max_lines: int) -> str:
    """Return only the trailing lines of output when truncation is requested."""
    if max_lines <= 0:
        return ""
    lines = output.splitlines()
    if len(lines) <= max_lines:
        return output
    return "\n".join(lines[-max_lines:])


def _print_command_logs(command_logs: list[Any], output_tail_lines: int) -> None:
    """Print grouped command logs for verbose remote execution."""
    for command_log in command_logs:
        print(f"{ANSI_DIM}$ {command_log.command}{ANSI_RESET}")
        if command_log.output:
            print(_truncate_output_lines(command_log.output, output_tail_lines))


def _print_live_command_status(command: str, command_index: int, total_commands: int) -> None:
    """Print the currently executing command as soon as its trace marker appears."""
    print(f"> [{command_index}/{total_commands}] {command}", flush=True)


class _LiveCommandOutputPrinter:
    """Print each traced command's buffered output before the next command starts."""

    def __init__(self, total_commands: int, output_tail_lines: int) -> None:
        self.total_commands = total_commands
        self.output_tail_lines = output_tail_lines
        self.command_count = 0
        self._output_chunks: list[str] = []
        self._lock = threading.Lock()

    def start_command(self, command: str) -> None:
        """Start a command section, flushing the previous command's output first."""
        with self._lock:
            if self.command_count:
                self._flush_locked()
            self.command_count += 1
            _print_live_command_status(command, self.command_count, self.total_commands)

    def append_output(self, chunk: str) -> None:
        """Buffer output for the active traced command."""
        if not chunk:
            return
        with self._lock:
            self._output_chunks.append(chunk)

    def finish(self) -> None:
        """Flush the final command's output after the traced process exits."""
        with self._lock:
            if self.command_count:
                self._flush_locked()

    def _flush_locked(self) -> None:
        output = "".join(self._output_chunks).strip()
        self._output_chunks = []
        if output:
            print(_truncate_output_lines(output, self.output_tail_lines), flush=True)


def _group_blocks_for_parallel_execution(blocks: list[Block]) -> list[list[Block]]:
    """Group blocks for parallel execution based on parallel annotations.

    Consecutive blocks with 'parallel' or 'parallel_group' annotations are grouped together.

    Args:
        blocks: List of blocks to group.

    Returns:
        List of block groups, where each group is a list of blocks to execute in parallel.
    """
    groups: list[list[Block]] = []
    current_group: list[Block] = []
    current_group_key: str | None = None

    for block in blocks:
        group_key = _parallel_group_key(block)
        if group_key is None:
            if current_group:
                groups.append(current_group)
                current_group = []
                current_group_key = None
            groups.append([block])
            continue

        if current_group and current_group_key != group_key:
            groups.append(current_group)
            current_group = []

        current_group.append(block)
        current_group_key = group_key

    if current_group:
        groups.append(current_group)

    return groups


def _parallel_group_key(block: Block) -> str | None:
    """Return the effective parallel grouping key for a block."""
    if "parallel_group" in block.annotations:
        return f"group:{block.annotations['parallel_group']}"
    if "parallel" in block.annotations:
        return "parallel"
    return None


def _execute_block_commands_sequential(
    block: Block,
    context: ExecutionContext,
    servers: dict[str, dict[str, str]] | None,
    no_input: bool,
    verbose: bool,
    block_index: int,
    total_blocks: int,
    output_tail_lines: int,
) -> ExecutionResult:
    """Execute block commands sequentially, printing output after each command.

    For local blocks, commands are executed one at a time for verbose output.
    For remote blocks, all commands are executed in a single SSH connection
    to preserve execution state (e.g., working directory) between commands.

    Returns:
        ExecutionResult combining all command outputs.
    """
    if verbose:
        _print_block_header(block, block_index, total_blocks)

    commands_to_execute = _commands_for_display(block)

    if block.is_remote:
        return _execute_remote_block_sequential(
            block,
            context,
            servers,
            no_input,
            verbose,
            commands_to_execute,
            output_tail_lines,
        )

    return _execute_local_block_sequential(block, context, no_input, verbose, commands_to_execute, output_tail_lines)


def _print_block_header(block: Block, block_index: int, total_blocks: int) -> None:
    """Print block header for verbose output."""
    BLUE = ANSI_BLUE
    YELLOW = ANSI_YELLOW
    RESET = ANSI_RESET

    if block.is_local:
        print(f"{BLUE}[{block_index}/{total_blocks}] LOCAL{RESET}")
    else:
        host = block.host or "unknown"
        print(f"{YELLOW}[{block_index}/{total_blocks}] REMOTE: {host}{RESET}")


def _execute_remote_block_sequential(
    block: Block,
    context: ExecutionContext,
    servers: dict[str, dict[str, str]] | None,
    no_input: bool,
    verbose: bool,
    commands_to_execute: list[str],
    output_tail_lines: int,
) -> ExecutionResult:
    """Execute remote block commands in a single SSH connection."""
    RED = ANSI_RED
    DIM = ANSI_DIM
    RESET = ANSI_RESET

    live_printer = _LiveCommandOutputPrinter(len(commands_to_execute), output_tail_lines) if verbose else None

    result = executor_module.execute_remote(
        block,
        context,
        ssh_config=None,
        no_input=no_input,
        servers=servers,
        on_command=live_printer.start_command if live_printer else None,
        on_output=live_printer.append_output if live_printer else None,
    )

    if verbose:
        if live_printer:
            live_printer.finish()

        # Assign actual command names to parsed logs
        if result.command_logs:
            for i, cl in enumerate(result.command_logs):
                if cl.command == "<remote-command>" and i < len(commands_to_execute):
                    cl.command = commands_to_execute[i]

        # Print grouped logs only when no live trace markers were observed.
        if not (live_printer and live_printer.command_count):
            if result.command_logs:
                _print_command_logs(result.command_logs, output_tail_lines)
                if result.output and not any(command_log.output for command_log in result.command_logs):
                    print(_truncate_output_lines(result.output, output_tail_lines))
            else:
                # Fallback: no command logs, just show commands
                for cmd in commands_to_execute:
                    print(f"{DIM}$ {cmd}{RESET}")
                if result.output:
                    truncated = _truncate_output_lines(result.output, output_tail_lines)
                    print(truncated)
        elif not result.success and result.stderr:
            print(f"{RED}{result.stderr.strip()}{RESET}")

    context.last_output = result.output
    context.success = result.success

    if not result.success and verbose:
        print(f"{RED}✗ {result.error_message}{RESET}\n")

    return result


def _build_local_trace_script(block: Block, context: ExecutionContext, shell: str | None) -> str:
    """Build a local script without tracing for clean output.

    For local execution, we execute all commands in a single script without
    tracing to ensure clean output interleaving. Each command's output
    (stdout and stderr) will be shown in order.

    Args:
        block: The block to execute
        context: Execution context with variables
        shell: Shell to use (bash, zsh, etc.)

    Returns:
        Complete shell script as string
    """

    script_lines = ["set -e"]
    from .executor import _build_context_exports, _build_shell_bootstrap

    script_lines.extend(_build_context_exports(context))
    script_lines.extend(_build_shell_bootstrap(shell))

    # Add all user commands without tracing
    script_lines.extend(block.commands)

    return "\n".join(script_lines)


def _execute_local_block_sequential(
    block: Block,
    context: ExecutionContext,
    no_input: bool,
    verbose: bool,
    commands_to_execute: list[str],
    output_tail_lines: int,
) -> ExecutionResult:
    """Execute a local block with traced per-command verbose output."""
    RED = ANSI_RED
    RESET = ANSI_RESET

    live_printer = _LiveCommandOutputPrinter(len(commands_to_execute), output_tail_lines) if verbose else None

    result = execute_local_traced(
        block,
        context,
        no_input=no_input,
        on_command=live_printer.start_command if live_printer else None,
        on_output=live_printer.append_output if live_printer else None,
    )

    if verbose:
        if live_printer:
            live_printer.finish()

        if not (live_printer and live_printer.command_count):
            if result.command_logs:
                _print_command_logs(result.command_logs, output_tail_lines)
                if result.output and not any(command_log.output for command_log in result.command_logs):
                    print(_truncate_output_lines(result.output, output_tail_lines))
            elif result.output:
                print(_truncate_output_lines(result.output, output_tail_lines))

    # Print exit code if failed
    if not result.success and verbose:
        print(f"{RED}exit {result.exit_code}{RESET}")

    # Update context
    context.last_output = result.output
    context.success = result.success

    return result


def _failure_kind_for_result(result: ExecutionResult) -> str | None:
    """Infer the top-level failure category for a block result."""
    if result.success:
        return None
    if result.timed_out:
        from .constants import FAILURE_TIMEOUT

        return FAILURE_TIMEOUT
    if result.failure_kind is not None:
        return result.failure_kind
    return FAILURE_RUNTIME


def _exit_code_for_failure(failure_kind: str | None) -> int:
    """Map a failure category to the stable CLI exit code."""
    from .constants import (
        EXIT_EXECUTION_FAILURE,
        EXIT_PARSE_FAILURE,
        EXIT_SSH_CONFIG_FAILURE,
        EXIT_SUCCESS,
        EXIT_TIMEOUT_FAILURE,
        FAILURE_PARSE,
        FAILURE_RUNTIME,
        FAILURE_SSH_CONFIG,
        FAILURE_TIMEOUT,
    )

    mapping = {
        None: EXIT_SUCCESS,
        FAILURE_RUNTIME: EXIT_EXECUTION_FAILURE,
        FAILURE_PARSE: EXIT_PARSE_FAILURE,
        FAILURE_SSH_CONFIG: EXIT_SSH_CONFIG_FAILURE,
        FAILURE_TIMEOUT: EXIT_TIMEOUT_FAILURE,
    }
    return mapping.get(failure_kind, EXIT_EXECUTION_FAILURE)


def execute_hook(
    hook_name: str,
    hooks: dict[str, list[str]],
    context: ExecutionContext,
    no_input: bool = False,
) -> ExecutionResult | None:
    """Execute a lifecycle hook if defined.

    Args:
        hook_name: Name of the hook to execute (PRE, POST, etc.)
        hooks: Dictionary of hook definitions
        context: Current execution context
        no_input: Whether to disable interactive input

    Returns:
        ExecutionResult if hook was executed, None if no hook defined
    """
    if hook_name not in hooks:
        return None

    # Create a temporary block for hook execution
    hook_block = Block(
        target="LOCAL",
        commands=hooks[hook_name],
        source_line=0,  # Hooks don't have source lines
    )

    # Execute hook locally
    from .executor import execute_local

    result = execute_local(hook_block, context, no_input=no_input)

    # Update context with hook results
    context.last_output = result.output
    context.success = result.success

    return result


def run_parallel(
    blocks: list[Block],
    context: ExecutionContext,
    servers: dict[str, dict[str, str]] | None,
    no_input: bool,
    verbose: bool,
    output_tail_lines: int,
    run_id: str,
    total_blocks: int,
) -> list[tuple[ExecutionResult, dict[str, str]]]:
    """Execute multiple blocks in parallel.

    Args:
        blocks: List of blocks to execute in parallel
        context: Shared execution context
        servers: Server configuration dictionary
        no_input: Whether to disable interactive input
        verbose: Whether to enable verbose output
        output_tail_lines: Maximum lines for verbose output
        run_id: Unique run identifier
        total_blocks: Total number of blocks in the script

    Returns:
        Ordered block results paired with the env values exported by each block.
    """
    del verbose, output_tail_lines, run_id, total_blocks

    indexed_blocks = list(enumerate(blocks, 1))
    completed: list[tuple[int, ExecutionResult, dict[str, str]]] = []

    def execute_parallel_block(index: int, block: Block) -> tuple[int, ExecutionResult, dict[str, str]]:
        child_context = _copy_execution_context(context)
        attempt_count = 0
        max_attempts = block.retry_count + 1
        result: ExecutionResult | None = None

        while True:
            attempt_count += 1
            started_at = time.perf_counter()
            result = _execute_block_once(block, child_context, no_input=no_input, servers=servers)
            result = _finalize_block_result(result, block, index, started_at)
            result.attempts = attempt_count
            if result.success or result.timed_out or attempt_count >= max_attempts:
                break

        result.exported_env = _apply_block_exports(block, result, child_context)
        exported_env = {name: child_context.env[name] for name in result.exported_env if name in child_context.env}
        return index, result, exported_env

    with ThreadPoolExecutor(max_workers=len(indexed_blocks)) as executor:
        future_map = {executor.submit(execute_parallel_block, index, block): index for index, block in indexed_blocks}
        completed.extend(future.result() for future in as_completed(future_map))

    completed.sort(key=lambda item: item[0])
    return [(result, exported_env) for _, result, exported_env in completed]
