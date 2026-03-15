"""BDD step definitions for Shellflow."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from unittest import mock

from behave import given, then, when

if TYPE_CHECKING:
    from behave.runner import Context

# Add src to path for importing shellflow
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from shellflow import Block, ExecutionContext, ExecutionResult, ParseError, SSHConfig, parse_script, run_script


def create_temp_script(content: str) -> Path:
    """Create a temporary script file with the given content."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as handle:
        handle.write(content)
        return Path(handle.name)


def given_script_file_with_content(context: Context, content: str) -> None:
    """Create a script file with the given content."""
    cleaned_content = content.strip("\n")
    script_path = create_temp_script(cleaned_content)
    context.script_path = script_path
    context.script_content = cleaned_content


def given_script_with_content(context: Context, content: str) -> None:
    """Store script content for parsing tests."""
    context.script_content = content.strip("\n")


def given_host_configured_in_ssh_config(context: Context, host: str) -> None:
    """Record a host that is available for mocked SSH execution."""
    configured_hosts = getattr(context, "configured_hosts", set())
    configured_hosts.add(host)
    context.configured_hosts = configured_hosts


def _fake_execute_remote(
    block: Block,
    context_state: ExecutionContext,
    ssh_config: SSHConfig | None,
) -> ExecutionResult:
    """Execute remote blocks in tests without requiring a real SSH server."""
    del context_state
    host = block.host or (ssh_config.host if ssh_config else "unknown")
    script = "\n".join(block.commands)

    for command in block.commands:
        stripped = command.strip()
        if stripped.startswith("exit "):
            exit_code = int(stripped.split(maxsplit=1)[1])
            return ExecutionResult(
                success=False,
                output="",
                exit_code=exit_code,
                error_message=f"SSH exit code: {exit_code}",
            )

    return ExecutionResult(
        success=True,
        output=f"remote execution on {host}\n{script}".strip(),
        exit_code=0,
    )


def when_run_the_script(context: Context) -> None:
    """Run the parsed script against the in-process shellflow runner."""
    script_content = getattr(context, "script_content", None)
    if not script_content:
        raise ValueError("No script content set. Did you call the Given step first?")

    blocks = parse_script(script_content)

    with mock.patch(
        "shellflow.read_ssh_config",
        side_effect=lambda host: SSHConfig(host=host),
    ), mock.patch("shellflow.execute_remote", side_effect=_fake_execute_remote):
        result = run_script(blocks, verbose=getattr(context, "verbose", False))

    context.run_result = result
    context.block_results = result.block_results
    context.stdout = "\n".join(block.output for block in result.block_results if block.output)
    context.stderr = result.error_message if not result.success else ""
    context.exit_code = 0 if result.success else 1


def when_the_script_is_parsed(context: Context) -> None:
    """Parse the script content into blocks."""
    script_content = getattr(context, "script_content", None)
    if script_content is None:
        raise ValueError("No script content set. Did you call the Given step first?")

    try:
        context.parsed_blocks = parse_script(script_content)
        context.parse_error = None
    except ParseError as error:
        context.parsed_blocks = None
        context.parse_error = error


def then_execution_should_succeed(context: Context) -> None:
    """Assert that the script execution succeeded."""
    if getattr(context, "exit_code", None) != 0:
        raise AssertionError(
            f"Expected success but got exit code {context.exit_code}.\n"
            f"STDOUT: {getattr(context, 'stdout', '')}\n"
            f"STDERR: {getattr(context, 'stderr', '')}"
        )


def then_execution_should_fail(context: Context) -> None:
    """Assert that the script execution failed."""
    if getattr(context, "exit_code", None) == 0:
        raise AssertionError("Expected execution to fail, but it succeeded.")


def then_output_should_contain(context: Context, text: str) -> None:
    """Assert that combined output contains the expected text."""
    combined_output = getattr(context, "stdout", "") + getattr(context, "stderr", "")
    if text not in combined_output:
        raise AssertionError(
            f"Expected output to contain {text!r}, but it did not.\n"
            f"Combined output: {combined_output}"
        )


def then_output_should_not_contain(context: Context, text: str) -> None:
    """Assert that combined output does not contain the given text."""
    combined_output = getattr(context, "stdout", "") + getattr(context, "stderr", "")
    if text in combined_output:
        raise AssertionError(
            f"Expected output not to contain {text!r}, but it did.\n"
            f"Combined output: {combined_output}"
        )


def then_count_block_should_be_found(context: Context, count: int) -> None:
    """Assert the expected number of blocks were parsed."""
    blocks = getattr(context, "parsed_blocks", None)
    if blocks is None:
        raise AssertionError(f"Parsing failed: {getattr(context, 'parse_error', None)}")
    if len(blocks) != count:
        raise AssertionError(f"Expected {count} block(s), found {len(blocks)}.")


def then_the_block_type_should_be(context: Context, block_type: str) -> None:
    """Assert that the first parsed block has the expected type."""
    blocks = getattr(context, "parsed_blocks", None)
    if not blocks:
        raise AssertionError("No parsed blocks found.")

    block = blocks[0]
    if block_type == "LOCAL" and not block.is_local:
        raise AssertionError(f"Expected LOCAL block, got {block.target!r}.")
    if block_type == "REMOTE" and not block.is_remote:
        raise AssertionError(f"Expected REMOTE block, got {block.target!r}.")


def then_the_block_host_should_be(context: Context, host: str) -> None:
    """Assert that the first parsed remote block has the expected host."""
    blocks = getattr(context, "parsed_blocks", None)
    if not blocks:
        raise AssertionError("No parsed blocks found.")
    if blocks[0].host != host:
        raise AssertionError(f"Expected host {host!r}, got {blocks[0].host!r}.")


@given("a script file with the following content:")
def step_given_script_file_with_content(context: Context) -> None:
    given_script_file_with_content(context, context.text)


@given("a script with content:")
def step_given_script_with_content(context: Context) -> None:
    given_script_with_content(context, context.text)


@given('host "{host}" is configured in SSH config')
def step_given_host_configured_in_ssh_config(context: Context, host: str) -> None:
    given_host_configured_in_ssh_config(context, host)


@when("I run the script")
def step_when_run_the_script(context: Context) -> None:
    when_run_the_script(context)


@when("the script is parsed")
def step_when_the_script_is_parsed(context: Context) -> None:
    when_the_script_is_parsed(context)


@then("the execution should succeed")
def step_then_execution_should_succeed(context: Context) -> None:
    then_execution_should_succeed(context)


@then("the execution should fail")
def step_then_execution_should_fail(context: Context) -> None:
    then_execution_should_fail(context)


@then('the output should contain "{text}"')
def step_then_output_should_contain(context: Context, text: str) -> None:
    then_output_should_contain(context, text)


@then('the output should not contain "{text}"')
def step_then_output_should_not_contain(context: Context, text: str) -> None:
    then_output_should_not_contain(context, text)


@then("{count:d} block should be found")
def step_then_count_block_should_be_found(context: Context, count: int) -> None:
    then_count_block_should_be_found(context, count)


@then('the block type should be "{block_type}"')
def step_then_the_block_type_should_be(context: Context, block_type: str) -> None:
    then_the_block_type_should_be(context, block_type)


@then('the block host should be "{host}"')
def step_then_the_block_host_should_be(context: Context, host: str) -> None:
    then_the_block_host_should_be(context, host)
