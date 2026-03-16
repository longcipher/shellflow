"""BDD step definitions for Shellflow."""

from __future__ import annotations

import io
import json
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest import mock

from behave import given, then, when

if TYPE_CHECKING:
    from behave.runner import Context

# Add src to path for importing shellflow
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from shellflow import (
    Block,
    ExecutionContext,
    ExecutionResult,
    ParseError,
    SSHConfig,
    execute_remote,
    main,
    parse_script,
    run_script,
)


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


def _read_ssh_config_for_context(context: Context, host: str) -> SSHConfig | None:
    configured_hosts = getattr(context, "configured_hosts", set())
    if host in configured_hosts:
        return SSHConfig(host=host)
    return None


def _fake_execute_remote(
    block: Block,
    context_state: ExecutionContext,
    ssh_config: SSHConfig | None,
    no_input: bool = False,
) -> ExecutionResult:
    """Execute remote blocks in tests without requiring a real SSH server."""
    del context_state
    del no_input
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


def _try_parse_json(text: str) -> Any | None:
    stripped = text.strip()
    if not stripped:
        return None

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _parse_jsonl_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, dict):
            return []
        events.append(parsed)
    return events


def _event_name(event: dict[str, Any]) -> str | None:
    for key in ("event", "type", "name", "kind"):
        value = event.get(key)
        if isinstance(value, str):
            return value
    return None


def _first_block_from_json_report(context: Context) -> dict[str, Any]:
    payload = getattr(context, "json_output", None)
    if not isinstance(payload, dict):
        raise TypeError(f"Expected JSON object output, got: {getattr(context, 'stdout', '')}")

    blocks = payload.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        raise AssertionError(f"Expected JSON output with a non-empty 'blocks' list, got: {payload}")

    first_block = blocks[0]
    if not isinstance(first_block, dict):
        raise TypeError(f"Expected first block to be a JSON object, got: {first_block!r}")
    return first_block


def _require_jsonl_events(context: Context) -> list[dict[str, Any]]:
    events = getattr(context, "jsonl_events", [])
    if not events:
        raise AssertionError(f"Expected JSON Lines output, got: {getattr(context, 'stdout', '')}")
    return events


def _run_cli_script(
    context: Context,
    script_path: Path,
    extra_args: list[str],
    *,
    configured_hosts: set[str] | None = None,
) -> dict[str, Any]:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()

    configured = configured_hosts if configured_hosts is not None else getattr(context, "configured_hosts", set())

    def fake_or_real_remote(
        block: Block,
        context_state: ExecutionContext,
        ssh_config: SSHConfig | None,
        no_input: bool = False,
    ) -> ExecutionResult:
        if ssh_config is None:
            return execute_remote(block, context_state, ssh_config, no_input=no_input)
        return _fake_execute_remote(block, context_state, ssh_config, no_input=no_input)

    with (
        mock.patch(
            "shellflow.read_ssh_config",
            side_effect=lambda host: SSHConfig(host=host) if host in configured else None,
        ),
        mock.patch("shellflow.execute_remote", side_effect=fake_or_real_remote),
        redirect_stdout(stdout_buffer),
        redirect_stderr(stderr_buffer),
    ):
        try:
            exit_code = main(["run", str(script_path), *extra_args])
        except SystemExit as error:
            exit_code = error.code if isinstance(error.code, int) else 1

    stdout = stdout_buffer.getvalue().strip()
    stderr = stderr_buffer.getvalue().strip()
    return {
        "exit_code": int(exit_code),
        "stdout": stdout,
        "stderr": stderr,
        "json_output": _try_parse_json(stdout),
        "jsonl_events": _parse_jsonl_events(stdout),
    }


def _store_cli_result(context: Context, result: dict[str, Any]) -> None:
    context.exit_code = result["exit_code"]
    context.stdout = result["stdout"]
    context.stderr = result["stderr"]
    context.json_output = result["json_output"]
    context.jsonl_events = result["jsonl_events"]


def when_run_the_script(context: Context) -> None:
    """Run the parsed script against the in-process shellflow runner."""
    script_content = getattr(context, "script_content", None)
    if not script_content:
        raise ValueError("No script content set. Did you call the Given step first?")

    try:
        blocks = parse_script(script_content)
    except ParseError as error:
        context.run_result = None
        context.block_results = []
        context.stdout = ""
        context.stderr = str(error)
        context.exit_code = 1
        return

    with (
        mock.patch(
            "shellflow.read_ssh_config",
            side_effect=lambda host: _read_ssh_config_for_context(context, host),
        ),
        mock.patch("shellflow.execute_remote", side_effect=_fake_execute_remote),
    ):
        result = run_script(blocks, verbose=getattr(context, "verbose", False))

    context.run_result = result
    context.block_results = result.block_results
    context.stdout = "\n".join(block.output for block in result.block_results if block.output)
    context.stderr = result.error_message if not result.success else ""
    context.exit_code = 0 if result.success else 1


def when_run_the_script_with_cli_args(context: Context, *extra_args: str) -> None:
    script_path = getattr(context, "script_path", None)
    if script_path is None:
        raise ValueError("No script file set. Did you call the Given step first?")

    result = _run_cli_script(context, script_path, list(extra_args))
    _store_cli_result(context, result)

    audit_log_path = getattr(context, "audit_log_path", None)
    if audit_log_path and audit_log_path.exists():
        context.audit_log_text = audit_log_path.read_text()


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
            f"Expected output to contain {text!r}, but it did not.\nCombined output: {combined_output}"
        )


def then_output_should_not_contain(context: Context, text: str) -> None:
    """Assert that combined output does not contain the given text."""
    combined_output = getattr(context, "stdout", "") + getattr(context, "stderr", "")
    if text in combined_output:
        raise AssertionError(
            f"Expected output not to contain {text!r}, but it did.\nCombined output: {combined_output}"
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


def then_command_should_succeed(context: Context) -> None:
    then_execution_should_succeed(context)


def then_command_should_fail_deterministically(context: Context) -> None:
    then_execution_should_fail(context)


def then_json_output_should_contain_run_id(context: Context) -> None:
    payload = getattr(context, "json_output", None)
    if not isinstance(payload, dict) or not payload.get("run_id"):
        raise AssertionError(f"Expected JSON output to contain a run_id, got: {getattr(context, 'stdout', '')}")


def then_json_output_should_contain_schema_version(context: Context) -> None:
    payload = getattr(context, "json_output", None)
    if not isinstance(payload, dict) or not payload.get("schema_version"):
        raise AssertionError(f"Expected JSON output to contain a schema_version, got: {getattr(context, 'stdout', '')}")


def then_json_output_should_include_first_block_exit_code(context: Context) -> None:
    first_block = _first_block_from_json_report(context)
    if "exit_code" not in first_block:
        raise AssertionError(f"Expected first block to include exit_code, got: {first_block}")


def then_json_output_should_include_first_block_stdout_separately(context: Context) -> None:
    first_block = _first_block_from_json_report(context)
    if "stdout" not in first_block or "stderr" not in first_block:
        raise AssertionError(f"Expected first block to include stdout and stderr separately, got: {first_block}")


def then_output_should_contain_run_started_before_block_started(context: Context) -> None:
    events = _require_jsonl_events(context)
    names = [_event_name(event) for event in events]
    try:
        run_started_index = names.index("run_started")
        block_started_index = names.index("block_started")
    except ValueError as error:
        raise AssertionError(f"Expected run_started and block_started events, got: {names}") from error

    if run_started_index >= block_started_index:
        raise AssertionError(f"Expected run_started before block_started, got: {names}")


def then_output_should_contain_block_finished_for_each_block(context: Context, count: int) -> None:
    events = _require_jsonl_events(context)
    block_finished_count = sum(1 for event in events if _event_name(event) == "block_finished")
    if block_finished_count != count:
        raise AssertionError(f"Expected {count} block_finished events, got {block_finished_count}: {events}")


def then_output_should_end_with_run_finished_event(context: Context) -> None:
    events = _require_jsonl_events(context)
    if _event_name(events[-1]) != "run_finished":
        raise AssertionError(f"Expected last event to be run_finished, got: {events[-1]}")


def then_failure_should_exit_with_code(context: Context, case_name: str, expected_code: int) -> None:
    results = getattr(context, "machine_mode_results", None)
    if not isinstance(results, dict) or case_name not in results:
        raise AssertionError(f"No stored machine-readable result for {case_name!r}")

    actual_code = results[case_name]["exit_code"]
    if actual_code != expected_code:
        raise AssertionError(f"Expected {case_name} exit code {expected_code}, got {actual_code}: {results[case_name]}")


def then_command_should_fail_with_timeout_exit_code(context: Context, expected_code: int) -> None:
    actual_code = getattr(context, "exit_code", None)
    if actual_code != expected_code:
        raise AssertionError(
            f"Expected timeout exit code {expected_code}, got {actual_code}.\n"
            f"STDOUT: {getattr(context, 'stdout', '')}\nSTDERR: {getattr(context, 'stderr', '')}"
        )


def then_structured_output_should_mark_block_as_timed_out(context: Context) -> None:
    if isinstance(getattr(context, "json_output", None), dict):
        first_block = _first_block_from_json_report(context)
        if first_block.get("timed_out") is True:
            return

    for event in getattr(context, "jsonl_events", []):
        if event.get("timed_out") is True:
            return
        block = event.get("block")
        if isinstance(block, dict) and block.get("timed_out") is True:
            return

    raise AssertionError(
        f"Expected structured output to mark a block as timed out, got: {getattr(context, 'stdout', '')}"
    )


def then_structured_output_should_record_timeout_duration_policy(context: Context) -> None:
    if isinstance(getattr(context, "json_output", None), dict):
        first_block = _first_block_from_json_report(context)
        if any(key in first_block for key in ("timeout_seconds", "timeout", "timeout_policy")):
            return

    for event in getattr(context, "jsonl_events", []):
        if any(key in event for key in ("timeout_seconds", "timeout", "timeout_policy")):
            return
        block = event.get("block")
        if isinstance(block, dict) and any(key in block for key in ("timeout_seconds", "timeout", "timeout_policy")):
            return

    raise AssertionError(
        f"Expected structured output to record timeout policy details, got: {getattr(context, 'stdout', '')}"
    )


def then_structured_output_should_record_attempts(context: Context, expected_attempts: int) -> None:
    if isinstance(getattr(context, "json_output", None), dict):
        first_block = _first_block_from_json_report(context)
        if first_block.get("attempts") == expected_attempts:
            return

    for event in getattr(context, "jsonl_events", []):
        if event.get("attempts") == expected_attempts:
            return
        block = event.get("block")
        if isinstance(block, dict) and block.get("attempts") == expected_attempts:
            return

    raise AssertionError(
        f"Expected structured output to record {expected_attempts} attempts, got: {getattr(context, 'stdout', '')}"
    )


def then_structured_output_should_include_retrying_before_finish(context: Context) -> None:
    events = _require_jsonl_events(context)
    names = [_event_name(event) or "" for event in events]

    retry_indexes = [index for index, name in enumerate(names) if "retry" in name]
    finish_indexes = [index for index, name in enumerate(names) if name == "block_finished"]
    if not retry_indexes or not finish_indexes:
        raise AssertionError(f"Expected retrying and block_finished events, got: {names}")
    if retry_indexes[0] >= finish_indexes[-1]:
        raise AssertionError(f"Expected retrying event before final block_finished event, got: {names}")


def then_later_block_should_receive_version(context: Context, version: str) -> None:
    then_output_should_contain(context, f"VERSION={version}")


def then_shellflow_last_output_should_still_be_available(context: Context, value: str) -> None:
    then_output_should_contain(context, f"LAST={value}")


def then_structured_output_should_indicate_no_interactive_input(context: Context) -> None:
    payload = getattr(context, "json_output", None)
    if isinstance(payload, dict):
        payload_text = json.dumps(payload)
        if "input" in payload_text.lower() or payload.get("no_input") is True:
            return

    for event in getattr(context, "jsonl_events", []):
        event_text = json.dumps(event)
        if "input" in event_text.lower() or event.get("no_input") is True:
            return

    raise AssertionError(
        f"Expected structured output to mention unavailable interactive input, got: {getattr(context, 'stdout', '')}"
    )


def then_no_block_commands_should_be_executed(context: Context) -> None:
    marker_path = getattr(context, "dry_run_marker_path", None)
    if marker_path is None:
        raise AssertionError("No dry-run marker path recorded for this scenario.")
    if marker_path.exists():
        raise AssertionError(f"Expected dry-run to skip execution, but marker file exists: {marker_path}")


def then_output_should_describe_planned_blocks_in_order(context: Context) -> None:
    stdout = getattr(context, "stdout", "")
    local_index = stdout.find("LOCAL")
    remote_index = stdout.find("REMOTE")
    if local_index != -1 and remote_index != -1 and local_index < remote_index:
        return

    events = getattr(context, "jsonl_events", [])
    targets = [json.dumps(event) for event in events]
    joined_targets = "\n".join(targets)
    local_index = joined_targets.find("LOCAL")
    remote_index = joined_targets.find("REMOTE")
    if local_index != -1 and remote_index != -1 and local_index < remote_index:
        return

    raise AssertionError(f"Expected output to describe planned LOCAL and REMOTE blocks in order, got: {stdout}")


def then_output_should_include_structured_dry_run_events(context: Context) -> None:
    events = _require_jsonl_events(context)
    if any("dry" in (_event_name(event) or "") for event in events):
        return
    raise AssertionError(f"Expected JSONL dry-run events, got: {events}")


def then_audit_log_file_should_contain_jsonl_events(context: Context) -> None:
    audit_log_path = getattr(context, "audit_log_path", None)
    if audit_log_path is None or not audit_log_path.exists():
        raise AssertionError(f"Expected audit log file to exist, got: {audit_log_path}")

    audit_log_text = audit_log_path.read_text().strip()
    if not audit_log_text:
        raise AssertionError("Expected audit log file to contain data, but it was empty.")

    parsed_events = _parse_jsonl_events(audit_log_text)
    if not parsed_events:
        raise AssertionError(f"Expected audit log to contain JSONL events, got: {audit_log_text}")


def then_audit_log_should_redact_secret_like_value(context: Context, secret_value: str) -> None:
    audit_log_path = getattr(context, "audit_log_path", None)
    if audit_log_path is None or not audit_log_path.exists():
        raise AssertionError(f"Expected audit log file to exist, got: {audit_log_path}")

    audit_log_text = audit_log_path.read_text()
    if secret_value in audit_log_text:
        raise AssertionError(f"Expected audit log to redact {secret_value!r}, but it was present: {audit_log_text}")


@given("a script file with the following content:")
def step_given_script_file_with_content(context: Context) -> None:
    given_script_file_with_content(context, context.text)


@given("a script file with a local block that prints a release version")
def step_given_script_file_with_local_release_version(context: Context) -> None:
    given_script_file_with_content(
        context,
        """
        # @LOCAL
        echo "2026.03.15"
        """,
    )


@given("a script file with two local blocks that both succeed")
def step_given_script_file_with_two_local_blocks(context: Context) -> None:
    given_script_file_with_content(
        context,
        """
        # @LOCAL
        echo "first"

        # @LOCAL
        echo "second"
        """,
    )


@given("the relevant failing scripts for parse, missing SSH host, block failure, and timeout")
def step_given_relevant_failing_scripts(context: Context) -> None:
    timeout_script = create_temp_script(
        """
        # @LOCAL
        # @TIMEOUT 1
        sleep 5
        """.strip("\n")
    )

    context.machine_mode_scripts = {
        "parse": {
            "path": create_temp_script(
                """
                # @BROKEN
                echo "bad"
                """.strip("\n")
            ),
            "configured_hosts": set(),
        },
        "missing_ssh_host": {
            "path": create_temp_script(
                """
                # @REMOTE missing-host
                echo "missing"
                """.strip("\n")
            ),
            "configured_hosts": set(),
        },
        "block_failure": {
            "path": create_temp_script(
                """
                # @LOCAL
                exit 1
                """.strip("\n")
            ),
            "configured_hosts": set(),
        },
        "timeout": {
            "path": timeout_script,
            "configured_hosts": set(),
        },
    }


@given("a script file with a local block that exceeds its timeout directive")
def step_given_script_file_with_timeout_directive(context: Context) -> None:
    given_script_file_with_content(
        context,
        """
        # @LOCAL
        # @TIMEOUT 1
        sleep 5
        """,
    )


@given("a script file with a local block that fails once and then succeeds with a retry directive")
def step_given_script_file_with_retry_directive(context: Context) -> None:
    marker_dir = Path(tempfile.mkdtemp())
    retry_marker = marker_dir / "retry-once.marker"
    given_script_file_with_content(
        context,
        f"""
        # @LOCAL
        # @RETRY 1
        if [ ! -f \"{retry_marker}\" ]; then
          touch \"{retry_marker}\"
          exit 1
        fi
        echo \"recovered\"
        """,
    )


@given("a script file whose first block exports VERSION from stdout")
def step_given_script_file_with_export_version(context: Context) -> None:
    given_script_file_with_content(
        context,
        """
        # @LOCAL
        # @EXPORT VERSION=stdout
        echo "1.2.3"

        # @LOCAL
        printf 'VERSION=%s\n' "$VERSION"
        printf 'LAST=%s\n' "$SHELLFLOW_LAST_OUTPUT"
        """,
    )


@given("a script file with a local block that reads from standard input")
def step_given_script_file_that_reads_stdin(context: Context) -> None:
    given_script_file_with_content(
        context,
        """
        # @LOCAL
        read -r reply
        printf 'reply=%s\n' "$reply"
        """,
    )


@given("a script file with local and remote blocks")
def step_given_script_file_with_local_and_remote_blocks(context: Context) -> None:
    marker_dir = Path(tempfile.mkdtemp())
    marker_path = marker_dir / "dry-run-executed.marker"
    context.dry_run_marker_path = marker_path
    given_host_configured_in_ssh_config(context, "testhost")
    given_script_file_with_content(
        context,
        f"""
        # @LOCAL
        printf 'executed' > \"{marker_path}\"

        # @REMOTE testhost
        echo "remote preview"
        """,
    )


@given("a script file with a named export that looks like a secret")
def step_given_script_file_with_secret_like_export(context: Context) -> None:
    context.secret_like_value = "super" + "-secret-token"
    given_script_file_with_content(
        context,
        f"""
        # @LOCAL
        # @EXPORT API_TOKEN=stdout
        echo "{context.secret_like_value}"
        """,
    )


@given('a script file with a remote "{shell_name}" block')
def step_given_script_file_with_remote_shell_block(context: Context, shell_name: str) -> None:
    given_script_file_with_content(
        context,
        f"""
        # @REMOTE testhost
        # @SHELL {shell_name}
        echo "bootstrap-check"
        """,
    )


@given("a script with content:")
def step_given_script_with_content(context: Context) -> None:
    given_script_with_content(context, context.text)


@given('host "{host}" is configured in SSH config')
def step_given_host_configured_in_ssh_config(context: Context, host: str) -> None:
    given_host_configured_in_ssh_config(context, host)


@when("I run the script")
def step_when_run_the_script(context: Context) -> None:
    when_run_the_script(context)


@when("I inspect the generated remote script payload")
def step_when_inspect_generated_remote_script_payload(context: Context) -> None:
    script_content = getattr(context, "script_content", None)
    if not script_content:
        raise ValueError("No script content set. Did you call the Given step first?")

    blocks = parse_script(script_content)
    if len(blocks) != 1 or not blocks[0].is_remote:
        raise AssertionError(f"Expected exactly one remote block, got: {blocks}")

    block = blocks[0]
    ssh_config = _read_ssh_config_for_context(context, block.host or "")
    if ssh_config is None:
        raise AssertionError(f"Remote host not configured for test: {block.host}")

    mock_result = mock.Mock(returncode=0, stdout="", stderr="")
    with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
        result = execute_remote(block, ExecutionContext(), ssh_config)

    if not result.success:
        raise AssertionError(f"Expected execute_remote to succeed, got: {result}")

    context.stdout = mock_run.call_args.kwargs["input"]
    context.stderr = ""
    context.exit_code = 0


@when("I run the script with JSON output enabled")
def step_when_run_the_script_with_json_output(context: Context) -> None:
    when_run_the_script_with_cli_args(context, "--json")


@when("I run the script with JSON Lines output enabled")
def step_when_run_the_script_with_json_lines_output(context: Context) -> None:
    when_run_the_script_with_cli_args(context, "--jsonl")


@when("I run each script in machine-readable mode")
def step_when_run_each_script_in_machine_readable_mode(context: Context) -> None:
    machine_mode_scripts = getattr(context, "machine_mode_scripts", None)
    if not isinstance(machine_mode_scripts, dict):
        raise TypeError("No machine-mode scripts set. Did you call the Given step first?")

    results: dict[str, dict[str, Any]] = {}
    for case_name, case_data in machine_mode_scripts.items():
        results[case_name] = _run_cli_script(
            context,
            case_data["path"],
            ["--json"],
            configured_hosts=case_data["configured_hosts"],
        )

    context.machine_mode_results = results


@when("I run the script in machine-readable mode")
def step_when_run_the_script_in_machine_readable_mode(context: Context) -> None:
    when_run_the_script_with_cli_args(context, "--jsonl")


@when("I run the script with no-input enabled")
def step_when_run_the_script_with_no_input_enabled(context: Context) -> None:
    when_run_the_script_with_cli_args(context, "--no-input", "--json")


@when("I run the script in dry-run mode")
def step_when_run_the_script_in_dry_run_mode(context: Context) -> None:
    when_run_the_script_with_cli_args(context, "--dry-run", "--jsonl")


@when("I run the script with an audit log path")
def step_when_run_the_script_with_audit_log_path(context: Context) -> None:
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as audit_log_file:
        audit_log_path = Path(audit_log_file.name)
    audit_log_path.unlink()
    context.audit_log_path = audit_log_path
    when_run_the_script_with_cli_args(context, "--audit-log", str(audit_log_path), "--jsonl")


@when("the script is parsed")
def step_when_the_script_is_parsed(context: Context) -> None:
    when_the_script_is_parsed(context)


@then("the execution should succeed")
def step_then_execution_should_succeed(context: Context) -> None:
    then_execution_should_succeed(context)


@then("the execution should fail")
def step_then_execution_should_fail(context: Context) -> None:
    then_execution_should_fail(context)


@then("the command should succeed")
def step_then_command_should_succeed(context: Context) -> None:
    then_command_should_succeed(context)


@then("the JSON output should contain a run id")
def step_then_json_output_should_contain_run_id(context: Context) -> None:
    then_json_output_should_contain_run_id(context)


@then("the JSON output should contain a schema version")
def step_then_json_output_should_contain_schema_version(context: Context) -> None:
    then_json_output_should_contain_schema_version(context)


@then("the JSON output should include the first block exit code")
def step_then_json_output_should_include_first_block_exit_code(context: Context) -> None:
    then_json_output_should_include_first_block_exit_code(context)


@then("the JSON output should include the first block stdout separately from stderr")
def step_then_json_output_should_include_first_block_stdout_separately(context: Context) -> None:
    then_json_output_should_include_first_block_stdout_separately(context)


@then("the output should contain a run_started event before a block_started event")
def step_then_output_should_contain_run_started_before_block_started(context: Context) -> None:
    then_output_should_contain_run_started_before_block_started(context)


@then("the output should contain a block_finished event for each block")
def step_then_output_should_contain_block_finished_event_for_each_block(context: Context) -> None:
    then_output_should_contain_block_finished_for_each_block(context, 2)


@then("the output should end with a run_finished event")
def step_then_output_should_end_with_run_finished_event(context: Context) -> None:
    then_output_should_end_with_run_finished_event(context)


@then("the parse failure should exit with code 2")
def step_then_parse_failure_should_exit_with_code(context: Context) -> None:
    then_failure_should_exit_with_code(context, "parse", 2)


@then("the missing SSH host failure should exit with code 3")
def step_then_missing_ssh_host_failure_should_exit_with_code(context: Context) -> None:
    then_failure_should_exit_with_code(context, "missing_ssh_host", 3)


@then("the block execution failure should exit with code 1")
def step_then_block_execution_failure_should_exit_with_code(context: Context) -> None:
    then_failure_should_exit_with_code(context, "block_failure", 1)


@then("the timeout failure should exit with code 4")
def step_then_timeout_failure_should_exit_with_code(context: Context) -> None:
    then_failure_should_exit_with_code(context, "timeout", 4)


@then("the command should fail with timeout exit code 4")
def step_then_command_should_fail_with_timeout_exit_code(context: Context) -> None:
    then_command_should_fail_with_timeout_exit_code(context, 4)


@then("the structured output should mark the block as timed out")
def step_then_structured_output_should_mark_block_as_timed_out(context: Context) -> None:
    then_structured_output_should_mark_block_as_timed_out(context)


@then("the structured output should record the timeout duration policy")
def step_then_structured_output_should_record_timeout_duration_policy(context: Context) -> None:
    then_structured_output_should_record_timeout_duration_policy(context)


@then("the structured output should record 2 attempts for that block")
def step_then_structured_output_should_record_two_attempts(context: Context) -> None:
    then_structured_output_should_record_attempts(context, 2)


@then("the structured output should include a retrying event before the successful finish event")
def step_then_structured_output_should_include_retrying_before_finish(context: Context) -> None:
    then_structured_output_should_include_retrying_before_finish(context)


@then("the later block should receive VERSION in its environment")
def step_then_later_block_should_receive_version(context: Context) -> None:
    then_later_block_should_receive_version(context, "1.2.3")


@then("SHELLFLOW_LAST_OUTPUT should still be available")
def step_then_shellflow_last_output_should_still_be_available(context: Context) -> None:
    then_shellflow_last_output_should_still_be_available(context, "1.2.3")


@then("the command should fail deterministically instead of waiting for input")
def step_then_command_should_fail_deterministically(context: Context) -> None:
    then_command_should_fail_deterministically(context)


@then("the structured output should indicate that no interactive input was available")
def step_then_structured_output_should_indicate_no_interactive_input(context: Context) -> None:
    then_structured_output_should_indicate_no_interactive_input(context)


@then("no block commands should be executed")
def step_then_no_block_commands_should_be_executed(context: Context) -> None:
    then_no_block_commands_should_be_executed(context)


@then("the output should describe the planned blocks in order")
def step_then_output_should_describe_planned_blocks_in_order(context: Context) -> None:
    then_output_should_describe_planned_blocks_in_order(context)


@then("the output should include structured dry-run events when machine-readable mode is enabled")
def step_then_output_should_include_structured_dry_run_events(context: Context) -> None:
    then_output_should_include_structured_dry_run_events(context)


@then("the audit log file should contain JSON Lines events")
def step_then_audit_log_file_should_contain_json_lines_events(context: Context) -> None:
    then_audit_log_file_should_contain_jsonl_events(context)


@then("the audit log should redact the secret-like exported value")
def step_then_audit_log_should_redact_secret_like_exported_value(context: Context) -> None:
    then_audit_log_should_redact_secret_like_value(context, context.secret_like_value)


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
