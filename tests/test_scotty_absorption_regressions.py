"""Regression tests for Scotty-inspired Shellflow features."""

from __future__ import annotations

import argparse
import json
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

from shellflow import (
    Block,
    ExecutionContext,
    _build_remote_trace_script,
    _parse_debug_trace_command_logs,
    cmd_run,
    main,
    parse_script,
    run_script,
)


def test_remote_trace_preserves_multiline_bash() -> None:
    """Remote tracing must execute the whole block, not line-wrap shell syntax."""
    block = Block(
        target="REMOTE:testhost",
        commands=[
            "if [ -f /tmp/shellflow-file-that-should-not-exist ]; then",
            "echo yes",
            "else",
            "echo no",
            "fi",
        ],
    )

    payload = _build_remote_trace_script(block, ExecutionContext(), "bash")
    result = subprocess.run(
        ["/bin/bash", "--norc", "-s", "-e"],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "no"
    assert "__SHELLFLOW_CMD_" in result.stderr


def test_remote_trace_preserves_repeated_command_entries() -> None:
    """Repeated loop commands should remain visible to the agent trace."""
    logs = _parse_debug_trace_command_logs(
        """__SHELLFLOW_CMD_deadbeef:for i in 1 2
__SHELLFLOW_CMD_deadbeef:echo "$i"
__SHELLFLOW_CMD_deadbeef:echo "$i"
""",
        success=True,
        exit_code=0,
    )

    assert [log.command for log in logs] == ["for i in 1 2", 'echo "$i"', 'echo "$i"']


def test_agent_run_parses_hooks_without_crashing(capsys: pytest.CaptureFixture[str]) -> None:
    """agent-run should use the same parser path as run and not reference an undefined hook variable."""
    script = "# @LOCAL\necho hi\n"
    exit_code = main(["agent-run", "--json-input", json.dumps({"script": script})])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["success"] is True
    assert payload["blocks"][0]["stdout"] == "hi"


def test_agent_run_empty_script_still_emits_json(capsys: pytest.CaptureFixture[str]) -> None:
    """The empty-block agent path should keep the same JSON contract."""
    exit_code = main(["agent-run", "--json-input", json.dumps({"script": "# @option branch=main\n"})])

    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["success"] is True
    assert payload["blocks"] == []


def test_parallel_mode_reports_one_based_stable_block_indexes() -> None:
    """Parallel groups must preserve the agent-facing one-based block indexes."""
    blocks = parse_script(
        """
# @PARALLEL
# @LOCAL
echo first
# @PARALLEL
# @LOCAL
echo second
""".strip()
    )

    result = run_script(blocks, mode="parallel")

    assert [(block.block_id, block.block_index, block.output) for block in result.block_results] == [
        ("block-1", 1, "first"),
        ("block-2", 2, "second"),
    ]


def test_parallel_marker_only_applies_to_the_next_block() -> None:
    """A parallel marker should not leak onto every following block."""
    blocks = parse_script(
        """
# @PARALLEL
# @LOCAL
echo parallel

# @LOCAL
echo sequential
""".strip()
    )

    assert blocks[0].annotations == {"parallel": "true"}
    assert blocks[1].annotations == {}


def test_cli_exposes_parallel_execution_mode(tmp_path: Path) -> None:
    """The run command should expose parallel mode instead of leaving it API-only."""
    script = tmp_path / "parallel.sh"
    script.write_text(
        """
# @PARALLEL
# @LOCAL
echo first
# @PARALLEL
# @LOCAL
echo second
""".strip()
    )

    assert main(["run", str(script), "--mode", "parallel", "--json"]) == 0


def test_preamble_uppercase_assignments_are_frozen_once() -> None:
    """Uppercase prelude assignments should be evaluated once and reused by all blocks."""
    blocks = parse_script(
        """
BUILD_ID=$(date +%s%N)
# @LOCAL
echo "$BUILD_ID"
# @LOCAL
echo "$BUILD_ID"
""".strip()
    )

    result = run_script(blocks)

    assert result.success
    assert result.block_results[0].stdout == result.block_results[1].stdout


def test_dynamic_options_are_resolved_for_run_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Declared options should become stable uppercase env vars for block execution."""
    script = tmp_path / "options.sh"
    script.write_text(
        """
# @option branch=main
# @option release-name=
# @LOCAL
echo "$BRANCH/$RELEASE_NAME"
""".strip()
    )

    exit_code = main(["run", str(script), "--branch=develop", "--release-name", "v1", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["blocks"][0]["stdout"] == "develop/v1"


def test_missing_required_option_fails_before_execution(tmp_path: Path) -> None:
    """Required @option declarations should be enforced before any block runs."""
    script = tmp_path / "required.sh"
    script.write_text(
        """
# @option release-name=
# @LOCAL
echo "should not run"
""".strip()
    )

    assert main(["run", str(script)]) == 2


def test_task_filter_and_macro_target_select_blocks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Named tasks and macros should let callers run a focused subset of a playbook."""
    script = tmp_path / "tasks.sh"
    script.write_text(
        """
# @MACRO deploy build ship
# @TASK build
# @LOCAL
echo build
# @TASK ship
# @LOCAL
echo ship
# @TASK cleanup
# @LOCAL
echo cleanup
""".strip()
    )

    exit_code = main(["run", str(script), "--task", "deploy", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert [block["stdout"] for block in payload["blocks"]] == ["build", "ship"]


def test_unknown_task_target_fails_parse(tmp_path: Path) -> None:
    """Unknown --task targets should fail clearly instead of running the full script."""
    script = tmp_path / "tasks.sh"
    script.write_text("# @TASK build\n# @LOCAL\necho build\n")

    assert main(["run", str(script), "--task", "missing"]) == 2


def test_lifecycle_hooks_run_on_success_and_finished(tmp_path: Path) -> None:
    """SUCCESS and FINISHED hooks should run after successful main execution."""
    marker = tmp_path / "hooks.log"
    blocks = parse_script(
        f"""
# @HOOK SUCCESS
#   echo success >> {marker}
# @ENDHOOK
# @HOOK FINISHED
#   echo finished >> {marker}
# @ENDHOOK
# @LOCAL
echo main
""".strip()
    )
    from hooks import parse_hooks

    result = run_script(
        blocks,
        hooks=parse_hooks(
            blocks[0].commands[0]
            if False
            else f"""
# @HOOK SUCCESS
#   echo success >> {marker}
# @ENDHOOK
# @HOOK FINISHED
#   echo finished >> {marker}
# @ENDHOOK
# @LOCAL
echo main
"""
        ),
    )

    assert result.success
    assert marker.read_text().splitlines() == ["success", "finished"]


def test_error_and_finished_hooks_run_after_failure(tmp_path: Path) -> None:
    """ERROR and FINISHED hooks should run when a main block fails."""
    marker = tmp_path / "hooks.log"
    script = f"""
# @HOOK ERROR
#   echo error >> {marker}
# @ENDHOOK
# @HOOK FINISHED
#   echo finished >> {marker}
# @ENDHOOK
# @LOCAL
exit 7
""".strip()
    from hooks import parse_hooks

    result = run_script(parse_script(script, hooks=parse_hooks(script)), hooks=parse_hooks(script))

    assert not result.success
    assert marker.read_text().splitlines() == ["error", "finished"]


def test_server_config_errors_are_reported_as_parse_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Malformed server definitions should not escape cmd_run as raw ValueError exceptions."""
    script = tmp_path / "bad-server.sh"
    script.write_text("# @SERVER web\n#   user: deploy\n# @LOCAL\necho hi\n")
    args = argparse.Namespace(
        script=str(script),
        ssh_config=None,
        no_input=False,
        dry_run=False,
        verbose=False,
        json=False,
        jsonl=False,
        audit_log=None,
        output_lines=20,
        mode="sequential",
        task=None,
        extra_args=[],
    )

    assert cmd_run(args) == 2
    assert "Parse error" in capsys.readouterr().err
