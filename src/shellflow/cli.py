"""Command-line interface for Shellflow."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .constants import EXIT_EXECUTION_FAILURE, EXIT_PARSE_FAILURE, EXIT_SUCCESS, PACKAGE_NAME
from .exceptions import ParseError

if TYPE_CHECKING:
    from .models import OptionDefinition, RunResult


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="shellflow",
        description="A minimal shell script orchestrator with SSH support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shellflow run script.sh              # Run a script
  shellflow run script.sh -v          # Run with verbose output
    shellflow run script.sh --json       # Emit one machine-readable JSON report
    shellflow run script.sh --jsonl      # Emit streaming JSON Lines events
    shellflow run script.sh --no-input   # Disable interactive stdin consumption
    shellflow run script.sh --dry-run    # Preview the execution plan only
    shellflow run script.sh --audit-log audit.jsonl --jsonl
                                                                             # Mirror redacted events to an audit file
  shellflow --version                  # Show version
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Run command
    run_parser = subparsers.add_parser(
        "run",
        help="Run a shellflow script",
        description="Parse and execute a shellflow script.",
    )
    run_parser.add_argument(
        "script",
        help="Path to the shell script to execute",
    )
    run_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output with colored progress",
    )
    run_parser.add_argument(
        "--output-lines",
        type=int,
        default=20,
        help="Maximum number of trailing log lines to print per command in verbose mode",
    )
    run_parser.add_argument(
        "--ssh-config",
        help="Path to an SSH config file to use instead of ~/.ssh/config",
    )
    run_parser.add_argument(
        "--no-input",
        action="store_true",
        dest="no_input",
        help="Run without interactive stdin and report non-interactive mode in structured output",
    )
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Preview the execution plan without running any block commands",
    )
    run_parser.add_argument(
        "--mode",
        choices=("sequential", "parallel"),
        default="sequential",
        help="Execution mode for blocks annotated with @PARALLEL",
    )
    run_parser.add_argument(
        "--task",
        help="Run a named @TASK or @MACRO target",
    )
    run_parser.add_argument(
        "--audit-log",
        dest="audit_log",
        help="Write a redacted JSON Lines audit log to the given path",
    )
    output_group = run_parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON run report",
    )
    output_group.add_argument(
        "--jsonl",
        action="store_true",
        help="Emit machine-readable JSON Lines events",
    )

    # Agent command for Pydantic-based execution
    agent_parser = subparsers.add_parser(
        "agent-run",
        help="Run a shellflow script via agent interface",
        description="Execute a script using Pydantic-validated input for agent integration.",
    )
    agent_parser.add_argument(
        "--json-input",
        help="JSON input conforming to ShellFlowRunArgs schema",
    )
    agent_parser.add_argument(
        "--ssh-config",
        help="Path to an SSH config file to use instead of ~/.ssh/config",
    )

    # Doctor command for configuration diagnostics
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Check configuration and SSH connections",
        description="Run diagnostics to verify Shellflow configuration and SSH connectivity.",
    )
    doctor_parser.add_argument(
        "script",
        nargs="?",
        help="Optional Shellflow script to validate",
    )
    doctor_parser.add_argument(
        "--ssh-config",
        help="Path to an SSH config file to use instead of ~/.ssh/config",
    )

    return parser


def cmd_run(args: argparse.Namespace) -> int:  # noqa: PLR0915
    """Execute the run command.

    Args:
        args: Parsed arguments for the run command.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    script_path = Path(args.script)

    if args.ssh_config:
        import os

        os.environ["SHELLFLOW_SSH_CONFIG"] = str(Path(args.ssh_config).expanduser())

    if not script_path.exists():
        sys.stderr.write(f"Error: Script not found: {script_path}\n")
        return EXIT_EXECUTION_FAILURE

    try:
        content = script_path.read_text()
    except OSError as e:
        sys.stderr.write(f"Error: Cannot read script: {e}\n")
        return EXIT_EXECUTION_FAILURE

    try:
        from .config import parse_helpers, parse_hooks, parse_macros, parse_server_config, parse_variables
        from .parser import parse_options, parse_script, select_blocks_for_target

        options = parse_options(content)
        option_overrides = _parse_option_overrides(getattr(args, "extra_args", []))
        option_env = resolve_option_values(options, option_overrides)
        macros = parse_macros(content)
        helpers = parse_helpers(content)
        variables = parse_variables(content)
        hooks = parse_hooks(content)
        blocks = parse_script(content, macros, helpers, hooks, option_env)
        blocks = select_blocks_for_target(blocks, macros, getattr(args, "task", None))
        servers = parse_server_config(content)
    except (ParseError, ValueError) as e:
        sys.stderr.write(f"Parse error: {e}\n")
        from .constants import FAILURE_PARSE

        return _exit_code_for_failure(FAILURE_PARSE)

    if not blocks:
        from .runner import run_script

        empty_result = run_script(
            [],
            servers,
            no_input=args.no_input,
            dry_run=args.dry_run,
            mode=args.mode,
            macros=macros,
            helpers=helpers,
            variables=variables,
            hooks=hooks,
        )
        if args.json or args.jsonl:
            if args.json:
                _emit_structured_output_json(empty_result)
            else:
                _emit_structured_output_jsonl(empty_result)
        if args.audit_log:
            _write_audit_log(Path(args.audit_log), empty_result)
        if args.verbose:
            print("No executable blocks found in script.")
        return EXIT_SUCCESS

    machine_mode = args.json or args.jsonl
    from .runner import run_script

    result = run_script(
        blocks,
        servers,
        verbose=args.verbose and not machine_mode,
        no_input=args.no_input,
        dry_run=args.dry_run,
        mode=args.mode,
        output_tail_lines=args.output_lines,
        macros=macros,
        helpers=helpers,
        variables=variables,
        hooks=hooks,
    )

    if args.audit_log:
        _write_audit_log(Path(args.audit_log), result)

    if args.json:
        _emit_structured_output_json(result)
    elif args.jsonl:
        _emit_structured_output_jsonl(result)

    if not result.success:
        exit_code = result.exit_code if result.exit_code != EXIT_SUCCESS else EXIT_EXECUTION_FAILURE
        if not machine_mode:
            sys.stderr.write(f"\n{result.error_message}\n")
        return exit_code

    if args.verbose and not machine_mode:
        print(f"\nCompleted: {result.blocks_executed} block(s) executed successfully.")

    return EXIT_SUCCESS


def cmd_agent_run(args: argparse.Namespace) -> int:
    """Execute the agent-run command using Pydantic-validated input.

    Args:
        args: Parsed arguments for the agent-run command.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    if not args.json_input:
        sys.stderr.write("Error: --json-input is required for agent-run\n")
        return EXIT_EXECUTION_FAILURE

    try:
        # Parse and validate input using Pydantic
        from shellflow_models import ShellFlowRunArgs

        run_args = ShellFlowRunArgs.model_validate_json(args.json_input)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"Error: Invalid input JSON: {e}\n")
        return EXIT_EXECUTION_FAILURE

    if args.ssh_config:
        import os

        os.environ["SHELLFLOW_SSH_CONFIG"] = str(Path(args.ssh_config).expanduser())

    try:
        from .config import parse_helpers, parse_hooks, parse_macros, parse_server_config, parse_variables
        from .parser import parse_options, parse_script

        options = parse_options(run_args.script)
        option_overrides = getattr(run_args, "options", {}) or {}
        option_env = resolve_option_values(options, option_overrides)
        macros = parse_macros(run_args.script)
        helpers = parse_helpers(run_args.script)
        variables = parse_variables(run_args.script)
        hooks = parse_hooks(run_args.script)
        blocks = parse_script(run_args.script, macros, helpers, hooks, option_env)
        servers = parse_server_config(run_args.script)
    except (ParseError, ValueError) as e:
        sys.stderr.write(f"Parse error: {e}\n")
        return EXIT_PARSE_FAILURE

    if not blocks:
        from .runner import run_script

        result = run_script(
            [],
            servers,
            no_input=True,
            dry_run=run_args.dry_run,
            mode="sequential",
            macros=macros,
            helpers=helpers,
            variables=variables,
            hooks=hooks,
        )
        print(json.dumps(result.to_dict()))
        return EXIT_SUCCESS

    from .runner import run_script

    result = run_script(
        blocks,
        servers,
        verbose=False,  # Agent mode doesn't need verbose output
        no_input=True,  # Always non-interactive for agents
        dry_run=run_args.dry_run,
        mode="sequential",
        output_tail_lines=20,
        macros=macros,
        helpers=helpers,
        variables=variables,
        hooks=hooks,
    )

    # Output structured result
    print(json.dumps(result.to_dict()))
    return EXIT_SUCCESS if result.success else EXIT_EXECUTION_FAILURE


def cmd_doctor(args: argparse.Namespace) -> int:
    """Execute the doctor command.

    Args:
        args: Parsed arguments for the doctor command.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    if args.ssh_config:
        import os

        os.environ["SHELLFLOW_SSH_CONFIG"] = str(Path(args.ssh_config).expanduser())

    try:
        script_path = Path(args.script) if args.script else None
        blocks = []
        remote_hosts: list[str] = []
        if script_path is not None:
            if not script_path.exists():
                sys.stderr.write(f"Doctor check failed: script not found: {script_path}\n")
                return EXIT_EXECUTION_FAILURE
            content = script_path.read_text()
            from .config import parse_helpers, parse_hooks, parse_macros, parse_server_config
            from .parser import parse_options, parse_script

            options = parse_options(content)
            option_env = resolve_option_values(options)
            macros = parse_macros(content)
            helpers = parse_helpers(content)
            hooks = parse_hooks(content)
            blocks = parse_script(content, macros, helpers, hooks, option_env)
            parse_server_config(content)
            remote_hosts = sorted({block.host for block in blocks if block.host})

    except (OSError, ParseError, ValueError) as e:
        sys.stderr.write(f"Doctor check failed: {e}\n")
        return EXIT_EXECUTION_FAILURE
    else:
        from .doctor import run_doctor

        result = run_doctor(
            script_path=script_path,
            block_count=len(blocks) if script_path else None,
            remote_hosts=remote_hosts,
        )
        print(result)
        return EXIT_SUCCESS


def _get_version() -> str:
    """Resolve the installed package version, falling back to the source default."""
    try:
        from importlib.metadata import version

        return version(PACKAGE_NAME)
    except Exception:  # noqa: BLE001
        from .constants import DEFAULT_VERSION

        return DEFAULT_VERSION


def _exit_code_for_failure(failure_kind: str) -> int:
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


def _parse_option_overrides(extra_args: list[str]) -> dict[str, str | bool]:
    """Parse dynamic CLI options left over after argparse handles static flags."""
    overrides: dict[str, str | bool] = {}
    i = 0
    while i < len(extra_args):
        raw = extra_args[i]
        if not raw.startswith("--"):
            raise ParseError(f"Unexpected argument '{raw}'")

        item = raw[2:]
        if not item:
            raise ParseError("Unexpected empty option")

        if "=" in item:
            name, value = item.split("=", 1)
            overrides[name] = value
            i += 1
            continue

        name = item
        if i + 1 < len(extra_args) and not extra_args[i + 1].startswith("--"):
            overrides[name] = extra_args[i + 1]
            i += 2
        else:
            overrides[name] = True
            i += 1
    return overrides


def resolve_option_values(
    options: dict[str, OptionDefinition],
    overrides: dict[str, str | bool] | None = None,
) -> dict[str, str]:
    """Resolve declared option values using CLI, environment, then defaults."""
    overrides = overrides or {}
    values: dict[str, str] = {}
    unknown = sorted(set(overrides) - set(options))
    if unknown:
        joined = ", ".join(f"--{name}" for name in unknown)
        raise ParseError(f"Unknown option(s): {joined}")

    for option in options.values():
        raw_value = overrides.get(option.name)
        if option.is_boolean:
            if raw_value is True:
                values[option.env_name] = "1"
            elif isinstance(raw_value, str):
                values[option.env_name] = raw_value
            continue

        value: str | None
        import os

        if isinstance(raw_value, bool):
            raise ParseError(f"--{option.name} expects a value")
        value = raw_value if raw_value is not None else os.environ.get(option.env_name) or option.default

        if option.is_required and not value:
            raise ParseError(f"Missing required option --{option.name}")
        if value is not None:
            values[option.env_name] = value
    return values


def _emit_structured_output_json(run_result: RunResult) -> None:
    """Print a JSON run report."""
    print(json.dumps(run_result.to_dict()))


def _emit_structured_output_jsonl(run_result: RunResult, *, redact_secret_exports: bool = False) -> None:
    """Print JSON Lines events for a run."""
    for event in run_result.events:
        print(json.dumps(event.to_dict(redact_secret_exports=redact_secret_exports)))


def _write_audit_log(path: Path, run_result: RunResult) -> None:
    """Mirror structured JSONL events to an audit log with redaction applied."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(event.to_dict(redact_secret_exports=True)) for event in run_result.events]
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
