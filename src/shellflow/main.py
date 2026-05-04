"""Shellflow CLI entry point."""

from __future__ import annotations

import sys

from .cli import cmd_agent_run, cmd_doctor, cmd_run, create_parser


def main(args: list[str] | None = None) -> int:
    """Main entry point for the CLI.

    Args:
        args: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = create_parser()
    parsed_args, extra_args = parser.parse_known_args(args)
    parsed_args.extra_args = extra_args

    if not parsed_args.command:
        parser.print_help()
        return 1  # EXIT_EXECUTION_FAILURE

    if extra_args and parsed_args.command != "run":
        parser.error(f"unrecognized arguments: {' '.join(extra_args)}")

    if parsed_args.command == "run":
        return cmd_run(parsed_args)
    if parsed_args.command == "agent-run":
        return cmd_agent_run(parsed_args)
    if parsed_args.command == "doctor":
        return cmd_doctor(parsed_args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
