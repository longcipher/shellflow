"""Script parsing functionality for Shellflow."""

from __future__ import annotations

import re
import shlex
import subprocess
import uuid

from .constants import VALID_EXPORT_SOURCES
from .exceptions import ParseError
from .models import Block, OptionDefinition, StructuredExport

BLOCK_MARKER_RE = re.compile(r"^\s*#\s*@(?P<marker>[A-Za-z_]+)(?:\s+(?P<argument>.*?))?\s*$")
MARKER_PREFIX_RE = re.compile(r"^\s*#\s*@")
EXPORT_JSON_RE = re.compile(r"^@EXPORT_JSON")


def _parse_block_marker(line: str) -> tuple[str, str | None] | None:
    """Parse a line as a shellflow marker if it matches exactly."""
    match = BLOCK_MARKER_RE.match(line)
    if not match:
        return None
    argument = match.group("argument")
    return match.group("marker").upper(), argument.strip() if argument is not None else None


def _expand_macros_and_helpers_in_commands(
    commands: list[str],
    macros: dict[str, list[str]] | None,
    helpers: dict[str, list[str]] | None,
    line_no: int,
) -> list[str]:
    """Expand macro and helper calls in a list of commands."""
    if not macros and not helpers:
        return commands

    # Common shell builtins and commands that shouldn't be treated as undefined macros/helpers
    shell_builtins = {
        "echo",
        "cd",
        "pwd",
        "ls",
        "cat",
        "grep",
        "sed",
        "awk",
        "find",
        "xargs",
        "sort",
        "uniq",
        "head",
        "tail",
        "wc",
        "cut",
        "tr",
        "rev",
        "tac",
        "nl",
        "mkdir",
        "rmdir",
        "rm",
        "cp",
        "mv",
        "touch",
        "chmod",
        "chown",
        "ln",
        "tar",
        "gzip",
        "gunzip",
        "bzip2",
        "bunzip2",
        "zip",
        "unzip",
        "ssh",
        "scp",
        "rsync",
        "curl",
        "wget",
        "ping",
        "traceroute",
        "ps",
        "top",
        "kill",
        "killall",
        "pkill",
        "pgrep",
        "sudo",
        "su",
        "whoami",
        "id",
        "groups",
        "passwd",
        "date",
        "cal",
        "uptime",
        "df",
        "du",
        "free",
        "vmstat",
        "iostat",
        "which",
        "whereis",
        "locate",
        "updatedb",
        "make",
        "gcc",
        "g++",
        "javac",
        "java",
        "python",
        "python3",
        "pip",
        "npm",
        "yarn",
        "node",
        "ruby",
        "perl",
        "php",
        "git",
        "svn",
        "hg",
        "bzr",
        "docker",
        "docker-compose",
        "kubectl",
        "helm",
        "systemctl",
        "service",
        "chkconfig",
        "update-rc.d",
        "apt",
        "yum",
        "dnf",
        "pacman",
        "brew",
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "do",
        "done",
        "case",
        "esac",
        "select",
        "function",
        "return",
        "exit",
        "break",
        "continue",
    }

    expanded_commands: list[str] = []
    for command in commands:
        stripped = command.strip()
        if stripped:
            # Check if this entire line is a helper name first (helpers take precedence)
            if helpers and stripped in helpers:
                # Expand the helper
                expanded_commands.extend(helpers[stripped])
            # Check if this entire line is a macro name
            elif macros and stripped in macros:
                # Expand the macro
                expanded_commands.extend(macros[stripped])
            elif re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", stripped) and stripped not in shell_builtins:
                # Single identifier that looks like a macro/helper but isn't defined and not a builtin
                raise ParseError(f"Line {line_no}: Undefined macro or helper '{stripped}'")
            else:
                # Regular command
                expanded_commands.append(command)
        else:
            # Empty line
            expanded_commands.append(command)
    return expanded_commands


def _build_block_commands(
    prelude: list[str],
    body: list[str],
    macros: dict[str, list[str]] | None = None,
    helpers: dict[str, list[str]] | None = None,
    line_no: int = 0,
) -> list[str]:
    """Combine shared prelude with block-specific commands."""
    cleaned_body = _clean_commands(body)
    if not cleaned_body:
        return []
    combined = [*prelude, *cleaned_body]
    return _expand_macros_and_helpers_in_commands(combined, macros, helpers, line_no)


def _parse_positive_int(argument: str | None, *, directive: str, line_no: int) -> int:
    """Parse a positive integer directive argument."""
    if argument is None or not argument.isdigit() or int(argument) <= 0:
        raise ParseError(f"Line {line_no}: @{directive} expects a positive integer")
    return int(argument)


def _parse_non_negative_int(argument: str | None, *, directive: str, line_no: int) -> int:
    """Parse a non-negative integer directive argument."""
    if argument is None or not argument.isdigit():
        raise ParseError(f"Line {line_no}: @{directive} expects a non-negative integer")
    return int(argument)


def _parse_export_directive(argument: str | None, *, line_no: int) -> tuple[str, str]:
    """Parse an @EXPORT NAME=source directive."""
    if not argument or "=" not in argument:
        raise ParseError(f"Line {line_no}: @EXPORT expects NAME=source format")

    name, source = argument.split("=", 1)
    name = name.strip()
    source = source.strip()

    if not _is_valid_env_name(name):
        raise ParseError(f"Line {line_no}: @EXPORT expects a valid environment variable name")

    if source not in VALID_EXPORT_SOURCES:
        valid_sources = ", ".join(sorted(VALID_EXPORT_SOURCES))
        raise ParseError(f"Line {line_no}: @EXPORT source is invalid. Valid sources: {valid_sources}")

    return name, source


def _option_env_name(name: str) -> str:
    """Convert an option name to its canonical shell environment variable."""
    return name.replace("-", "_").upper()


def parse_options(content: str) -> dict[str, OptionDefinition]:
    """Parse Scotty-style # @option declarations from script content."""
    options: dict[str, OptionDefinition] = {}
    for line_no, line in enumerate(content.splitlines(), 1):
        marker = _parse_block_marker(line)
        if not marker or marker[0] != "OPTION":
            continue

        signature = marker[1]
        if not signature:
            raise ParseError(f"Line {line_no}: @OPTION requires a name")

        if "=" in signature:
            name, default = signature.split("=", 1)
            name = name.strip()
            default = _strip_optional_quotes(default.strip())
            is_required = default == ""
            is_boolean = False
            default_value = None if is_required else default
        else:
            name = signature.strip()
            is_required = False
            is_boolean = True
            default_value = None

        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name):
            raise ParseError(f"Line {line_no}: Invalid @OPTION name '{name}'")

        options[name] = OptionDefinition(
            name=name,
            env_name=_option_env_name(name),
            default=default_value,
            is_boolean=is_boolean,
            is_required=is_required,
        )
    return options


def _strip_optional_quotes(value: str) -> str:
    """Remove simple matching quotes around a directive value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


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
        if isinstance(raw_value, bool):
            raise ParseError(f"--{option.name} expects a value")
        value = raw_value if raw_value is not None else __import__("os").environ.get(option.env_name) or option.default

        if option.is_required and not value:
            raise ParseError(f"Missing required option --{option.name}")
        if value is not None:
            values[option.env_name] = value
    return values


def select_blocks_for_target(
    blocks: list[Block],
    macros: dict[str, list[str]],
    target: str | None,
) -> list[Block]:
    """Select blocks for a named task or macro target."""
    if not target:
        return blocks

    tasks_in_file = {block.annotations.get("task") for block in blocks if block.annotations.get("task")}
    tasks_in_file.discard(None)
    if target in macros:
        task_names = macros[target]
        missing = [name for name in task_names if name not in tasks_in_file]
        if missing:
            raise ParseError(f"Macro '{target}' references unknown task(s): {', '.join(missing)}")
        wanted = set(task_names)
        selected = [block for block in blocks if block.annotations.get("task") in wanted]
        selected.sort(key=lambda block: task_names.index(block.annotations["task"]))
        return selected

    if target in tasks_in_file:
        return [block for block in blocks if block.annotations.get("task") == target]

    raise ParseError(f"Unknown task or macro target '{target}'")


def _freeze_preamble(prelude_lines: list[str], injected_env: dict[str, str] | None = None) -> list[str]:
    """Evaluate uppercase prelude assignments once and return frozen exports."""
    injected_env = injected_env or {}
    variable_names = _extract_preamble_variable_names(prelude_lines)
    frozen_env: dict[str, str] = dict(injected_env)

    if variable_names:
        frozen_env.update(_evaluate_preamble_variables(prelude_lines, variable_names, injected_env))

    remaining = _strip_preamble_assignments(prelude_lines)
    export_lines = [f"export {name}={shlex.quote(value)}" for name, value in sorted(frozen_env.items())]
    return [*export_lines, *remaining]


def _extract_preamble_variable_names(lines: list[str]) -> list[str]:
    """Return uppercase assignment names from prelude lines."""
    names: list[str] = []
    seen: set[str] = set()
    for line in lines:
        match = re.match(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)=", line)
        if match and match.group(1) not in seen:
            names.append(match.group(1))
            seen.add(match.group(1))
    return names


def _evaluate_preamble_variables(
    prelude_lines: list[str],
    variable_names: list[str],
    injected_env: dict[str, str],
) -> dict[str, str]:
    """Run the prelude locally and capture selected variable values."""
    begin_marker = f"__SHELLFLOW_PREAMBLE_BEGIN_{uuid.uuid4().hex}__"
    end_marker = f"__SHELLFLOW_PREAMBLE_END_{uuid.uuid4().hex}__"
    dump_lines = [f'printf "%s=%s\\n" {shlex.quote(name)} "${{{name}}}"' for name in variable_names]
    script = "\n".join(
        [
            "set -e",
            *prelude_lines,
            f"echo {shlex.quote(begin_marker)}",
            *dump_lines,
            f"echo {shlex.quote(end_marker)}",
        ]
    )
    env = __import__("os").environ.copy()
    env.update(injected_env)
    try:
        result = subprocess.run(
            ["/bin/bash", "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ParseError(f"Failed to evaluate preamble locally: {exc}") from exc

    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
        raise ParseError(f"Failed to evaluate preamble locally: {message}")

    return _parse_preamble_dump(result.stdout, begin_marker, end_marker, set(variable_names))


def _parse_preamble_dump(output: str, begin_marker: str, end_marker: str, variable_names: set[str]) -> dict[str, str]:
    """Parse the captured variable section from prelude output."""
    lines = output.splitlines()
    try:
        start = lines.index(begin_marker)
        end = lines.index(end_marker)
    except ValueError as exc:
        raise ParseError("Failed to evaluate preamble locally: missing variable markers") from exc
    if end < start:
        raise ParseError("Failed to evaluate preamble locally: malformed variable markers")

    values: dict[str, str] = {}
    for line in lines[start + 1 : end]:
        name, separator, value = line.partition("=")
        if separator and name in variable_names:
            values[name] = value
    return values


def _strip_preamble_assignments(lines: list[str]) -> list[str]:
    """Remove frozen uppercase assignment lines from the prelude."""
    return [line for line in lines if not re.match(r"^\s*(?:export\s+)?[A-Z_][A-Z0-9_]*=", line)]


def _skip_macro_definition(lines: list[str], start_index: int) -> int:
    """Skip a macro definition block from @MACRO to @ENDMACRO.

    Args:
        lines: All lines of the script
        start_index: Index of the @MACRO line

    Returns:
        The index after the @ENDMACRO line
    """
    i = start_index + 1  # Start from the line after @MACRO
    while i < len(lines):
        line = lines[i]
        marker = _parse_block_marker(line)
        if marker and marker[0] == "ENDMACRO":
            return i + 1  # Return index after @ENDMACRO
        i += 1
    # Single-line macros do not have @ENDMACRO.
    return start_index + 1


def _skip_helper_definition(lines: list[str], start_index: int) -> int:
    """Skip a helper definition block from @HELPER to @ENDHELPER.

    Args:
        lines: All lines of the script
        start_index: Index of the @HELPER line

    Returns:
        The index after the @ENDHELPER line
    """
    i = start_index + 1  # Start from the line after @HELPER
    while i < len(lines):
        line = lines[i]
        marker = _parse_block_marker(line)
        if marker and marker[0] == "ENDHELPER":
            return i + 1  # Return index after @ENDHELPER
        i += 1
    # If we reach the end without finding @ENDHELPER, return the end index
    return len(lines)


def _skip_hook_definition(lines: list[str], start_index: int) -> int:
    """Skip a hook definition block from @HOOK to @ENDHOOK.

    Args:
        lines: All lines of the script
        start_index: Index of the @HOOK line

    Returns:
        The index after the @ENDHOOK line
    """
    i = start_index + 1  # Start from the line after @HOOK
    while i < len(lines):
        line = lines[i]
        marker = _parse_block_marker(line)
        if marker and marker[0] == "ENDHOOK":
            return i + 1  # Return index after @ENDHOOK
        i += 1
    # If we reach the end without finding @ENDHOOK, return the end index
    return len(lines)


def _parse_annotation_block(lines: list[str], start_index: int) -> tuple[dict[str, str], int]:
    """Parse an annotation block starting from the given line index.

    Parses indented lines as key: value pairs until a non-indented line or marker.

    Args:
        lines: All lines of the script
        start_index: Index of the @ANNOTATE line (0-indexed)

    Returns:
        Tuple of (annotations dict, lines_consumed)

    Raises:
        ParseError: If annotation format is invalid
    """
    annotations: dict[str, str] = {}
    i = start_index + 1  # Start from the line after @ANNOTATE
    lines_consumed = 1  # Count the @ANNOTATE line itself

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Stop if we hit a non-comment line or a marker
        if not stripped or not stripped.startswith("#"):
            break

        # Check if it's a marker (starts with # @)
        if stripped.startswith("# @"):
            break

        # Parse indented annotation line
        # Check if the line after # has indentation (spaces or tab)
        after_hash = line[1:]  # Remove the leading #
        if after_hash.startswith((" ", "\t")):
            # Remove the comment marker and indentation
            content = stripped[1:].strip()  # Remove # and trim

            if ":" not in content:
                raise ParseError(f"Line {i + 1}: Invalid annotation format, expected 'key: value'")

            key, value = content.split(":", 1)
            key = key.strip()
            value = value.strip()

            if not key:
                raise ParseError(f"Line {i + 1}: Annotation key cannot be empty")

            annotations[key] = value
            lines_consumed += 1
        else:
            # Non-indented comment line, stop parsing annotations
            break

        i += 1

    return annotations, lines_consumed


def _apply_block_directive(block: Block, marker_name: str, marker_argument: str | None, line_no: int) -> None:
    """Apply block-local directive metadata to a block."""
    if marker_name == "TIMEOUT":
        block.timeout_seconds = _parse_positive_int(marker_argument, directive=marker_name, line_no=line_no)
        return
    if marker_name == "RETRY":
        block.retry_count = _parse_non_negative_int(marker_argument, directive=marker_name, line_no=line_no)
        return
    if marker_name == "EXPORT":
        export_name, export_source = _parse_export_directive(marker_argument, line_no=line_no)
        block.exports[export_name] = export_source
        return
    if marker_name == "EXPORT_JSON":
        export_name, export_source = _parse_export_directive(marker_argument, line_no=line_no)
        # For now, create a basic structured export without schema validation
        # In a full implementation, you might parse schema from the directive
        block.structured_exports[export_name] = StructuredExport(
            name=export_name,
            json_schema={},  # Empty schema for basic JSON validation
            source=export_source,
        )
        return
    if marker_name == "SHELL":
        if not marker_argument:
            raise ParseError(f"Line {line_no}: @SHELL requires a shell name (e.g., zsh, bash)")
        block.shell = marker_argument
        return
    raise ParseError(f"Line {line_no}: Unknown marker @{marker_name}")


def parse_script(  # noqa: PLR0915
    content: str,
    macros: dict[str, list[str]] | None = None,
    helpers: dict[str, list[str]] | None = None,
    hooks: dict[str, list[str]] | None = None,
    option_env: dict[str, str] | None = None,
) -> list[Block]:
    """Parse a shell script into execution blocks.

    Parses scripts with comment markers:
        # @LOCAL         - Start a local execution block
        # @REMOTE <host> - Start a remote execution block

    Now includes Pydantic validation to catch hallucinations and malformed directives.

    Args:
        content: The script content to parse.
        macros: Optional macro definitions for expansion
        helpers: Optional helper definitions for expansion
        hooks: Optional hook definitions
        option_env: Optional option environment variables

    Returns:
        List of execution blocks.

    Raises:
        ParseError: If the script cannot be parsed.
    """
    """Parse a shell script into execution blocks.

    Parses scripts with comment markers:
        # @LOCAL         - Start a local execution block
        # @REMOTE <host> - Start a remote execution block

    Now includes Pydantic validation to catch hallucinations and malformed directives.

    Args:
        content: The script content to parse.
        macros: Optional macro definitions for expansion
        helpers: Optional helper definitions for expansion
        hooks: Optional hook definitions
        option_env: Optional option environment variables

    Returns:
        List of execution blocks.

    Raises:
        ParseError: If the script cannot be parsed.
    """
    del hooks
    blocks: list[Block] = []
    current_block: Block | None = None
    accumulated_lines: list[str] = []
    prelude_lines: list[str] = []
    directive_phase = False
    pending_annotations: dict[str, str] = {}
    pending_parallel_annotations: dict[str, str] = {}
    current_task_name: str | None = None
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line_no = i + 1
        line = lines[i]
        marker = _parse_block_marker(line)
        if marker:
            marker_name, marker_argument = marker
            if marker_name == "SERVER":
                i += 1
                continue  # Skip server definitions
            if marker_name == "OPTION":
                i += 1
                continue  # Skip option declarations
            if marker_name == "TASK":
                if not marker_argument:
                    raise ParseError(f"Line {line_no}: @TASK requires a task name")
                if current_block is None:
                    if not blocks:
                        prelude_lines = _clean_commands(accumulated_lines)
                        accumulated_lines = []
                else:
                    current_block.commands = _build_block_commands(
                        [],
                        accumulated_lines,
                        macros,
                        helpers,
                        line_no,
                    )
                    if current_block.commands:
                        _validate_block_with_pydantic(current_block, line_no)
                        blocks.append(current_block)
                    current_block = None
                    accumulated_lines = []
                    directive_phase = False
                current_task_name = marker_argument
                i += 1
                continue
            if marker_name == "ANNOTATE":
                if not marker_argument:
                    raise ParseError(f"Line {line_no}: @ANNOTATE marker missing task name")
                pending_annotations, lines_consumed = _parse_annotation_block(lines, i)
                i += lines_consumed
                continue
            if marker_name == "MACRO":
                # Skip macro definitions - they don't create execution blocks
                i = _skip_macro_definition(lines, i)
                continue
            if marker_name == "HELPER":
                # Skip helper definitions - they don't create execution blocks
                i = _skip_helper_definition(lines, i)
                continue
            if marker_name == "VAR":
                # Skip variable definitions - they don't create execution blocks
                i += 1
                continue
            if marker_name == "HOOK":
                # Skip hook definitions - they don't create execution blocks
                i = _skip_hook_definition(lines, i)
                continue
            if marker_name == "PARALLEL":
                if current_block is not None and directive_phase:
                    if marker_argument:
                        current_block.annotations["parallel_group"] = marker_argument
                    else:
                        current_block.annotations["parallel"] = "true"
                    i += 1
                    continue

                if marker_argument:
                    pending_parallel_annotations = {"parallel_group": marker_argument}
                else:
                    pending_parallel_annotations = {"parallel": "true"}
                i += 1
                continue
            if marker_name in {"LOCAL", "REMOTE"}:
                if current_block is None:
                    prelude_lines = _clean_commands(accumulated_lines)
                else:
                    current_block.commands = _build_block_commands(
                        [],
                        accumulated_lines,
                        macros,
                        helpers,
                        line_no,
                    )
                    if current_block.commands:
                        # Validate the completed block using Pydantic
                        _validate_block_with_pydantic(current_block, line_no)
                        blocks.append(current_block)

                accumulated_lines = []
                directive_phase = True

                if marker_name == "LOCAL":
                    annotations = {**pending_parallel_annotations, **pending_annotations}
                    if current_task_name is not None:
                        annotations["task"] = current_task_name
                    current_block = Block(
                        target="LOCAL",
                        source_line=line_no,
                        preamble_commands=list(prelude_lines),
                        preamble_env=dict(option_env or {}),
                        annotations=annotations,
                    )
                else:
                    if not marker_argument:
                        raise ParseError(f"Line {line_no}: @REMOTE marker missing host")
                    annotations = {**pending_parallel_annotations, **pending_annotations}
                    if current_task_name is not None:
                        annotations["task"] = current_task_name
                    current_block = Block(
                        target=f"REMOTE:{marker_argument}",
                        source_line=line_no,
                        preamble_commands=list(prelude_lines),
                        preamble_env=dict(option_env or {}),
                        annotations=annotations,
                    )
                pending_annotations = {}  # Clear after applying
                pending_parallel_annotations = {}
                i += 1
                continue

            if current_block is not None and directive_phase:
                _apply_block_directive(current_block, marker_name, marker_argument, line_no)
                i += 1
                continue

            raise ParseError(f"Line {line_no}: Unknown marker @{marker_name}")

        if current_block is not None and directive_phase and MARKER_PREFIX_RE.match(line):
            raise ParseError(f"Line {line_no}: Malformed marker syntax")

        accumulated_lines.append(line)
        if current_block is not None and line.strip():
            directive_phase = False
        i += 1

    # Don't forget the last block
    if current_block:
        current_block.commands = _build_block_commands([], accumulated_lines, macros, helpers, len(lines))
        if current_block.commands:
            # Validate the final block using Pydantic
            _validate_block_with_pydantic(current_block, len(lines))
            blocks.append(current_block)

    return blocks


def _validate_block_with_pydantic(block: Block, line_no: int) -> None:
    """Validate a parsed block using Pydantic models to catch hallucinations.

    Args:
        block: The block to validate
        line_no: Line number for error reporting

    Raises:
        ParseError: If validation fails
    """
    try:
        # Convert Block to Pydantic ScriptBlock for validation
        block_type = "LOCAL" if block.is_local else "REMOTE"
        target = None if block.is_local else block.host

        # Import Pydantic models for validation
        from shellflow_models import BlockDirective, ScriptBlock

        directive = BlockDirective(
            block_type=block_type,
            target=target,
            timeout=block.timeout_seconds,
            retry=block.retry_count,
            shell=block.shell if block.shell in ("bash", "zsh", "sh") else "bash",
        )

        # The validation happens during model construction
        ScriptBlock(directive=directive, code_lines=block.commands, source_line=block.source_line)
        # If there are any validation errors, Pydantic will raise them

    except Exception as e:
        raise ParseError(f"Line {line_no}: Block validation failed: {e}") from e


def _clean_commands(lines: list[str]) -> list[str]:
    """Clean accumulated lines into executable commands.

    Removes leading empty lines and common leading whitespace while
    preserving the relative indentation of the commands.

    Args:
        lines: Raw lines accumulated from the script.

    Returns:
        List of cleaned command lines.
    """
    # Remove empty lines from start and end
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]

    if not lines:
        return []

    # Find common leading whitespace (excluding empty lines)
    non_empty_lines = [line for line in lines if line.strip()]
    if not non_empty_lines:
        return []

    common_indent = min(len(line) - len(line.lstrip()) for line in non_empty_lines)

    # Remove common leading whitespace
    return [line[common_indent:] for line in lines]


def _is_valid_env_name(name: str) -> bool:
    """Check whether a string is a valid shell environment variable name."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))
