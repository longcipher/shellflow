"""Execution functionality for Shellflow blocks."""

from __future__ import annotations

import json
import shlex
import signal
import subprocess
import threading
import uuid
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from .constants import TRACE_MARKER
from .models import Block, BlockExecutor, CommandLog, ExecutionContext, ExecutionResult, SSHConfig


class LocalExecutor(BlockExecutor):
    """Executor for local block execution."""

    def execute(
        self,
        block: Block,
        context: ExecutionContext,
        no_input: bool = False,
        servers: dict[str, dict[str, str]] | None = None,
    ) -> ExecutionResult:
        """Execute a local block."""
        del servers
        # Local execution doesn't use servers
        if no_input:
            return execute_local(block, context, no_input=True)
        return execute_local(block, context)


class RemoteExecutor(BlockExecutor):
    """Executor for remote block execution via SSH."""

    def execute(
        self,
        block: Block,
        context: ExecutionContext,
        no_input: bool = False,
        servers: dict[str, dict[str, str]] | None = None,
    ) -> ExecutionResult:
        """Execute a remote block."""
        host = block.host
        if not host:
            return ExecutionResult(
                success=False,
                output="",
                exit_code=-1,
                error_message="No host specified for remote block",
                stdout="",
                stderr="",
                failure_kind="ssh_config",
                no_input=no_input,
                timeout_seconds=block.timeout_seconds,
            )

        ssh_config = read_ssh_config(host, servers)
        if ssh_config is None:
            ssh_config_path = _get_ssh_config_path()
            return ExecutionResult(
                success=False,
                output="",
                exit_code=-1,
                error_message=(f"Remote host '{host}' was not found in SSH config: {ssh_config_path}"),
                stdout="",
                stderr="",
                failure_kind="ssh_config",
                no_input=no_input,
                timeout_seconds=block.timeout_seconds,
            )

        return execute_remote(block, context, ssh_config, no_input, servers)


class ExecutorFactory:
    """Factory for creating appropriate executors for blocks."""

    def __init__(self) -> None:
        """Initialize factory."""
        self.remote_executor = RemoteExecutor()
        self.local_executor = LocalExecutor()

    def get_executor(self, block: Block) -> BlockExecutor:
        """Get appropriate executor for a block."""
        if block.is_local:
            return self.local_executor
        return self.remote_executor


_executor_factory = ExecutorFactory()


def _execute_block_once(
    block: Block,
    context: ExecutionContext,
    *,
    no_input: bool,
    servers: dict[str, dict[str, str]] | None = None,
) -> ExecutionResult:
    """Execute one block attempt using the executor abstraction."""
    executor = _executor_factory.get_executor(block)
    return executor.execute(block, context, no_input, servers)


def _build_executable_script(
    commands: list[str],
    context: ExecutionContext,
    *,
    include_context_exports: bool,
    shell: str | None = None,
) -> str:
    """Build a shell script payload for local or remote execution."""
    script_lines = ["set -e"]
    if include_context_exports:
        script_lines.extend(_build_context_exports(context))
    script_lines.extend(_build_shell_bootstrap(shell))
    # Substitute variables in commands
    substituted_commands = [context.substitute_variables(cmd) for cmd in commands]
    script_lines.extend(substituted_commands)
    return "\n".join(script_lines)


def _build_zsh_hook_cleanup() -> list[str]:
    """Disable zsh interactive hooks that pollute non-interactive automation."""
    return [
        "unset preexec_functions precmd_functions chpwd_functions 2>/dev/null || true",
        "unfunction preexec precmd chpwd 2>/dev/null || true",
    ]


def _build_shell_bootstrap(shell: str | None) -> list[str]:
    """Build shell-specific bootstrap lines needed for non-interactive automation."""
    if not shell:
        return []

    shell_name = Path(shell).name
    if shell_name == "zsh":
        return [
            "set +x 2>/dev/null || true",
            *_build_zsh_hook_cleanup(),
            "test -f ~/.zshrc && { source ~/.zshrc >/dev/null 2>&1 || true; }",
            "set +x 2>/dev/null || true",
            *_build_zsh_hook_cleanup(),
        ]
    if shell_name == "bash":
        return [
            "set +x 2>/dev/null || true",
            "test -f ~/.bashrc && { set +e; . ~/.bashrc >/dev/null 2>&1; set -e; }",
        ]
    return ["set +x 2>/dev/null || true"]


def _build_context_exports(context: ExecutionContext) -> list[str]:
    """Build export statements for explicit shellflow context values only."""
    exports = [f"export SHELLFLOW_LAST_OUTPUT={_quote_shell_value(context.last_output)}"]
    for key, value in context.env.items():
        if _is_valid_env_name(key):
            exports.append(f"export {key}={_quote_shell_value(value)}")
    return exports


def _extract_export_value(result: ExecutionResult, source: str) -> str:
    """Extract an exportable scalar value from a block result."""
    if source == "stdout":
        return result.stdout
    if source == "stderr":
        return result.stderr
    if source == "output":
        return result.output
    if source == "exit_code":
        return str(result.exit_code)
    return ""


def _apply_block_exports(block: Block, result: ExecutionResult, context: ExecutionContext) -> dict[str, Any]:
    """Apply explicit block exports to the shared execution context."""
    exported_env: dict[str, Any] = {}
    for name, source in block.exports.items():
        value = _extract_export_value(result, source)
        context.env[name] = value
        exported_env[name] = value

    # Handle structured JSON exports
    for name, structured_export in block.structured_exports.items():
        source_value = _extract_export_value(result, structured_export.source)
        try:
            # Validate and parse JSON
            parsed_value = validate_json_export(source_value, structured_export.json_schema)
            context.env[name] = json.dumps(parsed_value, separators=(",", ":"))
            exported_env[name] = parsed_value
        except ValueError:
            # If JSON validation fails, still export as string but log the error
            context.env[name] = source_value
            exported_env[name] = source_value
            # In a production system, you might want to log this validation failure

    return exported_env


def _is_valid_env_name(name: str) -> bool:
    """Check whether a string is a valid shell environment variable name."""
    import re

    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))


def _quote_shell_value(value: str) -> str:
    """Quote a value for use in a shell export statement."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return f'"{escaped}"'


def _combine_output(stdout: str, stderr: str) -> str:
    """Combine stdout and stderr into a single trimmed output string."""
    output = stdout.strip()
    error_output = stderr.strip()
    if output and error_output:
        return f"{output}\n{error_output}"
    return output or error_output


def _strip_trace_markers(output: str) -> str:
    """Remove shellflow trace marker lines from captured output."""
    cleaned_lines: list[str] = []
    for line in output.splitlines():
        if TRACE_MARKER in line or line.startswith("__SHELLFLOW_CMD_"):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines).strip()


def _parse_debug_trace_command_logs(stderr: str, *, success: bool, exit_code: int) -> list[CommandLog]:
    """Parse DEBUG-trap command markers from stderr into command logs."""
    command_logs: list[CommandLog] = []
    for line in stderr.splitlines():
        if not line.startswith("__SHELLFLOW_CMD_"):
            continue
        _, _, command = line.partition(":")
        command = command.strip()
        if not command or _is_trace_noise(command):
            continue
        command_logs.append(
            CommandLog(
                command=command,
                output="",
                exit_code=0,
                status="completed",
            )
        )

    if command_logs and not success:
        command_logs[-1].exit_code = exit_code
        command_logs[-1].status = "failed"
    return command_logs


def _is_trace_noise(command: str) -> bool:
    """Filter bootstrap commands from DEBUG-trap output."""
    noise_patterns = (
        r"^__SHELLFLOW_",
        r"^__shellflow_trace",
        r"^trap\b",
        r"^set\b",
        r"^export\s+SHELLFLOW_LAST_OUTPUT=",
        r"^export\s+[A-Z_][A-Z0-9_]*=",
        r"^test -f ~/.(?:bashrc|zshrc)",
        r"^\[{1,2}\s",
    )
    import re

    return any(re.match(pattern, command) for pattern in noise_patterns)


def _build_remote_trace_script(block: Block, context: ExecutionContext, shell: str) -> str:
    """Build a remote script that preserves native Bash syntax while tracing commands."""
    delimiter = uuid.uuid4().hex[:16]
    script_lines: list[str] = [
        "set +x 2>/dev/null || true",
        "set -e",
        f"__SHELLFLOW_DELIM__={shlex.quote(delimiter)}",
        "exec 3>&1 4>&2",
    ]
    script_lines.extend(_build_context_exports(context))
    script_lines.extend(_build_shell_bootstrap(shell))
    script_lines.extend(_build_debug_trap(shell, trace_fd="3"))
    script_lines.extend(block.commands)

    return "\n".join(script_lines)


def _build_debug_trap(shell: str, trace_fd: str = "2") -> list[str]:
    """Build shell-specific command tracing without wrapping user lines."""
    shell_name = Path(shell).name
    if shell_name == "zsh":
        return [
            "__shellflow_trace() {",
            f'  printf "__SHELLFLOW_CMD_%s:%s\\n" "$__SHELLFLOW_DELIM__" "$ZSH_DEBUG_CMD" >&{trace_fd}',
            "}",
            "trap __shellflow_trace DEBUG",
        ]
    return [
        "__shellflow_trace() {",
        f'  printf "__SHELLFLOW_CMD_%s:%s\\n" "$__SHELLFLOW_DELIM__" "$BASH_COMMAND" >&{trace_fd}',
        "}",
        "trap __shellflow_trace DEBUG",
    ]


def _run_remote_subprocess(
    ssh_args: list[str],
    remote_script: str,
    *,
    timeout_seconds: int | None,
    on_command: Callable[[str], None] | None = None,
    on_output: Callable[[str], None] | None = None,
) -> tuple[str, str, int, bool, bool]:
    """Run an SSH subprocess and preserve partial output on timeout or interruption."""
    process = subprocess.Popen(
        ssh_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return _run_traced_subprocess(
        process,
        input_text=remote_script,
        timeout_seconds=timeout_seconds,
        on_command=on_command,
        on_output=on_output,
    )


def execute_local(
    block: Block,
    context: ExecutionContext,
    no_input: bool = False,
) -> ExecutionResult:
    """Execute a local block.

    Runs the block's commands in a local subprocess with the given context.

    Args:
        block: The block to execute.
        context: The execution context with environment and state.

    Returns:
        ExecutionResult with success status and output.
    """
    if not block.commands:
        return ExecutionResult(success=True, output="")

    script = _build_executable_script(
        block.commands,
        context,
        include_context_exports=False,
    )
    env = context.to_shell_env()
    run_kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "env": env,
    }
    if block.timeout_seconds is not None:
        run_kwargs["timeout"] = block.timeout_seconds

    try:
        if no_input:
            result = subprocess.run(
                ["/bin/bash", "-se", "-c", script],
                stdin=subprocess.DEVNULL,
                **run_kwargs,
            )
        else:
            result = subprocess.run(
                ["/bin/bash", "-se"],
                input=script,
                **run_kwargs,
            )

        return ExecutionResult(
            success=result.returncode == 0,
            output=_combine_output(result.stdout, result.stderr),
            exit_code=result.returncode,
            error_message="" if result.returncode == 0 else f"Exit code: {result.returncode}",
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            timeout_seconds=block.timeout_seconds,
            failure_kind=None if result.returncode == 0 else "runtime",
            no_input=no_input,
        )
    except subprocess.TimeoutExpired as e:
        stdout = _stringify_subprocess_stream(e.output).strip()
        stderr = _stringify_subprocess_stream(e.stderr).strip()
        timeout_value = int(e.timeout) if isinstance(e.timeout, int | float) else e.timeout
        return ExecutionResult(
            success=False,
            output=_combine_output(stdout, stderr),
            exit_code=-1,
            error_message=f"Timed out after {timeout_value} second(s)",
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            timeout_seconds=block.timeout_seconds,
            failure_kind="timeout",
            no_input=no_input,
        )
    except subprocess.SubprocessError as e:
        return ShellflowExceptionHandler.handle_subprocess_error(e, block, no_input)
    except OSError as e:
        return ShellflowExceptionHandler.handle_os_error(e, block, no_input)


def execute_local_traced(
    block: Block,
    context: ExecutionContext,
    no_input: bool = False,
    on_command: Callable[[str], None] | None = None,
    on_output: Callable[[str], None] | None = None,
) -> ExecutionResult:
    """Execute a local block while preserving per-command trace logs."""
    if not block.commands:
        return ExecutionResult(success=True, output="")

    script = _build_local_trace_script(block, context)
    env = context.to_shell_env()

    if no_input:
        process = subprocess.Popen(
            ["/bin/bash", "-se", "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        input_text = None
    else:
        process = subprocess.Popen(
            ["/bin/bash", "-se"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        input_text = script

    try:
        stdout, stderr, exit_code, interrupted, timed_out = _run_traced_subprocess(
            process,
            input_text=input_text,
            timeout_seconds=block.timeout_seconds,
            on_command=on_command,
            on_output=on_output,
        )
        cleaned_stderr = _strip_trace_markers(stderr).strip()
        command_logs = _parse_grouped_trace_output(
            stdout,
            success=exit_code == 0 and not interrupted and not timed_out,
            exit_code=exit_code,
            interrupted=interrupted,
            timed_out=timed_out,
            trailing_error_output=cleaned_stderr,
        )
    except subprocess.SubprocessError as e:
        return ShellflowExceptionHandler.handle_subprocess_error(e, block, no_input)
    except OSError as e:
        return ShellflowExceptionHandler.handle_os_error(e, block, no_input)

    cleaned_stdout = _strip_trace_markers(stdout).strip()
    cleaned_stderr = _strip_trace_markers(stderr).strip()

    success = exit_code == 0 and not interrupted and not timed_out
    failure_kind = None if success else "runtime"
    result_exit_code = exit_code
    error_message = "" if success else f"Exit code: {exit_code}"

    if timed_out:
        result_exit_code = -1
        error_message = f"Timed out after {block.timeout_seconds} second(s)"
        failure_kind = "timeout"
    elif interrupted:
        error_message = "Interrupted by user"

    return ExecutionResult(
        success=success,
        output=_combine_output(cleaned_stdout, cleaned_stderr),
        exit_code=result_exit_code,
        error_message=error_message,
        stdout=cleaned_stdout,
        stderr=cleaned_stderr,
        timed_out=timed_out,
        timeout_seconds=block.timeout_seconds,
        failure_kind=failure_kind,
        no_input=no_input,
        command_logs=command_logs,
    )


def execute_remote(
    block: Block,
    context: ExecutionContext,
    ssh_config: SSHConfig | None,
    no_input: bool = False,
    servers: dict[str, dict[str, str]] | None = None,
    on_command: Callable[[str], None] | None = None,
    on_output: Callable[[str], None] | None = None,
) -> ExecutionResult:
    """Execute a remote block via SSH.

    Builds an SSH command and executes the block's commands on a remote host.

    Args:
        block: The block to execute.
        context: The execution context with environment and state.
        ssh_config: Optional SSH configuration for the remote host.

    Returns:
        ExecutionResult with success status and output.
    """
    if not block.commands:
        return ExecutionResult(success=True, output="")

    host = block.host
    if not host:
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message="No host specified for remote block",
            stdout="",
            stderr="",
            failure_kind="ssh_config",
            no_input=no_input,
        )

    if ssh_config is None:
        ssh_config = read_ssh_config(host, servers)

    if ssh_config is None:
        ssh_config_path = _get_ssh_config_path()
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=(f"Remote host '{host}' was not found in SSH config: {ssh_config_path}"),
            stdout="",
            stderr="",
            failure_kind="ssh_config",
            no_input=no_input,
        )

    ssh_args = ["ssh"]
    if no_input:
        ssh_args.append("-n")

    if ssh_config.port and ssh_config.port != 22:
        ssh_args.extend(["-p", str(ssh_config.port)])
    if ssh_config.user:
        ssh_args.extend(["-l", ssh_config.user])
    if ssh_config.identity_file:
        ssh_args.extend(["-i", str(Path(ssh_config.identity_file).expanduser())])

    ssh_config_path = _get_ssh_config_path()
    if ssh_config_path.exists():
        ssh_args.extend(["-F", str(ssh_config_path)])

    shell = block.shell or "bash"
    # Use --no-rcs for zsh or --norc for bash to prevent sourcing initialization files
    ssh_target = ssh_config.hostname or host
    if "zsh" in shell:
        ssh_args.extend(["-o", "BatchMode=yes", ssh_target, shell, "--no-rcs", "-s", "-e"])
    else:
        ssh_args.extend(["-o", "BatchMode=yes", ssh_target, shell, "--norc", "-s", "-e"])
    remote_script = _build_remote_trace_script(block, context, shell)

    try:
        stdout, stderr, exit_code, interrupted, timed_out = _run_remote_subprocess(
            ssh_args,
            remote_script,
            timeout_seconds=block.timeout_seconds,
            on_command=on_command,
            on_output=on_output,
        )
        cleaned_stdout = _strip_trace_markers(stdout)
        cleaned_stderr = _strip_trace_markers(stderr)
        success = exit_code == 0 and not interrupted and not timed_out
        if "__SHELLFLOW_CMD_" in stdout:
            command_logs = _parse_grouped_trace_output(
                stdout,
                success=success,
                exit_code=exit_code,
                interrupted=interrupted,
                timed_out=timed_out,
                trailing_error_output=cleaned_stderr,
            )
        else:
            command_logs = _parse_remote_command_logs(
                stdout,
                success=success,
                exit_code=exit_code,
                interrupted=interrupted,
                trailing_error_output=cleaned_stderr,
            )

        failure_kind = None if success else "runtime"
        result_exit_code = exit_code
        error_message = "" if success else f"SSH exit code: {exit_code}"

        if timed_out:
            result_exit_code = -1
            error_message = f"Timed out after {block.timeout_seconds} second(s)"
            failure_kind = "timeout"
        elif interrupted:
            error_message = "Interrupted by user"

        return ExecutionResult(
            success=success,
            output=_combine_output(cleaned_stdout, cleaned_stderr),
            exit_code=result_exit_code,
            error_message=error_message,
            stdout=cleaned_stdout,
            stderr=cleaned_stderr,
            timed_out=timed_out,
            timeout_seconds=block.timeout_seconds,
            failure_kind=failure_kind,
            no_input=no_input,
            command_logs=command_logs,
        )
    except subprocess.SubprocessError as e:
        return ShellflowExceptionHandler.handle_subprocess_error(e, block, no_input)
    except OSError as e:
        return ShellflowExceptionHandler.handle_os_error(e, block, no_input)


def _stringify_subprocess_stream(value: bytes | str | None) -> str:
    """Convert subprocess output values to text for reporting."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _parse_remote_command_logs(  # noqa: PLR0915
    output: str,
    *,
    success: bool,
    exit_code: int,
    interrupted: bool = False,
    trailing_error_output: str = "",
) -> list[CommandLog]:
    """Parse delimiter-separated remote output into one journal entry per command."""
    command_logs: list[CommandLog] = []

    # Find the delimiter from the output
    delim = None
    for line in output.splitlines():
        if line.startswith("__SHELLFLOW_START_") and line.endswith("__"):
            candidate = line[len("__SHELLFLOW_START_") : -2]
            if candidate:
                delim = candidate
                break

    if delim is None:
        # Fallback: no delimiters found, treat entire output as one command
        cleaned = _strip_trace_markers(output)
        combined = _combine_output(cleaned, trailing_error_output) if trailing_error_output else cleaned
        if combined:
            command_logs.append(
                CommandLog(
                    command="<remote-command>",
                    output=combined,
                    exit_code=exit_code,
                    status="completed" if success else "failed",
                )
            )
        return command_logs

    start_marker = f"__SHELLFLOW_START_{delim}__"
    end_marker = f"__SHELLFLOW_END_{delim}__"

    # Split output by start markers
    parts = output.split(start_marker)

    for part in parts[1:]:  # Skip text before the first start marker
        ec = None
        lines = part.split("\n")

        # Find end marker and exit code
        output_lines: list[str] = []
        for line in lines:
            if line.strip() == end_marker.strip():
                continue
            if line.startswith("__SHELLFLOW_EXITCODE__"):
                try:
                    ec = int(line[len("__SHELLFLOW_EXITCODE__") :].strip())
                except ValueError:
                    ec = None
                continue
            if line.startswith("__SHELLFLOW_"):
                continue
            output_lines.append(line)

        cleaned_output = "\n".join(output_lines).strip()
        cleaned_output = _strip_trace_markers(cleaned_output)

        command_logs.append(
            CommandLog(
                command="<remote-command>",
                output=cleaned_output,
                exit_code=ec,
                status="completed",
            )
        )

    # Assign proper commands from the block
    # (callers should set command names after parsing)

    # Set status based on overall result
    if command_logs:
        for cl in command_logs[:-1]:
            if cl.exit_code is None:
                cl.exit_code = 0
            cl.status = "completed" if cl.exit_code == 0 else "failed"

        last = command_logs[-1]
        if success:
            last.status = "completed"
            if last.exit_code is None:
                last.exit_code = 0
        elif interrupted:
            last.status = "interrupted"
            if last.exit_code is None:
                last.exit_code = exit_code
        else:
            last.status = "failed"
            if last.exit_code is None:
                last.exit_code = exit_code

    # Append SSH-level stderr to the last command
    if trailing_error_output.strip():
        if command_logs:
            last = command_logs[-1]
            last.output = _combine_output(last.output, trailing_error_output)
        else:
            command_logs.append(
                CommandLog(
                    command="<remote-command>",
                    output=trailing_error_output.strip(),
                    exit_code=exit_code,
                    status="failed",
                )
            )

    return command_logs


def _build_local_trace_script(
    block: Block,
    context: ExecutionContext,
) -> str:
    """Build a local script that emits DEBUG-trap command markers to stderr."""
    delimiter = uuid.uuid4().hex[:16]
    script_lines = [
        "set +x 2>/dev/null || true",
        "set -e",
        f"__SHELLFLOW_DELIM__={shlex.quote(delimiter)}",
        "exec 3>&1 4>&2",
    ]
    script_lines.extend(_build_context_exports(context))
    script_lines.extend(_build_debug_trap("bash", trace_fd="3"))
    script_lines.extend(block.commands)
    return "\n".join(script_lines)


def _run_traced_subprocess(
    process: subprocess.Popen[str],
    *,
    input_text: str | None,
    timeout_seconds: int | None,
    on_command: Callable[[str], None] | None = None,
    on_output: Callable[[str], None] | None = None,
) -> tuple[str, str, int, bool, bool]:
    """Read traced stdout/stderr streams while surfacing live command markers."""
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    stdout_stream = process.stdout
    stderr_stream = process.stderr
    if stdout_stream is None or stderr_stream is None:
        raise subprocess.SubprocessError("traced subprocess did not expose stdout/stderr pipes")

    stdout_thread = threading.Thread(
        target=_read_traced_stdout_stream,
        args=(stdout_stream, stdout_chunks, on_command, on_output),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_read_traced_output_stream,
        args=(stderr_stream, stderr_chunks, on_output),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    interrupted = False
    timed_out = False
    stdin_stream = process.stdin

    try:
        _write_process_input(stdin_stream, input_text)
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    except KeyboardInterrupt:
        interrupted = True
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    finally:
        if stdin_stream is not None and not stdin_stream.closed:
            stdin_stream.close()

    stdout_thread.join()
    stderr_thread.join()

    return (
        "".join(stdout_chunks),
        "".join(stderr_chunks),
        process.returncode if process.returncode is not None else -1,
        interrupted,
        timed_out,
    )


def _read_traced_stdout_stream(
    stdout_stream: Any,
    stdout_chunks: list[str],
    on_command: Callable[[str], None] | None,
    on_output: Callable[[str], None] | None,
) -> None:
    """Read traced stdout, separating command markers from regular output."""
    try:
        for line in iter(stdout_stream.readline, ""):
            stdout_chunks.append(line)
            command = _extract_trace_command_line(line)
            if command is not None and on_command is not None:
                on_command(command)
            elif command is None and on_output is not None:
                on_output(line)
    finally:
        stdout_stream.close()


def _read_traced_output_stream(
    stream: Any,
    chunks: list[str],
    on_output: Callable[[str], None] | None,
) -> None:
    """Read a traced process output stream and forward raw chunks."""
    try:
        for line in iter(stream.readline, ""):
            chunks.append(line)
            if on_output is not None:
                on_output(line)
    finally:
        stream.close()


def _write_process_input(stdin_stream: Any, input_text: str | None) -> None:
    """Write the traced script to stdin, tolerating early process exits."""
    if stdin_stream is None:
        return
    if input_text is not None:
        with suppress(BrokenPipeError):
            stdin_stream.write(input_text)
    stdin_stream.close()


def _parse_grouped_trace_output(
    combined_output: str,
    *,
    success: bool,
    exit_code: int,
    interrupted: bool = False,
    timed_out: bool = False,
    trailing_error_output: str = "",
) -> list[CommandLog]:
    """Parse a combined traced output stream into per-command logs."""
    command_logs: list[CommandLog] = []
    command_output_chunks: list[list[str]] = []
    for chunk in combined_output.splitlines(keepends=True):
        command = _extract_trace_command_line(chunk)
        if command is not None:
            command_logs.append(CommandLog(command=command))
            command_output_chunks.append([])
            continue

        _append_command_output(command_output_chunks, chunk)

    _finalize_command_logs(
        command_logs,
        command_output_chunks,
        exit_code=exit_code,
        interrupted=interrupted,
        timed_out=timed_out,
        success=success,
        trailing_error_output=trailing_error_output,
    )

    return command_logs


def _append_command_output(command_output_chunks: list[list[str]], chunk: str) -> None:
    """Append output to the currently active traced command."""
    if not command_output_chunks:
        return
    command_output_chunks[-1].append(chunk)


def _extract_trace_command_line(line: str) -> str | None:
    """Return the traced shell command for a marker line."""
    if not line.startswith("__SHELLFLOW_CMD_"):
        return None

    _, _, command = line.partition(":")
    command = command.strip()
    if not command or _is_trace_noise(command):
        return None
    return command


def _finalize_command_logs(
    command_logs: list[CommandLog],
    command_output_chunks: list[list[str]],
    *,
    exit_code: int,
    interrupted: bool,
    timed_out: bool,
    success: bool,
    trailing_error_output: str,
) -> None:
    """Populate grouped command outputs and terminal status for traced logs."""
    for command_log, output_chunks in zip(command_logs, command_output_chunks, strict=False):
        command_log.output = "".join(output_chunks).strip()
        command_log.exit_code = 0
        command_log.status = "completed"
        command_log.success = True

    if not command_logs:
        if trailing_error_output.strip():
            command_logs.append(
                CommandLog(
                    command="<local-command>",
                    output=trailing_error_output.strip(),
                    exit_code=exit_code,
                    status="completed" if success else "failed",
                    success=success,
                )
            )
        return

    last_command = command_logs[-1]
    if trailing_error_output.strip():
        last_command.output = _combine_output(last_command.output, trailing_error_output)

    if timed_out:
        last_command.exit_code = -1
        last_command.status = "failed"
        last_command.success = False
        return

    if interrupted:
        last_command.exit_code = exit_code
        last_command.status = "interrupted"
        last_command.success = False
        return

    if not success:
        last_command.exit_code = exit_code
        last_command.status = "failed"
        last_command.success = False


# Import here to avoid circular imports
from .config import _get_ssh_config_path, read_ssh_config  # noqa: E402


class ShellflowExceptionHandler:
    """Centralized exception handling for Shellflow operations."""

    @staticmethod
    def handle_subprocess_error(error: subprocess.SubprocessError, block: Block, no_input: bool) -> ExecutionResult:
        """Handle subprocess execution errors."""
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=str(error),
            stdout="",
            stderr="",
            timeout_seconds=block.timeout_seconds,
            failure_kind="runtime",
            no_input=no_input,
        )

    @staticmethod
    def handle_os_error(error: OSError, block: Block, no_input: bool) -> ExecutionResult:
        """Handle OS-level errors."""
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=str(error),
            stdout="",
            stderr="",
            timeout_seconds=block.timeout_seconds,
            failure_kind="runtime",
            no_input=no_input,
        )

    @staticmethod
    def handle_timeout(block: Block, no_input: bool) -> ExecutionResult:
        """Handle timeout errors."""
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=f"Timed out after {block.timeout_seconds} second(s)",
            stdout="",
            stderr="",
            timed_out=True,
            timeout_seconds=block.timeout_seconds,
            failure_kind="timeout",
            no_input=no_input,
        )

    @staticmethod
    def handle_ssh_config_error(host: str, block: Block, no_input: bool) -> ExecutionResult:
        """Handle SSH configuration errors."""
        ssh_config_path = _get_ssh_config_path()
        return ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message=(f"Remote host '{host}' was not found in SSH config: {ssh_config_path}"),
            stdout="",
            stderr="",
            failure_kind="ssh_config",
            no_input=no_input,
            timeout_seconds=block.timeout_seconds,
        )


def validate_json_export(source_value: str, json_schema: dict[str, Any]) -> Any:  # noqa: ARG001
    """Validate and parse JSON export value against schema."""
    # For now, just parse JSON without full schema validation
    import json

    try:
        return json.loads(source_value)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in export: {e}") from e
