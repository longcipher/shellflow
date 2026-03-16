"""Unit tests for shellflow module.

Tests for parse_script, execute_local, execute_remote, run_script,
and helper functions in src/shellflow.py.
"""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from shellflow import (
    VALID_EXPORT_SOURCES,
    Block,
    ExecutionContext,
    ExecutionError,
    ExecutionResult,
    ParseError,
    RunResult,
    ShellflowError,
    SSHConfig,
    _build_executable_script,
    _clean_commands,
    _is_valid_env_name,
    create_parser,
    execute_local,
    execute_remote,
    main,
    parse_script,
    read_ssh_config,
    run_script,
)

ZSH_AVAILABLE = Path("/bin/zsh").exists()

VALID_EXPORT_NAME_STRATEGY = st.from_regex(r"[A-Za-z_][A-Za-z0-9_]*", fullmatch=True)
INVALID_EXPORT_NAME_STRATEGY = st.one_of(
    st.from_regex(r"[0-9][A-Za-z0-9_]*", fullmatch=True),
    st.from_regex(r"[A-Za-z_][A-Za-z0-9_]*-[A-Za-z0-9_]+", fullmatch=True),
    st.from_regex(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_]+", fullmatch=True),
).filter(lambda name: not _is_valid_env_name(name))
VALID_EXPORT_SOURCE_STRATEGY = st.sampled_from(sorted(VALID_EXPORT_SOURCES))
MALFORMED_DIRECTIVE_LINE_STRATEGY = st.one_of(
    st.integers(min_value=1, max_value=1000).map(lambda value: f"# @TIMEOUT {value} extra"),
    st.integers(min_value=0, max_value=10).map(lambda value: f"# @RETRY {value} extra"),
    st.tuples(VALID_EXPORT_NAME_STRATEGY, VALID_EXPORT_SOURCE_STRATEGY).map(
        lambda parts: f"# @EXPORT {parts[0]}={parts[1]} extra"
    ),
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def execution_context() -> ExecutionContext:
    """Return a fresh execution context."""
    return ExecutionContext()


@pytest.fixture
def sample_block() -> Block:
    """Return a sample block with commands."""
    return Block(target="LOCAL", commands=['echo "hello"', 'echo "world"'])


# =============================================================================
# Block Dataclass Tests
# =============================================================================


class TestBlock:
    """Tests for Block dataclass."""

    def test_block_creation(self) -> None:
        """Test creating a Block instance."""
        block = Block(target="LOCAL", commands=["echo hello"])
        assert block.target == "LOCAL"
        assert block.commands == ["echo hello"]

    def test_block_default_commands(self) -> None:
        """Test Block with default empty commands."""
        block = Block(target="LOCAL")
        assert block.commands == []

    def test_is_local(self) -> None:
        """Test is_local property."""
        local_block = Block(target="LOCAL")
        remote_block = Block(target="REMOTE:host1")
        assert local_block.is_local is True
        assert remote_block.is_local is False

    def test_is_remote(self) -> None:
        """Test is_remote property."""
        local_block = Block(target="LOCAL")
        remote_block = Block(target="REMOTE:host1")
        assert local_block.is_remote is False
        assert remote_block.is_remote is True

    def test_host_property(self) -> None:
        """Test host property for remote blocks."""
        remote_block = Block(target="REMOTE:host1")
        local_block = Block(target="LOCAL")
        assert remote_block.host == "host1"
        assert local_block.host is None

    def test_host_property_with_colon_in_host(self) -> None:
        """Test host property when host contains colons (IPv6)."""
        # Note: The current implementation uses split(':', 1) which limits to 2 parts
        remote_block = Block(target="REMOTE:host1:8080")
        # This behavior might not be intended, documenting current behavior
        assert remote_block.host == "host1:8080"


# =============================================================================
# ExecutionContext Tests
# =============================================================================


class TestExecutionContext:
    """Tests for ExecutionContext dataclass."""

    def test_default_creation(self) -> None:
        """Test creating ExecutionContext with defaults."""
        ctx = ExecutionContext()
        assert ctx.env == {}
        assert ctx.last_output == ""
        assert ctx.success is True

    def test_custom_values(self) -> None:
        """Test creating ExecutionContext with custom values."""
        ctx = ExecutionContext(
            env={"KEY": "value"},
            last_output="previous output",
            success=False,
        )
        assert ctx.env == {"KEY": "value"}
        assert ctx.last_output == "previous output"
        assert ctx.success is False

    def test_to_shell_env(self) -> None:
        """Test converting context to shell environment."""
        ctx = ExecutionContext(
            env={"MY_VAR": "my_value"},
            last_output="previous result",
        )
        shell_env = ctx.to_shell_env()

        # Should include system environment
        assert "PATH" in shell_env
        # Should include custom env vars
        assert shell_env["MY_VAR"] == "my_value"
        # Should include last output
        assert shell_env["SHELLFLOW_LAST_OUTPUT"] == "previous result"


# =============================================================================
# ExecutionResult and RunResult Tests
# =============================================================================


class TestExecutionResult:
    """Tests for ExecutionResult dataclass."""

    def test_success_result(self) -> None:
        """Test successful execution result."""
        result = ExecutionResult(
            success=True,
            output="hello world",
            exit_code=0,
        )
        assert result.success is True
        assert result.output == "hello world"
        assert result.exit_code == 0

    def test_failure_result(self) -> None:
        """Test failed execution result."""
        result = ExecutionResult(
            success=False,
            output="",
            exit_code=1,
            error_message="Command not found",
        )
        assert result.success is False
        assert result.exit_code == 1
        assert result.error_message == "Command not found"


class TestRunResult:
    """Tests for RunResult dataclass."""

    def test_success(self) -> None:
        """Test successful run result."""
        result = RunResult(success=True, blocks_executed=3)
        assert result.success is True
        assert result.blocks_executed == 3

    def test_failure(self) -> None:
        """Test failed run result."""
        result = RunResult(
            success=False,
            blocks_executed=1,
            error_message="Block 2 failed",
        )
        assert result.success is False
        assert result.blocks_executed == 1
        assert result.error_message == "Block 2 failed"


# =============================================================================
# SSHConfig Tests
# =============================================================================


class TestSSHConfig:
    """Tests for SSHConfig dataclass."""

    def test_basic_creation(self) -> None:
        """Test creating SSHConfig with basic values."""
        config = SSHConfig(host="server1")
        assert config.host == "server1"
        assert config.port == 22  # Default
        assert config.hostname is None
        assert config.user is None
        assert config.identity_file is None

    def test_full_configuration(self) -> None:
        """Test creating SSHConfig with all values."""
        config = SSHConfig(
            host="server1",
            hostname="192.168.1.100",
            user="admin",
            port=2222,
            identity_file="~/.ssh/server1_key",
        )
        assert config.host == "server1"
        assert config.hostname == "192.168.1.100"
        assert config.user == "admin"
        assert config.port == 2222
        assert config.identity_file == "~/.ssh/server1_key"


# =============================================================================
# Exception Tests
# =============================================================================


class TestExceptions:
    """Tests for custom exceptions."""

    def test_shellflow_error(self) -> None:
        """Test ShellflowError can be raised and caught."""
        with pytest.raises(ShellflowError) as exc_info:
            raise ShellflowError("test error")
        assert str(exc_info.value) == "test error"

    def test_parse_error(self) -> None:
        """Test ParseError can be raised and caught."""
        with pytest.raises(ParseError):
            raise ParseError("parse error")

        # Verify it's a subclass of ShellflowError
        with pytest.raises(ShellflowError):
            raise ParseError("parse error")

    def test_execution_error(self) -> None:
        """Test ExecutionError can be raised and caught."""
        with pytest.raises(ExecutionError):
            raise ExecutionError("execution error")

        # Verify it's a subclass of ShellflowError
        with pytest.raises(ShellflowError):
            raise ExecutionError("execution error")


# =============================================================================
# parse_script Tests
# =============================================================================


class TestParseScript:
    """Tests for parse_script function."""

    def test_parse_empty_script(self) -> None:
        """Test parsing empty script returns empty list."""
        blocks = parse_script("")
        assert blocks == []

    def test_parse_whitespace_only(self) -> None:
        """Test parsing script with only whitespace returns empty list."""
        blocks = parse_script("   \n\t\n  ")
        assert blocks == []

    def test_parse_local_block(self) -> None:
        """Test parsing a simple LOCAL block."""
        script = """# @LOCAL
echo "hello"
echo "world"
"""
        blocks = parse_script(script)
        assert len(blocks) == 1
        assert blocks[0].target == "LOCAL"
        assert blocks[0].is_local is True
        assert blocks[0].commands == ['echo "hello"', 'echo "world"']

    def test_parse_remote_block(self) -> None:
        """Test parsing a REMOTE block with host."""
        script = """# @REMOTE server1
hostname
uptime
"""
        blocks = parse_script(script)
        assert len(blocks) == 1
        assert blocks[0].is_remote is True
        assert blocks[0].target == "REMOTE:server1"
        assert blocks[0].host == "server1"
        assert "hostname" in blocks[0].commands

    def test_parse_mixed_blocks(self) -> None:
        """Test parsing script with mixed local and remote blocks."""
        script = """# @LOCAL
echo "Starting locally"

# @REMOTE server1
hostname

# @LOCAL
echo "Back to local"

# @REMOTE server2
uptime
"""
        blocks = parse_script(script)
        assert len(blocks) == 4
        assert blocks[0].target == "LOCAL"
        assert blocks[0].is_local is True
        assert blocks[1].target == "REMOTE:server1"
        assert blocks[2].target == "LOCAL"
        assert blocks[3].target == "REMOTE:server2"

    def test_parse_with_comments_and_empty_lines(self) -> None:
        """Test parsing script with comments and empty lines."""
        script = """# @LOCAL

# This is a comment
echo "hello"

# Another comment
echo "world"

"""
        blocks = parse_script(script)
        assert len(blocks) == 1
        # Comments and empty lines should be preserved in commands
        assert 'echo "hello"' in blocks[0].commands
        assert 'echo "world"' in blocks[0].commands

    def test_parse_remote_with_empty_host(self) -> None:
        """Test that @REMOTE without host raises a parse error."""
        script = """# @REMOTE
hostname
"""
        with pytest.raises(ParseError, match="missing host"):
            parse_script(script)

    def test_parse_no_markers(self) -> None:
        """Test parsing script with no markers returns empty list."""
        script = """echo "hello"
echo "world"
"""
        blocks = parse_script(script)
        # Without markers, no blocks should be created
        assert blocks == []

    def test_multiple_local_blocks(self) -> None:
        """Test parsing multiple consecutive LOCAL blocks."""
        script = """# @LOCAL
echo "block 1"

# @LOCAL
echo "block 2"
"""
        blocks = parse_script(script)
        assert len(blocks) == 2
        assert blocks[0].commands == ['echo "block 1"']
        assert blocks[1].commands == ['echo "block 2"']


# =============================================================================
# _clean_commands Tests
# =============================================================================


class TestCleanCommands:
    """Tests for _clean_commands helper function."""

    def test_empty_list(self) -> None:
        """Test cleaning empty list returns empty list."""
        result = _clean_commands([])
        assert result == []

    def test_no_whitespace(self) -> None:
        """Test lines without common whitespace."""
        lines = ["echo hello", "echo world"]
        result = _clean_commands(lines)
        assert result == ["echo hello", "echo world"]

    def test_common_indentation(self) -> None:
        """Test removal of common leading whitespace."""
        lines = [
            "    echo hello",
            "    echo world",
        ]
        result = _clean_commands(lines)
        assert result == ["echo hello", "echo world"]

    def test_trailing_empty_lines_removed(self) -> None:
        """Test that trailing empty lines are removed."""
        lines = [
            "echo hello",
            "",
            "",
        ]
        result = _clean_commands(lines)
        assert result == ["echo hello"]

    def test_leading_empty_lines_removed(self) -> None:
        """Test that leading empty lines are removed."""
        lines = [
            "",
            "",
            "echo hello",
        ]
        result = _clean_commands(lines)
        assert result == ["echo hello"]


# =============================================================================
# execute_local Tests
# =============================================================================


class TestExecuteLocal:
    """Tests for execute_local function."""

    def test_timeout_directive_passes_timeout_to_subprocess(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test local execution applies the block timeout policy to subprocess.run."""
        block = Block(target="LOCAL", commands=['echo "hello"'], timeout_seconds=7)

        mock_result = mock.Mock(returncode=0, stdout="hello\n", stderr="")

        with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
            result = execute_local(block, execution_context)

        assert result.success is True
        assert mock_run.call_args.kwargs["timeout"] == 7

    def test_no_input_uses_devnull_stdin(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test no-input mode redirects stdin away from the terminal."""
        block = Block(target="LOCAL", commands=['echo "hello"'])

        mock_result = mock.Mock(returncode=0, stdout="hello\n", stderr="")

        with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
            result = execute_local(block, execution_context, no_input=True)

        assert result.success is True
        assert mock_run.call_args.kwargs["stdin"] is subprocess.DEVNULL
        assert "input" not in mock_run.call_args.kwargs

    def test_block_stops_on_first_failing_command(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test that a block is fail-fast within the shell itself."""
        block = Block(target="LOCAL", commands=["false", 'echo "should not run"'])

        result = execute_local(block, execution_context)

        assert result.success is False
        assert "should not run" not in result.output

    def test_empty_block(self, execution_context: ExecutionContext) -> None:
        """Test executing empty block returns success."""
        block = Block(target="LOCAL", commands=[])
        result = execute_local(block, execution_context)
        assert result.success is True
        assert result.output == ""
        assert result.exit_code == 0

    def test_successful_command(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test executing successful command."""
        block = Block(target="LOCAL", commands=['echo "hello world"'])
        result = execute_local(block, execution_context)
        assert result.success is True
        assert result.exit_code == 0
        assert "hello world" in result.output

    def test_multiple_commands(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test executing multiple commands."""
        block = Block(
            target="LOCAL",
            commands=['echo "line1"', 'echo "line2"'],
        )
        result = execute_local(block, execution_context)
        assert result.success is True
        assert "line1" in result.output
        assert "line2" in result.output

    def test_failed_command(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test executing command that fails."""
        block = Block(target="LOCAL", commands=["exit 1"])
        result = execute_local(block, execution_context)
        assert result.success is False
        assert result.exit_code == 1
        assert "exit code: 1" in result.error_message.lower()

    def test_stderr_capture(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test that stderr is captured in output."""
        block = Block(target="LOCAL", commands=['echo "error msg" >&2'])
        result = execute_local(block, execution_context)
        assert result.success is True
        assert "error msg" in result.output

    def test_context_env_vars(
        self,
    ) -> None:
        """Test that context environment variables are passed."""
        context = ExecutionContext(env={"MY_VAR": "test_value"})
        block = Block(target="LOCAL", commands=["echo $MY_VAR"])
        result = execute_local(block, context)
        assert result.success is True
        assert "test_value" in result.output

    def test_subprocess_error_handling(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test handling of subprocess errors."""
        # Create a mock that raises SubprocessError
        with mock.patch(
            "shellflow.subprocess.run",
            side_effect=subprocess.SubprocessError("Mocked error"),
        ):
            block = Block(target="LOCAL", commands=["echo hello"])
            result = execute_local(block, execution_context)
            assert result.success is False
            assert result.exit_code == -1
            assert "mocked error" in result.error_message.lower()


# =============================================================================
# execute_remote Tests
# =============================================================================


class TestExecuteRemote:
    """Tests for execute_remote function."""

    def test_timeout_directive_passes_timeout_to_remote_subprocess(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test remote execution applies the block timeout policy to subprocess.run."""
        block = Block(target="REMOTE:server1", commands=["hostname"], timeout_seconds=11)
        ssh_config = SSHConfig(host="server1")

        mock_result = mock.Mock(returncode=0, stdout="server1\n", stderr="")

        with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
            result = execute_remote(block, execution_context, ssh_config)

        assert result.success is True
        assert mock_run.call_args.kwargs["timeout"] == 11

    def test_no_input_adds_stdin_null_flag(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test no-input mode prevents SSH from reading caller stdin."""
        block = Block(target="REMOTE:server1", commands=["hostname"])
        ssh_config = SSHConfig(host="server1")

        mock_result = mock.Mock(returncode=0, stdout="server1\n", stderr="")

        with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
            result = execute_remote(block, execution_context, ssh_config, no_input=True)

        assert result.success is True
        call_args = mock_run.call_args[0][0]
        assert "-n" in call_args

    def test_empty_block(self, execution_context: ExecutionContext) -> None:
        """Test executing empty remote block returns success."""
        block = Block(target="REMOTE:host1", commands=[])
        ssh_config = SSHConfig(host="host1")
        result = execute_remote(block, execution_context, ssh_config)
        assert result.success is True
        assert result.output == ""

    def test_missing_host(self, execution_context: ExecutionContext) -> None:
        """Test block without host returns error."""
        block = Block(target="REMOTE:", commands=["hostname"])
        ssh_config = SSHConfig(host="host1")
        result = execute_remote(block, execution_context, ssh_config)
        assert result.success is False
        assert "no host specified" in result.error_message.lower()

    def test_successful_remote_execution(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test successful remote execution via SSH."""
        block = Block(target="REMOTE:server1", commands=["hostname"])
        ssh_config = SSHConfig(
            host="server1",
            hostname="192.168.1.100",
            user="admin",
            port=2222,
            identity_file="~/.ssh/key",
        )

        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = "server1\n"
        mock_result.stderr = ""

        with mock.patch("shellflow.subprocess.run", return_value=mock_result):
            result = execute_remote(block, execution_context, ssh_config)

        assert result.success is True
        assert result.exit_code == 0
        assert "server1" in result.output

    def test_ssh_config_used_in_command(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test that SSH config is properly used in SSH command."""
        block = Block(target="REMOTE:myhost", commands=["uptime"])
        ssh_config = SSHConfig(
            host="myhost",
            hostname="192.168.1.50",
            user="root",
            port=2222,
            identity_file="/path/to/key",
        )

        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
            execute_remote(block, execution_context, ssh_config)

            # Check that SSH command was called with correct args
            call_args = mock_run.call_args[0][0]
            assert "ssh" in call_args[0]
            assert "-p" in call_args
            assert "2222" in call_args
            assert "-l" in call_args
            assert "root" in call_args
            assert "-i" in call_args
            assert "/path/to/key" in call_args

    def test_custom_remote_shell_runs_as_login_shell(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test custom remote shells run in login mode so host PATH initialization is loaded."""
        block = Block(target="REMOTE:myhost", commands=["mise --version"], shell="zsh")  # noqa: S604
        ssh_config = SSHConfig(host="myhost")

        mock_result = mock.Mock(returncode=0, stdout="2026.1.0\n", stderr="")

        with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
            result = execute_remote(block, execution_context, ssh_config)

        assert result.success is True
        call_args = mock_run.call_args[0][0]
        assert call_args[-4:] == ["zsh", "-l", "-s", "-e"]

    def test_remote_zsh_bootstraps_zshrc_before_commands(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test remote zsh execution sources ~/.zshrc so non-login PATH customizations are available."""
        block = Block(target="REMOTE:myhost", commands=["mise --version"], shell="zsh")  # noqa: S604
        ssh_config = SSHConfig(host="myhost")

        mock_result = mock.Mock(returncode=0, stdout="2026.1.0\n", stderr="")

        with mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
            result = execute_remote(block, execution_context, ssh_config)

        assert result.success is True
        sent_script = mock_run.call_args.kwargs["input"]
        assert "test -f ~/.zshrc && { source ~/.zshrc >/dev/null 2>&1 || true; }" in sent_script
        assert sent_script.index(
            "test -f ~/.zshrc && { source ~/.zshrc >/dev/null 2>&1 || true; }"
        ) < sent_script.index("mise --version")

    def test_remote_execution_only_exports_explicit_context(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test that remote execution does not leak the entire local environment."""
        del execution_context
        block = Block(target="REMOTE:server1", commands=["env"])
        context = ExecutionContext(env={"DEPLOY_ENV": "prod"}, last_output="done")
        ssh_config = SSHConfig(host="server1")

        mock_result = mock.Mock(returncode=0, stdout="", stderr="")

        with (
            mock.patch.dict(
                "os.environ",
                {"AWS_SECRET_ACCESS_KEY": "super-secret"},
                clear=True,
            ),
            mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run,
        ):
            execute_remote(block, context, ssh_config)

        sent_script = mock_run.call_args.kwargs["input"]
        assert 'export DEPLOY_ENV="prod"' in sent_script
        assert 'export SHELLFLOW_LAST_OUTPUT="done"' in sent_script
        assert "AWS_SECRET_ACCESS_KEY" not in sent_script

    def test_remote_execution_failure(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test handling of failed remote execution."""
        block = Block(target="REMOTE:server1", commands=["false"])
        ssh_config = SSHConfig(host="server1")

        mock_result = mock.Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied"

        with mock.patch("shellflow.subprocess.run", return_value=mock_result):
            result = execute_remote(block, execution_context, ssh_config)

        assert result.success is False
        assert result.exit_code == 1
        assert "permission denied" in result.output.lower()

    def test_subprocess_error_handling(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test handling of subprocess errors."""
        block = Block(target="REMOTE:server1", commands=["hostname"])
        ssh_config = SSHConfig(host="server1")

        with mock.patch(
            "shellflow.subprocess.run",
            side_effect=subprocess.SubprocessError("SSH failed"),
        ):
            result = execute_remote(block, execution_context, ssh_config)

        assert result.success is False
        assert result.exit_code == -1
        assert "ssh failed" in result.error_message.lower()

    def test_no_ssh_config_uses_manual_lookup(
        self,
        execution_context: ExecutionContext,
    ) -> None:
        """Test that manual SSH config lookup is used when no config provided."""
        block = Block(target="REMOTE:myhost", commands=["hostname"])

        mock_ssh_config = SSHConfig(
            host="myhost",
            hostname="192.168.1.10",
            port=2222,
        )

        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with (
            mock.patch(
                "shellflow.read_ssh_config",
                return_value=mock_ssh_config,
            ) as mock_read_config,
            mock.patch(
                "shellflow.subprocess.run",
                return_value=mock_result,
            ) as mock_run,
        ):
            execute_remote(block, execution_context, None)

            # Verify SSH config was looked up
            mock_read_config.assert_called_once_with("myhost")

            # Verify the port from looked-up config was used
            call_args = mock_run.call_args[0][0]
            assert "-p" in call_args
            assert "2222" in call_args


class TestShellBootstrapIntegration:
    """Integration-style tests for non-interactive shell bootstrap behavior."""

    @pytest.mark.skipif(not ZSH_AVAILABLE, reason="zsh not available")
    def test_zsh_bootstrap_ignores_nonzero_zshrc_and_keeps_path_customizations(self, tmp_path: Path) -> None:
        """Test guarded zshrc bootstrap still exposes commands after a non-zero rc return."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake_mise = bin_dir / "mise"
        fake_mise.write_text("#!/bin/sh\necho fake-mise\n")
        fake_mise.chmod(0o755)

        (tmp_path / ".zshrc").write_text(f'export PATH="{bin_dir}:$PATH"\nfalse\n')

        script = _build_executable_script(  # noqa: S604
            ["command -v mise"],
            ExecutionContext(),
            include_context_exports=False,
            shell="zsh",
        )

        result = subprocess.run(
            ["/bin/zsh", "-l", "-s", "-e"],
            input=script,
            capture_output=True,
            text=True,
            env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            check=False,
        )

        assert result.returncode == 0
        assert str(fake_mise) in result.stdout

    def test_bash_bootstrap_ignores_nonzero_bashrc_and_keeps_path_customizations(self, tmp_path: Path) -> None:
        """Test guarded bashrc bootstrap still exposes commands after a non-zero rc return."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake_tool = bin_dir / "tool-from-bashrc"
        fake_tool.write_text("#!/bin/sh\necho fake-bash-tool\n")
        fake_tool.chmod(0o755)

        (tmp_path / ".bashrc").write_text(f'export PATH="{bin_dir}:$PATH"\nfalse\n')

        script = _build_executable_script(  # noqa: S604
            ["command -v tool-from-bashrc"],
            ExecutionContext(),
            include_context_exports=False,
            shell="bash",
        )

        result = subprocess.run(
            ["/bin/bash", "-l", "-s", "-e"],
            input=script,
            capture_output=True,
            text=True,
            env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            check=False,
        )

        assert result.returncode == 0
        assert str(fake_tool) in result.stdout


# =============================================================================
# parse_script Advanced Tests
# =============================================================================


class TestParseScriptAdvanced:
    """Advanced tests for parse_script function."""

    def test_parse_timeout_and_retry_directives(self) -> None:
        """Test timeout and retry directives become block-local policy metadata."""
        script = """# @LOCAL
# @TIMEOUT 15
# @RETRY 2
echo \"hello\"
"""

        blocks = parse_script(script)

        assert len(blocks) == 1
        assert blocks[0].timeout_seconds == 15
        assert blocks[0].retry_count == 2
        assert blocks[0].commands == ['echo "hello"']

    def test_parse_export_directives(self) -> None:
        """Test export directives become block-local export mappings."""
        script = """# @LOCAL
# @EXPORT VERSION=stdout
# @EXPORT STATUS=exit_code
echo \"hello\"
"""

        blocks = parse_script(script)

        assert len(blocks) == 1
        assert blocks[0].exports == {"VERSION": "stdout", "STATUS": "exit_code"}
        assert blocks[0].commands == ['echo "hello"']

    @pytest.mark.parametrize(
        ("directive", "value", "message"),
        [
            ("TIMEOUT", "0", "positive integer"),
            ("TIMEOUT", "abc", "positive integer"),
            ("RETRY", "-1", "non-negative integer"),
            ("RETRY", "abc", "non-negative integer"),
            ("EXPORT", "VERSION", "NAME=source format"),
            ("EXPORT", "1VERSION=stdout", "valid environment variable name"),
            ("EXPORT", "VERSION=stream", "Valid sources"),
        ],
    )
    def test_invalid_directive_values_raise_parse_error(
        self,
        directive: str,
        value: str,
        message: str,
    ) -> None:
        """Test invalid timeout and retry directives fail parsing."""
        script = f"""# @LOCAL
# @{directive} {value}
echo \"hello\"
"""

        with pytest.raises(ParseError, match=message):
            parse_script(script)

    def test_prelude_is_prepended_to_each_block(self) -> None:
        """Test that lines before the first marker are applied to each block."""
        script = """#!/bin/bash
set -eu

# @LOCAL
echo "one"

# @LOCAL
echo "two"
"""
        blocks = parse_script(script)

        assert blocks[0].commands[:2] == ["#!/bin/bash", "set -eu"]
        assert blocks[1].commands[:2] == ["#!/bin/bash", "set -eu"]

    def test_consecutive_markers_same_type(self) -> None:
        """Test consecutive markers of same type."""
        script = """# @LOCAL
echo "block 1"
# @LOCAL
echo "block 2"
"""
        blocks = parse_script(script)
        assert len(blocks) == 2
        assert blocks[0].commands == ['echo "block 1"']
        assert blocks[1].commands == ['echo "block 2"']

    def test_trailing_marker_no_content(self) -> None:
        """Test trailing marker with no following content."""
        script = """# @LOCAL
echo "hello"
# @REMOTE server1
"""
        blocks = parse_script(script)
        # The second block has no commands
        assert len(blocks) == 1
        assert blocks[0].commands == ['echo "hello"']

    def test_remote_with_extra_whitespace(self) -> None:
        """Test @REMOTE with extra whitespace."""
        script = """# @REMOTE   server1
hostname
"""
        blocks = parse_script(script)
        assert len(blocks) == 1
        assert blocks[0].target == "REMOTE:server1"

    def test_unknown_marker_raises_parse_error(self) -> None:
        """Test that unknown markers fail fast."""
        script = """# @UNKNOWN
echo "hello"
"""

        with pytest.raises(ParseError, match="Unknown marker"):
            parse_script(script)

    def test_inline_marker_text_is_not_treated_as_block_marker(self) -> None:
        """Test that only comment markers at line start create blocks."""
        script = """# @LOCAL
echo "# @REMOTE server1"
"""

        blocks = parse_script(script)

        assert len(blocks) == 1
        assert blocks[0].commands == ['echo "# @REMOTE server1"']

    def test_mixed_content_with_shell_comments(self) -> None:
        """Test parsing with shell comments mixed in."""
        script = """# @LOCAL
# This is a shell comment
echo "hello"  # inline comment
"""
        blocks = parse_script(script)
        assert len(blocks) == 1
        # Shell comments should be preserved as part of commands
        assert "# This is a shell comment" in blocks[0].commands


# =============================================================================
# _clean_commands Tests
# =============================================================================


class TestCleanCommandsAdvanced:
    """Advanced tests for _clean_commands function."""

    def test_all_empty_lines(self) -> None:
        """Test with all empty lines."""
        lines = ["", "  ", "\t"]
        result = _clean_commands(lines)
        assert result == []

    def test_mixed_indentation(self) -> None:
        """Test with mixed indentation."""
        lines = [
            "    echo hello",
            "    if true; then",
            "        echo nested",
            "    fi",
        ]
        result = _clean_commands(lines)
        assert result[0] == "echo hello"
        assert result[1] == "if true; then"
        assert result[2] == "    echo nested"  # Preserved relative indent

    def test_tabs_and_spaces(self) -> None:
        """Test with tabs and spaces."""
        lines = [
            "\t\techo hello",
            "\t\techo world",
        ]
        result = _clean_commands(lines)
        assert result == ["echo hello", "echo world"]


# =============================================================================
# read_ssh_config Tests
# =============================================================================


class TestReadSSHConfig:
    """Tests for read_ssh_config function."""

    def test_no_config_file(self, tmp_path: Path) -> None:
        """Test when SSH config file doesn't exist."""
        # Mock home directory to temp path
        with mock.patch.object(Path, "home", return_value=tmp_path):
            result = read_ssh_config("somehost")
            assert result is None

    def test_basic_fallback_parsing(self, tmp_path: Path) -> None:
        """Test basic SSH config parsing without paramiko."""
        # Create mock SSH config
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        config_file = ssh_dir / "config"
        config_file.write_text("""
Host testserver
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/test_key
""")

        with (
            mock.patch.object(Path, "home", return_value=tmp_path),
            mock.patch.dict(
                "sys.modules",
                {"paramiko": None},
            ),
        ):
            result = read_ssh_config("testserver")

        assert result is not None
        assert result.host == "testserver"
        assert result.hostname == "192.168.1.100"
        assert result.user == "admin"
        assert result.port == 2222
        assert result.identity_file == "~/.ssh/test_key"

    def test_host_not_found(self, tmp_path: Path) -> None:
        """Test looking up a host that doesn't exist."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        config_file = ssh_dir / "config"
        config_file.write_text("""
Host server1
    HostName 192.168.1.1
""")

        with (
            mock.patch.object(Path, "home", return_value=tmp_path),
            mock.patch.dict(
                "sys.modules",
                {"paramiko": None},
            ),
        ):
            result = read_ssh_config("nonexistent")

        assert result is None

    def test_wildcard_host_match(self, tmp_path: Path) -> None:
        """Test wildcard host matching."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        config_file = ssh_dir / "config"
        config_file.write_text("""
Host *
    User defaultuser
    Port 2222
""")

        with (
            mock.patch.object(Path, "home", return_value=tmp_path),
            mock.patch.dict(
                "sys.modules",
                {"paramiko": None},
            ),
        ):
            result = read_ssh_config("anyhost")

        assert result is not None
        assert result.host == "anyhost"
        assert result.user == "defaultuser"
        assert result.port == 2222

    def test_specific_host_overrides_wildcard(self, tmp_path: Path) -> None:
        """Test that a specific host stanza overrides wildcard defaults."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        config_file = ssh_dir / "config"
        config_file.write_text("""
Host *
    User defaultuser
    Port 22

Host deploy-box
    User deploy
    Port 2222
""")

        with (
            mock.patch.object(Path, "home", return_value=tmp_path),
            mock.patch.dict(
                "sys.modules",
                {"paramiko": None},
            ),
        ):
            result = read_ssh_config("deploy-box")

        assert result is not None
        assert result.user == "deploy"
        assert result.port == 2222

    def test_paramiko_lookup_requires_matching_host_rule(self, tmp_path: Path) -> None:
        """Test paramiko lookup rejects hosts not matched by any Host rule."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        config_file = ssh_dir / "config"
        config_file.write_text("""
Host deploy-box
    HostName 10.0.0.10
""")

        fake_ssh_config = mock.Mock()
        fake_ssh_config.lookup.return_value = {"hostname": "missing-host"}
        fake_ssh_config.get_hostnames.return_value = {"deploy-box"}

        fake_paramiko = mock.Mock()
        fake_paramiko.SSHConfig.return_value = fake_ssh_config

        with (
            mock.patch.object(Path, "home", return_value=tmp_path),
            mock.patch.dict(
                "sys.modules",
                {"paramiko": fake_paramiko},
            ),
        ):
            result = read_ssh_config("missing-host")

        assert result is None


# =============================================================================
# run_script Tests
# =============================================================================


class TestRunScript:
    """Tests for run_script function."""

    def test_dry_run_skips_execution_and_emits_plan_events(self) -> None:
        """Test dry-run mode emits a plan without executing any block commands."""
        blocks = [
            Block(target="LOCAL", commands=['echo "first"'], source_line=2),
            Block(target="REMOTE:staging", commands=["hostname"], source_line=6),
        ]

        with (
            mock.patch("shellflow.execute_local") as mock_execute_local,
            mock.patch("shellflow.execute_remote") as mock_execute_remote,
        ):
            result = run_script(blocks, dry_run=True)

        assert result.success is True
        assert result.blocks_executed == 0
        assert [event.event for event in result.events] == [
            "dry_run_started",
            "dry_run_block",
            "dry_run_block",
            "dry_run_finished",
        ]
        assert result.events[1].target == "LOCAL"
        assert result.events[2].target == "REMOTE:staging"
        mock_execute_local.assert_not_called()
        mock_execute_remote.assert_not_called()

    def test_named_exports_propagate_to_later_blocks(self) -> None:
        """Test explicit exports are added to later block environments."""
        blocks = [
            Block(target="LOCAL", commands=['echo "1.2.3"'], source_line=2, exports={"VERSION": "stdout"}),
            Block(target="LOCAL", commands=['printf "%s" "$VERSION"'], source_line=6),
        ]

        def fake_execute_local(block: Block, context: ExecutionContext, no_input: bool = False) -> ExecutionResult:
            del no_input
            if block.source_line == 2:
                assert context.env == {}
                assert context.last_output == ""
                return ExecutionResult(
                    success=True,
                    output="1.2.3",
                    exit_code=0,
                    stdout="1.2.3",
                )

            assert context.env["VERSION"] == "1.2.3"
            assert context.last_output == "1.2.3"
            return ExecutionResult(
                success=True,
                output="VERSION=1.2.3",
                exit_code=0,
                stdout="VERSION=1.2.3",
            )

        with mock.patch("shellflow.execute_local", side_effect=fake_execute_local):
            result = run_script(blocks)

        assert result.success is True
        assert result.block_results[0].exported_env == {"VERSION": "1.2.3"}
        assert result.block_results[1].output == "VERSION=1.2.3"

    def test_block_report_can_redact_secret_like_exports(self) -> None:
        """Test structured block serialization can redact obvious secret-like exports."""
        result = ExecutionResult(
            success=True,
            output="ok",
            stdout="ok",
            exported_env={
                "VERSION": "1.2.3",
                "API_TOKEN": "super-secret-token",
            },
        )

        payload = result.to_dict(redact_secret_exports=True)

        assert payload["exported_env"] == {
            "VERSION": "1.2.3",
            "API_TOKEN": "[REDACTED]",
        }

    def test_event_payload_can_redact_secret_like_export_values_for_audit(self) -> None:
        """Test audit serialization redacts secret-like exported values across the event payload."""
        secret_export_name = "API" + "_TOKEN"
        block_result = ExecutionResult(
            success=True,
            output="super-secret-token",
            stdout="super-secret-token",
            exported_env={secret_export_name: "super-secret-token"},
        )
        event = block_result

        payload = event.to_dict(redact_secret_exports=True)

        assert payload["output"] == "[REDACTED]"
        assert payload["stdout"] == "[REDACTED]"
        assert payload["exported_env"][secret_export_name] == "[REDACTED]"

    def test_retry_directive_reruns_failed_block_and_emits_retry_event(self) -> None:
        """Test retry policy reruns a transiently failing block and records retry metadata."""
        blocks = [
            Block(target="LOCAL", commands=['echo "retry"'], retry_count=1, source_line=4),
        ]

        attempt_results = [
            ExecutionResult(
                success=False,
                output="",
                exit_code=1,
                error_message="Exit code: 1",
                failure_kind="runtime",
            ),
            ExecutionResult(
                success=True,
                output="recovered",
                exit_code=0,
                stdout="recovered",
            ),
        ]

        with mock.patch("shellflow.execute_local", side_effect=attempt_results) as mock_execute:
            result = run_script(blocks)

        assert result.success is True
        assert result.block_results[0].attempts == 2
        assert [event.event for event in result.events] == [
            "run_started",
            "block_started",
            "block_retrying",
            "block_finished",
            "run_finished",
        ]
        assert mock_execute.call_count == 2

    def test_timeout_directive_stops_retry_and_records_timeout_policy(self) -> None:
        """Test timeout failures stay bounded and preserve timeout metadata in reports."""
        blocks = [
            Block(target="LOCAL", commands=["sleep 5"], timeout_seconds=3, retry_count=2, source_line=9),
        ]

        timed_out_result = ExecutionResult(
            success=False,
            output="",
            exit_code=-1,
            error_message="Timed out after 3 second(s)",
            timed_out=True,
            failure_kind="timeout",
        )

        with mock.patch("shellflow.execute_local", return_value=timed_out_result) as mock_execute:
            result = run_script(blocks)

        assert result.success is False
        assert result.exit_code == 4
        assert result.block_results[0].timed_out is True
        assert result.block_results[0].attempts == 1
        assert result.block_results[0].timeout_seconds == 3
        assert mock_execute.call_count == 1

    def test_block_report_keeps_split_output_and_metadata(self) -> None:
        """Test run results retain structured block metadata for reporting."""
        blocks = [
            Block(target="LOCAL", commands=['printf "out"', 'printf "err" >&2'], source_line=3),
        ]

        result = run_script(blocks)

        assert result.success is True
        assert result.run_id
        assert result.schema_version
        assert result.block_results[0].block_id == "block-1"
        assert result.block_results[0].block_index == 1
        assert result.block_results[0].source_line == 3
        assert result.block_results[0].stdout == "out"
        assert result.block_results[0].stderr == "err"
        assert result.block_results[0].duration_ms >= 0
        assert result.block_results[0].attempts == 1
        assert result.block_results[0].timed_out is False

    def test_run_script_records_ordered_events(self) -> None:
        """Test run results expose ordered events for JSONL output."""
        blocks = [
            Block(target="LOCAL", commands=['echo "first"'], source_line=1),
            Block(target="LOCAL", commands=['echo "second"'], source_line=4),
        ]

        result = run_script(blocks)

        assert [event.event for event in result.events] == [
            "run_started",
            "block_started",
            "block_finished",
            "block_started",
            "block_finished",
            "run_finished",
        ]
        assert result.events[1].block_id == "block-1"
        assert result.events[3].block_id == "block-2"

    @given(stdout=st.text(), stderr=st.text())
    def test_hypothesis_report_serialization_keeps_required_fields(self, stdout: str, stderr: str) -> None:
        """Test serialized reports always expose the required top-level and block fields."""
        result = RunResult(
            success=not stderr,
            blocks_executed=1,
            run_id="run-test",
            schema_version="1.0",
            block_results=[
                ExecutionResult(
                    success=not stderr,
                    output="\n".join(part for part in (stdout, stderr) if part),
                    stdout=stdout,
                    stderr=stderr,
                    block_id="block-1",
                    block_index=1,
                    source_line=7,
                )
            ],
        )

        payload = result.to_dict()

        assert payload["run_id"] == "run-test"
        assert payload["schema_version"] == "1.0"
        assert payload["blocks"][0]["block_id"] == "block-1"
        assert "stdout" in payload["blocks"][0]
        assert "stderr" in payload["blocks"][0]

    @given(name=VALID_EXPORT_NAME_STRATEGY, source=VALID_EXPORT_SOURCE_STRATEGY)
    def test_hypothesis_valid_export_directives_round_trip(self, name: str, source: str) -> None:
        """Test valid export directives always parse into block export mappings."""
        script = f"""# @LOCAL
# @EXPORT {name}={source}
echo \"hello\"
"""

        blocks = parse_script(script)

        assert len(blocks) == 1
        assert blocks[0].exports == {name: source}

    @given(name=INVALID_EXPORT_NAME_STRATEGY, source=VALID_EXPORT_SOURCE_STRATEGY)
    def test_hypothesis_invalid_export_names_are_rejected(self, name: str, source: str) -> None:
        """Test invalid export names are always rejected by the parser."""
        script = f"""# @LOCAL
# @EXPORT {name}={source}
echo \"hello\"
"""

        with pytest.raises(ParseError, match="valid environment variable name"):
            parse_script(script)

    @given(line=MALFORMED_DIRECTIVE_LINE_STRATEGY)
    def test_hypothesis_malformed_directive_lines_fail_parsing(self, line: str) -> None:
        """Test malformed directive-like comment lines fail instead of being treated as ordinary comments."""
        script = f"""# @LOCAL
{line}
echo \"hello\"
"""

        with pytest.raises(ParseError):
            parse_script(script)

    def test_empty_blocks(self) -> None:
        """Test running empty block list."""
        result = run_script([])
        assert result.success is True
        assert result.blocks_executed == 0

    def test_single_local_block_success(self) -> None:
        """Test running single local block successfully."""
        blocks = [
            Block(target="LOCAL", commands=['echo "hello"']),
        ]
        result = run_script(blocks)
        assert result.success is True
        assert result.blocks_executed == 1

    def test_multiple_local_blocks(self) -> None:
        """Test running multiple local blocks."""
        blocks = [
            Block(target="LOCAL", commands=['echo "block1"']),
            Block(target="LOCAL", commands=['echo "block2"']),
        ]
        result = run_script(blocks)
        assert result.success is True
        assert result.blocks_executed == 2

    def test_fail_fast_on_error(self) -> None:
        """Test that execution stops on first failure."""
        blocks = [
            Block(target="LOCAL", commands=['echo "first"']),
            Block(target="LOCAL", commands=["exit 1"]),
            Block(target="LOCAL", commands=['echo "third"']),
        ]
        result = run_script(blocks)
        assert result.success is False
        assert result.blocks_executed == 2
        assert "block 2 failed" in result.error_message.lower()

    def test_context_passing_between_blocks(self) -> None:
        """Test that context is passed between blocks."""
        blocks = [
            Block(target="LOCAL", commands=['echo "output1"']),
            Block(target="LOCAL", commands=["echo $SHELLFLOW_LAST_OUTPUT"]),
        ]
        result = run_script(blocks)
        assert result.success is True

    def test_remote_block_no_host(self) -> None:
        """Test remote block with no host returns error."""
        blocks = [
            Block(target="REMOTE:", commands=["hostname"]),
        ]
        result = run_script(blocks)
        assert result.success is False
        assert "no host specified" in result.error_message.lower()

    def test_remote_block_with_host(
        self,
    ) -> None:
        """Test remote block execution with host."""
        blocks = [
            Block(target="REMOTE:server1", commands=["hostname"]),
        ]

        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = "server1\n"
        mock_result.stderr = ""

        with (
            mock.patch(
                "shellflow.read_ssh_config",
                return_value=SSHConfig(host="server1"),
            ),
            mock.patch("shellflow.subprocess.run", return_value=mock_result),
        ):
            result = run_script(blocks)

        assert result.success is True

    def test_remote_block_requires_host_in_ssh_config(self) -> None:
        """Test remote execution fails before SSH when host is not defined in SSH config."""
        blocks = [
            Block(target="REMOTE:missing-host", commands=["hostname"]),
        ]

        with (
            mock.patch("shellflow.read_ssh_config", return_value=None),
            mock.patch("shellflow.subprocess.run") as mock_run,
        ):
            result = run_script(blocks)

        assert result.success is False
        assert "ssh config" in result.error_message.lower()
        mock_run.assert_not_called()

    def test_verbose_output(self, capsys: Any) -> None:
        """Test verbose mode produces output."""
        blocks = [
            Block(target="LOCAL", commands=['echo "__RESULT__"']),
        ]

        result = run_script(blocks, verbose=True)

        captured = capsys.readouterr()
        assert result.success is True
        assert "LOCAL" in captured.out or "local" in captured.out.lower()
        assert '\x1b[90m$ echo "__RESULT__"\x1b[0m' in captured.out
        assert captured.out.index('$ echo "__RESULT__"') < captured.out.index("__RESULT__")
        assert captured.out.index("__RESULT__") < captured.out.index("✓ Success")

    def test_verbose_remote_context_output_is_clean(self, capsys: Any) -> None:
        """Test verbose remote output shows clean context instead of shell trace internals."""
        blocks = [
            Block(target="LOCAL", commands=['printf "alpha"']),
            Block(target="REMOTE:server1", commands=["hostname"]),
        ]

        with (
            mock.patch(
                "shellflow.read_ssh_config",
                return_value=SSHConfig(host="server1"),
            ),
            mock.patch(
                "shellflow.execute_remote",
                return_value=ExecutionResult(success=True, output="server1"),
            ),
        ):
            result = run_script(blocks, verbose=True)

        captured = capsys.readouterr()
        assert result.success is True
        assert 'SHELLFLOW_LAST_OUTPUT="alpha"' in captured.out
        assert "export SHELLFLOW_LAST_OUTPUT" not in captured.out
        assert "$ hostname" in captured.out


# =============================================================================
# CLI Tests
# =============================================================================


class TestCreateParser:
    """Tests for create_parser function."""

    def test_parser_creation(self) -> None:
        """Test parser is created with expected arguments."""
        parser = create_parser()
        assert parser is not None

    def test_version_argument(self) -> None:
        """Test --version argument exists."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_run_command(self) -> None:
        """Test run subcommand exists."""
        parser = create_parser()
        args = parser.parse_args(["run", "script.sh"])
        assert args.command == "run"
        assert args.script == "script.sh"
        assert args.verbose is False

    def test_run_command_verbose(self) -> None:
        """Test run command with verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["run", "script.sh", "--verbose"])
        assert args.verbose is True

    def test_run_command_json(self) -> None:
        """Test run command with JSON flag."""
        parser = create_parser()
        args = parser.parse_args(["run", "script.sh", "--json"])
        assert args.json is True
        assert args.jsonl is False

    def test_run_command_jsonl(self) -> None:
        """Test run command with JSONL flag."""
        parser = create_parser()
        args = parser.parse_args(["run", "script.sh", "--jsonl"])
        assert args.jsonl is True
        assert args.json is False

    def test_run_command_no_input(self) -> None:
        """Test run command with no-input flag."""
        parser = create_parser()
        args = parser.parse_args(["run", "script.sh", "--no-input"])
        assert args.no_input is True

    def test_run_command_dry_run(self) -> None:
        """Test run command with dry-run flag."""
        parser = create_parser()
        args = parser.parse_args(["run", "script.sh", "--dry-run"])
        assert args.dry_run is True

    def test_run_command_audit_log(self, tmp_path: Path) -> None:
        """Test run command with audit-log path."""
        parser = create_parser()
        audit_log_path = tmp_path / "audit.jsonl"
        args = parser.parse_args(["run", "script.sh", "--audit-log", str(audit_log_path)])
        assert args.audit_log == str(audit_log_path)


class TestMain:
    """Tests for main function."""

    def test_no_args_prints_help(self, capsys: Any) -> None:
        """Test main with no arguments prints help."""
        del capsys
        main([])
        # Should return 1 when no command provided
        # Note: current implementation returns 1, which is expected

    def test_run_nonexistent_script(self, tmp_path: Path) -> None:
        """Test run command with non-existent script."""
        script_path = tmp_path / "nonexistent.sh"
        result = main(["run", str(script_path)])
        assert result == 1

    def test_run_script_success(self, tmp_path: Path) -> None:
        """Test run command with valid script."""
        script_path = tmp_path / "test.sh"
        script_path.write_text("""# @LOCAL
echo "hello"
""")

        with mock.patch("shellflow.run_script") as mock_run:
            mock_run.return_value = RunResult(success=True, blocks_executed=1)
            result = main(["run", str(script_path)])

        assert result == 0

    def test_run_script_failure(self, tmp_path: Path) -> None:
        """Test run command when script execution fails."""
        script_path = tmp_path / "test.sh"
        script_path.write_text("""# @LOCAL
exit 1
""")

        with mock.patch("shellflow.run_script") as mock_run:
            mock_run.return_value = RunResult(
                success=False,
                blocks_executed=1,
                error_message="Block 1 failed",
            )
            result = main(["run", str(script_path)])

        assert result == 1

    def test_run_script_parse_failure_uses_parse_exit_code(self, tmp_path: Path) -> None:
        """Test parse failures use the dedicated exit code."""
        script_path = tmp_path / "test.sh"
        script_path.write_text("""# @BROKEN
echo \"hello\"
""")

        result = main(["run", str(script_path)])

        assert result == 2

    def test_run_script_no_input_json_marks_interactive_input_unavailable(self, tmp_path: Path, capsys: Any) -> None:
        """Test no-input mode advertises non-interactive execution in structured output."""
        script_path = tmp_path / "stdin.sh"
        script_path.write_text("""# @LOCAL
read -r reply
printf 'reply=%s\n' "$reply"
""")

        result = main(["run", str(script_path), "--no-input", "--json"])

        captured = capsys.readouterr()
        payload = json.loads(captured.out)

        assert result == 1
        assert payload["no_input"] is True
        assert "input" in json.dumps(payload).lower()

    def test_run_script_json_output(self, tmp_path: Path, capsys: Any) -> None:
        """Test JSON mode emits a machine-readable run report."""
        script_path = tmp_path / "test.sh"
        script_path.write_text("""# @LOCAL
echo "hello"
""")

        result = main(["run", str(script_path), "--json"])

        captured = capsys.readouterr()
        payload = json.loads(captured.out)

        assert result == 0
        assert payload["run_id"]
        assert payload["schema_version"]
        assert payload["blocks"][0]["stdout"] == "hello"

    def test_run_script_jsonl_output(self, tmp_path: Path, capsys: Any) -> None:
        """Test JSONL mode emits ordered execution events."""
        script_path = tmp_path / "test.sh"
        script_path.write_text("""# @LOCAL
echo "hello"
""")

        result = main(["run", str(script_path), "--jsonl"])

        captured = capsys.readouterr()
        events = [json.loads(line) for line in captured.out.splitlines() if line.strip()]

        assert result == 0
        assert [event["event"] for event in events] == [
            "run_started",
            "block_started",
            "block_finished",
            "run_finished",
        ]

    def test_run_script_dry_run_jsonl_output(self, tmp_path: Path, capsys: Any) -> None:
        """Test dry-run mode emits structured plan events instead of executing blocks."""
        marker_path = tmp_path / "should-not-exist.marker"
        script_path = tmp_path / "dry-run.sh"
        script_path.write_text(
            f"""# @LOCAL
printf 'executed' > \"{marker_path}\"

# @REMOTE staging
echo "remote preview"
"""
        )

        result = main(["run", str(script_path), "--dry-run", "--jsonl"])

        captured = capsys.readouterr()
        events = [json.loads(line) for line in captured.out.splitlines() if line.strip()]

        assert result == 0
        assert marker_path.exists() is False
        assert [event["event"] for event in events] == [
            "dry_run_started",
            "dry_run_block",
            "dry_run_block",
            "dry_run_finished",
        ]
        assert [event.get("target") for event in events[1:3]] == ["LOCAL", "REMOTE:staging"]

    def test_run_script_audit_log_writes_redacted_jsonl(self, tmp_path: Path, capsys: Any) -> None:
        """Test audit-log mode mirrors redacted structured events to disk."""
        audit_log_path = tmp_path / "audit.jsonl"
        script_path = tmp_path / "audit.sh"
        script_path.write_text(
            """# @LOCAL
# @EXPORT API_TOKEN=stdout
echo "super-secret-token"
"""
        )

        result = main(["run", str(script_path), "--audit-log", str(audit_log_path), "--jsonl"])

        captured = capsys.readouterr()
        stdout_events = [json.loads(line) for line in captured.out.splitlines() if line.strip()]
        audit_log_text = audit_log_path.read_text()
        audit_events = [json.loads(line) for line in audit_log_text.splitlines() if line.strip()]

        assert result == 0
        assert stdout_events
        assert audit_events
        assert "super-secret-token" not in audit_log_text
        assert "[REDACTED]" in audit_log_text


class TestCmdRun:
    """Tests for cmd_run function."""

    def test_parse_error_handling(self, tmp_path: Path) -> None:
        """Test handling of parse errors.

        Note: The current implementation doesn't raise ParseError for missing
        @REMOTE host, it just parses it with empty host.
        """
        script_path = tmp_path / "test.sh"
        script_path.write_text("""# @INVALID_MARKER
""")  # Invalid marker

        # Current implementation handles this gracefully
        result = main(["run", str(script_path)])
        # Empty script or script with invalid markers returns 0
        assert result == 0

    def test_empty_script(self, tmp_path: Path) -> None:
        """Test handling of empty script (no blocks)."""
        script_path = tmp_path / "test.sh"
        script_path.write_text("")

        result = main(["run", str(script_path)])
        assert result == 0  # Empty script is not an error

    def test_missing_ssh_host_uses_ssh_config_exit_code(self, tmp_path: Path) -> None:
        """Test missing SSH config maps to the SSH-config exit code."""
        script_path = tmp_path / "remote.sh"
        script_path.write_text("""# @REMOTE missing-host
echo "hello"
""")

        with mock.patch("shellflow.read_ssh_config", return_value=None):
            result = main(["run", str(script_path)])

        assert result == 3

    def test_timeout_failure_uses_timeout_exit_code(self, tmp_path: Path) -> None:
        """Test timeout failures map to the timeout-specific exit code."""
        script_path = tmp_path / "timeout.sh"
        script_path.write_text("""# @LOCAL
echo "hello"
""")

        timed_out_result = RunResult(
            success=False,
            blocks_executed=1,
            error_message="Block 1 timed out",
            exit_code=4,
            block_results=[
                ExecutionResult(
                    success=False,
                    output="",
                    exit_code=-1,
                    error_message="timed out",
                    timed_out=True,
                )
            ],
        )

        with mock.patch("shellflow.run_script", return_value=timed_out_result):
            result = main(["run", str(script_path), "--json"])

        assert result == 4


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_full_workflow_local_only(self) -> None:
        """Test complete workflow with only local blocks."""
        script = """# @LOCAL
echo "Step 1"
# @LOCAL
echo "Step 2"
# @LOCAL
echo "Step 3"
"""
        blocks = parse_script(script)
        result = run_script(blocks)

        assert result.success is True
        assert result.blocks_executed == 3

    def test_fail_fast_stops_execution(self) -> None:
        """Test that fail-fast behavior stops on first failure."""
        script = """# @LOCAL
echo "This will succeed"
# @LOCAL
exit 1
# @LOCAL
echo "This should not run"
"""
        blocks = parse_script(script)
        result = run_script(blocks)

        assert result.success is False
        assert result.blocks_executed == 2


class TestPackagingConfig:
    """Tests for build packaging configuration."""

    def test_wheel_configuration_includes_single_module_entrypoint(self) -> None:
        """Test wheel build config includes the single-file module at top level."""
        pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
        pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

        wheel_config = pyproject_data["tool"]["hatch"]["build"]["targets"]["wheel"]
        force_include = wheel_config.get("force-include", {})

        assert force_include.get("src/shellflow.py") == "shellflow.py"

    def test_context_variable_passing(self) -> None:
        """Test that context variables are passed between blocks."""
        script = """# @LOCAL
export MY_VAR="test_value"
echo $MY_VAR
# @LOCAL
echo $MY_VAR
"""
        blocks = parse_script(script)
        # Just verify parsing and execution works
        run_script(blocks)
        # Note: Variable passing between blocks depends on implementation
        # This test documents current behavior


# =============================================================================
# SSHConfig Tests
# =============================================================================


class TestSSHConfigAdvanced:
    """Advanced tests for SSHConfig dataclass."""

    def test_default_port(self) -> None:
        """Test default SSH port."""
        config = SSHConfig(host="test")
        assert config.port == 22

    def test_custom_port(self) -> None:
        """Test custom SSH port."""
        config = SSHConfig(host="test", port=2222)
        assert config.port == 2222

    def test_optional_fields(self) -> None:
        """Test that optional fields can be None."""
        config = SSHConfig(host="test")
        assert config.hostname is None
        assert config.user is None
        assert config.identity_file is None


# =============================================================================
# Exception Tests
# =============================================================================


class TestExceptionsAdvanced:
    """Advanced tests for custom exceptions."""

    def test_exception_inheritance(self) -> None:
        """Test exception class inheritance."""
        assert issubclass(ParseError, ShellflowError)
        assert issubclass(ExecutionError, ShellflowError)

    def test_catch_parent_exception(self) -> None:
        """Test catching child exceptions as parent."""
        with pytest.raises(ShellflowError, match="parse error"):
            raise ParseError("parse error")

    def test_execution_error_with_details(self) -> None:
        """Test ExecutionError with detailed message."""
        error = ExecutionError("Command failed: exit code 1")
        assert str(error) == "Command failed: exit code 1"

    def test_parse_error_with_line_number(self) -> None:
        """Test ParseError with line number information."""
        error = ParseError("Line 5: Invalid syntax")
        assert "line 5" in str(error).lower()
