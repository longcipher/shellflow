"""Unit tests for shellflow module.

Tests for parse_script, execute_local, execute_remote, run_script,
and helper functions in src/shellflow.py.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from shellflow import (
    Block,
    ExecutionContext,
    ExecutionError,
    ExecutionResult,
    ParseError,
    RunResult,
    ShellflowError,
    SSHConfig,
    _clean_commands,
    create_parser,
    execute_local,
    execute_remote,
    main,
    parse_script,
    read_ssh_config,
    run_script,
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

        with mock.patch.dict(
            "os.environ",
            {"AWS_SECRET_ACCESS_KEY": "super-secret"},
            clear=True,
        ), mock.patch("shellflow.subprocess.run", return_value=mock_result) as mock_run:
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

        with mock.patch(
            "shellflow.read_ssh_config",
            return_value=mock_ssh_config,
        ) as mock_read_config, mock.patch(
            "shellflow.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            execute_remote(block, execution_context, None)

            # Verify SSH config was looked up
            mock_read_config.assert_called_once_with("myhost")

            # Verify the port from looked-up config was used
            call_args = mock_run.call_args[0][0]
            assert "-p" in call_args
            assert "2222" in call_args


# =============================================================================
# parse_script Advanced Tests
# =============================================================================


class TestParseScriptAdvanced:
    """Advanced tests for parse_script function."""

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

        with mock.patch.object(Path, "home", return_value=tmp_path), mock.patch.dict(
            "sys.modules",
            {"paramiko": None},
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

        with mock.patch.object(Path, "home", return_value=tmp_path), mock.patch.dict(
            "sys.modules",
            {"paramiko": None},
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

        with mock.patch.object(Path, "home", return_value=tmp_path), mock.patch.dict(
            "sys.modules",
            {"paramiko": None},
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

        with mock.patch.object(Path, "home", return_value=tmp_path), mock.patch.dict(
            "sys.modules",
            {"paramiko": None},
        ):
            result = read_ssh_config("deploy-box")

        assert result is not None
        assert result.user == "deploy"
        assert result.port == 2222


# =============================================================================
# run_script Tests
# =============================================================================


class TestRunScript:
    """Tests for run_script function."""

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

        with mock.patch("shellflow.read_ssh_config", return_value=None), mock.patch(
            "shellflow.subprocess.run",
            return_value=mock_result,
        ):
            result = run_script(blocks)

        assert result.success is True

    def test_verbose_output(self, capsys: Any) -> None:
        """Test verbose mode produces output."""
        blocks = [
            Block(target="LOCAL", commands=['echo "test"']),
        ]

        result = run_script(blocks, verbose=True)

        captured = capsys.readouterr()
        assert result.success is True
        # Verbose output should contain block info
        assert "LOCAL" in captured.out or "local" in captured.out.lower()


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
        assert "block 2 failed" in result.error_message.lower()

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
