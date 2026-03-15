"""Step definitions for shellflow BDD scenarios."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from behave import given, then, when

if TYPE_CHECKING:
    from behave.runner import Context


# Given steps


@given('the shellflow configuration is initialized')
def step_given_config_initialized(context: Context) -> None:
    """Initialize shellflow configuration."""
    context.config = {"runner": {"fail_fast": True, "verbose": False}}
    context.temp_dir = tempfile.mkdtemp()


@given('a script file "{filename}" with content')
def step_given_script_file(context: Context, filename: str) -> None:
    """Create a script file with the given content."""
    if not hasattr(context, "temp_dir"):
        context.temp_dir = tempfile.mkdtemp()

    script_path = Path(context.temp_dir) / filename
    script_path.write_text(context.text)
    context.script_path = script_path


@given('a script with content')
def step_given_script_content(context: Context) -> None:
    """Create a script with the given content (unnamed)."""
    if not hasattr(context, "temp_dir"):
        context.temp_dir = tempfile.mkdtemp()

    script_path = Path(context.temp_dir) / "test_script.sh"
    script_path.write_text(context.text)
    context.script_path = script_path


@given('an SSH host "{host}" is configured')
def step_given_ssh_host_configured(context: Context, host: str) -> None:
    """Configure an SSH host."""
    if not hasattr(context, "ssh_hosts"):
        context.ssh_hosts = {}
    context.ssh_hosts[host] = {
        "host": f"{host}.example.com",
        "port": 22,
        "user": "testuser",
    }


@given('a config file with content')
def step_given_config_file(context: Context) -> None:
    """Create a config file with the given content."""
    if not hasattr(context, "temp_dir"):
        context.temp_dir = tempfile.mkdtemp()

    config_path = Path(context.temp_dir) / "config.toml"
    config_path.write_text(context.text)
    context.config_path = config_path


@given('environment variable {var} is set')
def step_given_env_var_set(context: Context, var: str) -> None:
    """Set an environment variable."""
    if not hasattr(context, "env_vars"):
        context.env_vars = {}
    context.env_vars[var] = "/home/testuser"


@given('no config file exists at the specified path')
def step_given_no_config_file(context: Context) -> None:
    """Ensure no config file exists."""
    context.config_path = Path("/nonexistent/path/config.toml")


@given('a malformed TOML config file')
def step_given_malformed_config(context: Context) -> None:
    """Create a malformed TOML config file."""
    if not hasattr(context, "temp_dir"):
        context.temp_dir = tempfile.mkdtemp()

    config_path = Path(context.temp_dir) / "bad_config.toml"
    config_path.write_text("[invalid toml content {{{")
    context.config_path = config_path


# When steps


@when('I run the script with shellflow')
def step_when_run_script(context: Context) -> None:
    """Run the script using shellflow."""
    # This will be implemented to actually call the runner
    # For now, mark as pending implementation
    context.execution_result = {"status": "pending"}


@when('I run the script with shellflow with verbose mode enabled')
def step_when_run_verbose(context: Context) -> None:
    """Run the script with verbose mode."""
    context.verbose = True
    context.execution_result = {"status": "pending"}


@when('I run the script with shellflow with dry-run mode')
def step_when_run_dry_run(context: Context) -> None:
    """Run the script in dry-run mode."""
    context.dry_run = True
    context.execution_result = {"status": "pending"}


@when('I parse the script')
def step_when_parse_script(context: Context) -> None:
    """Parse the script."""
    # This will be implemented to call the parser
    context.parsed_blocks = []


@when('I load the configuration')
def step_when_load_config(context: Context) -> None:
    """Load the configuration."""
    # This will be implemented to call the config manager
    context.loaded_config = {"status": "pending"}


@when('I request SSH config for "{host}"')
def step_when_request_ssh_config(context: Context, host: str) -> None:
    """Request SSH config for a host."""
    # This will be implemented
    context.ssh_config_result = None


@when('I attempt to load the configuration')
def step_when_attempt_load_config(context: Context) -> None:
    """Attempt to load configuration (may fail)."""
    # This will be implemented
    context.config_load_error = None


# Then steps


@then('the execution should succeed')
def step_then_execution_succeed(context: Context) -> None:
    """Assert execution succeeded."""
    # Implementation pending
    pass


@then('the execution should fail')
def step_then_execution_fail(context: Context) -> None:
    """Assert execution failed."""
    # Implementation pending
    pass


@then('block {index:d} should have output "{output}"')
def step_then_block_output(context: Context, index: int, output: str) -> None:
    """Assert block has expected output."""
    # Implementation pending
    pass


@then('block {index:d} should have been executed on "{host}"')
def step_then_block_executed_on(context: Context, index: int, host: str) -> None:
    """Assert block was executed on specific host."""
    # Implementation pending
    pass


@then('block {index:d} should have succeeded')
def step_then_block_succeeded(context: Context, index: int) -> None:
    """Assert block succeeded."""
    # Implementation pending
    pass


@then('block {index:d} should have failed with exit code {exit_code:d}')
def step_then_block_failed(context: Context, index: int, exit_code: int) -> None:
    """Assert block failed with specific exit code."""
    # Implementation pending
    pass


@then('block {index:d} should not have been executed')
def step_then_block_not_executed(context: Context, index: int) -> None:
    """Assert block was not executed."""
    # Implementation pending
    pass


@then('the error message should include "{text}"')
def step_then_error_includes(context: Context, text: str) -> None:
    """Assert error message includes text."""
    # Implementation pending
    pass


@then('the error message should include the remote host')
def step_then_error_includes_host(context: Context) -> None:
    """Assert error includes remote host info."""
    # Implementation pending
    pass


@then('the output should include block execution details')
def step_then_output_includes_details(context: Context) -> None:
    """Assert verbose output includes details."""
    # Implementation pending
    pass


@then('the output should include timing information')
def step_then_output_includes_timing(context: Context) -> None:
    """Assert verbose output includes timing."""
    # Implementation pending
    pass


@then('no commands should have been executed')
def step_then_no_commands_executed(context: Context) -> None:
    """Assert dry-run mode didn't execute."""
    # Implementation pending
    pass


@then('the output should list blocks that would be executed')
def step_then_output_lists_blocks(context: Context) -> None:
    """Assert dry-run lists blocks."""
    # Implementation pending
    pass


@then('the output should show target hosts for remote blocks')
def step_then_output_shows_hosts(context: Context) -> None:
    """Assert dry-run shows hosts."""
    # Implementation pending
    pass


@then('I should get {count:d} block')
def step_then_get_blocks(context: Context, count: int) -> None:
    """Assert expected block count."""
    # Implementation pending
    pass


@then('block {index:d} should be a local block')
def step_then_block_is_local(context: Context, index: int) -> None:
    """Assert block is local type."""
    # Implementation pending
    pass


@then('block {index:d} should be a remote block')
def step_then_block_is_remote(context: Context, index: int) -> None:
    """Assert block is remote type."""
    # Implementation pending
    pass


@then('block {index:d} should have content "{content}"')
def step_then_block_has_content(context: Context, index: int, content: str) -> None:
    """Assert block has expected content."""
    # Implementation pending
    pass


@then('block {index:d} should have target host "{host}"')
def step_then_block_has_host(context: Context, index: int, host: str) -> None:
    """Assert block has expected host."""
    # Implementation pending
    pass


@then('block {index:d} should contain "{text}"')
def step_then_block_contains(context: Context, index: int, text: str) -> None:
    """Assert block content contains text."""
    # Implementation pending
    pass


@then('parsing should fail with error containing "{text}"')
def step_then_parsing_fails(context: Context, text: str) -> None:
    """Assert parsing fails with expected error."""
    # Implementation pending
    pass


@then('the runner should have fail_fast enabled')
def step_then_runner_fail_fast(context: Context) -> None:
    """Assert runner config has fail_fast."""
    # Implementation pending
    pass


@then('the SSH host "{host}" should be configured')
def step_then_ssh_host_configured(context: Context, host: str) -> None:
    """Assert SSH host is configured."""
    # Implementation pending
    pass


@then('"{host}" should have host "{hostname}"')
def step_then_host_has_hostname(context: Context, host: str, hostname: str) -> None:
    """Assert host has expected hostname."""
    # Implementation pending
    pass


@then('"{host}" should have user "{user}"')
def step_then_host_has_user(context: Context, host: str, user: str) -> None:
    """Assert host has expected user."""
    # Implementation pending
    pass


@then('runner.fail_fast should be {value}')
def step_then_runner_fail_fast_value(context: Context, value: str) -> None:
    """Assert runner fail_fast value."""
    # Implementation pending
    pass


@then('runner.verbose should be {value}')
def step_then_runner_verbose(context: Context, value: str) -> None:
    """Assert runner verbose value."""
    # Implementation pending
    pass


@then('runner.capture_output should be {value}')
def step_then_runner_capture_output(context: Context, value: str) -> None:
    """Assert runner capture_output value."""
    # Implementation pending
    pass


@then('runner.timeout should be {timeout:d}')
def step_then_runner_timeout(context: Context, timeout: int) -> None:
    """Assert runner timeout value."""
    # Implementation pending
    pass


@then('default configuration should be used')
def step_then_default_config_used(context: Context) -> None:
    """Assert default config is used."""
    # Implementation pending
    pass


@then('no error should be raised')
def step_then_no_error(context: Context) -> None:
    """Assert no error occurred."""
    # Implementation pending
    pass


@then('"{host}" should have port {port:d}')
def step_then_host_has_port(context: Context, host: str, port: int) -> None:
    """Assert host has expected port."""
    # Implementation pending
    pass


@then('"{host}" should use ssh agent')
def step_then_host_uses_agent(context: Context, host: str) -> None:
    """Assert host uses SSH agent."""
    # Implementation pending
    pass


@then('the SSH host "{host}" should be valid')
def step_then_ssh_host_valid(context: Context, host: str) -> None:
    """Assert SSH host config is valid."""
    # Implementation pending
    pass


@then('I should receive the SSH configuration for that host')
def step_then_receive_ssh_config(context: Context) -> None:
    """Assert SSH config was received."""
    # Implementation pending
    pass


@then('the config should include host, port, user, and key_file')
def step_then_config_includes_fields(context: Context) -> None:
    """Assert config has required fields."""
    # Implementation pending
    pass


@then('I should receive None')
def step_then_receive_none(context: Context) -> None:
    """Assert None was received."""
    # Implementation pending
    pass


@then('"{host}" should have port {port:d} (from defaults)')
def step_then_host_port_from_defaults(context: Context, host: str, port: int) -> None:
    """Assert host port from defaults."""
    # Implementation pending
    pass


@then('"{host}" should have user "{user}" (overrides default)')
def step_then_host_user_override(context: Context, host: str, user: str) -> None:
    """Assert host user overrides default."""
    # Implementation pending
    pass


@then('"{host}" should have timeout {timeout:d} (from defaults)')
def step_then_host_timeout_from_defaults(context: Context, host: str, timeout: int) -> None:
    """Assert host timeout from defaults."""
    # Implementation pending
    pass


@then('"key_file" should have expanded the HOME variable')
def step_then_key_file_expanded(context: Context) -> None:
    """Assert key_file expanded HOME."""
    # Implementation pending
    pass


@then('a ConfigError should be raised')
def step_then_config_error_raised(context: Context) -> None:
    """Assert ConfigError was raised."""
    # Implementation pending
    pass


@then('the error message should indicate the file and parsing issue')
def step_then_error_indicates_file_and_parsing(context: Context) -> None:
    """Assert error indicates file and parsing issue."""
    # Implementation pending
    pass


@then('all hosts should be accessible')
def step_then_all_hosts_accessible(context: Context) -> None:
    """Assert all hosts are accessible."""
    # Implementation pending
    pass


@then('each host should have its own configuration')
def step_then_each_host_has_own_config(context: Context) -> None:
    """Assert each host has own config."""
    # Implementation pending
    pass
