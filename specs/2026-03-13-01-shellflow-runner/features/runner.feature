Feature: Script Runner Execution

  As a DevOps engineer
  I want to execute bash scripts that run on different targets
  So that I can orchestrate operations across local and remote environments

  Background:
    Given the shellflow configuration is initialized

  Scenario: Execute local-only script
    Given a script file "local_only.sh" with content:
      """
      # @LOCAL
      echo "Hello from local"
      # @LOCAL
      echo "Second block"
      """
    When I run the script with shellflow
    Then the execution should succeed
    And block 1 should have output "Hello from local"
    And block 2 should have output "Second block"

  Scenario: Execute remote-only script
    Given a script file "remote_only.sh" with content:
      """
      # @REMOTE test-server
      echo "Hello from remote"
      """
    And an SSH host "test-server" is configured
    When I run the script with shellflow
    Then the execution should succeed
    And block 1 should have been executed on "test-server"

  Scenario: Execute mixed local and remote script
    Given a script file "mixed.sh" with content:
      """
      # @LOCAL
      echo "Local setup"
      # @REMOTE web-server
      echo "Remote deployment"
      # @LOCAL
      echo "Local verification"
      """
    And an SSH host "web-server" is configured
    When I run the script with shellflow
    Then the execution should succeed
    And block 1 should have output "Local setup"
    And block 2 should have been executed on "web-server"
    And block 3 should have output "Local verification"

  Scenario: Fail fast on local block failure
    Given a script file "fail_local.sh" with content:
      """
      # @LOCAL
      echo "First block"
      # @LOCAL
      exit 1
      # @LOCAL
      echo "Third block"
      """
    When I run the script with shellflow
    Then the execution should fail
    And block 1 should have succeeded
    And block 2 should have failed with exit code 1
    And block 3 should not have been executed
    And the error message should include "Block 2 failed"

  Scenario: Fail fast on remote block failure
    Given a script file "fail_remote.sh" with content:
      """
      # @LOCAL
      echo "Local setup"
      # @REMOTE test-server
      exit 42
      """
    And an SSH host "test-server" is configured
    When I run the script with shellflow
    Then the execution should fail
    And block 1 should have succeeded
    And block 2 should have failed with exit code 42
    And the error message should include the remote host

  Scenario: Capture output and pass to next block
    Given a script file "capture.sh" with content:
      """
      # @LOCAL
      echo "captured_value"
      # @LOCAL
      echo "Previous output was: $SHELLFLOW_OUTPUT"
      """
    When I run the script with shellflow
    Then the execution should succeed
    And block 2 should have output "Previous output was: captured_value"

  Scenario: Execute with verbose mode
    Given a script file "verbose.sh" with content:
      """
      # @LOCAL
      echo "Test"
      """
    When I run the script with shellflow with verbose mode enabled
    Then the execution should succeed
    And the output should include block execution details
    And the output should include timing information

  Scenario: Dry run mode
    Given a script file "dryrun.sh" with content:
      """
      # @LOCAL
      echo "Would execute this"
      # @REMOTE test-server
      echo "Would execute remotely"
      """
    And an SSH host "test-server" is configured
    When I run the script with shellflow with dry-run mode
    Then the execution should succeed
    And no commands should have been executed
    And the output should list blocks that would be executed
    And the output should show target hosts for remote blocks
