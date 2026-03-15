Feature: Agent-facing execution contract
  As an AI agent operating Shellflow
  I want structured execution results and stable exit codes
  So that I can observe outcomes and decide what to do next outside Shellflow

  Scenario: JSON report mode returns machine-readable run and block results
    Given a script file with a local block that prints a release version
    When I run the script with JSON output enabled
    Then the command should succeed
    And the JSON output should contain a run id
    And the JSON output should contain a schema version
    And the JSON output should include the first block exit code
    And the JSON output should include the first block stdout separately from stderr

  Scenario: JSONL mode emits ordered events suitable for live observation
    Given a script file with two local blocks that both succeed
    When I run the script with JSON Lines output enabled
    Then the command should succeed
    And the output should contain a run_started event before a block_started event
    And the output should contain a block_finished event for each block
    And the output should end with a run_finished event

  Scenario: Exit codes distinguish parse, SSH config, runtime, and timeout failures
    Given the relevant failing scripts for parse, missing SSH host, block failure, and timeout
    When I run each script in machine-readable mode
    Then the parse failure should exit with code 2
    And the missing SSH host failure should exit with code 3
    And the block execution failure should exit with code 1
    And the timeout failure should exit with code 4