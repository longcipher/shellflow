Feature: Resilience and context propagation
  As an AI agent using Shellflow as an action tool
  I want bounded retries, timeouts, and named exports
  So that I can recover from transient failures without turning Shellflow into a workflow engine

  Scenario: Timeout stops a stuck block and reports a timeout-specific failure
    Given a script file with a local block that exceeds its timeout directive
    When I run the script in machine-readable mode
    Then the command should fail with timeout exit code 4
    And the structured output should mark the block as timed out
    And the structured output should record the timeout duration policy

  Scenario: Retry reruns a transiently failing block and reports attempts
    Given a script file with a local block that fails once and then succeeds with a retry directive
    When I run the script in machine-readable mode
    Then the command should succeed
    And the structured output should record 2 attempts for that block
    And the structured output should include a retrying event before the successful finish event

  Scenario: Named exports become environment variables for later blocks
    Given a script file whose first block exports VERSION from stdout
    When I run the script
    Then the later block should receive VERSION in its environment
    And SHELLFLOW_LAST_OUTPUT should still be available