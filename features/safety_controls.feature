Feature: Safety controls for automated runs
  As an operator delegating execution to an AI agent
  I want non-interactive and audit-friendly controls
  So that automated runs are observable without relying on shell heuristics

  Scenario: No-input prevents blocking on stdin
    Given a script file with a local block that reads from standard input
    When I run the script with no-input enabled
    Then the command should fail deterministically instead of waiting for input
    And the structured output should indicate that no interactive input was available

  Scenario: Dry-run previews execution without running commands
    Given a script file with local and remote blocks
    When I run the script in dry-run mode
    Then no block commands should be executed
    And the output should describe the planned blocks in order
    And the output should include structured dry-run events when machine-readable mode is enabled

  Scenario: Audit-log writes structured events for later inspection
    Given a script file with a named export that looks like a secret
    When I run the script with an audit log path
    Then the command should succeed
    And the audit log file should contain JSON Lines events
    And the audit log should redact the secret-like exported value