Feature: Script Execution
  As a DevOps engineer
  I want to execute bash scripts across multiple environments
  So that I can automate deployment tasks

  Scenario: Execute local-only script
    Given a script file with the following content:
      """
      # @LOCAL
      echo "Hello, World!"
      """
    When I run the script
    Then the execution should succeed
    And the output should contain "Hello, World!"

  Scenario: Execute remote-only script
    Given a script file with the following content:
      """
      # @REMOTE testhost
      echo "Remote execution"
      """
    And host "testhost" is configured in SSH config
    When I run the script
    Then the execution should succeed

  Scenario: Execute mixed local and remote script
    Given a script file with the following content:
      """
      # @LOCAL
      echo "Local step"

      # @REMOTE testhost
      echo "Remote step"

      # @LOCAL
      echo "Final local step"
      """
    And host "testhost" is configured in SSH config
    When I run the script
    Then the execution should succeed

  Scenario: Fail fast on block failure
    Given a script file with the following content:
      """
      # @LOCAL
      echo "First step"

      # @LOCAL
      exit 1

      # @LOCAL
      echo "This should not execute"
      """
    When I run the script
    Then the execution should fail
    And the output should contain "First step"
    And the output should not contain "This should not execute"
