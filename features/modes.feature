Feature: Advanced Execution Modes
  As a DevOps engineer
  I want to execute scripts with different execution modes
  So that I can optimize execution time and control execution flow

  Scenario: Execute blocks in parallel
    Given a script file with the following content:
      """
      # @PARALLEL
      # @LOCAL
      echo "parallel-task-1"

      # @LOCAL
      echo "parallel-task-2"
      """
    When I run the script with mode "parallel"
    Then the execution should succeed
    And the output should contain "parallel-task-1"
    And the output should contain "parallel-task-2"

  Scenario: Execute blocks sequentially
    Given a script file with the following content:
      """
      # @LOCAL
      echo "sequential-task-1"

      # @LOCAL
      echo "sequential-task-2"
      """
    When I run the script with mode "sequential"
    Then the execution should succeed
    And the output should contain "sequential-task-1"
    And the output should contain "sequential-task-2"

  Scenario: Mixed parallel and sequential blocks
    Given a script file with the following content:
      """
      # @PARALLEL group1
      # @LOCAL
      echo "parallel-1"

      # @LOCAL
      echo "parallel-2"

      # @LOCAL
      echo "sequential"
      """
    When I run the script with mode "parallel"
    Then the execution should succeed
    And the output should contain "parallel-1"
    And the output should contain "parallel-2"
    And the output should contain "sequential"