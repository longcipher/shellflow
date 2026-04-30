Feature: Hook System
  Hooks allow execution of commands at different lifecycle points

  Scenario: PRE hook executes before main blocks
    Given a script with a PRE hook
    When the script is executed
    Then the PRE hook runs before the main block

  Scenario: PRE hook failure stops execution
    Given a script with a failing PRE hook
    When the script is executed
    Then execution stops with hook failure