Feature: Variable System

  Scenario: Define and use script-level variables
    Given a script with variable definitions and usage
    When the script is executed
    Then variables should be substituted in commands

  Scenario: Multiple variables
    Given a script with multiple variable definitions
    When the script is executed
    Then all variables should be substituted correctly