Feature: Doctor Command
  As a user
  I want to check my Shellflow configuration
  So that I can verify everything is set up correctly

  Scenario: Run doctor command
    When I run the doctor command
    Then the output should contain SSH connections status
    And the output should contain configuration status