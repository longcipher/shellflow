Feature: Script Parsing
  As a DevOps engineer
  I want scripts to be parsed correctly
  So that execution targets are properly identified

  Scenario: Parse local marker
    Given a script with content:
      """
      # @LOCAL
      echo "test"
      """
    When the script is parsed
    Then 1 block should be found
    And the block type should be "LOCAL"

  Scenario: Parse remote marker with host
    Given a script with content:
      """
      # @REMOTE myserver
      echo "remote test"
      """
    When the script is parsed
    Then 1 block should be found
    And the block type should be "REMOTE"
    And the block host should be "myserver"
