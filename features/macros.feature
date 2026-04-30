Feature: Macro Groups
  As a DevOps engineer
  I want to define reusable command sequences
  So that I can avoid repeating common patterns

  Scenario: Parse macro definition
    Given a script with content:
      """
      # @MACRO deploy
      #   echo "deploy step 1"
      #   echo "deploy step 2"
      # @ENDMACRO
      """
    When the script is parsed
    Then 0 block should be found
    And the macro "deploy" should contain 2 commands