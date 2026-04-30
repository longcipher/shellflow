Feature: Helper Functions
  As a DevOps engineer
  I want to define reusable helper functions
  So that I can avoid code duplication in scripts

  Scenario: Define and use a helper function
    Given a script with content:
      """
      # @HELPER backup_db
      #   mysqldump db > backup.sql
      # @ENDHELPER

      # @LOCAL
      backup_db
      """
    When the script is parsed
    Then 1 block should be found
    And the block should contain 1 command
    And the command should be "mysqldump db > backup.sql"

  Scenario: Helper with multiple commands
    Given a script with content:
      """
      # @HELPER setup_env
      #   export DATABASE_URL=localhost
      #   export DEBUG=true
      # @ENDHELPER

      # @LOCAL
      setup_env
      echo "Environment ready"
      """
    When the script is parsed
    Then 1 block should be found
    And the block should contain 3 commands