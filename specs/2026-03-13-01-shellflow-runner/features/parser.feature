Feature: Script Parser

  As a DevOps engineer
  I want to parse shell scripts with special comment markers
  So that I can extract executable blocks for different targets

  Background:
    Given a shellflow parser is initialized

  Scenario: Parse local marker
    Given a script with content:
      """
      # @LOCAL
      echo "Hello local"
      """
    When I parse the script
    Then I should get 1 block
    And block 1 should be a local block
    And block 1 should have content "echo \"Hello local\""

  Scenario: Parse remote marker with host
    Given a script with content:
      """
      # @REMOTE production-server
      echo "Hello remote"
      """
    When I parse the script
    Then I should get 1 block
    And block 1 should be a remote block
    And block 1 should have target host "production-server"
    And block 1 should have content "echo \"Hello remote\""

  Scenario: Parse mixed local and remote markers
    Given a script with content:
      """
      # @LOCAL
      echo "Step 1 local"

      # @REMOTE web-server
      echo "Step 2 remote"

      # @LOCAL
      echo "Step 3 local"
      """
    When I parse the script
    Then I should get 3 blocks
    And block 1 should be a local block with content "echo \"Step 1 local\""
    And block 2 should be a remote block with target host "web-server"
    And block 3 should be a local block with content "echo \"Step 3 local\""

  Scenario: Parse script with prelude before first marker
    Given a script with content:
      """
      #!/bin/bash
      # This is a setup script

      # @LOCAL
      echo "Main content"
      """
    When I parse the script
    Then I should get 1 block
    And block 1 should be a local block with content "echo \"Main content\""

  Scenario: Handle empty blocks
    Given a script with content:
      """
      # @LOCAL
      # @LOCAL
      echo "Second block"
      """
    When I parse the script
    Then I should get 1 block
    And block 1 should have content "echo \"Second block\""

  Scenario: Handle unknown markers
    Given a script with content:
      """
      # @UNKNOWN
      echo "Content"
      """
    When I parse the script
    Then parsing should fail with error containing "Unknown marker"

  Scenario: Handle empty script
    Given a script with content:
      """
      """
    When I parse the script
    Then I should get 0 blocks

  Scenario: Handle script with only comments
    Given a script with content:
      """
      # This is a comment
      # Another comment
      """
    When I parse the script
    Then I should get 0 blocks

  Scenario: Parse complex multi-line content
    Given a script with content:
      """
      # @LOCAL
      if [ -f "config.txt" ]; then
          echo "Config exists"
      else
          echo "Config missing"
      fi
      """
    When I parse the script
    Then I should get 1 block
    And block 1 should contain "if [ -f \"config.txt\" ]; then"
    And block 1 should contain "echo \"Config missing\""

  Scenario: Parse multiple remote hosts
    Given a script with content:
      """
      # @REMOTE web-01
      echo "On web-01"

      # @REMOTE web-02
      echo "On web-02"

      # @REMOTE db-01
      echo "On db-01"
      """
    When I parse the script
    Then I should get 3 blocks
    And block 1 should have target host "web-01"
    And block 2 should have target host "web-02"
    And block 3 should have target host "db-01"
