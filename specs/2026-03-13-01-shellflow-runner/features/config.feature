Feature: Configuration Management

  As a DevOps engineer
  I want to configure SSH hosts and runner settings
  So that I can manage connections and execution preferences

  Background:
    Given a shellflow configuration system is available

  Scenario: Load SSH configuration
    Given a config file with content:
      """
      [runner]
      fail_fast = true
      verbose = false

      [ssh.hosts.production-web]
      host = "web1.example.com"
      port = 22
      user = "deploy"
      key_file = "~/.ssh/production.pem"
      """
    When I load the configuration
    Then the runner should have fail_fast enabled
    And the SSH host "production-web" should be configured
    And "production-web" should have host "web1.example.com"
    And "production-web" should have user "deploy"

  Scenario: Load runner configuration
    Given a config file with content:
      """
      [runner]
      fail_fast = false
      verbose = true
      capture_output = true
      timeout = 300
      """
    When I load the configuration
    Then runner.fail_fast should be false
    And runner.verbose should be true
    And runner.capture_output should be true
    And runner.timeout should be 300

  Scenario: Handle missing config file
    Given no config file exists at the specified path
    When I load the configuration
    Then default configuration should be used
    And runner.fail_fast should default to true
    And no error should be raised

  Scenario: Validate SSH host configuration
    Given a config file with content:
      """
      [ssh.hosts.test-server]
      host = "test.example.com"
      port = 2222
      user = "testuser"
      use_agent = true
      """
    When I load the configuration
    Then the SSH host "test-server" should be valid
    And "test-server" should have port 2222
    And "test-server" should use ssh agent

  Scenario: Get SSH config for host
    Given a config file with SSH hosts defined
    When I request SSH config for "production-web"
    Then I should receive the SSH configuration for that host
    And the config should include host, port, user, and key_file

  Scenario: Handle unknown SSH host
    Given a config file with SSH hosts defined
    When I request SSH config for "unknown-host"
    Then I should receive None
    And no error should be raised

  Scenario: Merge SSH defaults with host config
    Given a config file with content:
      """
      [ssh.defaults]
      port = 22
      user = "admin"
      timeout = 30

      [ssh.hosts.custom]
      host = "custom.example.com"
      user = "customuser"
      """
    When I load the configuration
    Then "custom" should have port 22 (from defaults)
    And "custom" should have user "customuser" (overrides default)
    And "custom" should have timeout 30 (from defaults)

  Scenario: Environment variable expansion in config
    Given a config file with content:
      """
      [ssh.hosts.prod]
      host = "prod.example.com"
      key_file = "$HOME/.ssh/prod_key"
      """
    And environment variable HOME is set
    When I load the configuration
    Then "key_file" should have expanded the HOME variable

  Scenario: Malformed config file handling
    Given a malformed TOML config file
    When I attempt to load the configuration
    Then a ConfigError should be raised
    And the error message should indicate the file and parsing issue

  Scenario: Config with multiple SSH hosts
    Given a config file with multiple SSH hosts defined
    When I load the configuration
    Then all hosts should be accessible
    And each host should have its own configuration
