Feature: Server Definitions
  Scenario: Parse server config
    Given a script with server definitions:
      """
      # @SERVER web-server
      #   host: example.com
      #   user: deploy
      #   port: 22
      #   key: ~/.ssh/id_rsa
      """
    When parsed
    Then servers are extracted correctly