Feature: Task Annotations
  As a DevOps engineer
  I want to annotate tasks with metadata
  So that I can track task descriptions and other properties

  Scenario: Parse task annotations
    Given a script with task annotations:
      """
      # @ANNOTATE deploy-task
      #   description: Deploy web application
      #   timeout: 300
      #   priority: high
      # @LOCAL
      echo "Deploying application"
      """
    When the script is parsed
    Then 1 block should be found
    And the block should have annotations
    And the block annotation "description" should be "Deploy web application"
    And the block annotation "timeout" should be "300"
    And the block annotation "priority" should be "high"