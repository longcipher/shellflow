#!/bin/bash
# Example: Using @SHELL directive for remote servers with zsh

# This script demonstrates how to use the @SHELL directive
# to execute commands on remote servers that use zsh as their default shell.

# @REMOTE zsh-server
# @SHELL zsh
# Now zsh-specific commands will work
echo "Running in zsh on remote server"

# @REMOTE another-server
# Default bash shell will be used (no @SHELL directive)
echo "Running in bash on another server"
