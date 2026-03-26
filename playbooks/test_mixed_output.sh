#!/bin/bash
# Test script to verify mixed stdout/stderr output is handled correctly

# @REMOTE sui

# Command that produces output to stdout
echo "=== Systemd Status ==="
echo "This is stdout from systemctl status"

# Command that produces output to stderr (simulating curl progress)
echo "Downloading file..." >&2
echo "  0      0   0      0   0      0      0      0                              0" >&2

# Command that produces output to both stdout and stderr
echo "=== Another Status ==="
echo "This is stdout from another command"
echo "This is stderr from another command" >&2

# Final command
echo "=== Done ==="