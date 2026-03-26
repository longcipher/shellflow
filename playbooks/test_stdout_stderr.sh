#!/bin/bash
# Test script to verify stdout and stderr are handled correctly

# @REMOTE sui

# Command with stdout only
echo "=== Systemd Status ==="
echo "Main PID: 420746 (openobserve)"
echo "Tasks: 38 (limit: 154407)"

# Command with stderr only (simulating curl progress)
echo "Downloading file..." >&2
echo "  0      0   0      0   0      0      0      0                              0" >&2
echo "  0 105.1M   0   8949   0      0   8780      0 3:29:14   00:01 3:29:13   8781" >&2

# Command with both stdout and stderr
echo "=== Another Status ==="
echo "This is stdout from another command"
echo "This is stderr from another command" >&2

# Final command
echo "=== Done ==="