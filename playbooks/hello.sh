#!/bin/bash
set -euo pipefail

log() {
  printf '[hello] %s\n' "$*"
}

log "Shellflow Feature Demo"

# Block 1: Local execution with timeout, retry, and export
# Demonstrates: @TIMEOUT, @RETRY, @EXPORT, SHELLFLOW_LAST_OUTPUT
# @LOCAL
# @TIMEOUT 30
# @RETRY 1
# @EXPORT GREETING=stdout
log "block 1: local with export"
echo "Hello from Shellflow!"

# Block 2: Local execution reading exported variable
# Demonstrates: reading exported env vars
# @LOCAL
log "block 2: using exported variable"
echo "Received: $GREETING"

# Block 3: Local execution with SHELLFLOW_LAST_OUTPUT
# Demonstrates: SHELLFLOW_LAST_OUTPUT handoff
# @LOCAL
log "block 3: passing data via SHELLFLOW_LAST_OUTPUT"
echo "Data from block 2"

# Block 4: Local reading SHELLFLOW_LAST_OUTPUT
# Demonstrates: SHELLFLOW_LAST_OUTPUT
# @LOCAL
log "block 4: reading SHELLFLOW_LAST_OUTPUT"
echo "Previous output: $SHELLFLOW_LAST_OUTPUT"

# Block 5: Export exit_code
# Demonstrates: @EXPORT with exit_code source
# @LOCAL
# @EXPORT COMMAND_STATUS=exit_code
log "block 5: export exit_code"
true

# Block 6: Using exported exit_code
# @LOCAL
log "block 6: previous exit code was $COMMAND_STATUS"

# Block 7: Export stderr
# Demonstrates: @EXPORT with stderr source
# @LOCAL
# @EXPORT ERROR_OUTPUT=stderr
log "block 7: exporting stderr"
echo "normal output" >&2

# Block 8: Using exported stderr
# @LOCAL
log "block 8: stderr was: $ERROR_OUTPUT"

# Block 9: Export combined output
# Demonstrates: @EXPORT with output source
# @LOCAL
# @EXPORT COMBINED=output
log "block 9: exporting combined output"
echo "stdout line"
echo "stderr line" >&2

# Block 10: Using exported combined output
# @LOCAL
log "block 10: combined output:"
echo "$COMBINED"

# Block 11: Retry demonstration (will succeed on first try)
# Demonstrates: @RETRY with successful execution
# @LOCAL
# @RETRY 3
log "block 11: retry demo (succeeds)"
echo "Retry successful!"

# Block 12: Remote execution demonstration (requires SSH config)
# Demonstrates: @REMOTE for remote execution
# @REMOTE sui
uname -a

# Block 12: Final block
# @LOCAL
log "block 12: demo complete!"
echo "All Shellflow features demonstrated."


