#!/bin/bash
# ================================================================
# Manual QEMU Debug Script
# ------------------------------------------------
# Purpose:
#   This script allows a developer to manually launch a single 
#   QEMU run of a dm-verity test image, capturing both the main
#   log and serial console output for inspection.
#
# Key Features:
#   1. Uses a specified test image (default: rootfs.meta1.test.img)
#   2. Creates and manages separate log files:
#        - Main log: debug_manual_test.log
#        - Serial log: debug_manual_serial.log
#   3. Runs QEMU with a 45-second timeout to allow full 
#      dm-verity verification
#   4. Appends serial console output to main log
#   5. Provides basic log analysis:
#        - Line counts
#        - Kernel messages
#        - dm-verity messages
#        - Panic messages
#        - Signature verification messages
#   6. Displays key snippets of serial output for quick inspection
#   7. Cleans up remaining QEMU processes after execution
#
# Intended Use:
#   - Rapid debugging of specific test images
#   - Verifying manual QEMU execution outside the automated
#     harness (run_verity_tests.sh)
#   - Investigating kernel panics, signature failures, or dm-verity
#     boot behavior in isolation
#
# Usage:
#   1. Place the script anywhere inside the project directory
#   2. Make executable: chmod +x debug_single_test.sh
#   3. Run: ./debug_single_test.sh
#
# Notes:
#   - This script mimics the automated test harness but is
#     designed for manual exploration and debugging.
#   - Exit code of the QEMU run is captured and reported.
#   - Any remaining QEMU processes are forcibly killed to
#     prevent conflicts with subsequent runs.
#
# Maintainer: <TEAM A>
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARIES_DIR="$SCRIPT_DIR/Binaries"
TEST_IMAGE="$BINARIES_DIR/rootfs.meta1.test.img"
LOG_FILE="$SCRIPT_DIR/debug_manual_test.log"
SERIAL_LOG="$SCRIPT_DIR/debug_manual_serial.log"

echo "=== Manual QEMU Test (mimicking test script) ==="
echo "Project root: $PROJECT_ROOT"
echo "Test image: $TEST_IMAGE"
echo "Log file: $LOG_FILE"
echo "Serial log: $SERIAL_LOG"
echo ""

if [[ ! -f "$TEST_IMAGE" ]]; then
    echo "ERROR: Test image not found: $TEST_IMAGE"
    exit 1
fi

if [[ ! -f "$PROJECT_ROOT/bootloaders/qemu_tests.sh" ]]; then
    echo "ERROR: qemu_tests.sh not found at: $PROJECT_ROOT/bootloaders/qemu_tests.sh"
    exit 1
fi

echo "Creating log file..."
cat > "$LOG_FILE" <<EOF
=== Manual test ===
Test image: $TEST_IMAGE
Serial log: $SERIAL_LOG
EOF

# Remove old serial log if it exists
rm -f "$SERIAL_LOG"

echo "Changing to bootloaders directory..."
cd "$PROJECT_ROOT/bootloaders"
echo "Current dir: $(pwd)"
echo ""

echo "Running QEMU with 45 second timeout (to allow full dm-verity verification)..."
echo "Command: timeout 45 ./qemu_tests.sh '$TEST_IMAGE' '$SERIAL_LOG'"
echo ""

# Run with serial log file and longer timeout
timeout 45 ./qemu_tests.sh "$TEST_IMAGE" "$SERIAL_LOG" 2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}

echo "" | tee -a "$LOG_FILE"
echo "=== Test Complete ===" | tee -a "$LOG_FILE"
echo "Exit code: $EXIT_CODE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Append serial log to main log
if [[ -f "$SERIAL_LOG" ]]; then
    echo "=== Serial Console Output ===" | tee -a "$LOG_FILE"
    cat "$SERIAL_LOG" | tee -a "$LOG_FILE"
    echo "=== End Serial Output ===" | tee -a "$LOG_FILE"
fi

# Analyze the logs
LINE_COUNT=$(wc -l < "$LOG_FILE")
SERIAL_COUNT=$(wc -l < "$SERIAL_LOG" 2>/dev/null || echo 0)

echo ""
echo "Log file analysis:"
echo "  Main log lines: $LINE_COUNT"
echo "  Serial log lines: $SERIAL_COUNT"
echo "  Kernel messages: $(grep -c -i "linux\|kernel" "$LOG_FILE" "$SERIAL_LOG" 2>/dev/null || echo 0)"
echo "  dm-verity messages: $(grep -c -i "dm-verity\|verity" "$LOG_FILE" "$SERIAL_LOG" 2>/dev/null || echo 0)"
echo "  Panic messages: $(grep -c -i "panic" "$LOG_FILE" "$SERIAL_LOG" 2>/dev/null || echo 0)"
echo "  Signature messages: $(grep -c -i "signature\|pkcs" "$LOG_FILE" "$SERIAL_LOG" 2>/dev/null || echo 0)"
echo ""

if [[ $SERIAL_COUNT -lt 20 ]]; then
    echo "⚠ WARNING: Very few lines in serial log ($SERIAL_COUNT)!"
    echo "Full serial log:"
    [[ -f "$SERIAL_LOG" ]] && cat "$SERIAL_LOG" || echo "(serial log not created)"
else
    echo "✓ Good amount of serial output captured ($SERIAL_COUNT lines)"
    echo ""
    echo "First 15 lines of serial log:"
    head -15 "$SERIAL_LOG"
    echo "..."
    echo "Last 10 lines of serial log:"
    tail -10 "$SERIAL_LOG"
fi

echo ""
echo "Killing any remaining QEMU processes..."
pkill -9 -f qemu-system 2>/dev/null || true

echo ""
echo "Logs saved to:"
echo "  Main: $LOG_FILE"
echo "  Serial: $SERIAL_LOG"