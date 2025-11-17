#!/usr/bin/env bash
# ======================================================================
#  qemu_tests.sh - Strict QEMU launcher for automated dm-verity testing
# ======================================================================
#
#  This script is intended **ONLY for automated test execution**.
#  It is called by the dm-verity security test harness and is designed
#  to behave in a strict, deterministic, and fail-fast manner.
#
#  Key characteristics:
#    • Uses `set -u` to treat unset variables as fatal errors.
#    • Requires at least one positional argument:
#          $1 = absolute path to the disk image
#          $2 = (optional) path to the serial log file
#    • Validates all inputs before launching QEMU.
#    • Resolves full paths to avoid cwd-dependent behavior.
#    • Searches for the kernel in multiple known build locations.
#    • Writes all output deterministically for test automation.
#
#  IMPORTANT:
#      Do NOT use this script for manual development or debugging.
#      You can use src/build/launch_qemu.sh for interactive approach  
#      or src/bootloaders/qemu_main.sh as minimal qemu launcher.
#
#  Used by:
#      • dm-verity Security Behavior Test Suite
#        (see: run_verity_tests.sh)
#
# ======================================================================
set -u  # treat unset vars as an error

# Get script directory for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use the first argument as the disk image (no fallback so the original rootfs.img does not get overwritten)
if [[ -z "$1" ]]; then
    echo "ERROR: No disk image specified" >&2
    echo "Usage: $0 <disk_image> [serial_log_file]" >&2
    exit 1
fi

IMG_REL="$1"

# Check if second argument is a log file for serial output
SERIAL_LOG="${2:-}"

# Resolve absolute path for disk image
if ! IMG_ABS=$(realpath "$IMG_REL"); then
    echo "ERROR: realpath($IMG_REL) failed" >&2
    exit 1
fi

# Check if disk image exists BEFORE doing anything else
if [[ ! -f "$IMG_ABS" ]]; then
    echo "ERROR: Disk image not found: $IMG_ABS" >&2
    exit 1
fi

# Look for kernel in multiple possible locations
KERNEL_LOCATIONS=(
    "${SCRIPT_DIR}/kernel_image.bin"
    "${SCRIPT_DIR}/../build/Binaries/bzImage"
    "${SCRIPT_DIR}/../Binaries/bzImage"
    "${SCRIPT_DIR}/bzImage"
)

KERNEL=""
for k in "${KERNEL_LOCATIONS[@]}"; do
    if [[ -f "$k" ]]; then
        KERNEL="$k"
        break
    fi
done

if [[ -z "$KERNEL" ]]; then
    echo "ERROR: Kernel not found. Searched in:" >&2
    for k in "${KERNEL_LOCATIONS[@]}"; do
        echo "  - $k" >&2
    done
    exit 1
fi

KERNEL_ABS=$(realpath "$KERNEL")

DRIVE_OPT="if=none,id=drv0,format=raw,media=disk,file=${IMG_ABS}"

APPEND_CMDLINE="console=ttyS0,115200 \
loglevel=7 \
dm_verity_autoboot.autoboot_device=/dev/vda \
root=/dev/dm-0 rootfstype=ext4 rootwait rootdelay=10"

echo "================================================"
echo "Launching QEMU"
echo "Kernel: ${KERNEL_ABS}"
echo "Disk:   ${IMG_ABS}"
echo "Cmdline: ${APPEND_CMDLINE}"

# Configure serial output based on whether we're in automated mode
if [[ -n "$SERIAL_LOG" ]]; then
    echo "Serial output: ${SERIAL_LOG}"
    SERIAL_OPT="-serial file:${SERIAL_LOG}"
else
    echo "Serial output: stdio"
    SERIAL_OPT="-serial mon:stdio"
fi

echo "================================================"
echo ""

# Force line buffering for stdout/stderr
stdbuf -oL -eL qemu-system-x86_64 \
    -m 1024 \
    -machine q35,accel=tcg \
    -cpu max \
    -nodefaults \
    -nographic \
    ${SERIAL_OPT} \
    -d guest_errors \
    -kernel "${KERNEL_ABS}" \
    -drive "${DRIVE_OPT}" \
    -device virtio-blk-pci,drive=drv0 \
    -append "${APPEND_CMDLINE}"

STATUS=$?
echo ""
echo "================================================"
echo "QEMU exited with status: ${STATUS}"
echo "================================================"
exit $STATUS