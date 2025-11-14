#!/usr/bin/env bash
set -euo pipefail

# ===========================================================
# dm-verity Parser Fuzz Testing & Robustness Validation Suite
#
# Purpose: Validates kernel dm-verity implementation against malicious/corrupted metadata
# 
# This script performs systematic corruption of dm-verity disk structures to test:
# - Input sanitization and bounds checking
# - Integer overflow protection  
# - Buffer overflow prevention
# - Graceful error handling under adversarial conditions
# - Parser resilience to malformed on-disk structures
#
# TYPICAL WORKFLOW:
#   1. Create test image: ./integrity_tests.sh <mode>
#   2. Launch QEMU:       ./launch_qemu.sh
#   3. Select test image from menu
#   4. Observe kernel behavior
#   5. Repeat for different test modes
#
# Each test mode targets specific vulnerability classes per Linux kernel security
# requirements for device-mapper and integrity verification subsystems.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_DEFAULT="$SCRIPT_DIR/Binaries/rootfs.img"

# Defaults
MODE=""
IMG_PATH="$IMG_DEFAULT"
INPLACE=0 DRYRUN=0 VERBOSE=0 YES=0 BACKUP=0 RESTORE=0

# Configuration
REQUIRED_CMDS=(sudo losetup python3 blockdev sha256sum dd cp mktemp printf)
VERITY_META_SIZE=4096
VLOC_MAGIC=0x564C4F43

usage() {
    cat <<EOF
dm-verity Parser Fuzz Testing & Robustness Validation Suite

SYNOPSIS:
    $0 <TEST_MODE> [IMAGE_PATH] [OPTIONS]

TEST MODES:
    meta1        - Flip single byte in dm-verity header structure at offset +64
                   Tests: Header checksum validation, structural integrity checks
    
    sig1         - Flip single byte in PKCS#7 signature blob  
                   Tests: Cryptographic signature verification, ASN.1 parsing
    
    int_overflow - Set locator fields to values that trigger integer wrap-around
                   Tests: 32/64-bit integer overflow protection, bounds validation
    
    buf_overflow - Set metadata length to maximum value (0xFFFFFFFF)
                   Tests: Buffer size validation, memory allocation limits
    
    trunc_meta   - Claim metadata region extends beyond physical disk capacity
                   Tests: Bounds checking, truncated read handling
    
    bad_offsets  - Set metadata/signature offsets beyond disk end boundary
                   Tests: Offset validation, out-of-bounds access prevention  
    
    sanitize     - Replace locator with completely random field values
                   Tests: Input sanitization, magic number validation

OPTIONS:
    --inplace    - Modify the original image in-place (DESTRUCTIVE)
    --yes        - Assume 'yes' to all prompts (required for automated testing)
    --backup     - Create backup of original image when using --inplace
    --dry-run    - Preview operations without making changes
    --verbose    - Enable detailed debug output
    --restore    - Restore from backup if available and exit
    -h, --help   - Show this help message

ENVIRONMENT:
    Default image path: $IMG_DEFAULT

EXAMPLES:
    # Create test image for signature corruption testing
    $0 sig1
    
    # Perform in-place metadata corruption (with backup)
    $0 meta1 --inplace --backup --yes
    
    # Test integer overflow protection
    $0 int_overflow /path/to/custom.img
    
    # Preview buffer overflow test without execution
    $0 buf_overflow --dry-run --verbose

SECURITY CONSIDERATIONS:
    - --inplace option will PERMANENTLY modify your rootfs image
    - Always use --backup when testing on production images
    - Test images should be used in isolated environments only
    - This tool is for security testing, not production use

EOF
}

# Helper functions
log() {
    (( VERBOSE )) && printf "%s\n" "$*"
}

print_offsets() {
    local label=$1; shift
    printf "  %s offset (disk): %d (0x%08x) len %d (0x%08x)\n" "$label" "$1" "$1" "$2" "$2"
}

cleanup() {
    if [[ -n "${LOOP:-}" ]]; then
        echo "Cleaning up loop device $LOOP"
        sudo losetup -d "$LOOP" >/dev/null 2>&1 || true
    fi
}

run_python() {
    sudo env LOOP="$LOOP" LOCATOR_OFFSET="$LOCATOR_OFFSET" DISK_BYTES="$DISK_BYTES" \
         META_OFFSET="$META_OFFSET" SIG_OFFSET="$SIG_OFFSET" python3 - "$@"
}

# Python helpers as functions
python_read_locator() {
    cat <<'PY'
import sys, struct, os
loop = sys.argv[1]
size = int(sys.argv[2])
loc_off = size - 4096

with open(loop, 'rb', buffering=0) as f:
    f.seek(loc_off)
    blk = f.read(32)
    
print("DEBUG: Raw locator bytes:", blk.hex(), file=sys.stderr)

try:
    magic, version, meta_off, meta_len, sig_off, sig_len = struct.unpack('<IIQIQI', blk[:32])
except struct.error as e:
    print(f"ERROR: Failed to unpack locator: {e}", file=sys.stderr)
    sys.exit(2)

print(f"DEBUG: magic=0x{magic:08x}, version={version}", file=sys.stderr)
print(f"DEBUG: meta_off={meta_off} (0x{meta_off:x}), meta_len={meta_len}", file=sys.stderr)  
print(f"DEBUG: sig_off={sig_off} (0x{sig_off:x}), sig_len={sig_len}", file=sys.stderr)

if magic == 0x564C4F43:  # VLOC
    print(f"{meta_off} {meta_len} {sig_off} {sig_len} {loc_off}")
else:
    print(f"ERROR: Invalid VLOC magic - got 0x{magic:08x}, expected 0x564C4F43", file=sys.stderr)
    sys.exit(1)
PY
}

python_flip_byte() {
    local offset=$1
    cat <<PY
import os, sys
p = os.environ['LOOP']
off = $offset
with open(p, 'r+b', buffering=0) as f:
    f.seek(off)
    b = f.read(1)
    if len(b) != 1:
        sys.stderr.write(f"ERROR: could not read 1 byte at {off}\n")
        sys.exit(2)
    f.seek(off)
    written = f.write(bytes([b[0] ^ 0x01]))
    if written != 1:
        sys.stderr.write("ERROR: short write when flipping byte\n")
        sys.exit(2)
    f.flush()
    os.fsync(f.fileno())
print(f"flipped 1 byte at {off}")
PY
}

python_corrupt_locator() {
    local meta_off=$1 meta_len=$2 sig_off=$3 sig_len=$4
    cat <<PY
import struct, os, sys
loop_dev = os.environ['LOOP']
loc_off = int(os.environ['LOCATOR_OFFSET'])

with open(loop_dev, 'rb', buffering=0) as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    if len(locator_data) < 24:
        sys.stderr.write('ERROR: short locator read\n')
        sys.exit(2)
    magic, version, orig_meta_off, orig_meta_len, orig_sig_off, orig_sig_len = struct.unpack('<IIIIII', locator_data)

print('Original values:')
print(f'  meta_off: {orig_meta_off}, meta_len: {orig_meta_len}')
print(f'  sig_off:  {orig_sig_off}, sig_len:  {orig_sig_len}')

print('Corrupted values:')
print(f'  meta_off: {$meta_off} (0x{$meta_off:08x})')
print(f'  meta_len: {$meta_len} (0x{$meta_len:08x})')
print(f'  sig_off:  {$sig_off} (0x{$sig_off:08x})')
print(f'  sig_len:  {$sig_len} (0x{$sig_len:08x})')

new_locator = struct.pack('<IIIIII', magic, version, $meta_off, $meta_len, $sig_off, $sig_len)
with open(loop_dev, 'r+b', buffering=0) as f:
    f.seek(loc_off)
    written = f.write(new_locator)
    if written != len(new_locator):
        sys.stderr.write('ERROR: short write when updating locator\n')
        sys.exit(2)
    f.flush(); os.fsync(f.fileno())

print('SUCCESS: Locator corrupted')
PY
}

# Main script execution begins here
echo "===================================================================="
echo "dm-verity Parser Fuzz Testing & Robustness Validation Suite"
echo "===================================================================="

# Argument parsing
args=()
for a in "$@"; do
    case "$a" in
        --inplace) INPLACE=1 ;;
        --dry-run) DRYRUN=1 ;;
        --verbose) VERBOSE=1 ;;
        --yes) YES=1 ;;
        --backup) BACKUP=1 ;;
        --restore) RESTORE=1 ;;
        -h|--help) usage; exit 0 ;;
        meta1|sig1|int_overflow|buf_overflow|trunc_meta|bad_offsets|sanitize) MODE="$a" ;;
        *) args+=("$a") ;;
    esac
done

# Optional explicit image path
((${#args[@]} > 0)) && IMG_PATH="${args[0]}"

# Restore functionality
if (( RESTORE )); then
    IMG="$(readlink -f -- "$IMG_PATH")"
    BAK="${IMG}.bak"
    if [[ -f "$BAK" ]]; then
        echo "Restoring $BAK -> $IMG"
        (( DRYRUN )) && echo "(dry-run) would copy $BAK -> $IMG" && exit 0
        cp -f -- "$BAK" "$IMG"
        echo "Restore complete"
        exit 0
    else
        echo "No backup found at $BAK" >&2
        exit 1
    fi
fi

# Validation
[[ -z "$MODE" ]] && { echo "ERROR: missing test mode" >&2; usage; exit 2; }

for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: required command '$cmd' not found" >&2; exit 2; }
done

IMG="$(readlink -f -- "$IMG_PATH")"
[[ ! -f "$IMG" ]] && { echo "ERROR: disk image not found: $IMG" >&2; exit 1; }

# User interaction
if (( ! INPLACE )) && (( ! YES )) && [[ -t 0 ]]; then
    echo "Test Configuration:"
    echo "  Mode:        $MODE"
    echo "  Source:      $IMG" 
    echo "  Test Image:  rootfs.${MODE}.test.img"
    echo ""
    echo "Execution Mode:"
    echo "  1) Create test image (rootfs.${MODE}.test.img) - RECOMMENDED"
    echo "  2) Overwrite original image (rootfs.img) - DESTRUCTIVE"
    echo "  3) Cancel operation"
    echo ""
    read -r -p "Select option [1/2/3] (default: 1): " choice
    case "${choice:-1}" in
        1) INPLACE=0; echo "Creating test image: rootfs.${MODE}.test.img" ;;
        2) 
            INPLACE=1
            echo "WARNING: DESTRUCTIVE OPERATION - Original image will be permanently modified!"
            read -r -p "CONFIRM: Overwrite original image? This cannot be undone! [y/N] " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Operation cancelled."; exit 0; }
            ;;
        *) echo "Operation cancelled."; exit 0 ;;
    esac
fi

# Prepare output image
if (( INPLACE )); then
    BAD_IMG="$IMG"
    if (( BACKUP )); then
        BAK_PATH="${IMG}.bak"
        if [[ -f "$BAK_PATH" ]]; then
            echo "Backup already exists at $BAK_PATH; not overwriting unless --yes provided"
            if [[ -t 0 ]] && (( ! YES )); then
                read -r -p "Overwrite backup $BAK_PATH? [y/N] " r
                [[ "$r" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
            fi
        fi
        if (( DRYRUN )); then
            echo "(dry-run) would create backup: $BAK_PATH"
        else
            echo "Creating backup: $BAK_PATH"
            cp -a -- "$IMG" "$BAK_PATH"
        fi
    fi
    echo "==> IN-PLACE MODIFICATION REQUESTED: $IMG"
else
    tmpdir="$(dirname -- "$IMG")"
    BAD_IMG="$tmpdir/rootfs.${MODE}.test.img"
    echo "==> CREATING TEST IMAGE: $BAD_IMG"
    
    if (( DRYRUN )); then
        echo "(dry-run) would copy $IMG -> $BAD_IMG"
    else
        if ! cp -f --reflink=auto -- "$IMG" "$BAD_IMG" 2>/dev/null; then
            echo "reflink not available or failed; falling back to regular copy"
            cp -f -- "$IMG" "$BAD_IMG"
        fi
    fi
fi

(( DRYRUN )) && { echo "Dry-run mode: no changes will be written."; exit 0; }

printf "==> Test Mode    : %s\n" "$MODE"
printf "==> Source Image : %s\n" "$IMG"
printf "==> Target Image : %s\n" "$BAD_IMG"

# Setup loop device
trap cleanup EXIT
echo "==> Attaching loop device…"
LOOP="$(sudo losetup -f --show -- "$BAD_IMG")" || { echo "ERROR: losetup failed" >&2; exit 1; }
sleep 1

# Read disk metadata
DISK_BYTES="$(sudo blockdev --getsize64 "$LOOP")"
read -r META_OFFSET META_LEN SIG_OFFSET SIG_SIZE LOCATOR_OFFSET <<<"$(
    sudo env LOOP="$LOOP" python3 - "$LOOP" "$DISK_BYTES" < <(python_read_locator)
)"

[[ -z "$META_OFFSET" || -z "$SIG_OFFSET" ]] && { echo "ERROR: failed to compute offsets" >&2; exit 1; }

echo "Disk Structure Analysis:"
print_offsets "META" "$META_OFFSET" "$META_LEN"
print_offsets "SIG " "$SIG_OFFSET" "$SIG_SIZE"
printf "  LOC  offset (disk): %d (0x%08x)\n" "$LOCATOR_OFFSET" "$LOCATOR_OFFSET"

# Store original header checksum for meta1 mode
if [[ "$MODE" == "meta1" ]]; then
    BEFORE="$(sudo dd if="$LOOP" bs=1 skip="$META_OFFSET" count=196 2>/dev/null | sha256sum | awk '{print $1}')"
    echo "  Header SHA256 (before): $BEFORE"
fi

# Perform corruption based on mode
case "$MODE" in
    meta1)
        echo "==> Executing: Header Structure Corruption Test"
        echo "    Modifying: Single byte flip at metadata offset +64"
        echo "    Tests: Structural integrity validation, checksum verification"
        run_python < <(python_flip_byte $((META_OFFSET + 64)))
        AFTER="$(sudo dd if="$LOOP" bs=1 skip="$META_OFFSET" count=196 2>/dev/null | sha256sum | awk '{print $1}')"
        echo "  Header SHA256 (after):  $AFTER"
        [[ "$BEFORE" == "$AFTER" ]] && echo "!! WARNING: header digest unchanged — check offsets" >&2
        ;;

    sig1)
        echo "==> Executing: Cryptographic Signature Corruption Test" 
        echo "    Modifying: Single byte flip in PKCS#7 signature blob"
        echo "    Tests: ASN.1 parsing, cryptographic verification"
        ACTUAL_SIG_OFFSET=$((SIG_OFFSET + 196))
        echo "DEBUG: Signature location: $ACTUAL_SIG_OFFSET"
        
        echo "Signature preview (before):"
        sudo dd if="$LOOP" bs=1 skip="$ACTUAL_SIG_OFFSET" count=16 status=none | hexdump -C
        
        run_python < <(python_flip_byte "$ACTUAL_SIG_OFFSET")
        
        echo "Signature preview (after):"
        sudo dd if="$LOOP" bs=1 skip="$ACTUAL_SIG_OFFSET" count=16 status=none | hexdump -C
        ;;

    int_overflow)
        echo "==> Executing: Integer Overflow Protection Test"
        echo "    Modifying: Locator fields with wrap-around values"
        echo "    Tests: 32/64-bit integer overflow detection, bounds validation"
        run_python < <(python_corrupt_locator 0xFFFFFF00 0xFFFFFF00 0xFFFF0000 0xFFFF0000)
        ;;

    buf_overflow)
        echo "==> Executing: Buffer Overflow Protection Test"
        echo "    Modifying: Metadata length field set to 0xFFFFFFFF"
        echo "    Tests: Memory allocation limits, buffer size validation"
        run_python < <(python_corrupt_locator "$META_OFFSET" 0xFFFFFFFF "$SIG_OFFSET" "$SIG_SIZE")
        ;;

    trunc_meta)
        echo "==> Executing: Truncated Metadata Handling Test"
        echo "    Modifying: Metadata region extends beyond disk capacity"
        echo "    Tests: Bounds checking, truncated read error handling"
        run_python < <(python_corrupt_locator $((DISK_BYTES - 100)) 4096 "$SIG_OFFSET" "$SIG_SIZE")
        ;;

    bad_offsets)
        echo "==> Executing: Out-of-Bounds Offset Validation Test"
        echo "    Modifying: Metadata/signature offsets beyond disk boundary"
        echo "    Tests: Offset validation, out-of-bounds access prevention"
        run_python < <(python_corrupt_locator $((DISK_BYTES + (1 << 20))) 512 $((DISK_BYTES + (1 << 21))) 256)
        ;;

    sanitize)
        echo "==> Executing: Input Sanitization Fuzz Test"
        echo "    Modifying: Complete locator replacement with random data"
        echo "    Tests: Magic number validation, input field sanitization"
        run_python <<'PY'
import struct, os, random, sys
loop_dev = os.environ['LOOP']
loc_off = int(os.environ['LOCATOR_OFFSET'])
magic = random.randint(0, 0xFFFFFFFF)
version = random.randint(0, 10)
meta_off = random.randint(0, 0xFFFFFFFF)
meta_len = random.randint(0, 0xFFFFFFFF)
sig_off = random.randint(0, 0xFFFFFFFF)
sig_len = random.randint(0, 0xFFFFFFFF)

print('Random garbage values:')
print(f'  magic:    0x{magic:08x}')
print(f'  version:  {version}')

new_locator = struct.pack('<IIIIII', magic, version, meta_off, meta_len, sig_off, sig_len)
with open(loop_dev, 'r+b', buffering=0) as f:
    f.seek(loc_off)
    written = f.write(new_locator)
    if written != len(new_locator):
        sys.stderr.write('ERROR: short write when updating locator\n')
        sys.exit(2)
    f.flush(); os.fsync(f.fileno())

print('SUCCESS: Locator replaced with random garbage')
PY
        ;;

    *)
        echo "ERROR: unknown test mode: $MODE" >&2
        exit 2
        ;;
esac

# Cleanup
sync
sudo losetup -d "$LOOP" || true
unset LOOP
trap - EXIT

# Results summary
echo ""
echo "===================================================================="
echo "TEST EXECUTION COMPLETE"
echo "===================================================================="
echo "Output: $BAD_IMG"
echo ""
echo "EXPECTED KERNEL BEHAVIOR:"

case "$MODE" in
    meta1) 
        echo "  - Kernel detects corrupted header and fails verification"
        echo "  - dm-verity rejects metadata with invalid structure"
        echo "  - Kernel may panic if metadata is untrusted" ;;

    sig1)
        echo "  - PKCS#7 signature verification fails"
        echo "  - Kernel does not proceed with invalid cryptographic signature"
        echo "  - Error is logged; boot process halts" ;;

    int_overflow)
        echo "  - Parser detects integer wrap-around in offset calculations"
        echo "  - Kernel rejects locator with overflowed field values"
        echo "  - Returns error code (EINVAL) without crashing" ;;

    buf_overflow)
        echo "  - Kernel safely rejects excessive metadata length"
        echo "  - Does not attempt to allocate unreasonable memory buffers"
        echo "  - Fails with appropriate resource limit / invalid argument error" ;;

    trunc_meta)
        echo "  - Parser detects metadata region extending beyond disk"
        echo "  - Handles truncated reads gracefully without crashing"
        echo "  - Returns error indicating out-of-bounds access" ;;

    bad_offsets)
        echo "  - Offset validation rejects values beyond disk capacity"
        echo "  - Kernel does not attempt to read from invalid locations"
        echo "  - Fails with bounds checking / invalid argument error" ;;

    sanitize)
        echo "  - Parser rejects locator with invalid magic number"
        echo "  - Handles arbitrary garbage input without kernel panic"
        echo "  - Fails cleanly with input validation error" ;;
esac

echo ""
echo "Next steps:"
echo "  1. Launch QEMU with: ./launch_qemu.sh"
echo "  2. Select appropriate test image from menu"
echo "  3. Observe kernel behavior during boot verification"
echo "  4. Check kernel logs for expected error patterns"
echo ""

exit 0