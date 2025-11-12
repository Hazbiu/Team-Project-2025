#!/bin/bash
# dm-verity rootfs corruption and parser robustness test script
#
# This script operates on the same rootfs.img that the bootloader uses.
# By default, it looks for ./Binaries/rootfs.img when run from src/build.
#
# Usage:
#   ./corrupt_rootfs.sh <mode> [image-path] [--inplace]
#
# Modes:
#   meta1        – flip 1 byte in the dm-verity metadata header (meta_off + 64)
#   sig1         – flip 1 byte in the detached PKCS#7 signature (sig_off)
#   int_overflow – write locator fields with overflowed offsets/lengths to test wrap-around checks
#   buf_overflow – set a metadata length that exceeds the image size to test bounds checking
#   trunc_meta   – claim more metadata bytes than actually exist (truncated metadata test)
#   bad_offsets  – use offsets that point beyond the end of the disk (malformed locator test)
#   sanitize     – fill locator with random values to check general input validation
#
# Defaults:
#   image-path = Binaries/rootfs.img
#   --inplace  = modify the image directly (used by bootloader)
#   Without --inplace, a new file *.bad.img is created instead.
#
# Purpose:
#   This script helps verify that the kernel-side metadata parser fails safely
#   when given corrupted or malformed input. Each mode targets a different class
#   of error (overflow, truncation, bad offsets, random data) to confirm that
#   the module rejects invalid data without crashing.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_DEFAULT="$SCRIPT_DIR/Binaries/rootfs.img"

MODE=""
IMG_PATH="$IMG_DEFAULT"
INPLACE=0

# Parse args
args=()
for a in "$@"; do
  case "$a" in
    --inplace) INPLACE=1 ;;
    meta1|sig1|int_overflow|buf_overflow|trunc_meta|bad_offsets|sanitize) MODE="$a" ;;
    *) args+=("$a") ;;
  esac
done

# Optional explicit image path (first non-flag arg that is not the mode)
if ((${#args[@]} > 0)); then
  IMG_PATH="${args[0]}"
fi

# Require a mode
if [[ -z "${MODE:-}" ]]; then
  echo "Usage: $0 <meta1|sig1|int_overflow|buf_overflow|trunc_meta|bad_offsets|sanitize> [image-path] [--inplace]" >&2
  echo "  meta1 : flip 1 byte in VERI header" >&2
  echo "  sig1  : flip 1 byte in detached PKCS7 signature" >&2
  exit 2
fi

# Resolve and validate image path
IMG="$(readlink -f -- "$IMG_PATH")"
[[ -f "$IMG" ]] || { echo "ERROR: image not found: $IMG"; exit 1; }

# Output image (copy or in-place)
if (( INPLACE )); then
  BAD_IMG="$IMG"
  echo "==> IN-PLACE corruption requested"
else
  BAD_IMG="${IMG%.img}.bad.img"
  echo "==> Copying pristine image..."
  cp -f --reflink=auto -- "$IMG" "$BAD_IMG"
fi

echo "==> Mode  : $MODE"
echo "==> Input : $IMG"
echo "==> Output: $BAD_IMG"

# Attach loop (whole disk, no partitions)
echo "==> Attaching loop…"
LOOP="$(sudo losetup -f --show -- "$BAD_IMG")"
export LOOP   # make loop device path visible inside embedded python snippets
trap 'sudo losetup -d "$LOOP" >/dev/null 2>&1 || true' EXIT
sleep 1

# Read disk size and parse VLOC to get META & SIG offsets
DISK_BYTES="$(sudo blockdev --getsize64 "$LOOP")"
read -r META_OFFSET META_LEN SIG_OFFSET SIG_SIZE LOCATOR_OFFSET <<<"$(
  sudo env LOOP="$LOOP" python3 - "$LOOP" "$DISK_BYTES" <<'PY'
import sys, struct
loop = sys.argv[1]
size = int(sys.argv[2])
loc_off = size - 4096
with open(loop, 'rb', buffering=0) as f:
    f.seek(loc_off)
    blk = f.read(24)  # Read 24 bytes for locator
# Correct format: 6x 4-byte integers
magic, ver, meta_off, meta_len, sig_off, sig_len = struct.unpack('<IIIIII', blk[:24])
# Magic 0x564C4F43 == 'VLOC'
if magic == 0x564C4F43:
    print(f"{meta_off} {meta_len} {sig_off} {sig_len} {loc_off}")
else:
    # Fallback guess
    sig_len = 4096
    sig_off = loc_off - 4096
    meta_off = sig_off - 4096
    meta_len = 4096
    print(f"{meta_off} {meta_len} {sig_off} {sig_len} {loc_off}")
PY
)"

[[ -n "${META_OFFSET:-}" && -n "${SIG_OFFSET:-}" ]] || { echo "ERROR: failed to compute offsets"; exit 1; }

echo "Offsets:"
printf "  META offset (disk): %d (len %d)\n" "$META_OFFSET" "$META_LEN"
printf "  SIG  offset (disk): %d (len %d)\n" "$SIG_OFFSET" "$SIG_SIZE"
printf "  LOC  offset (disk): %d\n" "$LOCATOR_OFFSET"

# For meta1, capture header digest before/after (proof)
if [[ "$MODE" == "meta1" ]]; then
  BEFORE="$(sudo dd if="$LOOP" bs=1 skip="$META_OFFSET" count=196 status=none | sha256sum | awk '{print $1}')"
fi

case "$MODE" in
  meta1)
    echo "==> Flipping 1 byte in METADATA header (offset META+64)…"
    sudo env LOOP="$LOOP" python3 - <<PY
p="$LOOP"; off=$META_OFFSET+64
with open(p,"r+b", buffering=0) as f:
    f.seek(off); b=f.read(1)
    f.seek(off); f.write(bytes([b[0]^0x01]))
print("    flipped 1 byte at", off)
PY
    AFTER="$(sudo dd if="$LOOP" bs=1 skip="$META_OFFSET" count=196 status=none | sha256sum | awk '{print $1}')"
    echo "    header digest before: $BEFORE"
    echo "    header digest after : $AFTER"
    [[ "$BEFORE" != "$AFTER" ]] || echo "!! header digest unchanged — check offsets" >&2
    ;;

  sig1)
    echo "==> Flipping 1 byte in SIGNATURE (offset SIG)…"
    sudo env LOOP="$LOOP" python3 - <<PY
p="$LOOP"; off=$SIG_OFFSET
with open(p,"r+b", buffering=0) as f:
    f.seek(off); b=f.read(1)
    f.seek(off); f.write(bytes([b[0]^0x01]))
print("    flipped 1 byte at", off)
PY
    ;;

  int_overflow)
    echo "==> Writing locator with integer overflow fields (wrap-around test)..."
    sudo python3 - <<'PY'
import struct, os

img_path = "Binaries/rootfs.bad.img"
size = os.path.getsize(img_path)
loc_off = size - 4096

print(f"Disk size: {size} bytes")

# Read current locator first
with open(img_path, "rb") as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    magic, version, orig_meta_off, orig_meta_len, orig_sig_off, orig_sig_len = struct.unpack("<IIIIII", locator_data)

print("Original values:")
print(f"  meta_off: {orig_meta_off}, meta_len: {orig_meta_len}")
print(f"  sig_off:  {orig_sig_off}, sig_len:  {orig_sig_len}")

# Use values that would cause integer overflow/wrap-around
meta_off = 0xFFFFFF00    # Large offset near max uint32
meta_len = 0xFFFFFF00    # Large length that would overflow when added
sig_off = 0xFFFF0000     # Large signature offset
sig_len = 0xFFFF0000     # Large signature length

print("Corrupted values:")
print(f"  meta_off: {meta_off} (0x{meta_off:08x})")
print(f"  meta_len: {meta_len} (0x{meta_len:08x})")
print(f"  sig_off:  {sig_off} (0x{sig_off:08x})")
print(f"  sig_len:  {sig_len} (0x{sig_len:08x})")

# Create new locator with CORRECT 4-byte format
new_locator = struct.pack("<IIIIII", magic, version, meta_off, meta_len, sig_off, sig_len)

# Write directly to file (bypass loop device restrictions)
with open(img_path, "r+b") as f:
    f.seek(loc_off)
    f.write(new_locator)
    f.flush()
    os.fsync(f.fileno())

print("SUCCESS: Locator corrupted with overflow values")

# Verify
with open(img_path, "rb") as f:
    f.seek(loc_off)
    verify_data = f.read(24)
    v_magic, v_ver, v_meta_off, v_meta_len, v_sig_off, v_sig_len = struct.unpack("<IIIIII", verify_data)
    print("Verification:")
    print(f"  meta_off: {v_meta_off} (0x{v_meta_off:08x})")
    print(f"  meta_len: {v_meta_len} (0x{v_meta_len:08x})")
PY
    ;;

  buf_overflow)
    echo "==> Setting huge metadata length (correct 4-byte format)..."
    
    sudo python3 - <<'PY'
import struct, os

img_path = "Binaries/rootfs.bad.img"
size = os.path.getsize(img_path)
loc_off = size - 4096

print(f"Disk size: {size} bytes")

# Read current locator
with open(img_path, "rb") as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    magic, version, meta_off, meta_len, sig_off, sig_len = struct.unpack("<IIIIII", locator_data)
    
    print("Before corruption:")
    print(f"  meta_off:  {meta_off} (0x{meta_off:08x})")
    print(f"  meta_len:  {meta_len} (0x{meta_len:08x})")
    print(f"  sig_off:   {sig_off} (0x{sig_off:08x})")
    print(f"  sig_len:   {sig_len} (0x{sig_len:08x})")

# Set meta_len to maximum 32-bit value
new_meta_len = 0xFFFFFFFF  # Max uint32 value
print(f"Setting meta_len to: {new_meta_len} (0x{new_meta_len:08x})")

# Create new locator with corrupted meta_len
new_locator = struct.pack("<IIIIII", magic, version, meta_off, new_meta_len, sig_off, sig_len)

# Write back to file
with open(img_path, "r+b") as f:
    f.seek(loc_off)
    f.write(new_locator)
    f.flush()
    os.fsync(f.fileno())

print("SUCCESS: Locator corrupted with huge meta_len")

# Verify
with open(img_path, "rb") as f:
    f.seek(loc_off)
    verify_data = f.read(24)
    v_magic, v_ver, v_meta_off, v_meta_len, v_sig_off, v_sig_len = struct.unpack("<IIIIII", verify_data)
    print("After corruption:")
    print(f"  meta_len: {v_meta_len} (0x{v_meta_len:08x})")
    print(f"  Verification: {'SUCCESS' if v_meta_len == new_meta_len else 'FAILED'}")
    print(f"  Exceeds disk size: {'YES' if v_meta_len > size else 'NO'}")
PY
    ;;

  trunc_meta)
    echo "==> Declaring longer metadata than exists (truncated metadata test)..."
    sudo python3 - <<'PY'
import struct, os

img_path = "Binaries/rootfs.bad.img"
size = os.path.getsize(img_path)
loc_off = size - 4096

print(f"Disk size: {size} bytes")

# Read current locator first
with open(img_path, "rb") as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    magic, version, orig_meta_off, orig_meta_len, orig_sig_off, orig_sig_len = struct.unpack("<IIIIII", locator_data)

print("Original values:")
print(f"  meta_off: {orig_meta_off}, meta_len: {orig_meta_len}")

# Set metadata to start near end but claim much larger length
# This simulates truncated metadata - the parser will try to read beyond disk end
meta_off = size - 100    # Only 100 bytes left in disk
meta_len = 4096          # But claim we need 4K (truncated!)
sig_off = orig_sig_off   # Keep original signature offset
sig_len = orig_sig_len   # Keep original signature length

print("Truncated metadata values:")
print(f"  meta_off: {meta_off} (only {size - meta_off} bytes available)")
print(f"  meta_len: {meta_len} (but only {size - meta_off} bytes exist)")
print(f"  Would read to: {meta_off + meta_len} (beyond disk end!)")

# Create new locator
new_locator = struct.pack("<IIIIII", magic, version, meta_off, meta_len, sig_off, sig_len)

# Write directly to file
with open(img_path, "r+b") as f:
    f.seek(loc_off)
    f.write(new_locator)
    f.flush()
    os.fsync(f.fileno())

print("SUCCESS: Locator corrupted with truncated metadata claim")

# Verify
with open(img_path, "rb") as f:
    f.seek(loc_off)
    verify_data = f.read(24)
    v_magic, v_ver, v_meta_off, v_meta_len, v_sig_off, v_sig_len = struct.unpack("<IIIIII", verify_data)
    print("Verification:")
    print(f"  meta_off: {v_meta_off}, meta_len: {v_meta_len}")
    print(f"  Truncation: {'YES' if v_meta_off + v_meta_len > size else 'NO'}")
PY
    ;;

  bad_offsets)
    echo "==> Writing locator with offsets beyond disk end (malformed fields)..."
    sudo python3 - <<'PY'
import struct, os

img_path = "Binaries/rootfs.bad.img"
size = os.path.getsize(img_path)
loc_off = size - 4096

print(f"Disk size: {size} bytes")

# Read current locator first
with open(img_path, "rb") as f:
    f.seek(loc_off)
    locator_data = f.read(24)
    magic, version, orig_meta_off, orig_meta_len, orig_sig_off, orig_sig_len = struct.unpack("<IIIIII", locator_data)

print("Original values:")
print(f"  meta_off: {orig_meta_off}, sig_off: {orig_sig_off}")

# Set offsets that point beyond disk end
meta_off = size + (1 << 20)  # 1MB beyond disk end
sig_off = size + (1 << 21)   # 2MB beyond disk end
meta_len = 512
sig_len = 256

print("Bad offset values:")
print(f"  meta_off: {meta_off} ({meta_off - size} bytes beyond disk)")
print(f"  sig_off:  {sig_off} ({sig_off - size} bytes beyond disk)")
print(f"  meta_len: {meta_len}, sig_len: {sig_len}")

# Create new locator
new_locator = struct.pack("<IIIIII", magic, version, meta_off, meta_len, sig_off, sig_len)

# Write directly to file
with open(img_path, "r+b") as f:
    f.seek(loc_off)
    f.write(new_locator)
    f.flush()
    os.fsync(f.fileno())

print("SUCCESS: Locator corrupted with beyond-end offsets")

# Verify
with open(img_path, "rb") as f:
    f.seek(loc_off)
    verify_data = f.read(24)
    v_magic, v_ver, v_meta_off, v_meta_len, v_sig_off, v_sig_len = struct.unpack("<IIIIII", verify_data)
    print("Verification:")
    print(f"  meta_off: {v_meta_off}, sig_off: {v_sig_off}")
    print(f"  Beyond end: {'YES' if v_meta_off > size or v_sig_off > size else 'NO'}")
PY
    ;;

  sanitize)
    echo "==> Writing locator with random garbage fields (general input sanitation test)..."
    sudo python3 - <<'PY'
import struct, os, random

img_path = "Binaries/rootfs.bad.img"
size = os.path.getsize(img_path)
loc_off = size - 4096

print(f"Disk size: {size} bytes")

# Generate random values for all fields
magic = random.randint(0, 0xFFFFFFFF)
version = random.randint(0, 10)
meta_off = random.randint(0, 0xFFFFFFFF)
meta_len = random.randint(0, 0xFFFFFFFF)
sig_off = random.randint(0, 0xFFFFFFFF)
sig_len = random.randint(0, 0xFFFFFFFF)

print("Random garbage values:")
print(f"  magic:    0x{magic:08x}")
print(f"  version:  {version}")
print(f"  meta_off: 0x{meta_off:08x} ({meta_off})")
print(f"  meta_len: 0x{meta_len:08x} ({meta_len})")
print(f"  sig_off:  0x{sig_off:08x} ({sig_off})")
print(f"  sig_len:  0x{sig_len:08x} ({sig_len})")

# Create completely random locator
random_locator = struct.pack("<IIIIII", magic, version, meta_off, meta_len, sig_off, sig_len)

# Write directly to file
with open(img_path, "r+b") as f:
    f.seek(loc_off)
    f.write(random_locator)
    f.flush()
    os.fsync(f.fileno())

print("SUCCESS: Locator replaced with random garbage")

# Verify
with open(img_path, "rb") as f:
    f.seek(loc_off)
    verify_data = f.read(24)
    v_magic, v_ver, v_meta_off, v_meta_len, v_sig_off, v_sig_len = struct.unpack("<IIIIII", verify_data)
    print("Verification - random values written:")
    print(f"  magic: 0x{v_magic:08x}, version: {v_ver}")
PY
    ;;

esac
sync
sudo losetup -d "$LOOP"
trap - EXIT

echo " Done → $BAD_IMG"
case "$MODE" in
  meta1)
    echo "Expected: dm-verity metadata header changed → dm table or verification should fail early."
    ;;
  sig1)
    echo "Expected: dm-verity parameters still parse, but PKCS7 verification fails in your module."
    ;;
    int_overflow)
    echo "Expected: parser should detect wrap-around or overflow in locator offsets."
    ;;
  buf_overflow)
    echo "Expected: kernel should safely reject metadata length exceeding image bounds."
    ;;
  trunc_meta)
    echo "Expected: parser should fail cleanly on truncated metadata reads."
    ;;
  bad_offsets)
    echo "Expected: parser should validate offsets and reject beyond-end values."
    ;;
  sanitize)
    echo "Expected: parser should handle arbitrary garbage fields without panic."
    ;;
esac

# End
