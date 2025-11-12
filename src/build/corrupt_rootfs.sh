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
read -r META_OFFSET SIG_OFFSET SIG_SIZE LOCATOR_OFFSET <<<"$(
  sudo python3 - "$LOOP" "$DISK_BYTES" <<'PY'
import sys, struct
loop = sys.argv[1]
size = int(sys.argv[2])
loc_off = size - 4096
with open(loop, 'rb', buffering=0) as f:
    f.seek(loc_off)
    blk = f.read(4096)
magic, ver, meta_off, meta_len, sig_off, sig_len = struct.unpack('<IIQIQI', blk[:32])
# Magic 0x564C4F43 == 'VLOC'
if magic == 0x564C4F43:
    print(f"{meta_off} {sig_off} {sig_len} {loc_off}")
else:
    # Fallback guess (only used if locator missing)
    sig_len = 4096
    sig_off = loc_off - 4096
    meta_off = sig_off - 4096
    print(f"{meta_off} {sig_off} {sig_len} {loc_off}")
PY
)"

[[ -n "${META_OFFSET:-}" && -n "${SIG_OFFSET:-}" ]] || { echo "ERROR: failed to compute offsets"; exit 1; }

echo "Offsets:"
printf "  META offset (disk): %d\n" "$META_OFFSET"
printf "  SIG  offset (disk): %d (len %d)\n" "$SIG_OFFSET" "$SIG_SIZE"
printf "  LOC  offset (disk): %d\n" "$LOCATOR_OFFSET"

# For meta1, capture header digest before/after (proof)
if [[ "$MODE" == "meta1" ]]; then
  BEFORE="$(sudo dd if="$LOOP" bs=1 skip="$META_OFFSET" count=196 status=none | sha256sum | awk '{print $1}')"
fi

case "$MODE" in
  meta1)
    echo "==> Flipping 1 byte in METADATA header (offset META+64)…"
    sudo python3 - <<PY
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
    sudo python3 - <<PY
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

loop = os.environ["LOOP"]
size = os.path.getsize(loop)
loc_off = size - 4096
meta_off = 0xFFFFFFFFFFFFF000  # huge 64-bit offset to test wrap-around
meta_len = 0xFFFFFFF0
sig_off  = meta_off + 0x10
sig_len  = 0xFFFFFFF0

locator = struct.pack("<IIQIQI", 0x564C4F43, 1, meta_off, meta_len, sig_off, sig_len)
with open(loop, "r+b", buffering=0) as f:
    f.seek(loc_off)
    f.write(locator)

print(f"Wrote overflow locator at {loc_off:#x}")
PY
    ;;

  buf_overflow)
    echo "==> Declaring huge metadata length that exceeds image size..."
    sudo python3 - <<'PY'
import struct, os

loop = os.environ["LOOP"]
size = os.path.getsize(loop)
loc_off = size - 4096
meta_off = 4096
meta_len = size * 10  # 10× larger than the disk
sig_off  = meta_off + 512
sig_len  = 256

locator = struct.pack("<IIQIQI", 0x564C4F43, 1, meta_off, meta_len, sig_off, sig_len)
with open(loop, "r+b", buffering=0) as f:
    f.seek(loc_off)
    f.write(locator)

print("Locator written with excessive meta_len")
PY
    ;;

  trunc_meta)
    echo "==> Declaring longer metadata than exists (truncated metadata test)..."
    sudo python3 - <<'PY'
import struct, os

loop = os.environ["LOOP"]
size = os.path.getsize(loop)
loc_off = size - 4096
meta_off = size - 8192  # last 8K
meta_len = 16384        # claim twice that
sig_off  = meta_off + 4096
sig_len  = 512

locator = struct.pack("<IIQIQI", 0x564C4F43, 1, meta_off, meta_len, sig_off, sig_len)
with open(loop, "r+b", buffering=0) as f:
    f.seek(loc_off)
    f.write(locator)

print("Locator written with too-large metadata_len")
PY
    ;;

  bad_offsets)
    echo "==> Writing locator with offsets beyond disk end (malformed fields)..."
    sudo python3 - <<'PY'
import struct, os

loop = os.environ["LOOP"]
size = os.path.getsize(loop)
loc_off = size - 4096
meta_off = size + (1 << 30)  # +1GB beyond disk end
meta_len = 512
sig_off  = meta_off + 512
sig_len  = 256

locator = struct.pack("<IIQIQI", 0x564C4F43, 1, meta_off, meta_len, sig_off, sig_len)
with open(loop, "r+b", buffering=0) as f:
    f.seek(loc_off)
    f.write(locator)

print("Locator written with beyond-end offsets")
PY
    ;;

  sanitize)
    echo "==> Writing locator with random garbage fields (general input sanitation test)..."
    sudo python3 - <<'PY'
import struct, os, random

loop = os.environ["LOOP"]
size = os.path.getsize(loop)
loc_off = size - 4096
meta_off = random.randint(0, size * 2)
meta_len = random.randint(0, 1 << 31)
sig_off  = random.randint(0, size * 2)
sig_len  = random.randint(0, 1 << 31)

locator = struct.pack("<IIQIQI", 0x564C4F43, random.randint(0, 10),
                      meta_off, meta_len, sig_off, sig_len)
with open(loop, "r+b", buffering=0) as f:
    f.seek(loc_off)
    f.write(locator)

print("Randomized locator written for sanitation test")
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
