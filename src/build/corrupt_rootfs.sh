#!/usr/bin/env bash
set -euo pipefail

# Minimal dm-verity corrupter (1-byte flip) for your whole-disk rootfs image.
#
# This operates on the same rootfs.img that the bootloader passes to QEMU:
#   - bootloader realpaths ../build/Binaries/rootfs.img (from ../bootloaders)
#   - this script defaults to ./Binaries/rootfs.img when run from src/build
#
# Usage:
#   ./corrupt_rootfs.sh <meta1|sig1> [image-path] [--inplace]
#
# Modes:
#   meta1 : flip 1 byte in 196-byte VERI header (at meta_off + 64)
#   sig1  : flip 1 byte in detached PKCS#7 signature (at sig_off)
#
# Defaults:
#   image-path = Binaries/rootfs.img (same image your bootloader uses)
#   --inplace  : overwrite that file in place (so bootloader sees corruption)
#   (without --inplace a copy *.bad.img is created instead)

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
    meta1|sig1) MODE="$a" ;;
    *) args+=("$a") ;;
  esac
done

# Optional explicit image path (first non-flag arg that is not the mode)
if ((${#args[@]} > 0)); then
  IMG_PATH="${args[0]}"
fi

# Require a mode
if [[ -z "${MODE:-}" ]]; then
  echo "Usage: $0 <meta1|sig1> [image-path] [--inplace]" >&2
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
esac

# End
