#!/usr/bin/env bash
set -euo pipefail

# Minimal dm-verity corrupter (1-byte flip) + auto-relink.
# Usage:
#   ./corrupt_rootfs.sh <meta1|sig1> [img-or-link] [--inplace] [--no-link] [--link-good]
#   ./corrupt_rootfs.sh --link-good
#
# Modes:
#   meta1 : flip 1 byte in 196-byte VERI header (at meta_off + 64)
#   sig1  : flip 1 byte in detached PKCS#7 signature (at sig_off)
#
# Defaults:
#   img-or-link = ../bootloaders/rootfs.img (resolved to real target)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_LINK_DEFAULT="$SCRIPT_DIR/../bootloaders/rootfs.img"

# Defaults
MODE=""
IMG_LINK="$IMG_LINK_DEFAULT"
INPLACE=0
LINK=1
LINK_GOOD=0

# Parse args (flags can come first)
args=()
for a in "$@"; do
  case "$a" in
    --inplace)   INPLACE=1 ;;
    --no-link)   LINK=0 ;;
    --link-good) LINK_GOOD=1 ;;
    meta1|sig1)  MODE="$a" ;;
    *)           args+=("$a") ;;
  esac
done

# If user passed a custom image/link path, take the first non-flag leftover
if ((${#args[@]} > 0)); then
  IMG_LINK="${args[0]}"
fi

# Helper: atomic relink of src/bootloaders/rootfs.img
relink() {
  local target="$1"
  local link="$SCRIPT_DIR/../bootloaders/rootfs.img"
  local abs tmp
  abs="$(readlink -f -- "$target")"
  [[ -f "$abs" ]] || { echo "ERROR: not a file: $abs"; exit 1; }
  tmp="${link}.tmp.$$"
  ln -s -- "$abs" "$tmp"
  mv -Tf -- "$tmp" "$link"
  echo "Symlink updated: $link -> $(readlink -f "$link")"
}

# Handle --link-good early (no mode required)
if (( LINK_GOOD )); then
  relink "$SCRIPT_DIR/../build/Binaries/rootfs.img"
  exit 0
fi

# Require a mode now
if [[ -z "${MODE:-}" ]]; then
  echo "Usage: $0 <meta1|sig1> [img-or-link] [--inplace] [--no-link] [--link-good]" >&2
  exit 2
fi

# Resolve input
IMG="$(readlink -f -- "$IMG_LINK")"
[[ -f "$IMG" ]] || { echo "ERROR: image not found: $IMG"; exit 1; }

# Output image (copy or in-place)
if (( INPLACE )); then
  BAD_IMG="$IMG"
else
  BAD_IMG="${IMG%.img}.bad.img"
  echo "==> Copying pristine image..."
  cp -f --reflink=auto -- "$IMG" "$BAD_IMG"
fi

echo "==> Mode  : $MODE"
echo "==> Input : $IMG (from link $IMG_LINK)"
echo "==> Output: $BAD_IMG"

# Attach loop (whole disk, with partitions)
echo "==> Attaching loop…"
LOOP="$(sudo losetup -fP --show -- "$BAD_IMG")"
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
  meta1) echo "Expected: dm table likely fails → early VFS panic (header altered).";;
  sig1)  echo "Expected: dm table loads; your module rejects PKCS7 and panics with your message.";;
esac

# Repoint bootloader symlink unless disabled
if (( LINK )); then
  relink "$BAD_IMG"
else
  echo "(symlink not updated: --no-link set)"
fi

# End
