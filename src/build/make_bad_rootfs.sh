#!/usr/bin/env bash
set -euo pipefail

# Run from anywhere; paths are anchored to this script's folder.
GOOD_IMG="../bootloaders/rootfs.img"      # default input: ./rootfs.img
BAD_IMG="../bootloaders/rootfs.bad.img"         # output:        ./rootfs.bad.img

MODE="${2:-headerflip}"                # headerflip | footer | data | hash
BYTES_TO_CORRUPT=4096                  # for footer/data/hash

echo "==> Input : $GOOD_IMG"
echo "==> Output: $BAD_IMG"
echo "==> Mode  : $MODE"
[[ -f "$GOOD_IMG" ]] || { echo "ERROR: $GOOD_IMG not found"; exit 1; }

echo "==> Copying pristine image to: $BAD_IMG"
cp -f --reflink=auto "$GOOD_IMG" "$BAD_IMG"

echo "==> Attaching loop device (with partitions) ..."
LOOP_DEV="$(sudo losetup -fP --show "$BAD_IMG")"
trap 'sudo losetup -d "$LOOP_DEV" >/dev/null 2>&1 || true' EXIT
PART_DEV="${LOOP_DEV}p1"
[[ -e "$PART_DEV" ]] || { echo "ERROR: $PART_DEV not found"; exit 1; }

echo "==> Reading geometry ..."
BLKSZ="$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block size:/ {print $3; exit}')"
BLKCNT="$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block count:/ {print $3; exit}')"
[[ -n "${BLKSZ:-}" && -n "${BLKCNT:-}" ]] || { echo "ERROR: dumpe2fs parse failed"; exit 1; }
DISK_BYTES="$(sudo blockdev --getsize64 "$LOOP_DEV")"
PART_BYTES="$(sudo blockdev --getsize64 "$PART_DEV")"

DATA_BYTES=$(( BLKSZ * BLKCNT ))            # FS payload
HASH_OFFSET=$(( DATA_BYTES ))               # start of hash tree (inside partition)
FOOTER_OFFSET=$(( DISK_BYTES - 4096 ))      # 4K footer at end of WHOLE DISK
HEADER_SAFE_FLIP_OFF=$(( FOOTER_OFFSET + 180 ))  # flip inside signed header (keeps magic/version)

printf "Geometry:\n"
printf "  Data bytes:        %d\n" "$DATA_BYTES"
printf "  Hash offset:       %d (partition-relative)\n" "$HASH_OFFSET"
printf "  Footer offset:     %d (disk absolute)\n" "$FOOTER_OFFSET"

rand_tmp="$(mktemp)"
dd if=/dev/urandom of="$rand_tmp" bs="$BYTES_TO_CORRUPT" count=1 status=none

case "$MODE" in
  headerflip)
    echo "==> Flipping 1 byte in signed header (should break PKCS7)"
    sudo python3 - <<PY
p = "$BAD_IMG"; off = $HEADER_SAFE_FLIP_OFF
with open(p, "r+b") as f:
    f.seek(off); b=f.read(1)
    if not b: raise SystemExit("EOF while reading")
    f.seek(off); f.write(bytes([b[0]^0x01]))
print(f"Flipped byte at absolute offset {off}")
PY
    ;;

  footer)
    echo "==> Blasting footer (4KiB at disk tail)"
    sudo dd if="$rand_tmp" of="$LOOP_DEV" bs=1 seek="$FOOTER_OFFSET" conv=notrunc status=none
    ;;

  data)
    echo "==> Corrupting data region (first safe block after superblock)"
    DATA_CORR_OFF=$(( BLKSZ * 1 ))
    (( DATA_CORR_OFF + BYTES_TO_CORRUPT <= DATA_BYTES )) || { echo "ERROR: data too small"; exit 1; }
    sudo dd if="$rand_tmp" of="$PART_DEV" bs=1 seek="$DATA_CORR_OFF" conv=notrunc status=none
    ;;

  hash)
    echo "==> Corrupting hash tree region (immediately after data)"
    (( HASH_OFFSET + BYTES_TO_CORRUPT <= PART_BYTES )) || { echo "ERROR: hash beyond partition"; exit 1; }
    sudo dd if="$rand_tmp" of="$PART_DEV" bs=1 seek="$HASH_OFFSET" conv=notrunc status=none
    ;;

  *)
    echo "Usage: $0 [path/to/rootfs.img] [headerflip|footer|data|hash]"
    exit 2
    ;;
esac

rm -f "$rand_tmp"; sync
echo "==> Done. Bad image at: $BAD_IMG"
# losetup detach happens via trap
