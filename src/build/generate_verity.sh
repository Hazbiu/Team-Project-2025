#!/bin/bash
set -euo pipefail

echo "========================================"
echo "  Generating dm-verity metadata (DETACHED signature mode)"
echo "========================================"

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$BUILD_DIR/Binaries"
META_DIR="$BIN_DIR/metadata"
ROOTFS_IMG="$BIN_DIR/rootfs.img"
ROOT_HASH_FILE="$META_DIR/root.hash"

# Detached signature artifacts
METADATA_HEADER="$META_DIR/verity_header.bin"      # 196-byte signed header (input to signature)
SIG_FILE="$META_DIR/verity_header.sig"             # Detached PKCS7 signature (DER)
LOCATOR_FILE="$META_DIR/verity_locator.bin"        # 4KB locator footer

# Signing key + cert
PRIV_KEY="$BUILD_DIR/../boot/bl_private.pem"
CERT_FILE="$BUILD_DIR/../boot/bl_cert.pem"

mkdir -p "$META_DIR"

# --- sanity checks ---
[[ -f "$ROOTFS_IMG" ]] || { echo "ERROR: rootfs.img not found: $ROOTFS_IMG"; exit 1; }
[[ -f "$PRIV_KEY"   ]] || { echo "ERROR: bl_private.pem not found: $PRIV_KEY"; exit 1; }
[[ -f "$CERT_FILE"  ]] || { echo "ERROR: bl_cert.pem not found:  $CERT_FILE"; exit 1; }

echo "[1/9] Setting up loop device for disk image..."
LOOP_DEV=$(sudo losetup -fP --show "$ROOTFS_IMG")
trap 'sudo losetup -d "$LOOP_DEV" >/dev/null 2>&1 || true' EXIT
echo "  Loop device: $LOOP_DEV"

sleep 1
PART_DEV="${LOOP_DEV}p1"
if [[ ! -e "$PART_DEV" ]]; then
  echo "  ERROR: Partition $PART_DEV not found!"
  exit 1
fi
echo "  Partition device: $PART_DEV (rootfs + verity tree)"

echo "[2/9] Reading filesystem geometry..."
BLOCK_SIZE=$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block size:/ {print $3}')
BLOCK_COUNT=$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block count:/ {print $3}')
if [[ -z "${BLOCK_SIZE:-}" || -z "${BLOCK_COUNT:-}" ]]; then
  echo "ERROR: Could not read ext filesystem geometry from $PART_DEV"; exit 1
fi

PART_SIZE=$(sudo blockdev --getsize64 "$PART_DEV")
PART_SIZE_BLOCKS=$((PART_SIZE / BLOCK_SIZE))

echo "  Filesystem block size : $BLOCK_SIZE bytes"
echo "  Filesystem block count: $BLOCK_COUNT blocks"
echo "  Partition size        : $PART_SIZE bytes ($PART_SIZE_BLOCKS blocks)"

# Where the hash tree begins (immediately after FS data)
DATA_SIZE=$((BLOCK_COUNT * BLOCK_SIZE))
HASH_OFFSET=$DATA_SIZE
HASH_OFFSET_SECTORS=$((HASH_OFFSET / 512))
AVAILABLE_SPACE=$((PART_SIZE - DATA_SIZE))

echo "  Filesystem data size  : $DATA_SIZE bytes"
echo "  Hash tree offset      : $HASH_OFFSET bytes (sector $HASH_OFFSET_SECTORS)"
echo "  Space after data      : $AVAILABLE_SPACE bytes"

echo "[3/9] Estimating Merkle tree size (sha256) and shrinking FS if needed..."
read HASH_BYTES HASH_BLOCKS < <(
  BLOCK_COUNT="$BLOCK_COUNT" BLOCK_SIZE="$BLOCK_SIZE" python3 - <<'PY'
import os
BLOCK_COUNT = int(os.environ["BLOCK_COUNT"])
BLOCK_SIZE  = int(os.environ["BLOCK_SIZE"])
g = 32  # sha256 digest size (bytes)
n = BLOCK_COUNT
levels = []
while n > 1:
    lvl = (n * g + BLOCK_SIZE - 1) // BLOCK_SIZE
    levels.append(lvl)
    n = lvl
hash_blocks = sum(levels) if levels else 0
print(hash_blocks * BLOCK_SIZE, hash_blocks)
PY
)

echo "  Estimated Merkle tree size: ${HASH_BYTES} bytes (${HASH_BLOCKS} blocks of $BLOCK_SIZE)"
if (( AVAILABLE_SPACE < HASH_BYTES )); then
  NEED=$((HASH_BYTES - AVAILABLE_SPACE))
  echo "  Not enough space for tree; need extra $NEED bytes. Shrinking filesystem..."

  sudo e2fsck -pf "$PART_DEV" || sudo e2fsck -fy "$PART_DEV"

  SAFETY=$((1<<20))  # 1 MiB slack
  TARGET_BYTES=$((PART_SIZE - HASH_BYTES - SAFETY))
  TARGET_BLOCKS=$((TARGET_BYTES / BLOCK_SIZE))
  if (( TARGET_BLOCKS <= 0 )); then
    echo "FATAL: partition too small for data + verity tree"; exit 1
  fi

  echo "  resize2fs $PART_DEV $TARGET_BLOCKS"
  sudo resize2fs "$PART_DEV" "$TARGET_BLOCKS"

  # Recompute after shrink
  BLOCK_COUNT=$TARGET_BLOCKS
  DATA_SIZE=$((BLOCK_COUNT * BLOCK_SIZE))
  HASH_OFFSET=$DATA_SIZE
  HASH_OFFSET_SECTORS=$((HASH_OFFSET / 512))
  AVAILABLE_SPACE=$((PART_SIZE - DATA_SIZE))
  echo "  After shrink:"
  echo "    BLOCK_COUNT=$BLOCK_COUNT"
  echo "    DATA_SIZE=$DATA_SIZE"
  echo "    HASH_OFFSET=$HASH_OFFSET (sector $HASH_OFFSET_SECTORS)"
  echo "    AVAILABLE_SPACE=$AVAILABLE_SPACE"
fi

echo "[4/9] Generating dm-verity hash tree (same partition, NO superblock)..."
# Single location: data + tree both inside /dev/loopXp1.
sudo veritysetup format \
  --data-block-size="$BLOCK_SIZE" \
  --hash-block-size="$BLOCK_SIZE" \
  --data-blocks="$BLOCK_COUNT" \
  --hash-offset="$HASH_OFFSET" \
  --no-superblock \
  "$PART_DEV" "$PART_DEV" \
  | tee "$META_DIR/verity_info.txt"

echo "[5/9] Extracting root hash + salt from veritysetup output..."
ROOT_HASH=$(grep -i "^Root hash:" "$META_DIR/verity_info.txt" | awk '{print $3}')
SALT_HEX=$(grep -i "^Salt:"      "$META_DIR/verity_info.txt" | awk '{print $2}')
[[ -n "$ROOT_HASH" ]] || { echo "ERROR: Failed to extract root hash"; exit 1; }
[[ -n "$SALT_HEX"  ]] || { echo "ERROR: Failed to extract salt"; exit 1; }

echo "$ROOT_HASH" > "$ROOT_HASH_FILE"
echo "     Root hash : $ROOT_HASH"
echo "     Salt (hex): $SALT_HEX"

echo "[6/9] Building metadata header (196 bytes, to be signed)..."
python3 - <<EOF
import struct, binascii
MAGIC = 0x56455249  # "VERI"
VERSION = 1
DATA_BLOCKS = ${BLOCK_COUNT}
HASH_START_SECTOR = ${HASH_OFFSET_SECTORS}   # sectors, relative to vda1
DATA_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_ALGORITHM = b"sha256"
ROOT_HASH = bytes.fromhex("${ROOT_HASH}")
SALT = binascii.unhexlify("${SALT_HEX}")[:64]
SALT_SIZE = len(SALT)

header = bytearray(196); off = 0
pack = struct.pack_into
pack('<I', header, off, MAGIC); off += 4
pack('<I', header, off, VERSION); off += 4
pack('<Q', header, off, DATA_BLOCKS); off += 8
pack('<Q', header, off, HASH_START_SECTOR); off += 8
pack('<I', header, off, DATA_BLOCK_SIZE); off += 4
pack('<I', header, off, HASH_BLOCK_SIZE); off += 4
header[off:off+32] = HASH_ALGORITHM + b'\x00'*(32-len(HASH_ALGORITHM)); off += 32
header[off:off+64] = ROOT_HASH + b'\x00'*(64-len(ROOT_HASH)); off += 64
header[off:off+64] = SALT + b'\x00'*(64-len(SALT)); off += 64
pack('<I', header, off, SALT_SIZE); off += 4
assert off == 196
open("${METADATA_HEADER}", 'wb').write(header)
print("  Metadata header written (196 bytes)")
EOF

echo "[7/9] Creating DETACHED PKCS7 signature..."
openssl smime -sign -binary -noattr \
    -in "$METADATA_HEADER" \
    -signer "$CERT_FILE" -inkey "$PRIV_KEY" \
    -outform DER -nosmimecap > "$SIG_FILE"
SIG_SIZE=$(stat -c%s "$SIG_FILE")
echo "  Signature size: $SIG_SIZE bytes"

echo "[8/9] Laying out header+sig+locator at end of disk..."
DISK_SIZE=$(sudo blockdev --getsize64 "$LOOP_DEV")
LOCATOR_SIZE=4096
LOCATOR_OFFSET=$((DISK_SIZE - LOCATOR_SIZE))
SIG_ALIGNED_SIZE=$(( (SIG_SIZE + 4095) / 4096 * 4096 ))
SIG_OFFSET=$((LOCATOR_OFFSET - SIG_ALIGNED_SIZE))
META_ALIGNED_SIZE=4096
META_OFFSET=$((SIG_OFFSET - META_ALIGNED_SIZE))

echo "  Disk size     : $DISK_SIZE"
echo "  Meta  offset  : $META_OFFSET (len 196, aligned 4096)"
echo "  Sig   offset  : $SIG_OFFSET  (len $SIG_SIZE, aligned $SIG_ALIGNED_SIZE)"
echo "  Locator offset: $LOCATOR_OFFSET (len 4096)"

python3 - <<EOF
import struct
loc = bytearray(4096)
off = 0
def pack(fmt, v):
    global off
    struct.pack_into(fmt, loc, off, v)
    off += struct.calcsize(fmt)

# "VLOC" footer
pack('<I', 0x564C4F43)   # magic
pack('<I', 1)            # version
pack('<Q', ${META_OFFSET})
pack('<I', 196)
pack('<Q', ${SIG_OFFSET})
pack('<I', ${SIG_SIZE})

open("${LOCATOR_FILE}", 'wb').write(loc)
print("  Locator created")
EOF

echo "  Writing metadata header..."
sudo dd if="$METADATA_HEADER" of="$LOOP_DEV" bs=4096 seek=$((META_OFFSET/4096)) conv=notrunc status=none

echo "  Writing signature..."
sudo dd if="$SIG_FILE" of="$LOOP_DEV" bs=4096 seek=$((SIG_OFFSET/4096)) conv=notrunc status=none

echo "  Writing locator footer..."
sudo dd if="$LOCATOR_FILE" of="$LOOP_DEV" bs=4096 seek=$((LOCATOR_OFFSET/4096)) conv=notrunc status=none

sync
sudo chown -R "$USER:$USER" "$META_DIR"

echo
echo "========================================"
echo "  dm-verity generation complete (DETACHED, NO superblock)"
echo "========================================"
echo "Artifacts in $META_DIR:"
echo "  • verity_info.txt        (dm-verity format output)"
echo "  • root.hash              (Merkle root)"
echo "  • verity_header.bin      (196-byte metadata header - SIGNED)"
echo "  • verity_header.sig      (PKCS7 detached signature)"
echo "  • verity_locator.bin     (4KB locator footer - NOT signed)"
echo
echo "On-disk layout (end of disk):"
echo "  [...ext4 data...][hash tree @ $HASH_OFFSET][metadata@$META_OFFSET][sig@$SIG_OFFSET][locator@$LOCATOR_OFFSET]"
echo
echo "Boot flow (no initramfs):"
echo "  - dm-init consumes dm-mod.create= and creates /dev/dm-0 from vda1"
echo "  - your module runs later (verify-only) and panics if untrusted"
echo "  - kernel mounts root=/dev/dm-0"
