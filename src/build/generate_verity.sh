#!/bin/bash
set -euo pipefail

echo "========================================"
echo "  Generating dm-verity metadata"
echo "  (DETACHED PKCS7, NO superblock, WHOLE DISK)"
echo "========================================"

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$BUILD_DIR/Binaries"
META_DIR="$BIN_DIR/metadata"
ROOTFS_IMG="$BIN_DIR/rootfs.img"
ROOT_HASH_FILE="$META_DIR/root.hash"

# Detached signature artifacts
METADATA_HEADER="$META_DIR/verity_header.bin"      # 196-byte signed header (input to PKCS7)
SIG_FILE="$META_DIR/verity_header.sig"             # Detached PKCS7 signature (DER)
LOCATOR_FILE="$META_DIR/verity_locator.bin"        # 4KB locator footer ("VLOC")

# Metadata header length (must match VERITY_FOOTER_SIGNED_LEN in kernel module)
META_LEN=196

# Signing key + cert (trusted by kernel keyring)
PRIV_KEY="$BUILD_DIR/../boot/bl_private.pem"
CERT_FILE="$BUILD_DIR/../boot/bl_cert.pem"

mkdir -p "$META_DIR"

# --- sanity checks ---
[[ -f "$ROOTFS_IMG" ]] || { echo "ERROR: rootfs.img not found: $ROOTFS_IMG"; exit 1; }
[[ -f "$PRIV_KEY"   ]] || { echo "ERROR: bl_private.pem not found: $PRIV_KEY"; exit 1; }
[[ -f "$CERT_FILE"  ]] || { echo "ERROR: bl_cert.pem not found:  $CERT_FILE"; exit 1; }

echo "[1/9] Setting up loop device for disk image (WHOLE DISK, no partitions)..."
# NOTE: no -P here; we work directly on the whole image (ext4 on entire disk)
LOOP_DEV=$(sudo losetup -f --show "$ROOTFS_IMG")
trap 'sudo losetup -d "$LOOP_DEV" >/dev/null 2>&1 || true' EXIT
DISK_DEV="$LOOP_DEV"
echo "  Disk device: $DISK_DEV (whole image)"

echo "[2/9] Reading filesystem geometry from whole disk..."
BLOCK_SIZE=$(sudo dumpe2fs -h "$DISK_DEV" 2>/dev/null | awk '/Block size:/ {print $3}')
BLOCK_COUNT=$(sudo dumpe2fs -h "$DISK_DEV" 2>/dev/null | awk '/Block count:/ {print $3}')
if [[ -z "${BLOCK_SIZE:-}" || -z "${BLOCK_COUNT:-}" ]]; then
  echo "ERROR: Could not read ext filesystem geometry from $DISK_DEV"; exit 1
fi

DISK_SIZE=$(sudo blockdev --getsize64 "$DISK_DEV")
DISK_SIZE_BLOCKS=$((DISK_SIZE / BLOCK_SIZE))

echo "  Filesystem block size : $BLOCK_SIZE bytes"
echo "  Filesystem block count: $BLOCK_COUNT blocks"
echo "  Disk size             : $DISK_SIZE bytes ($DISK_SIZE_BLOCKS blocks)"

# Where the hash tree begins (immediately after FS data)
DATA_SIZE=$((BLOCK_COUNT * BLOCK_SIZE))
HASH_OFFSET=$DATA_SIZE
HASH_OFFSET_SECTORS=$((HASH_OFFSET / 512))
AVAILABLE_SPACE=$((DISK_SIZE - DATA_SIZE))

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

  sudo e2fsck -pf "$DISK_DEV" || sudo e2fsck -fy "$DISK_DEV"

  SAFETY=$((1<<20))  # 1 MiB slack
  TARGET_BYTES=$((DISK_SIZE - HASH_BYTES - SAFETY))
  TARGET_BLOCKS=$((TARGET_BYTES / BLOCK_SIZE))
  if (( TARGET_BLOCKS <= 0 )); then
    echo "FATAL: disk too small for data + verity tree"; exit 1
  fi

  echo "  resize2fs $DISK_DEV $TARGET_BLOCKS"
  sudo resize2fs "$DISK_DEV" "$TARGET_BLOCKS"

  # Recompute after shrink (we want data_blocks to match the ext4 data area)
  BLOCK_COUNT=$TARGET_BLOCKS
  DATA_SIZE=$((BLOCK_COUNT * BLOCK_SIZE))
  HASH_OFFSET=$DATA_SIZE
  HASH_OFFSET_SECTORS=$((HASH_OFFSET / 512))
  AVAILABLE_SPACE=$((DISK_SIZE - DATA_SIZE))
  echo "  After shrink:"
  echo "    BLOCK_COUNT=$BLOCK_COUNT"
  echo "    DATA_SIZE=$DATA_SIZE"
  echo "    HASH_OFFSET=$HASH_OFFSET (sector $HASH_OFFSET_SECTORS)"
  echo "    AVAILABLE_SPACE=$AVAILABLE_SPACE"
fi

echo "[4/9] Generating dm-verity hash tree (same disk, NO superblock)..."
sudo veritysetup format \
  --data-block-size="$BLOCK_SIZE" \
  --hash-block-size="$BLOCK_SIZE" \
  --data-blocks="$BLOCK_COUNT" \
  --hash-offset="$HASH_OFFSET" \
  --no-superblock \
  "$DISK_DEV" "$DISK_DEV" \
  | tee "$META_DIR/verity_info.txt"

echo "[5/9] Extracting root hash + salt from veritysetup output..."
ROOT_HASH=$(grep -i "^Root hash:" "$META_DIR/verity_info.txt" | awk '{print $3}')
SALT_HEX=$(grep -i "^Salt:"      "$META_DIR/verity_info.txt" | awk '{print $2}')
[[ -n "$ROOT_HASH" ]] || { echo "ERROR: Failed to extract root hash"; exit 1; }
[[ -n "$SALT_HEX"  ]] || { echo "ERROR: Failed to extract salt"; exit 1; }

echo "$ROOT_HASH" > "$ROOT_HASH_FILE"
echo "     Root hash : $ROOT_HASH"
echo "     Salt (hex): $SALT_HEX"

echo "[6/9] Building metadata header (${META_LEN} bytes, to be signed)..."
python3 - <<EOF
import struct, binascii
MAGIC = 0x56455249  # "VERI"
VERSION = 1
DATA_BLOCKS = ${BLOCK_COUNT}
HASH_START_SECTOR = ${HASH_OFFSET_SECTORS}   # absolute sectors on this disk (for logging / tooling)
DATA_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_ALGORITHM = b"sha256"
ROOT_HASH = bytes.fromhex("${ROOT_HASH}")
SALT = binascii.unhexlify("${SALT_HEX}")[:64]
SALT_SIZE = len(SALT)

header = bytearray(${META_LEN}); off = 0
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
assert off == ${META_LEN}
open("${METADATA_HEADER}", 'wb').write(header)
print("  Metadata header written (${META_LEN} bytes)")
EOF

echo "[7/9] Creating DETACHED PKCS7 signature..."
openssl smime -sign -binary -noattr \
    -in "$METADATA_HEADER" \
    -signer "$CERT_FILE" -inkey "$PRIV_KEY" \
    -outform DER -nosmimecap > "$SIG_FILE"
SIG_SIZE=$(stat -c%s "$SIG_FILE")
echo "  Signature size: $SIG_SIZE bytes"

echo "[8/9] Laying out header+sig+locator at end of DISK..."
LOCATOR_SIZE=4096
LOCATOR_OFFSET=$((DISK_SIZE - LOCATOR_SIZE))
SIG_ALIGNED_SIZE=$(( (SIG_SIZE + 4095) / 4096 * 4096 ))
SIG_OFFSET=$((LOCATOR_OFFSET - SIG_ALIGNED_SIZE))
META_ALIGNED_SIZE=4096
META_OFFSET=$((SIG_OFFSET - META_ALIGNED_SIZE))

echo "  Disk size      : $DISK_SIZE"
echo "  Meta  offset   : $META_OFFSET"
echo "  Sig   offset   : $SIG_OFFSET"
echo "  Locator offset : $LOCATOR_OFFSET"

echo "  Building VLOC locator (4 KiB)..."
python3 - <<EOF
import struct

VLOC_MAGIC  = 0x564C4F43  # 'VLOC'
VERSION     = 1
META_OFF    = ${META_OFFSET}
META_LEN    = ${META_LEN}
SIG_OFF     = ${SIG_OFFSET}
SIG_LEN     = ${SIG_SIZE}

buf = bytearray(4096)
off = 0
struct.pack_into('<I', buf, off, VLOC_MAGIC); off += 4
struct.pack_into('<I', buf, off, VERSION);    off += 4
struct.pack_into('<Q', buf, off, META_OFF);   off += 8
struct.pack_into('<I', buf, off, META_LEN);   off += 4
struct.pack_into('<Q', buf, off, SIG_OFF);    off += 8
struct.pack_into('<I', buf, off, SIG_LEN);    off += 4
# rest is zero
open("${LOCATOR_FILE}", "wb").write(buf)
print("  Locator written: magic=VLOC, meta_off=%d, meta_len=%d, sig_off=%d, sig_len=%d"
      % (META_OFF, META_LEN, SIG_OFF, SIG_LEN))
EOF

echo "  Writing metadata header to disk..."
sudo dd if="$METADATA_HEADER" of="$DISK_DEV" bs=4096 \
    seek=$((META_OFFSET/4096)) conv=notrunc status=none

echo "  Writing signature to disk..."
sudo dd if="$SIG_FILE" of="$DISK_DEV" bs=4096 \
    seek=$((SIG_OFFSET/4096)) conv=notrunc status=none

echo "  Writing locator footer to disk..."
sudo dd if="$LOCATOR_FILE" of="$DISK_DEV" bs=4096 \
    seek=$((LOCATOR_OFFSET/4096)) conv=notrunc status=none

sync
sudo chown -R "$USER:$USER" "$META_DIR"

echo
echo "========================================"
echo "  dm-verity generation complete"
echo "  (DETACHED, NO superblock, WHOLE DISK)"
echo "========================================"
echo "Artifacts in $META_DIR:"
echo "  • verity_info.txt        (dm-verity format output)"
echo "  • root.hash              (Merkle root)"
echo "  • verity_header.bin      (${META_LEN}-byte metadata header - SIGNED)"
echo "  • verity_header.sig      (PKCS7 detached signature)"
echo "  • verity_locator.bin     (4KB locator footer - NOT signed)"
echo
echo "On-disk layout (end of DISK):"
echo "  [...ext4 data...][hash tree @ $HASH_OFFSET][metadata@$META_OFFSET][sig@$SIG_OFFSET][locator@$LOCATOR_OFFSET]"
echo
echo "Boot flow (no initramfs):"
echo "  - Bootloader passes disk path: dm_verity_autoboot.autoboot_device=/dev/vda"
echo "  - dm-verity-autoboot kernel module opens /dev/vda"
echo "  - Module reads VLOC, then metadata+signature regions at end of DISK"
echo "  - Module verifies PKCS7 against the 196-byte header using kernel trusted keyring"
echo "  - Module creates dm-verity mapping \"verity_root\" via dm_early_create()"
echo "  - /dev/dm-0 (verity_root) is mounted as the ext4 root filesystem (root=/dev/dm-0)"
echo "========================================"
