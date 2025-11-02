#!/bin/bash
set -euo pipefail

echo "========================================"
echo "  Generating dm-verity metadata (PKCS7 footer @ end of disk)"
echo "========================================"

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$BUILD_DIR/Binaries"
META_DIR="$BIN_DIR/metadata"
ROOTFS_IMG="$BIN_DIR/rootfs.img"
ROOT_HASH_FILE="$META_DIR/root.hash"

SIG_FILE="$META_DIR/footer.pkcs7" 
METADATA_FILE="$META_DIR/verity_metadata.bin"
HEADER_BIN="$META_DIR/header.bin"

PRIV_KEY="$BUILD_DIR/../boot/bl_private.pem"
CERT_FILE="$BUILD_DIR/../boot/bl_cert.pem"

mkdir -p "$META_DIR"

# --- sanity checks ---
if [[ ! -f "$ROOTFS_IMG" ]]; then
    echo "❌ rootfs.img not found at: $ROOTFS_IMG"
    exit 1
fi

if [[ ! -f "$PRIV_KEY" ]]; then
    echo "❌ bl_private.pem not found at: $PRIV_KEY"
    exit 1
fi

if [[ ! -f "$CERT_FILE" ]]; then
    echo "❌ bl_cert.pem not found at: $CERT_FILE"
    exit 1
fi

echo "[1/7] Setting up loop device for disk image..."
LOOP_DEV=$(sudo losetup -fP --show "$ROOTFS_IMG")
echo "  Loop device: $LOOP_DEV"

sleep 1
PART_DEV="${LOOP_DEV}p1"
if [ ! -e "$PART_DEV" ]; then
    echo "  ❌ ERROR: Partition $PART_DEV not found!"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi
echo "  Partition device: $PART_DEV (rootfs)"

echo "[2/7] Analyzing filesystem on rootfs partition..."
BLOCK_SIZE=$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block size:/ {print $3}')
BLOCK_COUNT=$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block count:/ {print $3}')

PART_SIZE=$(sudo blockdev --getsize64 "$PART_DEV")
PART_SIZE_BLOCKS=$((PART_SIZE / BLOCK_SIZE))

echo "  Filesystem block size: $BLOCK_SIZE bytes"
echo "  Filesystem block count: $BLOCK_COUNT blocks"
echo "  Partition size:        $PART_SIZE bytes ($PART_SIZE_BLOCKS blocks)"

# Figure out where the hash tree (Merkle tree) starts:
DATA_SIZE=$((BLOCK_COUNT * BLOCK_SIZE))
HASH_OFFSET=$DATA_SIZE
HASH_OFFSET_SECTORS=$((HASH_OFFSET / 512))
AVAILABLE_SPACE=$((PART_SIZE - DATA_SIZE))

echo "  Filesystem data size:  $DATA_SIZE bytes"
echo "  Hash tree offset:      $HASH_OFFSET bytes (sector $HASH_OFFSET_SECTORS)"
echo "  Available space after data in partition: $AVAILABLE_SPACE bytes"

echo "[3/7] Generating dm-verity hash tree (Merkle) ..."
DATA_LOOP=$(sudo losetup -f --show --sizelimit=$DATA_SIZE "$PART_DEV")
echo "  Data device: $DATA_LOOP (size-limited to $DATA_SIZE bytes)"

HASH_LOOP=$(sudo losetup -f --show --offset=$DATA_SIZE "$PART_DEV")
echo "  Hash device: $HASH_LOOP (starts after data payload)"

sudo veritysetup format \
    --data-block-size="$BLOCK_SIZE" \
    --hash-block-size="$BLOCK_SIZE" \
    "$DATA_LOOP" "$HASH_LOOP" \
    | tee "$META_DIR/verity_info.txt"

sudo losetup -d "$DATA_LOOP"
sudo losetup -d "$HASH_LOOP"

echo "[4/7] Extracting root hash + salt from veritysetup output..."
ROOT_HASH=$(grep -i "^Root hash:" "$META_DIR/verity_info.txt" | awk '{print $3}')
SALT_HEX=$(grep -i "^Salt:" "$META_DIR/verity_info.txt" | awk '{print $2}')

if [ -z "$ROOT_HASH" ]; then
    echo "  ❌ ERROR: Failed to extract root hash"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi
if [ -z "$SALT_HEX" ]; then
    echo "  ❌ ERROR: Failed to extract salt"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi

echo "$ROOT_HASH" > "$ROOT_HASH_FILE"

echo "  ✅ Root hash: $ROOT_HASH"
echo "  ✅ Salt (hex): $SALT_HEX"
echo "     Salt length (hex chars): ${#SALT_HEX}"

echo "[5/7] Building unsigned metadata blob (4KB footer struct, PKCS7 mode)..."
python3 - <<EOF
import struct, binascii

MAGIC = 0x56455249  # "VERI"
VERSION = 1
DATA_BLOCKS = ${BLOCK_COUNT}
HASH_START_SECTOR = ${HASH_OFFSET_SECTORS}
DATA_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_ALGORITHM = b"sha256"
ROOT_HASH = bytes.fromhex("${ROOT_HASH}")

SALT = binascii.unhexlify("${SALT_HEX}")
SALT = SALT[:64]
SALT_SIZE = len(SALT)

VERITY_FOOTER_SIZE = 4096
VERITY_PKCS7_MAX   = 2048  # bumped from 1024

metadata = bytearray(VERITY_FOOTER_SIZE)
offset = 0

# magic (u32 LE)
struct.pack_into('<I', metadata, offset, MAGIC); offset += 4
# version (u32 LE)
struct.pack_into('<I', metadata, offset, VERSION); offset += 4
# data_blocks (u64 LE)
struct.pack_into('<Q', metadata, offset, DATA_BLOCKS); offset += 8
# hash_start_sector (u64 LE)
struct.pack_into('<Q', metadata, offset, HASH_START_SECTOR); offset += 8
# data_block_size (u32 LE)
struct.pack_into('<I', metadata, offset, DATA_BLOCK_SIZE); offset += 4
# hash_block_size (u32 LE)
struct.pack_into('<I', metadata, offset, HASH_BLOCK_SIZE); offset += 4

# hash_algorithm[32]
metadata[offset:offset+len(HASH_ALGORITHM)] = HASH_ALGORITHM
offset += 32  # now 64

# root_hash[64]
metadata[offset:offset+len(ROOT_HASH)] = ROOT_HASH
offset += 64  # now 128

# salt[64]
metadata[offset:offset+len(SALT)] = SALT
offset += 64  # now 192

# salt_size (u32 LE)
struct.pack_into('<I', metadata, offset, SALT_SIZE)
offset += 4   # now 196

# pkcs7_size (u32 LE) placeholder = 0 for now
struct.pack_into('<I', metadata, offset, 0)
offset += 4   # now 200

# pkcs7_blob[2048] reserved; zeroed by default because metadata is zeroed.

with open("${METADATA_FILE}", 'wb') as f:
    f.write(metadata)

print("  ✅ Metadata structure (PKCS7 mode) created (4096 bytes)")
print("     MAGIC=0x%08X VERSION=%d" % (MAGIC, VERSION))
print("     data_blocks=${BLOCK_COUNT}")
print("     hash_start_sector=${HASH_OFFSET_SECTORS}")
print("     SALT_SIZE=%d bytes" % SALT_SIZE)
EOF

echo "[6/7] Creating PKCS7 signature over first 196 bytes..."

SIGN_SIZE=196  # bytes 0..195

dd if="$METADATA_FILE" bs=1 count=$SIGN_SIZE of="$HEADER_BIN" 2>/dev/null

# produce DER PKCS7 (CMS) SignedData with embedded data, self-signed cert
openssl smime -sign \
    -binary \
    -in "$HEADER_BIN" \
    -signer "$CERT_FILE" \
    -inkey "$PRIV_KEY" \
    -outform DER \
    -nosmimecap \
    -nodetach \
    > "$SIG_FILE"

PKCS7_SIZE=$(stat -c%s "$SIG_FILE")
echo "  ✅ PKCS7 size: $PKCS7_SIZE bytes"
if [ "$PKCS7_SIZE" -gt 2048 ]; then
    echo "❌ PKCS7 blob ($PKCS7_SIZE bytes) does not fit reserved 2048 bytes"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi

echo "[7/7] Embedding PKCS7 blob into final 4KB footer..."
python3 - <<EOF
import struct

with open("${METADATA_FILE}", 'rb') as f:
    metadata = bytearray(f.read())

with open("${SIG_FILE}", 'rb') as f:
    pkcs7_blob = f.read()

pkcs7_size = len(pkcs7_blob)

# Write pkcs7_size (u32 LE) at byte offset 196
struct.pack_into('<I', metadata, 196, pkcs7_size)

# Write pkcs7_blob starting at byte offset 200
metadata[200:200+pkcs7_size] = pkcs7_blob

with open("${METADATA_FILE}", 'wb') as f:
    f.write(metadata)

print("  ✅ PKCS7 blob embedded at offset 200, size", pkcs7_size)
EOF

echo "[FINAL] Writing 4KB footer to END OF WHOLE DISK (/dev/vda model)..."

DISK_SIZE=$(sudo blockdev --getsize64 "$LOOP_DEV")
DISK_META_OFFSET=$((DISK_SIZE - 4096))

echo "  Disk size: $DISK_SIZE bytes"
echo "  Footer offset (disk tail): $DISK_META_OFFSET bytes"

sudo dd if="${METADATA_FILE}" of="$LOOP_DEV" \
    bs=4096 seek=$((DISK_META_OFFSET / 4096)) conv=notrunc 2>/dev/null
sync

echo "  ✅ Metadata written to last 4KB of disk image ($LOOP_DEV)"
echo "     NOTE: this overwrote the backup GPT on purpose."

sudo losetup -d "$LOOP_DEV"
sudo chown -R "$USER:$USER" "$META_DIR"

echo
echo "========================================"
echo "  ✅ dm-verity generation complete (with salt + PKCS7 signature)"
echo "========================================"
echo
echo "Artifacts in $META_DIR:"
echo "  • verity_info.txt        (dm-verity format output)"
echo "  • root.hash              (Merkle root)"
echo "  • header.bin             (signed region = footer[0..195])"
echo "  • footer.pkcs7           (PKCS7 SignedData blob)"
echo "  • verity_metadata.bin    (final 4KB footer we wrote to disk)"
echo
echo "Boot flow expectation:"
echo "  - Kernel opens /dev/vda directly (virtio-blk)"
echo "  - Reads last 4KB"
echo "  - Parses root hash / salt / etc"
echo "  - Verifies PKCS7 signature using built-in trusted cert"
echo "  - (Future) instantiates /dev/mapper/verified_root via dm-verity"
echo "========================================"
