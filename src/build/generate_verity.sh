#!/bin/bash
set -euo pipefail

echo "========================================"
echo "  Generating dm-verity metadata (DEV MODE: footer at end of disk)"
echo "========================================"

# We assume this script lives in src/build/
# rootfs.img is at ./Binaries/rootfs.img
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$BUILD_DIR/Binaries"
META_DIR="$BIN_DIR/metadata"
ROOTFS_IMG="$BIN_DIR/rootfs.img"
ROOT_HASH_FILE="$META_DIR/root.hash"
SIG_FILE="$META_DIR/root.hash.sig"
METADATA_FILE="$META_DIR/verity_metadata.bin"
PRIV_KEY="$BUILD_DIR/../boot/bl_private.pem"

mkdir -p "$META_DIR"

# Verify inputs
if [[ ! -f "$ROOTFS_IMG" ]]; then
    echo "❌ rootfs.img not found at: $ROOTFS_IMG"
    exit 1
fi

if [[ ! -f "$PRIV_KEY" ]]; then
    echo "❌ bl_private.pem not found at: $PRIV_KEY"
    exit 1
fi

echo "[1/5] Setting up loop device for disk image..."
LOOP_DEV=$(sudo losetup -fP --show "$ROOTFS_IMG")
echo "  Loop device: $LOOP_DEV"

# We still assume partition 1 is our rootfs (ext4)
sleep 1
PART_DEV="${LOOP_DEV}p1"
if [ ! -e "$PART_DEV" ]; then
    echo "  ❌ ERROR: Partition $PART_DEV not found!"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi
echo "  Partition device: $PART_DEV (rootfs)"

echo "[2/5] Analyzing filesystem on rootfs partition..."
BLOCK_SIZE=$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block size:/ {print $3}')
BLOCK_COUNT=$(sudo dumpe2fs -h "$PART_DEV" 2>/dev/null | awk '/Block count:/ {print $3}')

PART_SIZE=$(sudo blockdev --getsize64 "$PART_DEV")
PART_SIZE_BLOCKS=$((PART_SIZE / BLOCK_SIZE))

echo "  Filesystem block size: $BLOCK_SIZE bytes"
echo "  Filesystem block count: $BLOCK_COUNT blocks"
echo "  Partition size:        $PART_SIZE bytes ($PART_SIZE_BLOCKS blocks)"

# Hash tree placement after file data
DATA_SIZE=$((BLOCK_COUNT * BLOCK_SIZE))
HASH_OFFSET=$DATA_SIZE
HASH_OFFSET_SECTORS=$((HASH_OFFSET / 512))

AVAILABLE_SPACE=$((PART_SIZE - DATA_SIZE))
ESTIMATED_HASH_SIZE=$((DATA_SIZE / 10))  # rough guess, not exact

echo "  Filesystem data size:  $DATA_SIZE bytes"
echo "  Hash tree offset:      $HASH_OFFSET bytes (sector $HASH_OFFSET_SECTORS)"
echo "  Available space after data in partition: $AVAILABLE_SPACE bytes"
echo "  Estimated hash tree size: ~$ESTIMATED_HASH_SIZE bytes"

if [ $AVAILABLE_SPACE -lt $ESTIMATED_HASH_SIZE ]; then
    echo "  ⚠️  WARNING: Partition might be too small for hash tree"
fi

echo "[3/5] Generating dm-verity hash tree..."
# We create two loop views:
#  - DATA_LOOP = just the real filesystem payload (no hash tree area)
#  - HASH_LOOP = the "tail" region where veritysetup will write the Merkle tree
DATA_LOOP=$(sudo losetup -f --show --sizelimit=$DATA_SIZE "$PART_DEV")
echo "  Data device: $DATA_LOOP (size-limited to $DATA_SIZE bytes)"

HASH_LOOP=$(sudo losetup -f --show --offset=$DATA_SIZE "$PART_DEV")
echo "  Hash device: $HASH_LOOP (starts after data payload)"

sudo veritysetup format \
    --data-block-size=$BLOCK_SIZE \
    --hash-block-size=$BLOCK_SIZE \
    "$DATA_LOOP" "$HASH_LOOP" \
    | tee "$META_DIR/verity_info.txt"

sudo losetup -d "$DATA_LOOP"
sudo losetup -d "$HASH_LOOP"

# Extract root hash from veritysetup output
ROOT_HASH=$(grep "Root hash:" "$META_DIR/verity_info.txt" | awk '{print $3}')
if [ -z "$ROOT_HASH" ]; then
    echo "  ❌ ERROR: Failed to extract root hash from veritysetup"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi

echo "$ROOT_HASH" > "$ROOT_HASH_FILE"
echo "  ✅ Root hash: $ROOT_HASH"
echo "  Saved to: $ROOT_HASH_FILE"

echo "[4/5] Building unsigned metadata blob (4KB footer struct)..."
python3 - <<EOF
import struct

MAGIC = 0x56455249  # "VERI" (matches kernel's VERITY_META_MAGIC)
VERSION = 1
DATA_BLOCKS = ${BLOCK_COUNT}
HASH_START_SECTOR = ${HASH_OFFSET_SECTORS}
DATA_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_BLOCK_SIZE = ${BLOCK_SIZE}
HASH_ALGORITHM = b"sha256"
ROOT_HASH = bytes.fromhex("${ROOT_HASH}")
SALT = b""
SALT_SIZE = 0

# 4096-byte footer struct expected by the kernel
metadata = bytearray(4096)

offset = 0
struct.pack_into('<I', metadata, offset, MAGIC); offset += 4
struct.pack_into('<I', metadata, offset, VERSION); offset += 4
struct.pack_into('<Q', metadata, offset, DATA_BLOCKS); offset += 8
struct.pack_into('<Q', metadata, offset, HASH_START_SECTOR); offset += 8
struct.pack_into('<I', metadata, offset, DATA_BLOCK_SIZE); offset += 4
struct.pack_into('<I', metadata, offset, HASH_BLOCK_SIZE); offset += 4

metadata[offset:offset+len(HASH_ALGORITHM)] = HASH_ALGORITHM
offset += 32  # hash_algorithm[32]

metadata[offset:offset+len(ROOT_HASH)] = ROOT_HASH
offset += 64  # root_hash[64]

metadata[offset:offset+len(SALT)] = SALT
offset += 64  # salt[64]

struct.pack_into('<I', metadata, offset, SALT_SIZE)
offset += 4   # salt_size (u32)

# signature_size (u32) will be filled after signing
# signature[256] will be filled after signing
# remaining bytes stay 0

with open("${METADATA_FILE}", 'wb') as f:
    f.write(metadata)

print("  ✅ Metadata structure created (4096 bytes) at ${METADATA_FILE}")
EOF

echo "[5/5] Signing metadata and embedding signature..."
SIGN_SIZE=$((4 + 4 + 8 + 8 + 4 + 4 + 32 + 64 + 64 + 4))  # bytes before signature_size
dd if="$METADATA_FILE" bs=1 count=$SIGN_SIZE 2>/dev/null | \
    openssl dgst -sha256 -sign "$PRIV_KEY" -out "$SIG_FILE"

SIG_SIZE=$(stat -c%s "$SIG_FILE")
echo "  Signature size: $SIG_SIZE bytes"

python3 - <<EOF
import struct

with open("${METADATA_FILE}", 'rb') as f:
    metadata = bytearray(f.read())

with open("${SIG_FILE}", 'rb') as f:
    signature = f.read()

# offset 196 = signature_size (u32)
struct.pack_into('<I', metadata, 196, len(signature))
# offset 200 = signature[256]
metadata[200:200+len(signature)] = signature

with open("${METADATA_FILE}", 'wb') as f:
    f.write(metadata)

print("  ✅ Signature embedded into metadata blob")
EOF

echo "[6/6] Writing final 4KB footer to END OF WHOLE DISK (DEV MODE /dev/vda)..."

DISK_SIZE=$(sudo blockdev --getsize64 "$LOOP_DEV")
DISK_META_OFFSET=$((DISK_SIZE - 4096))

echo "  Disk size: $DISK_SIZE bytes"
echo "  Footer offset (disk tail): $DISK_META_OFFSET bytes"

sudo dd if="$METADATA_FILE" of="$LOOP_DEV" \
    bs=4096 seek=$((DISK_META_OFFSET / 4096)) conv=notrunc 2>/dev/null
sync

echo "  ✅ Metadata written to last 4KB of disk image ($LOOP_DEV)"
echo "     NOTE: this overwrites backup GPT, so guest sees /dev/vda but may not expose /dev/vda1"

# Cleanup
sudo losetup -d "$LOOP_DEV"
sudo chown -R "$USER:$USER" "$META_DIR"

echo
echo "========================================"
echo "  ✅ dm-verity generation complete (DEV MODE)"
echo "========================================"
echo
echo "📦 Artifacts:"
echo "   • $ROOTFS_IMG  (virtio-blk -> /dev/vda in guest)"
echo "     ├─ GPT primary header still valid"
echo "     ├─ Partition 1 'rootfs' (ext4 + Merkle tree)"
echo "     └─ dm-verity footer embedded at END OF DISK (overwrites backup GPT)"
echo
echo "   • $ROOT_HASH_FILE"
echo "     Root hash: $ROOT_HASH"
echo
echo "   • $METADATA_FILE"
echo "     4096-byte signed footer structure"
echo
echo "   • $SIG_FILE"
echo "     RSA signature blob"
echo
echo "🎯 Bootloader will:"
echo "   - Launch QEMU with this disk as virtio-blk"
echo "   - Pass dm_verity_autoboot.autoboot_device=/dev/vda"
echo
echo "🎯 Kernel will:"
echo "   - Open /dev/vda directly (no initramfs)"
echo "   - Read last 4KB of the block device"
echo "   - Parse verity metadata + root hash"
echo "   - (Future step) create /dev/mapper/verified_root automatically"
echo
echo "========================================"
