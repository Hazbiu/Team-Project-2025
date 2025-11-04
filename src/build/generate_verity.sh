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
METADATA_HEADER="$META_DIR/verity_header.bin"      # 196-byte signed header
SIG_FILE="$META_DIR/verity_header.sig"             # Detached PKCS7 signature
LOCATOR_FILE="$META_DIR/verity_locator.bin"        # 4KB locator footer

PRIV_KEY="$BUILD_DIR/../boot/bl_private.pem"
CERT_FILE="$BUILD_DIR/../boot/bl_cert.pem"

mkdir -p "$META_DIR"

# --- sanity checks ---
if [[ ! -f "$ROOTFS_IMG" ]]; then
    echo "ERROR: rootfs.img not found at: $ROOTFS_IMG"
    exit 1
fi

if [[ ! -f "$PRIV_KEY" ]]; then
    echo "ERROR: bl_private.pem not found at: $PRIV_KEY"
    exit 1
fi

if [[ ! -f "$CERT_FILE" ]]; then
    echo "ERROR: bl_cert.pem not found at: $CERT_FILE"
    exit 1
fi

echo "[1/8] Setting up loop device for disk image..."
LOOP_DEV=$(sudo losetup -fP --show "$ROOTFS_IMG")
echo "  Loop device: $LOOP_DEV"

sleep 1
PART_DEV="${LOOP_DEV}p1"
if [ ! -e "$PART_DEV" ]; then
    echo "  ERROR: Partition $PART_DEV not found!"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi
echo "  Partition device: $PART_DEV (rootfs)"

echo "[2/8] Analyzing filesystem on rootfs partition..."
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

echo "[3/8] Generating dm-verity hash tree (Merkle) ..."
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

echo "[4/8] Extracting root hash + salt from veritysetup output..."
ROOT_HASH=$(grep -i "^Root hash:" "$META_DIR/verity_info.txt" | awk '{print $3}')
SALT_HEX=$(grep -i "^Salt:" "$META_DIR/verity_info.txt" | awk '{print $2}')

if [ -z "$ROOT_HASH" ]; then
    echo "  ERROR: Failed to extract root hash"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi
if [ -z "$SALT_HEX" ]; then
    echo "  ERROR: Failed to extract salt"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi

echo "$ROOT_HASH" > "$ROOT_HASH_FILE"

echo "     Root hash: $ROOT_HASH"
echo "     Salt (hex): $SALT_HEX"
echo "     Salt length (hex chars): ${#SALT_HEX}"

echo "[5/8] Building metadata header (196 bytes, to be signed)..."
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

# Build only the 196-byte header (signed region)
# Structure matches verity_metadata_ondisk[0..195]:
#   magic (4) + version (4) + data_blocks (8) + hash_start_sector (8)
#   + data_block_size (4) + hash_block_size (4) + hash_algorithm[32]
#   + root_hash[64] + salt[64] + salt_size (4)
#   = 196 bytes

header = bytearray(196)
offset = 0

# magic (u32 LE)
struct.pack_into('<I', header, offset, MAGIC); offset += 4
# version (u32 LE)
struct.pack_into('<I', header, offset, VERSION); offset += 4
# data_blocks (u64 LE)
struct.pack_into('<Q', header, offset, DATA_BLOCKS); offset += 8
# hash_start_sector (u64 LE)
struct.pack_into('<Q', header, offset, HASH_START_SECTOR); offset += 8
# data_block_size (u32 LE)
struct.pack_into('<I', header, offset, DATA_BLOCK_SIZE); offset += 4
# hash_block_size (u32 LE)
struct.pack_into('<I', header, offset, HASH_BLOCK_SIZE); offset += 4

# hash_algorithm[32]
header[offset:offset+len(HASH_ALGORITHM)] = HASH_ALGORITHM
offset += 32

# root_hash[64]
header[offset:offset+len(ROOT_HASH)] = ROOT_HASH
offset += 64

# salt[64]
header[offset:offset+len(SALT)] = SALT
offset += 64

# salt_size (u32 LE)
struct.pack_into('<I', header, offset, SALT_SIZE)
offset += 4

assert offset == 196, f"Header size mismatch: {offset} != 196"

with open("${METADATA_HEADER}", 'wb') as f:
    f.write(header)

print(f"  Metadata header created: 196 bytes")
print(f"  MAGIC=0x{MAGIC:08X} VERSION={VERSION}")
print(f"  data_blocks={DATA_BLOCKS}")
print(f"  hash_start_sector={HASH_START_SECTOR}")
print(f"  SALT_SIZE={SALT_SIZE} bytes")
EOF

echo "[6/8] Creating DETACHED PKCS7 signature..."

# Create detached signature (no embedded data)
openssl smime -sign \
    -binary \
    -noattr \
    -in "$METADATA_HEADER" \
    -signer "$CERT_FILE" \
    -inkey "$PRIV_KEY" \
    -outform DER \
    -nosmimecap \
    > "$SIG_FILE"

SIG_SIZE=$(stat -c%s "$SIG_FILE")
echo "  Signature size: $SIG_SIZE bytes"

if [ "$SIG_SIZE" -gt 2048 ]; then
    echo "WARNING: Signature ($SIG_SIZE bytes) exceeds typical 2048 byte limit"
fi

echo "[7/8] Determining storage locations in disk image..."

DISK_SIZE=$(sudo blockdev --getsize64 "$LOOP_DEV")

# Layout strategy:
# - Locator footer: last 4KB of disk
# - Signature: before locator (aligned to 4KB)
# - Metadata header: before signature (aligned to 4KB)

LOCATOR_SIZE=4096
LOCATOR_OFFSET=$((DISK_SIZE - LOCATOR_SIZE))

# Align signature to 4KB boundary before locator
SIG_ALIGNED_SIZE=$(( (SIG_SIZE + 4095) / 4096 * 4096 ))
SIG_OFFSET=$((LOCATOR_OFFSET - SIG_ALIGNED_SIZE))

# Metadata header before signature (196 bytes, but align to 4KB)
META_ALIGNED_SIZE=4096
META_OFFSET=$((SIG_OFFSET - META_ALIGNED_SIZE))

echo "  Disk size: $DISK_SIZE bytes"
echo "  Metadata offset: $META_OFFSET (length: 196 bytes, aligned: $META_ALIGNED_SIZE)"
echo "  Signature offset: $SIG_OFFSET (length: $SIG_SIZE bytes, aligned: $SIG_ALIGNED_SIZE)"
echo "  Locator offset: $LOCATOR_OFFSET (length: $LOCATOR_SIZE bytes)"

echo "[8/8] Creating locator footer and writing to disk..."

python3 - <<EOF
import struct

VLOC_MAGIC = 0x564C4F43  # "VLOC"
VERSION = 1
META_OFF = ${META_OFFSET}
META_LEN = 196  # Only the signed header
SIG_OFF = ${SIG_OFFSET}
SIG_LEN = ${SIG_SIZE}

locator = bytearray(4096)

# Build locator structure
offset = 0
struct.pack_into('<I', locator, offset, VLOC_MAGIC); offset += 4
struct.pack_into('<I', locator, offset, VERSION); offset += 4
struct.pack_into('<Q', locator, offset, META_OFF); offset += 8
struct.pack_into('<I', locator, offset, META_LEN); offset += 4
struct.pack_into('<Q', locator, offset, SIG_OFF); offset += 8
struct.pack_into('<I', locator, offset, SIG_LEN); offset += 4
# Rest is reserved/zero

with open("${LOCATOR_FILE}", 'wb') as f:
    f.write(locator)

print(f"  Locator created: VLOC magic=0x{VLOC_MAGIC:08X}")
print(f"    meta_off={META_OFF} meta_len={META_LEN}")
print(f"    sig_off={SIG_OFF} sig_len={SIG_LEN}")
EOF

# Write metadata header
echo "  Writing metadata header to offset $META_OFFSET..."
sudo dd if="$METADATA_HEADER" of="$LOOP_DEV" \
    bs=4096 seek=$((META_OFFSET / 4096)) conv=notrunc 2>/dev/null

# Write signature
echo "  Writing signature to offset $SIG_OFFSET..."
sudo dd if="$SIG_FILE" of="$LOOP_DEV" \
    bs=4096 seek=$((SIG_OFFSET / 4096)) conv=notrunc 2>/dev/null

# Write locator footer
echo "  Writing locator footer to offset $LOCATOR_OFFSET..."
sudo dd if="$LOCATOR_FILE" of="$LOOP_DEV" \
    bs=4096 seek=$((LOCATOR_OFFSET / 4096)) conv=notrunc 2>/dev/null

sync

echo "  All data written to disk image ($LOOP_DEV)"
echo "     NOTE: this overwrote the backup GPT on purpose."

sudo losetup -d "$LOOP_DEV"
sudo chown -R "$USER:$USER" "$META_DIR"

echo
echo "========================================"
echo "  dm-verity generation complete (DETACHED signature mode)"
echo "========================================"
echo
echo "Artifacts in $META_DIR:"
echo "  • verity_info.txt        (dm-verity format output)"
echo "  • root.hash              (Merkle root)"
echo "  • verity_header.bin      (196-byte metadata header - SIGNED)"
echo "  • verity_header.sig      (PKCS7 detached signature)"
echo "  • verity_locator.bin     (4KB locator footer - NOT signed)"
echo
echo "On-disk layout (end of disk):"
echo "  [...data...][hash tree][metadata@$META_OFFSET][sig@$SIG_OFFSET][locator@$LOCATOR_OFFSET]"
echo
echo "Boot flow expectation:"
echo "  - Kernel opens /dev/vda"
echo "  - Reads locator footer (last 4KB)"
echo "  - Uses offsets to read metadata and signature separately"
echo "  - Verifies signature against metadata using pkcs7_supply_detached_data()"
echo "  - Instantiates /dev/mapper/verified_root via dm-verity"
echo "========================================"