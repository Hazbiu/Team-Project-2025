#!/bin/bash
set -euo pipefail

echo "============================================"
echo " dm-verity Hash Image Generation Script"
echo "============================================"

if [ -z "${BOOT_DIR:-}" ] || { [ -z "${ROOTFS_IMG:-}" ] && [ -z "${DISK_IMG:-}" ]; }; then
  echo "Error: BOOT_DIR and DISK_IMG/ROOTFS_IMG not set."
  exit 1
fi

# Prefer DISK_IMG if present
if [ -n "${DISK_IMG:-}" ]; then
  IMG_PATH="$DISK_IMG"
else
  IMG_PATH="$ROOTFS_IMG"
fi

# Ensure dm-verity tools
if ! command -v veritysetup &>/dev/null; then
  echo "[1/10] Installing dm-verity dependencies..."
  sudo apt update
  sudo apt install -y cryptsetup-bin uuid-runtime jq
fi

VERITY_INFO="${BOOT_DIR}/verity_info.txt"
META_FILE="${BOOT_DIR}/rootfs.verity.meta"

echo "[9.5/10] Creating dm-verity hash tree inside image..."
echo "Input image: $IMG_PATH"
echo

# --- Map and locate rootfs partition (p2) ---
LOOP=$(sudo losetup -f --show -P "$IMG_PATH")
ROOT_PART="${LOOP}p2"

if [ ! -b "$ROOT_PART" ]; then
  echo "Error: Rootfs partition (p2) not found inside $IMG_PATH"
  sudo losetup -d "$LOOP"
  exit 1
fi

# Create temporary hash tree file
TMP_HASH=$(mktemp --tmpdir rootfs_verity.XXXXXX)

sudo veritysetup format "$ROOT_PART" "$TMP_HASH" \
  --data-block-size=4096 \
  --hash-block-size=4096 \
  --hash=sha256 \
  --uuid="$(uuidgen)" | tee "$VERITY_INFO"

DATA_SIZE_BYTES=$(sudo blockdev --getsize64 "$ROOT_PART")

HASH_SIZE_BYTES=$(stat -c%s "$TMP_HASH")
HASH_OFFSET_BLOCKS=$((DATA_SIZE_BYTES / 4096))

# Append hash tree to the end of the WHOLE disk image, not inside p2
echo "[+] Appending verity hash tree to disk image..."
DATA_SIZE_BYTES=$(sudo blockdev --getsize64 "$ROOT_PART")
DISK_SIZE_BYTES=$(stat -c%s "$IMG_PATH")
NEW_SIZE=$((DISK_SIZE_BYTES + HASH_SIZE_BYTES))

# Extend disk image
sudo truncate -s "$NEW_SIZE" "$IMG_PATH"

# Append hash tree at the end of disk.img
sudo dd if="$TMP_HASH" of="$IMG_PATH" bs=1M seek=$((DISK_SIZE_BYTES / 1048576)) conv=notrunc status=none


ROOTHASH=$(grep -oP 'Root hash:\s+\K[0-9a-f]+' "$VERITY_INFO" || true)
SALT=$(grep -oP 'Salt:\s+\K[0-9a-f]+' "$VERITY_INFO" || true)

echo
echo "Metadata extracted:"
echo "  Root hash : $ROOTHASH"
echo "  Salt      : $SALT"
echo "  Offset    : $HASH_OFFSET_BLOCKS"
echo

cat > "$META_FILE" <<EOF
roothash=$ROOTHASH
salt=$SALT
offset=$HASH_OFFSET_BLOCKS
EOF

if [ -f "${BOOT_DIR}/bl_private.pem" ]; then
  openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
    -out "${META_FILE}.sig" \
    "$META_FILE"
  echo "Metadata signed successfully."
else
  echo "Warning: bl_private.pem not found — skipping metadata signature."
fi

rm -f "$TMP_HASH"
sudo losetup -d "$LOOP"

echo
echo "✅ dm-verity hash tree appended successfully."
echo "Root hash: ${ROOTHASH:-<missing>}"
echo "Offset (blocks): ${HASH_OFFSET_BLOCKS}"
echo "Artifacts stored in local boot directory: $BOOT_DIR"
