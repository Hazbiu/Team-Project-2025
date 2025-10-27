#!/bin/bash
set -euo pipefail

echo "============================================"
echo " dm-verity Hash Image Generation Script"
echo "============================================"

if [ -z "${BOOT_DIR:-}" ] || [ -z "${ROOTFS_IMG:-}" ]; then
  echo "Error: BOOT_DIR or ROOTFS_IMG not set."
  exit 1
fi

if ! command -v veritysetup &>/dev/null; then
  echo "[1/10] Installing dm-verity dependencies..."
  sudo apt update
  sudo apt install -y cryptsetup-bin uuid-runtime jq
fi

VERITY_INFO="${BOOT_DIR}/verity_info.txt"
META_FILE="${BOOT_DIR}/rootfs.verity.meta"

echo "[9.5/10] Creating dm-verity hash tree INSIDE rootfs.img..."
echo "Input rootfs:  $ROOTFS_IMG"
echo

# Create temporary hash tree file
TMP_HASH=$(mktemp --tmpdir rootfs_verity.XXXXXX)

sudo veritysetup format "$ROOTFS_IMG" "$TMP_HASH" \
  --data-block-size=4096 \
  --hash-block-size=4096 \
  --hash=sha256 \
  --uuid="$(uuidgen)" | tee "$VERITY_INFO"

DATA_SIZE_BYTES=$(stat -c%s "$ROOTFS_IMG")
HASH_SIZE_BYTES=$(stat -c%s "$TMP_HASH")
HASH_OFFSET_BLOCKS=$((DATA_SIZE_BYTES / 4096))

# Append the hash tree to the end of the rootfs
truncate -s $((DATA_SIZE_BYTES + HASH_SIZE_BYTES)) "$ROOTFS_IMG"
dd if="$TMP_HASH" of="$ROOTFS_IMG" bs=1 seek="$DATA_SIZE_BYTES" conv=notrunc status=none

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

# --- Commented out problematic Windows mount path (/mnt/d) ---
# DEST_PATH="/mnt/d/Team-Project-2025/src/boot"
# mkdir -p "$DEST_PATH"
# cp -f "$ROOTFS_IMG" "$VERITY_INFO" "$META_FILE" "$DEST_PATH/" 2>/dev/null || true
# [ -f "${META_FILE}.sig" ] && cp -f "${META_FILE}.sig" "$DEST_PATH/"

echo
echo "dm-verity hash tree appended successfully."
echo "Root hash: ${ROOTHASH:-<missing>}"
echo "Offset (blocks): ${HASH_OFFSET_BLOCKS}"
echo "Artifacts stored in local boot directory: $BOOT_DIR"
