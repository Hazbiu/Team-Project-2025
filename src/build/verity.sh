#!/bin/bash
set -e

echo "============================================"
echo " dm-verity Hash Image Generation Script "
echo "============================================"

# --- Environment sanity check ---
if [ -z "$BOOT_DIR" ] || [ -z "$ROOTFS_IMG" ]; then
  echo "Error: BOOT_DIR or ROOTFS_IMG not set."
  echo "This script must be called from build.sh after rootfs.img is created."
  exit 1
fi

# --- Ensure dependencies are installed ---
if ! command -v veritysetup &>/dev/null; then
echo "[1/10] Installing dm-verity and JSON dependencies..."
# This ensures you have the veritysetup tool and uuidgen
sudo apt update
sudo apt install -y cryptsetup-bin uuid-runtime jq
fi

# --- Define output paths ---
VERITY_IMG="${BOOT_DIR}/rootfs_verity.img"
VERITY_INFO="${BOOT_DIR}/verity_info.txt"

echo "[9.5/10] Creating dm-verity hash image..."
echo "Input rootfs:  $ROOTFS_IMG"
echo "Output image:  $VERITY_IMG"

# --- Create the dm-verity Hash Image ---
echo "[9/10] Creating dm-verity hash image (rootfs_verity.img)..."

# This command uses rootfs.img as the data source (it is NOT modified) and writes the hash tree to rootfs_verity.img.
sudo veritysetup format "$ROOTFS_IMG" "${BOOT_DIR}/rootfs_verity.img" \
  --data-block-size=4096 \
  --hash-block-size=4096 \
  --hash=sha256 \
  --uuid="$(uuidgen)" | tee "${BOOT_DIR}/verity_info.txt"

# --- Optionally sign the verity image ---
if [ -f "${BOOT_DIR}/bl_private.pem" ]; then
  echo "Signing rootfs_verity.img..."
  openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
    -out "${BOOT_DIR}/rootfs_verity.img.sig" \
    "$VERITY_IMG"
else
  echo "Warning: bl_private.pem not found — skipping signature."
fi


# Store the path to the original location on the Windows filesystem
DEST_PATH="/mnt/d/Team-Project-2025/src/boot"

# Copy all three generated artifacts back to the Windows path
echo "Copying rootfs.img, rootfs_verity.img, and verity_info.txt to $DEST_PATH"
cp "$ROOTFS_IMG" "$DEST_PATH/"
cp "${BOOT_DIR}/rootfs_verity.img" "$DEST_PATH/"
cp "${BOOT_DIR}/verity_info.txt" "$DEST_PATH/"

echo
echo "✅ dm-verity artifacts successfully generated and copied:"
ls -lh "$VERITY_IMG" "$VERITY_INFO" "${BOOT_DIR}/rootfs_verity.img.sig" 2>/dev/null || true
