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
  echo "[1/10] Installing dm-verity dependencies..."
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

# Important: remove stray Unicode spaces that sometimes sneak in
sudo veritysetup format "$ROOTFS_IMG" "$VERITY_IMG" \
  --data-block-size=4096 \
  --hash-block-size=4096 \
  --hash=sha256 \
  --uuid="$(uuidgen)" | tee "$VERITY_INFO"

# Fix permissions so OpenSSL can read the file
sudo chown "$USER:$USER" "$VERITY_IMG"
sudo chmod a+r "$VERITY_IMG"

# --- Optionally sign the verity image ---
if [ -f "${BOOT_DIR}/bl_private.pem" ]; then
  echo "Signing rootfs_verity.img..."
  openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
    -out "${VERITY_IMG}.sig" \
    "$VERITY_IMG"
else
  echo "Warning: bl_private.pem not found — skipping signature."
fi

# --- Copy results back to Windows side for convenience ---
# --- Copy results back to Windows side for convenience ---
DEST_PATH="/mnt/d/Team-Project-2025/src/boot"
mkdir -p "$DEST_PATH"

echo "Copying rootfs artifacts to $DEST_PATH (safe overwrite handling)..."

copy_safe() {
    local src="$1"
    local dest_dir="$2"
    local base="$(basename "$src")"
    local dest="$dest_dir/$base"

    # Fix ownership if needed so we can read/copy
    sudo chown "$USER:$USER" "$src" 2>/dev/null || true
    sudo chmod 644 "$src" 2>/dev/null || true

    # If destination file exists and is read-only or root-owned, delete it
    if [ -f "$dest" ]; then
        if ! rm -f "$dest" 2>/dev/null; then
            echo "⚠️  Cannot overwrite $dest — creating timestamped backup instead."
            local backup="${dest_dir}/backup_$(date +%Y%m%d_%H%M%S)"
            mkdir -p "$backup"
            cp "$src" "$backup/" && echo "✔ Copied $base → $backup/"
            return
        fi
    fi

    # Copy file normally
    cp -f "$src" "$dest_dir/" && echo "✔ Copied $base"
}

# Copy all generated artifacts safely
copy_safe "$ROOTFS_IMG" "$DEST_PATH"
copy_safe "$VERITY_IMG" "$DEST_PATH"
copy_safe "$VERITY_INFO" "$DEST_PATH"
[ -f "${VERITY_IMG}.sig" ] && copy_safe "${VERITY_IMG}.sig" "$DEST_PATH"

echo
echo "✅ dm-verity artifacts successfully copied to Windows (with ownership fixes if needed)."
ls -lh "$DEST_PATH" | grep -E "rootfs|verity" || true
