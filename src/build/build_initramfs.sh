#!/bin/bash
set -e

# Base paths (adjust automatically relative to this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOOT_DIR="$SCRIPT_DIR/../src/boot"
INITRAMFS_DIR="$BOOT_DIR/initramfs"
OUT_CPIO="$BOOT_DIR/initramfs.cpio"
OUT_GZ="${OUT_CPIO}.gz"
KERNEL_IMG="$BOOT_DIR/kernel_image.bin"
ROOTFS_IMG="$BOOT_DIR/rootfs.img"

echo "[*] Cleaning old initramfs..."
rm -f "$OUT_CPIO" "$OUT_GZ"

echo "[*] Packing initramfs from: $INITRAMFS_DIR"
(
  cd "$INITRAMFS_DIR"
  find . -print0 | cpio --null -ov --format=newc > "$OUT_CPIO"
)
gzip -f "$OUT_CPIO"

echo "[*] New archive created:"
ls -lh "$OUT_GZ"

echo "[*] Verifying archive integrity..."
gunzip -c "$OUT_GZ" | cpio -it > /dev/null
echo "    ✓ OK"

echo "[*] Running QEMU test boot..."
qemu-system-x86_64 \
  -m 1024 \
  -kernel "$KERNEL_IMG" \
  -initrd "$OUT_GZ" \
  -drive file="$ROOTFS_IMG",format=raw,if=virtio \
  -append "root=/dev/vda3 rw console=ttyS0" \
  -nographic | tee "$BOOT_DIR/boot_test.log"

# --- Commented-out /mnt/d sync (for safety) ---
# DEST_PATH="/mnt/d/Team-Project-2025/src/boot"
# mkdir -p "$DEST_PATH"
# cp -f "$OUT_GZ" "$BOOT_DIR/boot_test.log" "$DEST_PATH/" 2>/dev/null || true
# echo "Copied new initramfs and log to Windows path: $DEST_PATH"
