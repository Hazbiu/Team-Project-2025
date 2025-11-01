#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[1] Backing up .config..."
cp .config .config.$(date +%Y%m%d-%H%M%S).bak

echo "[2] Enabling CONFIG_VIRTIO_BLK=y..."
if grep -q '^CONFIG_VIRTIO_BLK=' .config; then
  sed -i 's/^CONFIG_VIRTIO_BLK=.*/CONFIG_VIRTIO_BLK=y/' .config
else
  echo 'CONFIG_VIRTIO_BLK=y' >> .config
fi

echo "[3] Ensuring device-mapper block layer is built-in..."
sed -i 's/^CONFIG_BLK_DEV_DM=m/CONFIG_BLK_DEV_DM=y/' .config || true
if ! grep -q '^CONFIG_BLK_DEV_DM=' .config; then
  echo 'CONFIG_BLK_DEV_DM=y' >> .config
fi

echo "[4] Applying config..."
make olddefconfig

echo "[5] Building kernel..."
make -j"$(nproc)"

echo "[6] Installing kernel_image.bin for bootloader..."
cp -v arch/x86/boot/bzImage kernel_image.bin

echo "✅ Done. Run ./secondary_bootloader to boot."
