#!/bin/bash
set -euo pipefail

KERNEL='../bootloaders/kernel_image.bin'
ROOTFS='Binaries/rootfs.img'

echo "====================================="
echo " Launching QEMU with dm-verity setup "
echo "====================================="

exec qemu-system-x86_64 \
    -kernel "$KERNEL" \
    -drive if=none,file="$ROOTFS",format=raw,id=hd0 \
    -device virtio-blk-pci,drive=hd0 \
    -append "console=ttyS0 loglevel=7 root=/dev/dm-0 rootfstype=ext4 rootwait dm_verity_autoboot.autoboot_device=/dev/vda" \
    -m 1024M -nographic
