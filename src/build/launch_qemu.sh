#!/bin/bash
set -euo pipefail

# Paths
KERNEL="../bootloaders/kernel_image.bin"
ROOTFS="Binaries/rootfs.img"

# Kernel parameters (what we send to QEMU)
APPEND_CMD="console=ttyS0 loglevel=7 root=/dev/dm-0 rootfstype=ext4 rootwait \
dm_verity_autoboot.autoboot_device=/dev/vda \
dm_verity_autoboot.mode=verify_and_map"

echo "====================================="
echo " Launching QEMU with dm-verity setup "
echo "====================================="

# Show preview of what will be executed
echo
echo "Command preview:"
echo "qemu-system-x86_64 \\"
echo "  -kernel $KERNEL \\"
echo "  -drive if=none,file=$ROOTFS,format=raw,id=hd0 \\"
echo "  -device virtio-blk-pci,drive=hd0 \\"
echo "  -append \"$APPEND_CMD\" \\"
echo "  -m 1024M -nographic"
echo

# Actually run QEMU
exec qemu-system-x86_64 \
  -kernel "$KERNEL" \
  -drive if=none,file="$ROOTFS",format=raw,id=hd0 \
  -device virtio-blk-pci,drive=hd0 \
  -append "$APPEND_CMD" \
  -m 1024M -nographic
