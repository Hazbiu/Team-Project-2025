#!/bin/bash
set -e

BASE="debian-12-genericcloud-amd64.tar.xz"
WORK="/mnt/root_work"
IMG="rootfs.img"

echo "[*] Checking base Debian cloud image..."
if [ ! -f "$BASE" ]; then
    echo "❌ $BASE not found in this directory!"
    exit 1
fi

echo "[*] Preparing temporary workspace..."
sudo rm -rf "$WORK"
sudo mkdir -p "$WORK"

echo "[*] Extracting disk.raw from cloud image..."
sudo tar --xattrs --numeric-owner -xf "$BASE" -C "$WORK"

if [ ! -f "$WORK/disk.raw" ]; then
    echo "❌ ERROR: disk.raw not found inside cloud image!"
    exit 1
fi

echo "[*] Using disk.raw directly as root filesystem..."
rm -f "$IMG"
sudo mv "$WORK/disk.raw" "$IMG"
sudo chown $USER:$USER "$IMG"

echo "[*] Mounting rootfs to apply modifications..."
LOOP=$(sudo losetup --find --show --partscan "$IMG")
sudo mount ${LOOP}p1 "$WORK"

echo "[*] Setting root password to 'root'..."
echo "root:root" | sudo chroot "$WORK" chpasswd

echo "[*] Ensuring /sbin/init → systemd..."
sudo ln -sf /usr/lib/systemd/systemd "$WORK/sbin/init" || \
sudo ln -sf /lib/systemd/systemd "$WORK/sbin/init"

echo "[*] Disabling /boot/efi mount (avoids emergency mode)..."
sudo sed -i 's|^[^#].*boot/efi|# &|' "$WORK/etc/fstab"

echo "[*] Cleanup..."
sudo umount "$WORK"
sudo losetup -d "$LOOP"
sudo rm -rf "$WORK"

echo "✅ DONE: rootfs.img is ready."
echo
echo "Run QEMU with:"
echo "qemu-system-x86_64 \\"
echo "  -m 2G -smp 2 \\"
echo "  -kernel bootloaders/kernel_image.bin \\"
echo "  -initrd Binaries/initramfs.cpio.gz \\"
echo "  -drive file=rootfs.img,format=raw \\"
echo "  -append \"root=/dev/sda1 rw console=ttyS0\" \\"
echo "  -nographic"
