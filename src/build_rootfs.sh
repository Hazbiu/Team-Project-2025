#!/bin/bash
set -e

BASE="debian-12-genericcloud-amd64.tar.xz"
IMG="rootfs.img"
MOUNT="/mnt/root_build"

# ---- Check prerequisites ----
command -v sgdisk >/dev/null || { echo "Install gdisk: sudo apt install gdisk"; exit 1; }
command -v losetup >/dev/null || { echo "Install util-linux: sudo apt install util-linux"; exit 1; }

# ---- Ensure base tarball exists ----
if [ ! -f "$BASE" ]; then
    echo "[*] Base image missing, downloading..."
    wget https://cloud.debian.org/images/cloud/bookworm/latest/$BASE
fi

# ---- Create raw disk ----
echo "[*] Creating 4GB disk image..."
dd if=/dev/zero of="$IMG" bs=1M count=4096

echo "[*] Creating GPT partition layout..."
sgdisk "$IMG" -o \
  -n 1:1M:3.9G -t 1:8300 -c 1:"rootfs" \
  -n 14:3.9G:3.91G -t 14:EF02 \
  -n 15:3.91G:4G   -t 15:EF00

# ---- Attach loop device ----
echo "[*] Mapping loop partitions..."
LOOP=$(sudo losetup --find --show --partscan "$IMG")
echo "→ Using loop device: $LOOP"

echo "[*] Creating ext4 filesystem..."
sudo mkfs.ext4 "${LOOP}p1"

echo "[*] Mounting filesystem..."
sudo mkdir -p "$MOUNT"
sudo mount "${LOOP}p1" "$MOUNT"

# ---- Extract Debian rootfs ----
echo "[*] Extracting base Debian system..."
sudo tar -xpf "$BASE" -C "$MOUNT"

# ---- SystemD Init Fix ----
echo "[*] Ensuring system boots with systemd..."
sudo ln -sf /lib/systemd/systemd "$MOUNT/sbin/init"

# ---- Set login password ----
echo "[*] Setting root password to 'root'..."
echo "root:root" | sudo chroot "$MOUNT" chpasswd

# ---- Cleanup ----
echo "[*] Unmounting and detaching loop..."
sudo umount "$MOUNT"
sudo losetup -d "$LOOP"

echo
echo "✅ Done! rootfs.img is ready."
echo
echo "Run with:"
echo "------------------------------------------------------------"
echo "qemu-system-x86_64 \\"
echo "  -m 2G \\"
echo "  -kernel linux/kernel_image.bin \\"
echo "  -initrd src/Binaries/initramfs.cpio.gz \\"
echo "  -drive file=rootfs.img,format=raw \\"
echo "  -append \"root=/dev/sda1 rw console=ttyS0 systemd.unified_cgroup_hierarchy=1\" \\"
echo "  -nographic"
echo "------------------------------------------------------------"

