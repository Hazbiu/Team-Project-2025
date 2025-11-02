#!/bin/bash
set -euo pipefail

echo "[ROOTFS] Building minimal root filesystem (simple mode)..."

# Base locations
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOTFS_DIR="$BUILD_DIR/Binaries/rootfs"
OUTPUT_IMG="$BUILD_DIR/Binaries/rootfs.img"

echo "[ROOTFS] Rootfs directory: $ROOTFS_DIR"
mkdir -p "$ROOTFS_DIR"

# 1) Install Debian base once
if [ ! -d "$ROOTFS_DIR/etc" ]; then
  sudo debootstrap \
    --arch=amd64 \
    --include=systemd,systemd-sysv,udev,passwd,login,sudo,net-tools,iproute2,ifupdown,openssh-server,vim,less \
    bookworm "$ROOTFS_DIR" http://deb.debian.org/debian/
  echo "✅ Base Debian installed."
fi

echo "[ROOTFS] Applying configuration..."

# Bind mount required pseudo-filesystems
sudo mount -t proc none "$ROOTFS_DIR/proc"
sudo mount -t sysfs none "$ROOTFS_DIR/sys"
sudo mount --bind /dev "$ROOTFS_DIR/dev"

sudo chroot "$ROOTFS_DIR" bash -c "
set -e
export DEBIAN_FRONTEND=noninteractive

echo 'root:root' | chpasswd

if ! id -u keti &>/dev/null; then
  useradd -m -s /bin/bash keti
fi

echo 'keti:keti' | chpasswd
usermod -aG sudo keti

echo 'secureboot-demo' > /etc/hostname

cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

apt-get clean
rm -rf /var/lib/apt/lists/*
"

# Unmount the pseudo-filesystems cleanly
sudo umount "$ROOTFS_DIR/proc" || true
sudo umount "$ROOTFS_DIR/sys" || true
sudo umount "$ROOTFS_DIR/dev" || true

echo "✅ Configuration done."

echo "[ROOTFS] Creating ext4 disk image..."

SIZE_MB=$(sudo du -s --block-size=1M "$ROOTFS_DIR" | awk '{print int($1*1.4)+132}')
echo "Allocating ${SIZE_MB}MB..."

truncate -s "${SIZE_MB}M" "$OUTPUT_IMG"
mkfs.ext4 -L rootfs "$OUTPUT_IMG" >/dev/null

sudo mkdir -p /mnt/rootfs-img
sudo mount "$OUTPUT_IMG" /mnt/rootfs-img

# Copy rootfs, excluding pseudo-filesystems
sudo rsync -aHAX \
  --exclude={"/proc/*","/sys/*","/dev/*","/run/*"} \
  "$ROOTFS_DIR"/ /mnt/rootfs-img/

sync
sudo umount /mnt/rootfs-img
sudo rmdir /mnt/rootfs-img

echo "✅ rootfs.img created successfully."
echo "📦 Image location: $OUTPUT_IMG"
echo "🎉 DONE!"
