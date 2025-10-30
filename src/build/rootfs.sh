#!/bin/bash
set -euo pipefail

echo "[8/10] Building minimal root filesystem..."

# Base paths
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOTFS_DIR="$BUILD_DIR/Binaries/rootfs"     # <-- your rootfs lives here
OUTPUT_IMG="$ROOTFS_DIR/rootfs.img"        # final image

echo "RootFS directory: $ROOTFS_DIR"
mkdir -p "$ROOTFS_DIR"

# 1) Create Debian base system only once
if [ ! -d "$ROOTFS_DIR/etc" ]; then
  sudo debootstrap \
    --arch=amd64 \
    --include=systemd,systemd-sysv,udev,passwd,login,sudo,net-tools,iproute2,ifupdown,openssh-server,vim,less \
    bookworm "$ROOTFS_DIR" http://deb.debian.org/debian/
  echo "✅ Base Debian created inside Binaries/rootfs"
fi

echo "[8.1] Configuring system inside chroot..."

cleanup() {
  sudo umount "$ROOTFS_DIR/dev/pts" 2>/dev/null || true
  sudo umount "$ROOTFS_DIR/dev"     2>/dev/null || true
  sudo umount "$ROOTFS_DIR/proc"    2>/dev/null || true
  sudo umount "$ROOTFS_DIR/sys"     2>/dev/null || true
}
trap cleanup EXIT

sudo mount --bind /dev      "$ROOTFS_DIR/dev"
sudo mount --bind /dev/pts  "$ROOTFS_DIR/dev/pts"
sudo mount --bind /proc     "$ROOTFS_DIR/proc"
sudo mount --bind /sys      "$ROOTFS_DIR/sys"

sudo chroot "$ROOTFS_DIR" bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update -y || true

passwd -d root || true
echo "root:root" | chpasswd
passwd -u root || true

if ! id -u keti &>/dev/null; then
  useradd -m -s /bin/bash keti
fi
echo "keti:keti" | chpasswd
usermod -aG sudo keti

systemctl enable serial-getty@ttyS0.service || true

echo "secureboot-demo" > /etc/hostname
printf "127.0.0.1\tlocalhost\n" > /etc/hosts

cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

cat > /etc/fstab <<EOF
LABEL=rootfs   /   ext4   defaults   0 1
EOF

apt-get clean
rm -rf /var/lib/apt/lists/*
'

echo "✅ Chroot setup complete."

echo "[8.2] Creating ext4 rootfs.img..."

# Remove runtime virtual mounts before copying
sudo rm -rf "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"
mkdir -p "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"

# Determine size
SIZE_MB=$(du -s --block-size=1M "$ROOTFS_DIR" | awk '{print int($1*1.4)+100}')
echo "Allocating ${SIZE_MB}MB image..."

truncate -s "${SIZE_MB}M" "$OUTPUT_IMG"
mkfs.ext4 -L rootfs "$OUTPUT_IMG"

mkdir -p /tmp/rootfs-mnt
sudo mount "$OUTPUT_IMG" /tmp/rootfs-mnt

sudo rsync -aHAX "$ROOTFS_DIR"/ /tmp/rootfs-mnt/

sudo umount /tmp/rootfs-mnt
rmdir /tmp/rootfs-mnt

echo "✅ rootfs.img created at: $OUTPUT_IMG"
echo "🎉 DONE"
