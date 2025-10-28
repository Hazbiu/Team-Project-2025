#!/bin/bash
set -euo pipefail

: "${ROOTFS_DIR:?ROOTFS_DIR must be set by build.sh}"

echo "[8/10] Building minimal root filesystem..."

# 1) Create Debian Bookworm base (include essentials so PID1 + udev work)
if [ ! -d "$ROOTFS_DIR/etc" ]; then
  sudo debootstrap \
    --arch=amd64 \
    --include=systemd,systemd-sysv,udev,passwd,login,sudo,net-tools,iproute2,ifupdown,openssh-server,vim,less \
    bookworm "$ROOTFS_DIR" http://deb.debian.org/debian/
  echo "RootFS created at $ROOTFS_DIR"
fi

echo "[8.1] Configuring users and base system inside rootfs..."

# 2) Always set up mounts for chroot
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

# 3) Configure inside chroot
sudo chroot "$ROOTFS_DIR" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive

  # Ensure package lists exist (if we created rootfs in a previous run)
  apt-get update -y || true

  # Users
  passwd -d root || true
  echo "root:root" | chpasswd
  passwd -u root || true

  if ! id -u keti &>/dev/null; then
    useradd -m -s /bin/bash keti
  fi
  echo "keti:keti" | chpasswd
  usermod -aG sudo keti

  # Enable serial console for QEMU
  systemctl enable serial-getty@ttyS0.service || true

  # Minimal networking and identity
  echo "secureboot-demo" > /etc/hostname
  printf "127.0.0.1\tlocalhost\n" > /etc/hosts

  cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

  # Make root mount robust by LABEL. Your build.sh formats with -L rootfs.
  cat > /etc/fstab <<EOF
LABEL=rootfs   /   ext4   defaults   0 1
EOF

  # Cleanup
  apt-get clean
  rm -rf /var/lib/apt/lists/*
'

echo "✅ User setup complete (root/root and keti/keti); rootfs configured."
