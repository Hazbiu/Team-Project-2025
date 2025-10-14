#!/bin/bash
set -e

# --- Build minimal root filesystem (once) ---
echo "[8/10] Building minimal root filesystem..."
if [ ! -d "$ROOTFS_DIR" ]; then
  sudo debootstrap --arch=amd64 bookworm "$ROOTFS_DIR" http://deb.debian.org/debian/
  echo "RootFS created at $ROOTFS_DIR"
fi

# --- ALWAYS configure users (even if rootfs already existed) ---
echo "[8.1] Configuring users inside rootfs..."
sudo mount --bind /dev  "$ROOTFS_DIR/dev"
sudo mount --bind /proc "$ROOTFS_DIR/proc"
sudo mount --bind /sys  "$ROOTFS_DIR/sys"

sudo chroot "$ROOTFS_DIR" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y passwd login sudo

  # Unlock and set root password
  passwd -d root || true
  echo "root:root" | chpasswd
  passwd -u root || true

  # Create user "keti" with sudo
  id -u keti &>/dev/null || useradd -m -s /bin/bash keti
  echo "keti:keti" | chpasswd
  usermod -aG sudo keti

  # Enable serial console login
  systemctl enable serial-getty@ttyS0.service || true

  apt-get clean
'

sudo umount "$ROOTFS_DIR/dev"  || true
sudo umount "$ROOTFS_DIR/proc" || true
sudo umount "$ROOTFS_DIR/sys"  || true

echo "User setup complete (root/root and keti/keti)"


