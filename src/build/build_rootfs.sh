#!/bin/bash
set -euo pipefail

echo "========================================"
echo "  Building Rootfs on Single-Disk Image (NO GPT)"
echo "========================================"

# Paths
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"      # Working script location
ROOTFS_DIR="$BUILD_DIR/Binaries/rootfs"         # Location of rootfs (root filesystem tree)
OUTPUT_IMG="$BUILD_DIR/Binaries/rootfs.img"     # Final disk image
TEMP_MOUNT="/mnt/temp-rootfs"                   # Temporary mount point

echo "[1/4] Creating base Debian rootfs..."
mkdir -p "$ROOTFS_DIR"

# Only install Debian if it's not built already
if [ ! -d "$ROOTFS_DIR/etc" ]; then
    echo "  Installing Debian base system..."

    sudo debootstrap \
        --arch=amd64 \
        --include=systemd,systemd-sysv,udev,passwd,login,sudo,net-tools,iproute2,ifupdown,openssh-server,vim,less \
        bookworm "$ROOTFS_DIR" http://deb.debian.org/debian/

    echo "  Base Debian installed."
else
    echo "  Debian base already exists, skipping debootstrap."
fi

echo "[2/4] Configuring rootfs..."

sudo chroot "$ROOTFS_DIR" bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive

# Root password
echo "root:root" | chpasswd

# User "keti"
if ! id -u keti &>/dev/null; then
  useradd -m -s /bin/bash keti
fi
echo "keti:keti" | chpasswd
usermod -aG sudo keti

# Hostname
echo "secureboot-demo" > /etc/hostname

# Network configuration
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

# Cleanup APT caches
apt-get clean
rm -rf /var/lib/apt/lists/*
'

echo "  Basic configuration done."

# Remove bind-mount-sensitive dirs and recreate empty
sudo rm -rf "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"
mkdir -p "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"

echo "[3/4] Sizing disk image and creating single ext4 filesystem..."

# Estimate space for actual files
ROOTFS_SIZE_MB=$(sudo du -s --block-size=1M "$ROOTFS_DIR" 2>/dev/null | awk '{print int($1*1.2)+100}')
echo "  Estimated filesystem data size: ${ROOTFS_SIZE_MB} MB"

# Add extra space for:
#  - slack
#  - future growth
#  - dm-verity hash tree + metadata (the verity script will shrink the FS again if needed)
VERITY_SPACE_MB=$((ROOTFS_SIZE_MB / 5 + 20))    # ~20% + 20 MB
DISK_SIZE_MB=$((ROOTFS_SIZE_MB + VERITY_SPACE_MB))

echo "  Planned disk size:"
echo "    - Data estimate : ${ROOTFS_SIZE_MB} MB"
echo "    - Extra (verity): ${VERITY_SPACE_MB} MB"
echo "    - Total disk    : ${DISK_SIZE_MB} MB"

# Create blank disk image
truncate -s "${DISK_SIZE_MB}M" "$OUTPUT_IMG"

# Create a single ext4 filesystem directly on the disk image (NO partitions)
echo "  Creating ext4 filesystem on whole disk image..."
mkfs.ext4 -F -L rootfs "$OUTPUT_IMG" >/dev/null 2>&1

echo "[4/4] Copying rootfs into disk image..."

sudo mkdir -p "$TEMP_MOUNT"
sudo mount "$OUTPUT_IMG" "$TEMP_MOUNT"

echo "  Copying files to filesystem..."
sudo rsync -aHAX --info=progress2 "$ROOTFS_DIR"/ "$TEMP_MOUNT"/
sync
sudo umount "$TEMP_MOUNT"
sudo rmdir "$TEMP_MOUNT"

sudo chown "$USER:$USER" "$OUTPUT_IMG"

echo
echo "========================================"
echo "  Rootfs disk image created!"
echo "========================================"
echo "Output: $OUTPUT_IMG"
echo
echo "Structure:"
echo "  - Single block device (no GPT, no partitions)"
echo "  - ext4 filesystem spanning (most of) the whole image"
echo "  - Extra free space at the end reserved for:"
echo "      dm-verity hash tree + metadata header + detached signature + VLOC footer"
echo
echo "Next step: Run the dm-verity metadata generation script"
echo "  (the one that works on the WHOLE disk and writes VLOC at the end)."
echo "========================================"
