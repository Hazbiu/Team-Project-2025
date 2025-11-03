#!/bin/bash
set -euo pipefail

echo "========================================"
echo "  Building Rootfs on GPT Disk Image"
echo "========================================"

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOTFS_DIR="$BUILD_DIR/Binaries/rootfs"
OUTPUT_IMG="$BUILD_DIR/Binaries/rootfs.img"
TEMP_FS="$BUILD_DIR/Binaries/temp_rootfs.img"

echo "[1/4] Creating base Debian rootfs..."
mkdir -p "$ROOTFS_DIR"

# Install Debian base once
if [ ! -d "$ROOTFS_DIR/etc" ]; then
    echo "  Installing Debian base system..."
    sudo debootstrap \
        --arch=amd64 \
        --include=systemd,systemd-sysv,udev,passwd,login,sudo,net-tools,iproute2,ifupdown,openssh-server,vim,less \
        bookworm "$ROOTFS_DIR" http://deb.debian.org/debian/
    echo "   Base Debian installed."
else
    echo "   Debian base already exists, skipping debootstrap"
fi

echo "[2/4] Configuring rootfs..."
sudo chroot "$ROOTFS_DIR" bash -c "
set -e
export DEBIAN_FRONTEND=noninteractive

# Set passwords
echo 'root:root' | chpasswd
if ! id -u keti &>/dev/null; then
  useradd -m -s /bin/bash keti
fi
echo 'keti:keti' | chpasswd
usermod -aG sudo keti

# Set hostname
echo 'secureboot-demo' > /etc/hostname

# Configure network
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

# Cleanup
apt-get clean
rm -rf /var/lib/apt/lists/*
"
echo "  Basic configuration done"

# Clean special directories
sudo rm -rf "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"
mkdir -p "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"

echo "[3/4] Creating temporary ext4 filesystem..."
# Calculate filesystem size (data only, no hash tree yet)
ROOTFS_SIZE_MB=$(sudo du -s --block-size=1M "$ROOTFS_DIR" 2>/dev/null | awk '{print int($1*1.2)+100}')
echo "  Filesystem (data only): ${ROOTFS_SIZE_MB}MB"

# Create temporary filesystem image
truncate -s "${ROOTFS_SIZE_MB}M" "$TEMP_FS"
mkfs.ext4 -F -L rootfs "$TEMP_FS" >/dev/null 2>&1

# Mount and copy rootfs
sudo mkdir -p /mnt/temp-rootfs
sudo mount "$TEMP_FS" /mnt/temp-rootfs
echo "  Copying files to filesystem..."
sudo rsync -aHAX --info=progress2 "$ROOTFS_DIR"/ /mnt/temp-rootfs/
sync
sudo umount /mnt/temp-rootfs
sudo rmdir /mnt/temp-rootfs
echo "  Temporary filesystem created"

echo "[4/4] Creating GPT-partitioned disk image..."

# Calculate total disk size:
# - Filesystem size (data only)
# - Space for dm-verity hash tree (~10% of data + some overhead)
# - Metadata footer (round up to 1MB)
# - GPT headers (1MB at start + 1MB at end)
VERITY_SPACE_MB=$((ROOTFS_SIZE_MB / 10 + 5))
PARTITION_SIZE_MB=$((ROOTFS_SIZE_MB + VERITY_SPACE_MB + 5))
DISK_SIZE_MB=$((PARTITION_SIZE_MB + 10))

echo "  Disk layout planning:"
echo "    - Filesystem data: ${ROOTFS_SIZE_MB}MB"
echo "    - Verity hash tree: ${VERITY_SPACE_MB}MB"
echo "    - Metadata: 5MB"
echo "    - Partition total: ${PARTITION_SIZE_MB}MB"
echo "    - Disk total (with GPT): ${DISK_SIZE_MB}MB"

# Create empty disk image
truncate -s "${DISK_SIZE_MB}M" "$OUTPUT_IMG"

# Create GPT partition table
echo "  Creating GPT partition table..."
parted -s "$OUTPUT_IMG" mklabel gpt

# Create rootfs partition
# Start at 1MiB (for GPT header)
# Size it to hold: filesystem + hash tree + metadata
parted -s "$OUTPUT_IMG" mkpart primary ext4 1MiB ${PARTITION_SIZE_MB}MiB

# Name the partition "rootfs" (critical for bootloader detection!)
parted -s "$OUTPUT_IMG" name 1 rootfs

# Set partition as bootable (optional)
parted -s "$OUTPUT_IMG" set 1 boot on

echo "  GPT partition table created"

# Show partition layout
echo
echo "  Partition layout:"
parted -s "$OUTPUT_IMG" print
echo

echo "  Writing filesystem to partition..."
# Setup loop device with partition support
LOOP_DEV=$(sudo losetup -fP --show "$OUTPUT_IMG")
echo "  Loop device: $LOOP_DEV"

# Wait for partition device node
sleep 1
if [ ! -e "${LOOP_DEV}p1" ]; then
    echo "  ERROR: Partition ${LOOP_DEV}p1 not found!"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi

# Copy filesystem to partition (only the filesystem, not filling partition)
# The partition is larger to leave room for hash tree
sudo dd if="$TEMP_FS" of="${LOOP_DEV}p1" bs=4M status=progress conv=fsync
sync

echo "  Filesystem written to partition 1"

# Verify: Check filesystem size vs partition size
FS_SIZE=$(stat -c%s "$TEMP_FS")
PART_SIZE=$(sudo blockdev --getsize64 "${LOOP_DEV}p1")
FREE_SPACE=$((PART_SIZE - FS_SIZE))

echo
echo "  Space allocation:"
echo "    Filesystem size: $((FS_SIZE / 1024 / 1024)) MB"
echo "    Partition size:  $((PART_SIZE / 1024 / 1024)) MB"
echo "    Free space:      $((FREE_SPACE / 1024 / 1024)) MB (for hash tree + metadata)"
echo

# Get partition info for reference
PART_INFO=$(sudo fdisk -l "$OUTPUT_IMG" | grep "^${OUTPUT_IMG}1")
echo
echo "  Partition 1 info:"
echo "    $PART_INFO"
echo

# Cleanup
sudo losetup -d "$LOOP_DEV"
rm -f "$TEMP_FS"

# Final ownership
sudo chown "$USER:$USER" "$OUTPUT_IMG"

echo
echo "========================================"
echo "  Rootfs disk image created!"
echo "========================================"
echo "Output: $OUTPUT_IMG"
echo
echo "Structure:"
echo "  - GPT partition table"
echo "  - Partition 1: 'rootfs' (ext4)"
echo "  - Ready for dm-verity hash tree"
echo
echo "Next step: Run verity metadata generation script"
echo "========================================"