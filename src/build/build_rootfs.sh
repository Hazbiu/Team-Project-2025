#!/bin/bash
set -euo pipefail

echo "========================================"
echo "  Building Rootfs on GPT Disk Image"
echo "========================================"

# Paths
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)" # Working script location
ROOTFS_DIR="$BUILD_DIR/Binaries/rootfs" # Location of rootfs (Root file system)
OUTPUT_IMG="$BUILD_DIR/Binaries/rootfs.img" # Final image
TEMP_FS="$BUILD_DIR/Binaries/temp_rootfs.img" # Temporary file

echo "[1/4] Creating base Debian rootfs..."
mkdir -p "$ROOTFS_DIR"

# Only install Debian if it's not built already
if [ ! -d "$ROOTFS_DIR/etc" ]; then
    echo "  Installing Debian base system..."
    
    # Installs a minimal Debian 
    sudo debootstrap S\
        --arch=amd64 \
        --include=systemd,systemd-sysv,udev,passwd,login,sudo,net-tools,iproute2,ifupdown,openssh-server,vim,less \ #some essential packages
        bookworm "$ROOTFS_DIR" http://deb.debian.org/debian/

    echo "   Base Debian installed."
else
    echo "   Debian base already exists, skipping debootstrap"
fi

echo "[2/4] Configuring rootfs..."

# Enters the newly created Debian
sudo chroot "$ROOTFS_DIR" bash -c "  
set -e
export DEBIAN_FRONTEND=noninteractive

# Set up user
echo 'root:root' | chpasswd
if ! id -u keti &>/dev/null; then
  useradd -m -s /bin/bash keti
fi
echo 'keti:keti' | chpasswd
usermod -aG sudo keti

# Sets hostname
echo 'secureboot-demo' > /etc/hostname

# Sets up netwrok configuration
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

# Removes and then recreates system folders so no host data is copied
sudo rm -rf "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"
mkdir -p "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev"

echo "[3/4] Creating temporary ext4 filesystem..."

# Calculate the root filesystem size so the filesystem image ia large enough to hold the entire root filesystem plus some extra space
ROOTFS_SIZE_MB=$(sudo du -s --block-size=1M "$ROOTFS_DIR" 2>/dev/null | awk '{print int($1*1.2)+100}')
echo "  Filesystem (data only): ${ROOTFS_SIZE_MB}MB"

# Create a blank, formatted ext4 filesystem so it can be mounted later
truncate -s "${ROOTFS_SIZE_MB}M" "$TEMP_FS"
mkfs.ext4 -F -L rootfs "$TEMP_FS" >/dev/null 2>&1

# Mount and copy rootfs
sudo mkdir -p /mnt/temp-rootfs #Temporary mount directory
sudo mount "$TEMP_FS" /mnt/temp-rootfs # Mounts the ext4 filesystem
echo "  Copying files to filesystem..." 
sudo rsync -aHAX --info=progress2 "$ROOTFS_DIR"/ /mnt/temp-rootfs/ # Copies files from ROOTFS_DIR into the mounted image
sync
sudo umount /mnt/temp-rootfs # Unmounts the file system
sudo rmdir /mnt/temp-rootfs # Removes the temporary mount directory
echo "  Temporary filesystem created"

echo "[4/4] Creating GPT-partitioned disk image..."

# Calculates total disk size
VERITY_SPACE_MB=$((ROOTFS_SIZE_MB / 10 + 5)) # Interity hash space
PARTITION_SIZE_MB=$((ROOTFS_SIZE_MB + VERITY_SPACE_MB + 5)) # rootfs and metadata
DISK_SIZE_MB=$((PARTITION_SIZE_MB + 10)) # Entire virtual disk

echo "  Disk layout planning:"
echo "    - Filesystem data: ${ROOTFS_SIZE_MB}MB"
echo "    - Verity hash tree: ${VERITY_SPACE_MB}MB"
echo "    - Metadata: 5MB"
echo "    - Partition total: ${PARTITION_SIZE_MB}MB"
echo "    - Disk total (with GPT): ${DISK_SIZE_MB}MB"

# Create empty disk image with calculated required size
truncate -s "${DISK_SIZE_MB}M" "$OUTPUT_IMG"

# Create GPT partition table to create partitions
echo "  Creating GPT partition table..."
parted -s "$OUTPUT_IMG" mklabel gpt

# Names the partition "rootfs" and marks it as bootable (Gurarantees all systems can recognise it as a startup partition)
parted -s "$OUTPUT_IMG" mkpart primary ext4 1MiB ${PARTITION_SIZE_MB}MiB
parted -s "$OUTPUT_IMG" name 1 rootfs
parted -s "$OUTPUT_IMG" set 1 boot on

echo "  GPT partition table created"

# Shows partition layout
echo
echo "  Partition layout:"
parted -s "$OUTPUT_IMG" print
echo

echo "  Writing filesystem to partition..."
# Setup a loop device for Linux to access and write to the partitions
LOOP_DEV=$(sudo losetup -fP --show "$OUTPUT_IMG")
echo "  Loop device: $LOOP_DEV"

# Veryfing partition before writting
sleep 1
if [ ! -e "${LOOP_DEV}p1" ]; then
    echo "  ERROR: Partition ${LOOP_DEV}p1 not found!"
    sudo losetup -d "$LOOP_DEV"
    exit 1
fi

# Writes the temporary filesystem to the partition
sudo dd if="$TEMP_FS" of="${LOOP_DEV}p1" bs=4M status=progress conv=fsync
sync

echo "  Filesystem written to partition 1"

# Calculates free space between filesystem and partition to check for extra space
FS_SIZE=$(stat -c%s "$TEMP_FS")
PART_SIZE=$(sudo blockdev --getsize64 "${LOOP_DEV}p1")
FREE_SPACE=$((PART_SIZE - FS_SIZE))

echo
echo "  Space allocation:"
echo "    Filesystem size: $((FS_SIZE / 1024 / 1024)) MB"
echo "    Partition size:  $((PART_SIZE / 1024 / 1024)) MB"
echo "    Free space:      $((FREE_SPACE / 1024 / 1024)) MB (for hash tree + metadata)"
echo

# Display partition details for verification
PART_INFO=$(sudo fdisk -l "$OUTPUT_IMG" | grep "^${OUTPUT_IMG}1")
echo
echo "  Partition 1 info:"
echo "    $PART_INFO"
echo

# Detach loop device, remove the temp file and fix image ownership (prevents resource locks)
sudo losetup -d "$LOOP_DEV"
rm -f "$TEMP_FS"
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