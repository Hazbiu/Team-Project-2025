#!/bin/bash
set -e

# =================================================================
#  AUTO-DETECT CURRENT USER
# =================================================================
# Get the username of the user executing this script (you)
# This assumes you are running the script with 'sudo'
CURRENT_LINUX_USER=$(whoami)
# If running with sudo, whoami is 'root'. We want the *original* user.
if [ "$CURRENT_LINUX_USER" == "root" ]; then
    # Use $SUDO_USER if available (standard practice when using sudo)
    TARGET_USER=${SUDO_USER:-$(logname)}
else
    TARGET_USER=$CURRENT_LINUX_USER
fi

# Fallback in case detection fails, though it shouldn't
if [ -z "$TARGET_USER" ]; then
    echo "Warning: Could not detect user. Falling back to default 'devuser'."
    TARGET_USER="devuser"
fi

echo "Detected target username for RootFS: $TARGET_USER"

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

# Pass the TARGET_USER variable into the chroot environment
# using a HERE-STRING and environment variable export
sudo chroot "$ROOTFS_DIR" bash -c "
    set -e
    export DEBIAN_FRONTEND=noninteractive
    
    # Target username is passed via the environment
    TARGET_USER="'"$TARGET_USER"'"

    apt-get update -y
    apt-get install -y passwd login sudo

    # Unlock and set root password
    passwd -d root || true
    echo "root:root" | chpasswd
    passwd -u root || true

    # Create user with detected name and sudo access
    id -u $TARGET_USER &>/dev/null || useradd -m -s /bin/bash $TARGET_USER
    # Set the password for the new user to be the same as their username
    echo "$TARGET_USER:$TARGET_USER" | chpasswd
    usermod -aG sudo $TARGET_USER

    # Enable serial console login
    systemctl enable serial-getty@ttyS0.service || true

    apt-get clean
"

# --- Clean up mounts ---
sudo umount "$ROOTFS_DIR/dev"   || true
sudo umount "$ROOTFS_DIR/proc" || true
sudo umount "$ROOTFS_DIR/sys"   || true

echo "User setup complete (root/root and $TARGET_USER/$TARGET_USER)"