#!/bin/bash
set -e

# Expect ROOT_DIR, BOOT_DIR, and KEYS_DIR to already be set by the caller (build.sh)

# --- Prerequirements (Build initramfs using gen_init_cpio) ---
echo "[8.2] Building initramfs using gen_init_cpio..."

INITRAMFS_DIR="${BOOT_DIR}/initramfs"
INITRAMFS_LIST="${BOOT_DIR}/initramfs_list.txt"
INITRAMFS_IMG="${BOOT_DIR}/initramfs.cpio.gz"

# Clean and recreate
sudo rm -rf "$INITRAMFS_DIR"
echo "INITRAMFS_DIR Succesfully deleted"                          #Later to be removed
mkdir -p "$INITRAMFS_DIR"/{bin,sbin,etc,proc,sys,dev,newroot}

# Copy BusyBox
if ! command -v busybox &>/dev/null; then
  echo "Error: busybox not installed. Run: sudo apt install busybox"
  exit 1
fi
cp "$(command -v busybox)" "$INITRAMFS_DIR/bin/"
# Add symlinks for common BusyBox utilities so we can inspect the kernel cmdline
for cmd in cat grep dmesg ls; do
    ln -sf /bin/busybox "$INITRAMFS_DIR/bin/$cmd"
done


# Add dmsetup and veritysetup if available
if command -v dmsetup &>/dev/null; then
  cp "$(command -v dmsetup)" "$INITRAMFS_DIR/sbin/"
fi
if command -v veritysetup &>/dev/null; then
  cp "$(command -v veritysetup)" "$INITRAMFS_DIR/sbin/"
fi


# Create minimal /init script
cat > "$INITRAMFS_DIR/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
echo "Booting from initramfs..."

# Initialize simple device manager (mdev)
echo /sbin/mdev > /proc/sys/kernel/hotplug
mdev -s

# Parse root device from kernel cmdline
ROOTDEV=$(grep -o 'root=[^ ]*' /proc/cmdline | cut -d= -f2)

if [ -z "$ROOTDEV" ]; then
    echo "Error: No root= argument found in /proc/cmdline!"
    echo "cmdline was: $(cat /proc/cmdline)"
    exec /bin/sh
fi

echo "Waiting for root device: $ROOTDEV ..."
for i in $(seq 1 10); do
    if [ -b "$ROOTDEV" ]; then
        echo "Found root device: $ROOTDEV"
        break
    fi
    sleep 1
    mdev -s
done

if [ ! -b "$ROOTDEV" ]; then
    echo "Error: Root device $ROOTDEV not found!"
    ls -l /dev
    exec /bin/sh
fi

echo "Mounting root filesystem from $ROOTDEV ..."
if ! mount -t ext4 "$ROOTDEV" /newroot; then
    echo "Mount failed for $ROOTDEV — trying read/write and debug:"
    mount -t ext4 -o rw "$ROOTDEV" /newroot || {
        echo "Still failed. Listing block devices:"
        lsblk || ls /dev
        exec /bin/sh
    }
fi

echo "Switching to real root filesystem..."
exec switch_root /newroot /sbin/init || {
    echo "switch_root failed!"
    exec /bin/sh
}
EOF
chmod +x "$INITRAMFS_DIR/init"


# Create initramfs_list.txt
cat > "$INITRAMFS_LIST" <<EOF
dir /dev 755 0 0
dir /proc 755 0 0
dir /sys 755 0 0
dir /bin 755 0 0
dir /sbin 755 0 0
dir /etc 755 0 0
dir /newroot 755 0 0
file /init ${INITRAMFS_DIR}/init 755 0 0
file /bin/busybox ${INITRAMFS_DIR}/bin/busybox 755 0 0
slink /bin/sh /bin/busybox 777 0 0
slink /sbin/mount /bin/busybox 777 0 0
slink /sbin/switch_root /bin/busybox 777 0 0
slink /sbin/mdev /bin/busybox 777 0 0
EOF

# Generate CPIO archive (newc format, gzip compressed)
cd "$BOOT_DIR"
if ! command -v gen_init_cpio &>/dev/null; then
  echo "Error: gen_init_cpio not found."
  echo "You can build it from Linux kernel source via:"
  echo "  make -C ~/linux-6.6 usr/gen_init_cpio"
  exit 1
fi

gen_init_cpio "$INITRAMFS_LIST" | gzip -9 > "$INITRAMFS_IMG"
echo "Initramfs image created: $INITRAMFS_IMG"

# --- Sign initramfs ---
openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
  -out "${INITRAMFS_IMG}.sig" \
  "$INITRAMFS_IMG"

echo "Initramfs signed successfully."

# --- Commented out Windows /mnt/d sync (future safety) ---
# DEST_PATH="/mnt/d/Team-Project-2025/src/boot"
# mkdir -p "$DEST_PATH"
# cp -f "$INITRAMFS_IMG" "$INITRAMFS_IMG.sig" "$DEST_PATH/" 2>/dev/null || true
# echo "Initramfs copied to Windows mount: $DEST_PATH"
