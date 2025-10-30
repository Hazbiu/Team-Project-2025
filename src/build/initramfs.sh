#!/bin/bash
set -euo pipefail

# ================================================================
#  Secure Boot Project — Initramfs Build Script
# ================================================================
# Requires: busybox, gen_init_cpio, (optional) dmsetup, veritysetup
# Environment: ROOT_DIR, BOOT_DIR, KEYS_DIR (exported by build.sh)
# Output: ${BOOT_DIR}/initramfs.cpio.gz and ${BOOT_DIR}/initramfs.cpio.gz.sig
# ================================================================

echo "[8.2] Building initramfs using gen_init_cpio..."

INITRAMFS_DIR="${BOOT_DIR}/initramfs"
INITRAMFS_LIST="${BOOT_DIR}/initramfs_list.txt"
INITRAMFS_IMG="${BOOT_DIR}/initramfs.cpio.gz"
META_FILE="${BOOT_DIR}/rootfs.verity.meta"   # for dm-verity info

# Clean & recreate
sudo rm -rf "$INITRAMFS_DIR"
mkdir -p "$INITRAMFS_DIR"/{bin,sbin,etc,proc,sys,dev,newroot,tmp,run}

# ------------------------------------------------
# Copy BusyBox
# ------------------------------------------------
if ! command -v busybox &>/dev/null; then
  echo "Error: busybox not installed. Run: sudo apt install busybox"
  exit 1
fi
cp "$(command -v busybox)" "$INITRAMFS_DIR/bin/"

# ------------------------------------------------
# Copy verity/dmsetup tools if available
# ------------------------------------------------
for tool in dmsetup veritysetup blkid lsblk; do
  if command -v "$tool" &>/dev/null; then
    cp "$(command -v "$tool")" "$INITRAMFS_DIR/sbin/"
  fi
done

# ================================================================
# Create the /init script (executed as PID 1 inside initramfs)
# ================================================================
cat > "$INITRAMFS_DIR/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
echo "[initramfs] Booting from initramfs..."

# Set up /dev and hotplug
echo /sbin/mdev > /proc/sys/kernel/hotplug
mdev -s

CMDLINE="$(cat /proc/cmdline)"
ROOTDEV=$(echo "$CMDLINE" | grep -o 'root=[^ ]*' | cut -d= -f2)
MODE="simple"

# Detect dm-verity mode from cmdline
echo "$CMDLINE" | grep -q "dm-mod.create=" && MODE="verity"

if [ -z "$ROOTDEV" ]; then
    echo "[initramfs] ERROR: No root= argument found!"
    echo "cmdline was: $CMDLINE"
    exec /bin/sh
fi

echo "[initramfs] Boot mode: $MODE"
echo "[initramfs] Root device from cmdline: $ROOTDEV"

# Helper: wait for device
wait_for_device() {
    DEV=$1
    for i in $(seq 1 15); do
        [ -b "$DEV" ] && return 0
        sleep 1
        mdev -s
    done
    return 1
}

if [ "$MODE" = "verity" ]; then
    echo "[initramfs] dm-verity mode detected."
    META="/boot/rootfs.verity.meta"
    if [ -f "$META" ]; then
        ROOTHASH=$(grep '^roothash=' "$META" | cut -d= -f2)
        SALT=$(grep '^salt=' "$META" | cut -d= -f2)
        OFFSET=$(grep '^offset=' "$META" | cut -d= -f2)
        echo "[initramfs] Using dm-verity params: hash=$ROOTHASH offset=$OFFSET"
    else
        echo "[initramfs] WARNING: Metadata file not found!"
    fi

    # Wait for base device
    wait_for_device /dev/vda1 || {
        echo "[initramfs] ERROR: /dev/vda1 not found!"
        exec /bin/sh
    }

    # Create verity mapping
    if command -v dmsetup >/dev/null; then
        echo "[initramfs] Creating verity mapping..."
        echo "0 $OFFSET verity 1 /dev/vda1 /dev/vda1 4096 4096 $ROOTHASH $SALT" | dmsetup create verity-root
        ROOTDEV="/dev/mapper/verity-root"
    else
        echo "[initramfs] dmsetup not found — cannot create verity mapping!"
    fi
else
    echo "[initramfs] Simple boot mode."
    wait_for_device "$ROOTDEV" || {
        echo "[initramfs] ERROR: Device $ROOTDEV not found!"
        ls -l /dev
        exec /bin/sh
    }
fi

echo "[initramfs] Mounting real root ($ROOTDEV)..."
mkdir -p /newroot
if ! mount -t ext4 -o ro "$ROOTDEV" /newroot; then
    echo "[initramfs] Mount failed for $ROOTDEV — trying rw..."
    mount -t ext4 -o rw "$ROOTDEV" /newroot || {
        echo "[initramfs] Mount failed. Debug shell."
        exec /bin/sh
    }
fi

echo "[initramfs] Switching to real root filesystem..."
exec switch_root /newroot /sbin/init || {
    echo "[initramfs] switch_root failed!"
    exec /bin/sh
}
EOF

chmod +x "$INITRAMFS_DIR/init"

# ================================================================
# Create initramfs manifest (for gen_init_cpio)
# ================================================================
cat > "$INITRAMFS_LIST" <<EOF
dir /dev 755 0 0
dir /proc 755 0 0
dir /sys 755 0 0
dir /bin 755 0 0
dir /sbin 755 0 0
dir /etc 755 0 0
dir /newroot 755 0 0
dir /boot 755 0 0
dir /tmp 1777 0 0
file /init ${INITRAMFS_DIR}/init 755 0 0
file /bin/busybox ${INITRAMFS_DIR}/bin/busybox 755 0 0
slink /bin/sh /bin/busybox 777 0 0
slink /sbin/mount /bin/busybox 777 0 0
slink /sbin/switch_root /bin/busybox 777 0 0
slink /sbin/mdev /bin/busybox 777 0 0
EOF

# Add optional tools dynamically
for tool in dmsetup veritysetup blkid lsblk; do
  if [ -f "$INITRAMFS_DIR/sbin/$tool" ]; then
    echo "file /sbin/$tool ${INITRAMFS_DIR}/sbin/$tool 755 0 0" >> "$INITRAMFS_LIST"
  fi
done

# Include metadata file for verity setup (optional)
if [ -f "$META_FILE" ]; then
  echo "file /boot/rootfs.verity.meta $META_FILE 644 0 0" >> "$INITRAMFS_LIST"
fi

# ================================================================
# Generate the initramfs image
# ================================================================
cd "$BOOT_DIR"

if ! command -v gen_init_cpio &>/dev/null; then
  echo "Error: gen_init_cpio not found."
  echo "Build it from kernel source via:"
  echo "  make -C ~/linux-6.6 usr/gen_init_cpio"
  exit 1
fi

gen_init_cpio "$INITRAMFS_LIST" | gzip -9 > "$INITRAMFS_IMG"
echo "[initramfs] Image created at $INITRAMFS_IMG"

# ================================================================
# Sign the initramfs (bootloader private key)
# ================================================================
if [ -f "${BOOT_DIR}/bl_private.pem" ]; then
  openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
    -out "${INITRAMFS_IMG}.sig" \
    "$INITRAMFS_IMG"
  echo "[initramfs] Signed successfully."
else
  echo "[initramfs] Warning: ${BOOT_DIR}/bl_private.pem not found — skipping signature."
fi
