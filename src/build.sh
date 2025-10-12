#!/bin/bash
set -e

echo "============================================"
echo " Secure Boot Chain Build & Execution Script  "
echo "============================================"

# ==========================================================
#  PREPARATION (copy project from Windows FS into Linux home)
# ==========================================================
echo "[0/10] Preparing clean workspace in Linux FS..."

cd ~
# Safely delete previous TeamRoot, including mounted dirs, with root permissions
if [ -d ~/TeamRoot ]; then
  echo "Cleaning up old TeamRoot workspace..."
  sudo umount ~/TeamRoot/rootfs/{proc,sys,dev} 2>/dev/null || true
  sudo rm -rf ~/TeamRoot
fi
mkdir -p ~/TeamRoot

# Copy core project files from Windows side into real Linux FS
cp -r /mnt/c/Programming/Team-Project-2025/src/boot \
      /mnt/c/Programming/Team-Project-2025/src/keys \
      /mnt/c/Programming/Team-Project-2025/src/build.sh \
      /mnt/c/Programming/Team-Project-2025/src/run_build.sh \
      ~/TeamRoot/ 2>/dev/null || true

# Copy local kernel source if it exists
if [ -d ~/linux-6.6 ]; then
  cp -r ~/linux-6.6 ~/TeamRoot/
else
  echo "No ~/linux-6.6 directory found — skipping kernel source copy."
fi

cd ~/TeamRoot
echo "Workspace ready at ~/TeamRoot"
ls

# ==========================================================
#  SECURE BOOT BUILD PROCESS
# ==========================================================

# --- Detect and normalize paths ---
ROOT_DIR="$(pwd)"
BOOT_DIR="${ROOT_DIR}/boot"
KEYS_DIR="${ROOT_DIR}/keys"
WORKSPACE="/workspace"
ROOTFS_DIR="${ROOT_DIR}/rootfs"
ROOTFS_IMG="${BOOT_DIR}/rootfs.img"

echo
echo "[1/10] Using project root: $ROOT_DIR"
echo "[1/10] Boot directory:     $BOOT_DIR"
echo "[1/10] Keys directory:     $KEYS_DIR"
echo ""

# --- Safety check: avoid Windows-mounted paths (/mnt/...) ---
if [[ "$ROOT_DIR" == /mnt/* ]]; then
  echo "ERROR: Running from a Windows-mounted path ($ROOT_DIR)."
  echo "Move the project into your Linux home (e.g., ~/TeamRoot) and run again."
  exit 1
fi

# --- Check dependencies ---
for cmd in gcc openssl qemu-system-x86_64 debootstrap; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' not found. Install with:"
    echo "  sudo apt install -y build-essential qemu-system-x86 openssl debootstrap"
    exit 1
  fi
done

# --- Create workspace ---
sudo mkdir -p "${WORKSPACE}/boot" "${WORKSPACE}/keys"

# --- Build Bootloaders ---
echo "[2/10] Building primary and secondary bootloaders..."
cd "$BOOT_DIR"
gcc -o primary_bootloader primary_bootloader.c -lcrypto -lssl
gcc -o secondary_bootloader secondary_bootloader.c -lcrypto -lssl
cp secondary_bootloader secondary_bootloader.bin

# --- Generate Root of Trust (RoT) keys ---
echo "[3/10] Generating Root of Trust keys (if missing)..."
if [ ! -f "${KEYS_DIR}/rot_private.pem" ]; then
  openssl genrsa -out "${KEYS_DIR}/rot_private.pem" 2048
  openssl rsa -in "${KEYS_DIR}/rot_private.pem" -pubout -out "${KEYS_DIR}/rot_public.pem"
  echo "Created rot_private.pem / rot_public.pem"
fi

# --- Generate Bootloader keys ---
echo "[4/10] Generating bootloader verification keys (if missing)..."
if [ ! -f "${BOOT_DIR}/bl_private.pem" ]; then
  openssl genrsa -out "${BOOT_DIR}/bl_private.pem" 2048
  openssl rsa -in "${BOOT_DIR}/bl_private.pem" -pubout -out "${BOOT_DIR}/bl_public.pem"
  echo "Created bl_private.pem / bl_public.pem"
fi

# --- Copy secondary bootloader to workspace ---
sudo cp secondary_bootloader.bin "${WORKSPACE}/boot/"

# --- Sign secondary bootloader with RoT private key ---
echo "[5/10] Signing secondary bootloader..."
sudo openssl dgst -sha256 -sign "${KEYS_DIR}/rot_private.pem" \
  -out "${WORKSPACE}/boot/secondary_bootloader.sig" \
  "${WORKSPACE}/boot/secondary_bootloader.bin"

# --- Copy signature back to project ---
cp "${WORKSPACE}/boot/secondary_bootloader.sig" "${BOOT_DIR}/"

# --- Sign kernel image with bootloader private key ---
echo "[6/10] Signing kernel image..."
openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
  -out "${BOOT_DIR}/kernel_image.sig" \
  "${BOOT_DIR}/kernel_image.bin"

# --- Show summary of generated artifacts ---
echo "[7/10] Generated files:"
ls -lh "${BOOT_DIR}" | grep -E "bootloader|kernel|pem|sig" || true

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

sudo chroot "$ROOTFS_DIR" bash -c "
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y passwd login sudo

  # Unlock and set root password
  passwd -d root || true
  echo 'root:root' | chpasswd
  passwd -u root || true

  # Create user 'keti' with sudo
  id -u keti &>/dev/null || useradd -m -s /bin/bash keti
  echo 'keti:keti' | chpasswd
  usermod -aG sudo keti

  # Enable serial console login
  systemctl enable serial-getty@ttyS0.service || true

  apt-get clean
"

sudo umount "$ROOTFS_DIR/dev"  || true
sudo umount "$ROOTFS_DIR/proc" || true
sudo umount "$ROOTFS_DIR/sys"  || true

echo "User setup complete (root/root and keti/keti)"

# --- Package rootfs into ext4 image ---
echo "Packaging rootfs into ext4 image..."
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=512
mkfs.ext4 -F "$ROOTFS_IMG"

sudo mkdir -p /mnt/rootfs_build
sudo mount -o loop "$ROOTFS_IMG" /mnt/rootfs_build
sudo cp -a "$ROOTFS_DIR"/* /mnt/rootfs_build
sudo umount /mnt/rootfs_build
echo "RootFS image ready at $ROOTFS_IMG"

# --- Sign the rootfs image ---
echo "[9/10] Signing rootfs image..."
openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
  -out "${BOOT_DIR}/rootfs.img.sig" \
  "$ROOTFS_IMG"

# --- Launch in QEMU ---
echo "[10/10] Launching Secure Boot Demo in QEMU..."
qemu-system-x86_64 \
  -m 1024 \
  -kernel "${BOOT_DIR}/kernel_image.bin" \
  -drive file="${ROOTFS_IMG}",format=raw,if=virtio \
  -append "root=/dev/vda rw console=ttyS0" \
  -nographic
