#!/bin/bash
set -euo pipefail

echo "============================================"
echo " Secure Boot Chain Build & Execution Script  "
echo "============================================"

# ==========================================================
#  PREPARATION (copy project from Windows FS into Linux home)
# ==========================================================
echo "[0/10] Preparing clean workspace in Linux FS..."

# Detect source directory (where build.sh lives)
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd ~
# Safely delete previous TeamRoot, including mounted dirs, with root permissions
if [ -d ~/TeamRoot ]; then
  echo "Cleaning up old TeamRoot workspace..."
  sudo umount ~/TeamRoot/rootfs/{proc,sys,dev} 2>/dev/null || true
  sudo rm -rf ~/TeamRoot
fi
mkdir -p ~/TeamRoot

echo "Copying project files to ~/TeamRoot..."
cp -r "${SRC_DIR}/boot" "${SRC_DIR}/keys" "${SRC_DIR}/build" ~/TeamRoot/

# Copy top-level scripts
cp "${SRC_DIR}/build.sh" "${SRC_DIR}/run_build.sh" ~/TeamRoot/

chmod +x ~/TeamRoot/build/*.sh 2>/dev/null || true

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

ROOT_DIR="$(pwd)"
BOOT_DIR="${ROOT_DIR}/boot"
KEYS_DIR="${ROOT_DIR}/keys"
WORKSPACE="/workspace"
ROOTFS_DIR="${ROOT_DIR}/rootfs"
ROOTFS_IMG="${BOOT_DIR}/rootfs.img"

# --- FLEXIBLE ROOT DEVICE SETTINGS ---
ROOT_PARTNUM=${ROOT_PARTNUM:-1}     # default partition number
ROOT_DEV_BASE=${ROOT_DEV_BASE:-vda} # default disk name

echo
echo "[1/10] Using project root: $ROOT_DIR"
echo "[1/10] Boot directory:     $BOOT_DIR"
echo "[1/10] Keys directory:     $KEYS_DIR"
echo "[1/10] Root device:        /dev/${ROOT_DEV_BASE}${ROOT_PARTNUM}"
echo ""

# --- Safety check: avoid Windows-mounted paths (/mnt/...) ---
if [[ "$ROOT_DIR" == /mnt/* ]]; then
  echo "ERROR: Running from a Windows-mounted path ($ROOT_DIR)."
  echo "Move the project into your Linux home (e.g., ~/TeamRoot) and run again."
  exit 1
fi

# --- Check dependencies ---
for cmd in gcc openssl qemu-system-x86_64 debootstrap parted; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' not found. Install with:"
    echo "  sudo apt install -y build-essential qemu-system-x86 openssl debootstrap parted"
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

# --- Build and configure root filesystem using external script ---
export ROOT_DIR BOOT_DIR KEYS_DIR ROOTFS_DIR
bash "${ROOT_DIR}/build/rootfs.sh"

# --- Build initramfs using external script ---
export ROOT_DIR BOOT_DIR KEYS_DIR
bash "${ROOT_DIR}/build/initramfs.sh"

# --- Package rootfs into ext4 image (flexible partition) ---
echo "[8/10] Packaging rootfs into ext4 image (partition ${ROOT_DEV_BASE}${ROOT_PARTNUM})..."
IMG_MB=512
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=$IMG_MB

parted -s "$ROOTFS_IMG" mklabel msdos

# Create dummy partitions up to the desired partition number
for ((i=1; i<ROOT_PARTNUM; i++)); do
  start=$((1 + (i-1)*2))
  end=$((start + 1))
  parted -s "$ROOTFS_IMG" mkpart primary ext4 "${start}MiB" "${end}MiB"
done

# Real root partition filling the rest
parted -s "$ROOTFS_IMG" mkpart primary ext4 "$((ROOT_PARTNUM*2))MiB" 100%

# Attach loop device and format root partition
LOOP=$(sudo losetup -f --show -P "$ROOTFS_IMG")
sudo mkfs.ext4 -F "${LOOP}p${ROOT_PARTNUM}"

sudo mkdir -p /mnt/rootfs_build
sudo mount "${LOOP}p${ROOT_PARTNUM}" /mnt/rootfs_build
sudo cp -a "$ROOTFS_DIR"/* /mnt/rootfs_build
sudo umount /mnt/rootfs_build
sudo losetup -d "$LOOP"

echo "RootFS image ready at $ROOTFS_IMG (root partition ${ROOT_DEV_BASE}${ROOT_PARTNUM})"

# --- Sign the rootfs image ---
echo "[9/10] Signing rootfs image..."
openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
  -out "${BOOT_DIR}/rootfs.img.sig" \
  "$ROOTFS_IMG"

# --- Generate dm-verity metadata using external script ---
export ROOT_DIR BOOT_DIR ROOTFS_IMG
bash "${ROOT_DIR}/build/verity.sh"

# --- Launch in QEMU ---
echo "[10/10] Launching Secure Boot Demo in QEMU..."
qemu-system-x86_64 \
  -m 1024 \
  -kernel "${BOOT_DIR}/kernel_image.bin" \
  -initrd "${BOOT_DIR}/initramfs.cpio.gz" \
  -drive file="${ROOTFS_IMG}",format=raw,if=virtio \
  -append "root=/dev/${ROOT_DEV_BASE}${ROOT_PARTNUM} rw console=ttyS0" \
  -nographic
