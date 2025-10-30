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
#  CLEAN OLD KERNEL BUILDS
# ==========================================================
echo "[0.5/10] Cleaning old kernel build files..."

if [ -d ~/linux-6.6 ]; then
  echo "Removing old kernel build artifacts in ~/linux-6.6 ..."
  sudo rm -rf ~/linux-6.6/{build,.tmp_versions,Module.symvers,*.o,*.o.cmd,*.mod,*.mod.c,*.order,*.dwo,*.d} 2>/dev/null || true
  sudo find ~/linux-6.6 -type f \( -name "*.o" -o -name "*.cmd" \) -delete
  echo "Kernel build tree cleaned."
else
  echo "No ~/linux-6.6 directory found — skipping kernel cleanup."
fi



# ==========================================================
#  SECURE BOOT BUILD PROCESS
# ==========================================================

ROOT_DIR="$(pwd)"
BOOT_DIR="${ROOT_DIR}/boot"
KEYS_DIR="${ROOT_DIR}/keys"
WORKSPACE="/workspace"
ROOTFS_DIR="${ROOT_DIR}/rootfs"
ROOTFS_IMG="${BOOT_DIR}/rootfs.img"
# Use a unified disk with 2 partitions: vda1=boot, vda2=rootfs
DISK_IMG="${BOOT_DIR}/disk.img"

# Boot mode switch: "simple" or "verity"
BOOT_MODE=${BOOT_MODE:-verity}

# --- FLEXIBLE ROOT DEVICE SETTINGS ---
ROOT_PARTNUM=${ROOT_PARTNUM:-1}     # default partition number
ROOT_DEV_BASE=${ROOT_DEV_BASE:-vda} # default disk name

echo
echo "[1/10] Using project root: $ROOT_DIR"
echo "[1/10] Boot directory:     $BOOT_DIR"
echo "[1/10] Keys directory:     $KEYS_DIR"
echo "[1/10] Root device:        /dev/${ROOT_DEV_BASE}${ROOT_PARTNUM}"
echo ""
read -p "Press ENTER to continue to step 2..."

# --- Safety check: avoid Windows-mounted paths (/mnt/...) ---
if [[ "$ROOT_DIR" == /mnt/* ]]; then
  echo "ERROR: Running from a Windows-mounted path ($ROOT_DIR)."
  echo "Move the project into your Linux home (e.g., ~/TeamRoot) and run again."
  exit 1
fi

# --- Check dependencies ---
for cmd in gcc openssl qemu-system-x86_64 debootstrap parted resize2fs; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' not found. Install with:"
    echo "  sudo apt install -y build-essential qemu-system-x86 openssl debootstrap parted e2fsprogs"
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
read -p "Step 2 complete. Press ENTER to continue to step 3..."

# --- Generate Root of Trust (RoT) keys ---
echo "[3/10] Generating Root of Trust keys (if missing)..."
if [ ! -f "${KEYS_DIR}/rot_private.pem" ]; then
  openssl genrsa -out "${KEYS_DIR}/rot_private.pem" 2048
  openssl rsa -in "${KEYS_DIR}/rot_private.pem" -pubout -out "${KEYS_DIR}/rot_public.pem"
  echo "Created rot_private.pem / rot_public.pem"
fi
read -p "Step 3 complete. Press ENTER to continue to step 4..."

# --- Generate Bootloader keys ---
echo "[4/10] Generating bootloader verification keys (if missing)..."
if [ ! -f "${BOOT_DIR}/bl_private.pem" ]; then
  openssl genrsa -out "${BOOT_DIR}/bl_private.pem" 2048
  openssl rsa -in "${BOOT_DIR}/bl_private.pem" -pubout -out "${BOOT_DIR}/bl_public.pem"
  echo "Created bl_private.pem / bl_public.pem"
fi
read -p "Step 4 complete. Press ENTER to continue to step 5..."

# --- Copy secondary bootloader to workspace ---
sudo cp secondary_bootloader.bin "${WORKSPACE}/boot/"

# --- Sign secondary bootloader with RoT private key ---
echo "[5/10] Signing secondary bootloader..."
sudo openssl dgst -sha256 -sign "${KEYS_DIR}/rot_private.pem" \
  -out "${WORKSPACE}/boot/secondary_bootloader.sig" \
  "${WORKSPACE}/boot/secondary_bootloader.bin"

# --- Copy signature back to project ---
cp "${WORKSPACE}/boot/secondary_bootloader.sig" "${BOOT_DIR}/"
read -p "Step 5 complete. Press ENTER to continue to step 6..."

# --- Sign kernel image with bootloader private key ---
echo "[6/10] Signing kernel image..."
openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
  -out "${BOOT_DIR}/kernel_image.sig" \
  "${BOOT_DIR}/kernel_image.bin"
read -p "Step 6 complete. Press ENTER to continue to step 7..."

# --- Show summary of generated artifacts ---
echo "[7/10] Generated files:"
ls -lh "${BOOT_DIR}" | grep -E "bootloader|kernel|pem|sig" || true
read -p "Step 7 complete. Press ENTER to continue to step 8..."

# --- Build and configure root filesystem using external script ---
export ROOT_DIR BOOT_DIR KEYS_DIR ROOTFS_DIR
sudo --preserve-env=ROOT_DIR,BOOT_DIR,KEYS_DIR,ROOTFS_DIR bash "${ROOT_DIR}/build/rootfs.sh"


# --- Build initramfs using external script ---
# export ROOT_DIR BOOT_DIR KEYS_DIR
# bash "${ROOT_DIR}/build/initramfs.sh"

# --- Package rootfs into ext4 image (flexible partition) ---
echo "[8/10] Packaging rootfs into ext4 image (partition ${ROOT_DEV_BASE}${ROOT_PARTNUM})..."
IMG_MB=512
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=$IMG_MB

parted -s "$DISK_IMG" mklabel msdos
parted -s "$DISK_IMG" mkpart primary ext4 1MiB "${BOOT_MB}MiB"
parted -s "$DISK_IMG" mkpart primary ext4 "${BOOT_MB}MiB" 100%

LOOP=$(sudo losetup -f --show -P "$DISK_IMG")

cleanup_loop() {
  set +e
  sudo umount /mnt/rootfs_build 2>/dev/null || true
  sudo umount /mnt/boot_build  2>/dev/null || true
  sudo losetup -d "$LOOP" 2>/dev/null || true
  set -e
}
trap cleanup_loop EXIT

echo "[8/10] Formatting partitions..."
sudo mkfs.ext4 -F -L boot   "${LOOP}p1" >/dev/null
sudo mkfs.ext4 -F -L rootfs "${LOOP}p2" >/dev/null

FS_SIZE_MB=$((ROOT_MB - 24))
sudo resize2fs "${LOOP}p2" "${FS_SIZE_MB}M" >/dev/null

echo "[8/10] Populating rootfs on p2..."
sudo mkdir -p /mnt/rootfs_build
sudo mount "${LOOP}p2" /mnt/rootfs_build
sudo cp -a "$ROOTFS_DIR"/* /mnt/rootfs_build
sudo sync
sudo umount /mnt/rootfs_build
sudo e2fsck -fy "${LOOP}p2" >/dev/null || true

echo "[8/10] Populating boot on p1..."
sudo mkdir -p /mnt/boot_build
sudo mount "${LOOP}p1" /mnt/boot_build
sudo cp -a "${BOOT_DIR}/kernel_image.bin" "${BOOT_DIR}/initramfs.cpio.gz" /mnt/boot_build/
sudo cp -a "${BOOT_DIR}/kernel_image.sig" 2>/dev/null || true
sudo sync
sudo umount /mnt/boot_build

sudo losetup -d "$LOOP"
trap - EXIT

echo "[8.1] Verifying disk partition layout..."
sudo fdisk -l "$DISK_IMG" || true
echo "[8.2] Probing filesystems inside the image..."
sudo blkid -p -o full -u filesystem "$DISK_IMG" || true
echo "Disk ready at $DISK_IMG (vda1=boot, vda2=rootfs)"
read -p "Step 8 complete. Press ENTER to continue to step 9..."

# ==============================================================
# [FIXED STEP 9]  Sign & generate PKCS#7 metadata safely
# ==============================================================

echo "[9/10] Signing rootfs image..."
openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
  -out "${BOOT_DIR}/rootfs.img.sig" \
  "$DISK_IMG"

echo "[9.1] Creating PKCS#7 signature for verity metadata..."

META_FILE="${BOOT_DIR}/verity_metadata.txt"
echo "dm-verity metadata root hash, salt, etc. placeholder" > "$META_FILE"

if [ ! -f "${BOOT_DIR}/bl_cert.pem" ] || [ ! -f "${BOOT_DIR}/bl_cert.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "${BOOT_DIR}/bl_cert.key" \
    -out "${BOOT_DIR}/bl_cert.pem" \
    -subj "/CN=verity-signed/"
fi

openssl smime -sign -binary -in "$META_FILE" \
  -signer "${BOOT_DIR}/bl_cert.pem" -inkey "${BOOT_DIR}/bl_cert.key" \
  -noattr -outform DER -out "${BOOT_DIR}/verity_metadata.p7s"

echo "PKCS#7 metadata signature created at ${BOOT_DIR}/verity_metadata.p7s"


# --- Generate PKCS#7-signed metadata for dm-verity-signed ---
echo "[9.1] Creating PKCS#7 signature for verity metadata..."

META_FILE="${BOOT_DIR}/verity_metadata.txt"
echo "dm-verity metadata root hash, salt, etc. placeholder" > "$META_FILE"

if [ ! -f "${BOOT_DIR}/bl_cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "${BOOT_DIR}/bl_private.pem" \
    -out "${BOOT_DIR}/bl_cert.pem" \
    -subj "/CN=verity-signed/"
fi

openssl smime -sign -binary -in "$META_FILE" \
  -signer "${BOOT_DIR}/bl_cert.pem" -inkey "${BOOT_DIR}/bl_private.pem" \
  -noattr -outform DER -out "${BOOT_DIR}/verity_metadata.p7s"

echo "PKCS#7 metadata signature created at ${BOOT_DIR}/verity_metadata.p7s"

# --- Generate dm-verity metadata using external script ---
export ROOT_DIR BOOT_DIR
bash "${ROOT_DIR}/build/verity.sh"

read -p "Step 9 complete. Press ENTER to continue to step 10..."

