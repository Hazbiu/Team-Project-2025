#!/bin/bash
set -e
# --- Ensure dos2unix is available ---
if ! command -v dos2unix &> /dev/null; then
  echo "Installing dos2unix..."
  sudo apt update -y && sudo apt install -y dos2unix
fi
# --- Force all shell scripts to use Unix line endings ---
find . -type f -name "*.sh" -exec dos2unix {} \; 2>/dev/null

echo "============================================"
echo " Secure Boot Chain Build & Execution Script  "
echo "============================================"

# --- Detect and normalize paths ---
ROOT_DIR="$(pwd)"
BOOT_DIR="${ROOT_DIR}/boot"
KEYS_DIR="${ROOT_DIR}/keys"
WORKSPACE="/workspace"

echo "[1/10] Using project root: $ROOT_DIR"
echo "[1/10] Boot directory:     $BOOT_DIR"
echo "[1/10] Keys directory:     $KEYS_DIR"
echo ""

# --- Check dependencies ---
for cmd in gcc openssl qemu-system-x86_64; do
  if ! command -v $cmd &> /dev/null; then
    echo "Error: '$cmd' not found. Please install it via apt:"
    echo "sudo apt install build-essential qemu-system-x86 openssl -y"
    exit 1
  fi
done

# --- Create workspace ---
sudo mkdir -p ${WORKSPACE}/boot ${WORKSPACE}/keys

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
sudo cp secondary_bootloader.bin ${WORKSPACE}/boot/

# --- Sign secondary bootloader with RoT private key ---
echo "[5/10] Signing secondary bootloader..."
sudo openssl dgst -sha256 -sign "${KEYS_DIR}/rot_private.pem" \
  -out ${WORKSPACE}/boot/secondary_bootloader.sig \
  ${WORKSPACE}/boot/secondary_bootloader.bin

# --- Copy signature back to project ---
cp ${WORKSPACE}/boot/secondary_bootloader.sig "${BOOT_DIR}/"

# --- Sign kernel image with bootloader private key ---
echo "[6/10] Signing kernel image..."
openssl dgst -sha256 -sign "${BOOT_DIR}/bl_private.pem" \
  -out "${BOOT_DIR}/kernel_image.sig" \
  "${BOOT_DIR}/kernel_image.bin"

# --- Show summary of generated artifacts ---
echo "[7/10] Generated files:"
ls -lh "${BOOT_DIR}" | grep -E "bootloader|kernel|pem|sig"

# --- Run Primary Bootloader ---
echo "[8/10] Executing primary bootloader (will chain to secondary)..."
cd "$BOOT_DIR"
./primary_bootloader
