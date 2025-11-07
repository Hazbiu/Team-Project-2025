#!/bin/bash
set -euo pipefail

# Colors for readability
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

echo -e "${YELLOW}========================================"
echo -e " Unified Boot Preparation & Launch Script"
echo -e "========================================${RESET}"

# Paths
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
BOOTLOADER_DIR="$BUILD_DIR/../bootloaders"
ROOTFS_IMG="$BUILD_DIR/Binaries/rootfs.img"

# Build rootfs (build_rootfs.sh)
echo -e "${YELLOW}[1/3] Building Root Filesystem...${RESET}"
if bash "$BUILD_DIR/build_rootfs.sh"; then
    echo -e "${GREEN}✔ Root filesystem built successfully${RESET}"
else
    echo -e "${RED}✖ Failed to build root filesystem${RESET}"
    exit 1
fi

# Generate dm-verity data (generate_verity.sh)
echo -e "${YELLOW}[2/3] Generating dm-verity metadata...${RESET}"
if bash "$BUILD_DIR/generate_verity.sh"; then
    echo -e "${GREEN}✔ dm-verity metadata generated successfully${RESET}"
else
    echo -e "${RED}✖ Failed to generate dm-verity metadata${RESET}"
    exit 1
fi

#  Verifies rootfs image exists 
if [[ ! -f "$ROOTFS_IMG" ]]; then
    echo -e "${RED}✖ rootfs.img not found at $ROOTFS_IMG${RESET}"
    exit 1
fi

# Copy image to bootloader directory
cp -f "$ROOTFS_IMG" "$BOOTLOADER_DIR/"

# Bootloader launcher
echo -e "${YELLOW}[3/3] Launching bootloader...${RESET}"
cd "$BOOTLOADER_DIR"

if sudo ./secondary_bootloader; then
    echo -e "${GREEN}✔ Bootloader executed successfully${RESET}"
else
    echo -e "${RED}✖ Bootloader failed to execute${RESET}"
    exit 1
fi

echo -e "${GREEN}========================================"
echo -e " All stages completed successfully!"
echo -e " System is ready and booted."
echo -e "========================================${RESET}"
