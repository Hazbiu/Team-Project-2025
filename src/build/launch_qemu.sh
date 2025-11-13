#!/bin/bash
set -eo pipefail

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL="$SCRIPT_DIR/../bootloaders/kernel_image.bin"
ORIGINAL_ROOTFS="$SCRIPT_DIR/Binaries/rootfs.img"

# Find all mode-specific test images
TEST_IMAGES=()
if [[ -d "$SCRIPT_DIR/Binaries" ]]; then
    while IFS= read -r -d '' img; do
        TEST_IMAGES+=("$img")
    done < <(find "$SCRIPT_DIR/Binaries" -name "rootfs.*.test.img" -print0 2>/dev/null | sort -z)
fi

# Kernel parameters (what we send to QEMU)
APPEND_CMD="console=ttyS0 loglevel=7 root=/dev/dm-0 rootfstype=ext4 rootwait \
dm_verity_autoboot.autoboot_device=/dev/vda \
dm_verity_autoboot.mode=verify_and_map"

echo "====================================="
echo " Launching QEMU with dm-verity setup "
echo "====================================="

# Check if original image exists
if [[ ! -f "$ORIGINAL_ROOTFS" ]]; then
    echo "WARNING: Original image not found at: $ORIGINAL_ROOTFS"
    ORIGINAL_EXISTS=0
else
    ORIGINAL_EXISTS=1
fi

# Image selection
if [[ $ORIGINAL_EXISTS -eq 0 && ${#TEST_IMAGES[@]} -eq 0 ]]; then
    echo "ERROR: No rootfs images found!" >&2
    echo "Please make sure you have either:" >&2
    echo "  - $ORIGINAL_ROOTFS" >&2
    echo "  - or test images in $SCRIPT_DIR/Binaries/" >&2
    exit 1
fi

# Build menu
echo "Choose which rootfs image to use:"
if [[ $ORIGINAL_EXISTS -eq 1 ]]; then
    echo "  1) Original image ($(basename "$ORIGINAL_ROOTFS"))"
    menu_start=2
else
    echo "  (Original image not available)"
    menu_start=1
fi

for i in "${!TEST_IMAGES[@]}"; do
    img_name=$(basename "${TEST_IMAGES[i]}")
    # Extract mode name from filename (rootfs.MODE.test.img -> MODE)
    mode_name="${img_name#rootfs.}"
    mode_name="${mode_name%.test.img}"
    echo "  $((i + menu_start))) $mode_name test image"
done

max_choice=$((${#TEST_IMAGES[@]} + menu_start - 1))
default_choice=1

# If original doesn't exist but we have test images, default to first test image
if [[ $ORIGINAL_EXISTS -eq 0 && ${#TEST_IMAGES[@]} -gt 0 ]]; then
    default_choice=1
    ROOTFS="${TEST_IMAGES[0]}"
    echo "No original image found, defaulting to: $(basename "$ROOTFS")"
else
    ROOTFS="$ORIGINAL_ROOTFS"
fi

echo ""
read -r -p "Enter your choice [1-$max_choice] (default: $default_choice): " choice

if [[ $ORIGINAL_EXISTS -eq 1 ]]; then
    case "${choice:-$default_choice}" in
        1)
            ROOTFS="$ORIGINAL_ROOTFS"
            echo "Using original image"
            ;;
        *)
            index=$((choice - 2))
            if [[ $index -ge 0 && $index -lt ${#TEST_IMAGES[@]} ]]; then
                ROOTFS="${TEST_IMAGES[index]}"
                echo "Using test image: $(basename "$ROOTFS")"
            else
                ROOTFS="$ORIGINAL_ROOTFS"
                echo "Invalid choice, using original image"
            fi
            ;;
    esac
else
    # Only test images available
    index=$((choice - 1))
    if [[ $index -ge 0 && $index -lt ${#TEST_IMAGES[@]} ]]; then
        ROOTFS="${TEST_IMAGES[index]}"
        echo "Using test image: $(basename "$ROOTFS")"
    else
        ROOTFS="${TEST_IMAGES[0]}"
        echo "Invalid choice, using first test image: $(basename "$ROOTFS")"
    fi
fi

# Verify the selected image exists
if [[ ! -f "$ROOTFS" ]]; then
    echo "ERROR: Selected image not found: $ROOTFS" >&2
    exit 1
fi

# Show preview of what will be executed
echo
echo "Command preview:"
echo "qemu-system-x86_64 \\"
echo "  -kernel $KERNEL \\"
echo "  -drive if=none,file=$ROOTFS,format=raw,id=hd0 \\"
echo "  -device virtio-blk-pci,drive=hd0 \\"
echo "  -append \"$APPEND_CMD\" \\"
echo "  -m 1024M -nographic"
echo

# Actually run QEMU
exec qemu-system-x86_64 \
  -kernel "$KERNEL" \
  -drive if=none,file="$ROOTFS",format=raw,id=hd0 \
  -device virtio-blk-pci,drive=hd0 \
  -append "$APPEND_CMD" \
  -m 1024M -nographic
