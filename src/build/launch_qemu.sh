#
# QEMU System Launcher with dm-verity Support
# ==============================================
#
# Purpose: Boots Linux kernel with dm-verity enabled root filesystem
#
# This launcher provides an interactive menu to select between:
# - Original (uncorrupted) rootfs image
# - Test images with specific dm-verity corruptions
#
# COMPLETE WORKFLOW:
#   Option 1: Test corrupted images
#     1. Create test images: ./integrity_tests.sh <mode>
#     2. Launch this script: ./launch_qemu.sh  
#     3. Select test image from menu
#     4. Observe kernel dm-verity behavior during boot
#     5. Check for expected security validation failures
#
#   Option 2: Test working system
#     1. Ensure original rootfs.img exists in Binaries/
#     2. Launch this script: ./launch_qemu.sh
#     3. Select option 1 (original image)
#     4. Observe successful dm-verity boot
#
# The script automatically detects all available test images and presents
# them in a numbered menu for easy selection.
#
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

# Kernel parameters for dm-verity testing
APPEND_CMD="console=ttyS0 loglevel=7 root=/dev/dm-0 rootfstype=ext4 rootwait \
dm_verity_autoboot.autoboot_device=/dev/vda \
dm_verity_autoboot.mode=verify_and_map"

echo "===================================================================="
echo "QEMU System Launcher with dm-verity Support"
echo "===================================================================="

# Check if original image exists
if [[ ! -f "$ORIGINAL_ROOTFS" ]]; then
    echo "WARNING: Original image not found at: $ORIGINAL_ROOTFS"
    ORIGINAL_EXISTS=0
else
    ORIGINAL_EXISTS=1
fi

# Validate we have at least one image to boot
if [[ $ORIGINAL_EXISTS -eq 0 && ${#TEST_IMAGES[@]} -eq 0 ]]; then
    echo "ERROR: No bootable images found!" >&2
    echo ""
    echo "SETUP REQUIRED:"
    echo "---------------"
    echo "You need either:"
    echo ""
    echo "A) Original working system:"
    echo "   - Ensure $ORIGINAL_ROOTFS exists"
    echo "   - This should be a valid dm-verity enabled rootfs"
    echo ""
    echo "B) Test images (for security testing):"
    echo "   - Create using: ./integrity_tests.sh <mode>"
    echo "   - Available modes: meta1, sig1, int_overflow, buf_overflow, etc."
    echo "   - Example: ./integrity_tests.sh sig1"
    echo ""
    echo "Then run this script again to select boot image."
    exit 1
fi

# Display available images menu
echo ""
echo "AVAILABLE BOOT IMAGES:"
echo "----------------------"

if [[ $ORIGINAL_EXISTS -eq 1 ]]; then
    echo "  1) Original image ($(basename "$ORIGINAL_ROOTFS"))"
    echo "     - Clean, uncorrupted root filesystem"
    echo "     - Expected: Successful boot with dm-verity verification"
    menu_start=2
else
    echo "  (Original image not available)"
    menu_start=1
fi

# Display test images with descriptions
for i in "${!TEST_IMAGES[@]}"; do
    img_name=$(basename "${TEST_IMAGES[i]}")
    # Extract mode name from filename (rootfs.MODE.test.img -> MODE)
    mode_name="${img_name#rootfs.}"
    mode_name="${mode_name%.test.img}"
    
    echo "  $((i + menu_start))) $mode_name test image"
        #Description of Test images
        case "$mode_name" in
        meta1) echo "     - Corrupts header structure" ;;
        sig1) echo "     - Corrupts PKCS#7 signature" ;;
        int_overflow) echo "     - Tests integer overflow protection" ;;
        buf_overflow) echo "     - Tests buffer overflow protection" ;;
        trunc_meta) echo "     - Tests truncated metadata handling" ;;
        bad_offsets) echo "     - Tests bounds checking" ;;
        sanitize) echo "     - Tests input validation" ;;
    esac
done

max_choice=$((${#TEST_IMAGES[@]} + menu_start - 1))
default_choice=1

# Set default selection
if [[ $ORIGINAL_EXISTS -eq 0 && ${#TEST_IMAGES[@]} -gt 0 ]]; then
    default_choice=1
    ROOTFS="${TEST_IMAGES[0]}"
    echo ""
    echo "NOTE: Original image not found, defaulting to first test image"
else
    ROOTFS="$ORIGINAL_ROOTFS"
fi

# Get user selection
echo ""
read -r -p "Select boot image [1-$max_choice] (default: $default_choice): " choice

# Process selection
if [[ $ORIGINAL_EXISTS -eq 1 ]]; then
    case "${choice:-$default_choice}" in
        1)
            ROOTFS="$ORIGINAL_ROOTFS"
            echo "✓ Using ORIGINAL image - expected successful boot"
            ;;
        *)
            index=$((choice - 2))
            if [[ $index -ge 0 && $index -lt ${#TEST_IMAGES[@]} ]]; then
                ROOTFS="${TEST_IMAGES[index]}"
                echo "✓ Using TEST image: $(basename "$ROOTFS")"
                echo "  Expected: dm-verity validation failure"
            else
                ROOTFS="$ORIGINAL_ROOTFS"
                echo "⚠ Invalid selection, using ORIGINAL image"
            fi
            ;;
    esac
else
    # Only test images available
    index=$((choice - 1))
    if [[ $index -ge 0 && $index -lt ${#TEST_IMAGES[@]} ]]; then
        ROOTFS="${TEST_IMAGES[index]}"
        echo "✓ Using TEST image: $(basename "$ROOTFS")"
        echo "  Expected: dm-verity validation failure"
    else
        ROOTFS="${TEST_IMAGES[0]}"
        echo "⚠ Invalid selection, using first TEST image: $(basename "$ROOTFS")"
    fi
fi

# Verify the selected image exists
if [[ ! -f "$ROOTFS" ]]; then
    echo "ERROR: Selected image not found: $ROOTFS" >&2
    echo "Please check the file exists and try again."
    exit 1
fi

# Display execution preview
echo ""
echo "BOOT CONFIGURATION:"
echo "-------------------"
echo "Kernel:    $(basename "$KERNEL")"
echo "RootFS:    $(basename "$ROOTFS")"
echo "Memory:    1024MB"
echo "Console:   Serial (ttyS0)"
echo "-------------------"

# Brief pause to let user read the configuration
sleep 1

echo "Starting QEMU..."
echo "===================================================================="

# Actually run QEMU
exec qemu-system-x86_64 \
  -kernel "$KERNEL" \
  -drive if=none,file="$ROOTFS",format=raw,id=hd0 \
  -device virtio-blk-pci,drive=hd0 \
  -append "$APPEND_CMD" \
  -m 1024M -nographic