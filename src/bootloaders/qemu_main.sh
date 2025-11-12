#!/usr/bin/env bash
# Minimal userspace bootloader for the dm-verity demo.
#
# Responsibilities:
#   - Resolve the absolute path to the GPT disk image (rootfs.img)
#   - Start QEMU with:
#       * the Linux kernel image (kernel_image.bin)
#       * the disk image attached as a virtio-blk drive (/dev/vda in guest)
#       * a kernel cmdline that:
#           - tells dm-verity-autoboot which disk to verify (/dev/vda)
#           - sets root=/dev/dm-0 so the kernel mounts the dm-verity device
#
# All security logic (dm-verity tree, detached PKCS7 verification,
# dm-verity mapping creation, and mounting the verified rootfs) happens
# entirely inside the kernel.

set -u  # treat unset vars as an error

IMG_REL="../build/Binaries/rootfs.img"

# Resolve the absolute path for the disk image
if ! IMG_ABS=$(realpath "$IMG_REL"); then
    echo "realpath($IMG_REL) failed" >&2
    exit 1
fi

# QEMU -drive option: attach the image as a raw, whole disk (/dev/vda in guest)
DRIVE_OPT="if=none,id=drv0,format=raw,media=disk,file=${IMG_ABS}"

# Kernel command line
APPEND_CMDLINE="console=ttyS0,115200 \
loglevel=7 \
dm_verity_autoboot.autoboot_device=/dev/vda \
root=/dev/dm-0 rootfstype=ext4 rootwait rootdelay=10"

echo "================================================"
echo "  SIMPLE dm-verity BOOTLOADER (QEMU launcher)"
echo "  Kernel does all verification + mapping"
echo "================================================"
echo
echo "Using disk image (whole GPT disk):"
echo "  ${IMG_ABS}"
echo
echo "QEMU -drive argument:"
echo "  ${DRIVE_OPT}"
echo
echo "This bootloader ONLY:"
echo "  - Loads the Linux kernel image"
echo "  - Attaches the rootfs disk as a virtio-blk drive (/dev/vda)"
echo "  - Passes the kernel command line with:"
echo "      * dm_verity_autoboot.autoboot_device=/dev/vda"
echo "      * root=/dev/dm-0 (ext4, verified)"
echo
echo "Inside the guest, the kernel + dm-verity-autoboot will:"
echo "  1. Bring up virtio-blk and expose /dev/vda (whole disk)"
echo "  2. Read the dm-verity locator + metadata + PKCS7 signature"
echo "     from the end of /dev/vda"
echo "  3. Verify the PKCS7 signature against the kernel trusted keyring"
echo "  4. Create a read-only dm-verity mapping over /dev/vda"
echo "     (device name \"verity_root\", typically /dev/dm-0)"
echo "  5. Let the kernel mount /dev/dm-0 as the ext4 root filesystem"
echo

read -r -p "Press ENTER to boot QEMU..." _

echo
echo "=== Launching QEMU ==="
echo "Kernel cmdline:"
echo "  ${APPEND_CMDLINE}"
echo

qemu-system-x86_64 \
    -m 1024 \
    -machine q35,accel=tcg \
    -cpu max \
    -nodefaults \
    -nographic \
    -serial mon:stdio \
    -d guest_errors \
    -kernel kernel_image.bin \
    -drive "${DRIVE_OPT}" \
    -device virtio-blk-pci,drive=drv0 \
    -append "${APPEND_CMDLINE}"

STATUS=$?
echo
echo "QEMU exited with status: ${STATUS}"
