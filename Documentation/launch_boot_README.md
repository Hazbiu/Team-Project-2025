# Unified Boot Preparation & Launch Script (`launch_boot.sh`)

This script automates the entire process of building, verifying, and launching a Debian-based root filesystem with **dm-verity** integrity checking and a custom **secondary bootloader**.

#Overview

The script runs through three automated stages:

1. Root Filesystem Build
   - Runs `build_rootfs.sh` to generate a Debian base system using `debootstrap`.
   - Packages it into a GPT-partitioned `rootfs.img` disk image.

2. dm-verity Metadata Generation**
   - Runs `generate_verity.sh` to create a Merkle hash tree and sign it.
   - Produces verifiable metadata and signatures under `Binaries/metadata/`.

3. Bootloader Launch
   - Copies the resulting `rootfs.img` to the bootloader directory.
   - Starts the `secondary_bootloader`, which launches QEMU and boots the verified image.

# Usage

bash
./launch_boot.sh [options]
