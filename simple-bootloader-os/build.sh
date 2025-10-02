#!/bin/bash
set -e

# Assemble bootloader and kernel
nasm -f bin boot.asm -o boot.bin
nasm -f bin kernel.asm -o kernel.bin

# Ensure kernel is exactly 512 bytes for sector alignment
truncate -s 512 kernel.bin

# Combine into a single floppy image
cat boot.bin kernel.bin > os-image.img

# Run in QEMU
qemu-system-x86_64 -fda os-image.img
