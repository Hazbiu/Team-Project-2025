#!/bin/bash
set -e  #exit if any command fails

# Assemble bootloader and kernel
nasm -f bin boot.asm -o boot.bin
nasm -f bin kernel.asm -o kernel.bin

# Ensure kernel is exactly 512 bytes for sector alignment
truncate -s 512 kernel.bin

# Concatenates the boot sector and the kernel sector into one file
cat boot.bin kernel.bin > os-image.img

# Boot the image in QEMU as floppy A:
qemu-system-x86_64 -fda os-image.img
