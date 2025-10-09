# Team-Project-2025

# Running Simple Bootloader OS in Docker

This project can be built and run inside a Docker container so that everyone has a **uniform environment**.

---

## Prerequisites

- Install **Docker Desktop** (make sure it is running).
- Clone this repository and navigate into the project folder:
  ```powershell
  cd Team-Project-2025\simple-bootloader-os

## Build the Docker Image

    docker build -t simple-os .

## OR Force a fresh build (no cache):

    docker build --no-cache -t simple-os .
Use this option if you’ve updated the Dockerfile or run into errors during the normal build. 
It ensures all dependencies are installed from scratch.

## Run container with mounted volume:

    docker run -it --rm -v ${PWD}:/project simple-os
## The container sees your changes, rebuilds os-image.img, and runs QEMU.

## Expected output

    Bootloader: Hello from Simple OS!
    Kernel: Hello from the Kernel!

## Quit QUEMU and return to PowerShell
    Ctrl + A, then X


# Build Linux Kernel with dm-verity (inside Docker)

1. Start the container (interactive) with your project mounted:
```bash
# from D:\Team_project\Team-Project-2025\simple-bootloader-os in PowerShell
docker run -it -v ${PWD}:/project simple-os bash

cd /project
rm -f linux-6.6.3.tar.xz
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.3.tar.xz

cd /root
tar -xf /project/linux-6.6.3.tar.xz
cd linux-6.6.3

make defconfig
./scripts/config --enable BLK_DEV_DM
./scripts/config --enable DM_VERITY
./scripts/config --enable DM_VERITY_FEC
./scripts/config --enable CRYPTO_SHA256
make olddefconfig

make -j$(nproc)
cp arch/x86/boot/bzImage /project/