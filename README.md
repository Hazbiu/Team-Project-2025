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

## Run container with mounted volume:

    docker run -it --rm -v ${PWD}:/project simple-os
## The container sees your changes, rebuilds os-image.img, and runs QEMU.

## Expected output

    Bootloader: Hello from Simple OS!
    Kernel: Hello from the Kernel!

## Quit QUEMU and return to PowerShell
    Ctrl + A, then X

# Build Linux Kernel with dm-verity (inside Docker)

This document describes how to build a Linux kernel with dm-verity support inside the project Docker container, generate a dummy rootfs and verity metadata, and boot it in QEMU.

> Assumes you already have the project Docker image (see `DOCKER_SETUP.md`) and Docker Desktop running.

---

# Build Linux Kernel with dm-verity (inside Docker)

1. Start the container (interactive) with your project mounted:
```bash
# from D:\Team_project\Team-Project-2025\simple-bootloader-os in PowerShell
docker run -it --rm -v ${PWD}:/project simple-os bash

## Download a stable kernel tarball (example v6.6.3)

wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.3.tar.xz
tar -xvf linux-6.6.3.tar.xz
cd linux-6.6.3
make defconfig
make menuconfig
# after running make menuconfig, go to Device Drivers -> Multiple devices driver support (RAID and LVM)
  -> Device mapper support (Y)
  -> Verity target support (Y)
# build Kernel
    ## in linux-6.6.3 folder
    make -j$(nproc)