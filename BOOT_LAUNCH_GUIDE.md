# Unified Boot & QEMU Launcher

This folder contains the scripts for preparing and launching the virtualized system using QEMU.

## Overview
The previous C-based secondary bootloader has been replaced by a Bash-based launcher.  
The new flow automates:
1. Building the root filesystem  
2. Generating dm-verity metadata  
3. Launching QEMU with the correct kernel and rootfs image  

## Usage

From the project root:
```bash
cd src/build
bash launch_boot.sh
