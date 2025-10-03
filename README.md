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

