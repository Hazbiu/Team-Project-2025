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

## Run the Docker Container

    docker run -it --rm simple-os
  ```

## Expected output

    Bootloader: Hello from Simple OS!
    Kernel: Hello from the Kernel!
