FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    nasm \
    qemu-system-x86 \
    qemu-utils \
    dos2unix \
    build-essential \ 
    # for make menuconfig
    libncurses-dev \  
    # required by kernel parser
    bison flex \
    # required for cryptography(dm-verify requires caching)
    libssl-dev \
    # kernel build script
    bc \
    # to fetch kernel sources
    wget git \
    libelf-dev \
    && rm -rf /var/lib/apt/lists/*

# Set workdir inside container
WORKDIR /project

# Copy your source code into the container
COPY . .

# Ensure build.sh has proper line endings and permissions
RUN dos2unix build.sh && chmod +x build.sh

# Default command: build and run
CMD ["qemu-system-x86_64", "-drive", "format=raw,file=os-image.img,if=floppy","-nographic"]



