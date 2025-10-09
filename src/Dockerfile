FROM ubuntu:24.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update & install packages
RUN apt-get update && apt-get install -y \
    build-essential pkg-config git \
    libssl-dev openssl \
    qemu-system-x86 qemu-utils \
    libncurses-dev flex bison libelf-dev libudev-dev \
    libpci-dev libiberty-dev liblz4-tool zstd cpio \
    initramfs-tools busybox \
    gdb strace xxd \
    && rm -rf /var/lib/apt/lists/*
    
# Create working directory
WORKDIR /workspace

# Copy project files into container
COPY . /workspace

# Default command: open shell
CMD ["/bin/bash"]
