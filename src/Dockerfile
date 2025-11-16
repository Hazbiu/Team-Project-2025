FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

# -----------------------------------------------------------
# Install required packages (full set)
# -----------------------------------------------------------
RUN apt-get update && apt-get install -y \
    sudo \
    qemu-utils \
    qemu-system-x86 \
    qemu-kvm \
    debootstrap \
    cryptsetup \
    kmod \
    e2fsprogs \
    rsync \
    openssl \
    python3 \
    python3-pip \
    ca-certificates \
    coreutils \
    xxd \
    util-linux \
    squashfs-tools \
    dosfstools \
    systemd \
    file \
    vim \
    git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------
# Workspace inside container
# -----------------------------------------------------------
WORKDIR /workspace

# -----------------------------------------------------------
# Copy project files from host into container
# -----------------------------------------------------------
COPY . /workspace

# -----------------------------------------------------------
# Ensure bzImage is copied correctly to /boot
# -----------------------------------------------------------
RUN mkdir -p /workspace/boot && \
    if [ -f "/workspace/bootloaders/bzImage" ]; then \
        cp /workspace/bootloaders/bzImage /workspace/boot/bzImage; \
    else \
        echo "WARNING: bzImage not found in bootloaders/"; \
    fi

# -----------------------------------------------------------
# Ensure build scripts are executable
# -----------------------------------------------------------
RUN chmod +x /workspace/build/*.sh || true

# -----------------------------------------------------------
# Fix permissions (rootfs folder sometimes gets root-owned)
# -----------------------------------------------------------
RUN chmod -R a+rwX /workspace || true

# -----------------------------------------------------------
# Print info message
# -----------------------------------------------------------
RUN echo "==================================================" && \
    echo " SECURE OS BUILDER - DOCKER IMAGE READY" && \
    echo " Inside the container you can run:" && \
    echo "   cd /workspace/build" && \
    echo "   ./build_artifacts.sh" && \
    echo "   ./launch_qemu.sh" && \
    echo "=================================================="

CMD ["/bin/bash"]
