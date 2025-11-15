#!/bin/bash
set -e

IMAGE_NAME="secureos-builder"

echo "=============================================="
echo " Cleaning old QEMU and Docker processes"
echo "=============================================="

# 1) Kill QEMU on host that locks rootfs.img
if pgrep -f "qemu-system-x86_64" > /dev/null; then
    echo "Killing leftover QEMU processes..."
    sudo kill -9 $(pgrep -f "qemu-system-x86_64") || true
fi

# 2) Kill Docker containers still running 
if [ ! -z "$(docker ps -q)" ]; then
    echo "Stopping running Docker containers..."
    docker stop $(docker ps -q) >/dev/null 2>&1 || true
fi

# 3) Remove stopped containers too
if [ ! -z "$(docker ps -aq)" ]; then
    echo "Removing stopped Docker containers..."
    docker rm $(docker ps -aq) >/dev/null 2>&1 || true
fi

# 4) Remove lock files from previous QEMU runs
if [ -d "$(pwd)/build/Binaries" ]; then
    echo "Removing leftover .lck files..."
    rm -f "$(pwd)/build/Binaries/"*.lck || true
fi

echo ""
echo "=============================================="
echo " Building Docker image: $IMAGE_NAME"
echo "=============================================="

docker build -t $IMAGE_NAME .

echo ""
echo "=============================================="
echo " Running container and building system"
echo "=============================================="

docker run --privileged -it \
    -v "$(pwd)":/workspace \
    $IMAGE_NAME \
    bash -c "
        echo '--- Cleaning lock files inside container ---';
        rm -f /workspace/build/Binaries/*.lck || true;

        echo '--- Running build_artifacts.sh ---';
        cd /workspace/build;
        ./build_artifacts.sh;

        echo '--- Launching QEMU ---';
        ./launch_qemu.sh
    "
