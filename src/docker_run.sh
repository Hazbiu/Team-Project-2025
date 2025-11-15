#!/bin/bash
set -e

IMAGE_NAME="secureos-builder"

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
        cd /workspace/build;
        echo '--- Running build_artifacts.sh ---';
        ./build_artifacts.sh;

        echo '--- Launching QEMU ---';
        ./launch_qemu.sh
    "
