#!/bin/bash
set -e

echo "============================================"
echo " WSL Helper: Ensure dos2unix & Run build.sh "
echo "============================================"

# --- Check and install dos2unix if missing ---
if ! command -v dos2unix &> /dev/null; then
    echo "dos2unix not found. Installing..."
    sudo apt update -y
    sudo apt install -y dos2unix
else
    echo "dos2unix already installed."
fi

# --- Convert all .sh files to Unix line endings ---
echo "Converting all .sh files to Unix line endings..."
find . -type f -name "*.sh" -exec dos2unix {} \;

# --- Make all .sh files executable ---
echo "Making all .sh files executable..."
find . -type f -name "*.sh" -exec chmod +x {} \;

# --- Run build.sh ---
echo "Running build.sh..."
./build.sh
