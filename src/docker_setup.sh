#!/bin/bash
set -e

echo "=== Updating system ==="
sudo apt update

echo "=== Installing required packages ==="
sudo apt install -y ca-certificates curl gnupg lsb-release

echo "=== Adding Docker's GPG key ==="
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "=== Adding Docker APT repository ==="
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "=== Updating APT sources ==="
sudo apt update

echo "=== Removing old docker.io if it exists ==="
sudo apt remove -y docker.io || true

echo "=== Installing Docker Engine (docker-ce) ==="
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "=== Enabling docker.socket (critical fix for VMware) ==="
sudo systemctl enable docker.socket
sudo systemctl start docker.socket

echo "=== Starting Docker daemon ==="
sudo systemctl restart docker

echo "=== Adding current user to docker group ==="
sudo usermod -aG docker $USER

echo ""
echo "=== Docker installation complete! ==="
echo "If this is your first run, log out & log back in to use docker without sudo."
echo "=== Rebooting system now ==="
sudo reboot
