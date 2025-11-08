#!/bin/bash
echo "=== Setting up Advanced Test Environment ==="
echo "Note: This requires root privileges"
mkdir -p test_env
cd test_env

echo "Creating test disk image..."
dd if=/dev/zero of=test_disk.img bs=1M count=10 status=none
echo "✓ Test environment setup complete"