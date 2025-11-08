#!/bin/bash
echo "=== Setting up Safe Test Environment ==="
mkdir -p safe_test_env
cd safe_test_env

echo "1. Generating test keys..."
openssl genrsa -out test_key.pem 2048 2>/dev/null
openssl rsa -in test_key.pem -pubout -out test_pubkey.pem 2>/dev/null

echo "2. Creating test data..."
echo "test-file-content" > test_data.txt

echo "✓ Safe test environment ready!"