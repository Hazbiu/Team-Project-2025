#!/bin/bash
set -euo pipefail

echo "[9/10] Generating dm-verity metadata (same partition layout)..."

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$BUILD_DIR/Binaries"
META_DIR="$BIN_DIR/metadata"

ROOTFS_IMG="$BIN_DIR/rootfs.img"
ROOT_HASH_FILE="$META_DIR/root.hash"
SIG_FILE="$META_DIR/root.hash.sig"
PRIV_KEY="$BUILD_DIR/../boot/bl_private.pem"

mkdir -p "$META_DIR"

if [[ ! -f "$ROOTFS_IMG" ]]; then
    echo "❌ rootfs.img not found at: $ROOTFS_IMG"
    exit 1
fi

if [[ ! -f "$PRIV_KEY" ]]; then
    echo "❌ bl_private.pem not found at: $PRIV_KEY"
    exit 1
fi

echo "[9.1] Detecting filesystem layout..."
BLOCK_SIZE=$(dumpe2fs -h "$ROOTFS_IMG" 2>/dev/null | awk '/Block size:/ {print $3}')
BLOCK_COUNT=$(dumpe2fs -h "$ROOTFS_IMG" 2>/dev/null | awk '/Block count:/ {print $3}')

echo "  Block size:  $BLOCK_SIZE"
echo "  Block count: $BLOCK_COUNT"

HASH_OFFSET=$((BLOCK_COUNT * BLOCK_SIZE))

echo "[9.2] Appending dm-verity hash tree to the image..."
sudo veritysetup format \
    --hash-offset="$HASH_OFFSET" \
    "$ROOTFS_IMG" "$ROOTFS_IMG" \
    > "$META_DIR/info.tmp"

ROOT_HASH=$(grep "Root hash:" "$META_DIR/info.tmp" | awk '{print $3}')
echo "$ROOT_HASH" > "$ROOT_HASH_FILE"
rm "$META_DIR/info.tmp"

echo "✅ Root hash stored → $ROOT_HASH_FILE"
echo "   Root hash = $ROOT_HASH"

echo "[9.3] Signing root hash..."
openssl dgst -sha256 -sign "$PRIV_KEY" -out "$SIG_FILE" "$ROOT_HASH_FILE"

echo "✅ Signature stored → $SIG_FILE"

sudo chown -R "$USER:$USER" "$META_DIR"

echo
echo "🎯 FINAL ARTIFACTS:"
echo "   • $ROOTFS_IMG        (contains filesystem + dm-verity hash tree)"
echo "   • $ROOT_HASH_FILE    (root hash used by kernel/bootloader)"
echo "   • $SIG_FILE          (signature for secure validation)"
echo
echo "🎉 Metadata generation complete."
