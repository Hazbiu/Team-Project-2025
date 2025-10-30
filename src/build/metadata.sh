#!/bin/bash
set -euo pipefail

echo "[9/10] Generating RootFS dm-verity metadata..."

# Paths
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BOOT_DIR="$ROOT_DIR/boot"
OUT_DIR="$ROOT_DIR/build/Binaries/metadata"

mkdir -p "$OUT_DIR"

ROOTFS_IMG="$BOOT_DIR/rootfs.img"
META_OUT="$OUT_DIR/rootfs.verity.meta"
SIG_OUT="$OUT_DIR/rootfs.verity.meta.sig"
PRIV_KEY="$BOOT_DIR/bl_private.pem"

if [[ ! -f "$ROOTFS_IMG" ]]; then
    echo "❌ rootfs.img not found at $ROOTFS_IMG"
    exit 1
fi

echo "[9.1] Running veritysetup to compute hash tree + root hash..."
TMP_INFO=$(mktemp)

sudo veritysetup format "$ROOTFS_IMG" "$META_OUT" > "$TMP_INFO"
ROOT_HASH=$(grep "Root hash:" "$TMP_INFO" | awk '{print $3}')
echo "$ROOT_HASH" > "$OUT_DIR/root.hash"
rm "$TMP_INFO"

echo "✅ Root hash stored at $OUT_DIR/root.hash"
echo "   root hash = $ROOT_HASH"

echo "[9.2] Signing metadata..."
openssl dgst -sha256 -sign "$PRIV_KEY" -out "$SIG_OUT" "$META_OUT"

echo "✅ Metadata signature created: $SIG_OUT"

echo "[9.3] Copying metadata next to rootfs for final bootloader usage..."
cp "$META_OUT" "$BOOT_DIR/"
cp "$SIG_OUT" "$BOOT_DIR/"

echo "✅ Copied:"
echo "   $META_OUT → $BOOT_DIR/rootfs.verity.meta"
echo "   $SIG_OUT  → $BOOT_DIR/rootfs.verity.meta.sig"

echo "🎉 Metadata generation complete."
