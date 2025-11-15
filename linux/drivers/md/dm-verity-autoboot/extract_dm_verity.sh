#!/bin/bash

# Directory containing the source files
SRC_DIR="./"   # You are already inside drivers/md/dm-verity-autoboot/

# Output file
OUT_FILE="dm_verity_extracted_all.c"

echo ">> Extracting C code from:"
echo "   - dm-verity-autoboot.c"
echo "   - mapping.c"
echo "   - metadata_parse.c"
echo "   - signature_verify.c"
echo ""

# Write header
echo "/* Combined extraction of dm-verity autoboot files */" > "$OUT_FILE"
echo "" >> "$OUT_FILE"

# Append each existing file
for f in dm-verity-autoboot.c mapping.c metadata_parse.c signature_verify.c; do
    if [[ -f "$SRC_DIR/$f" ]]; then
        echo "/* ========== $f ========== */" >> "$OUT_FILE"
        cat "$SRC_DIR/$f" >> "$OUT_FILE"
        echo -e "\n\n" >> "$OUT_FILE"
        echo "[OK] Added $f"
    else
        echo "[WARN] File not found: $f"
    fi
done

echo ""
echo ">> Extraction complete!"
echo "Output saved to: $OUT_FILE"
