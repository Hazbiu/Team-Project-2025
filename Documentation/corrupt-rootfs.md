# corrupt_rootfs.sh — quick guide

Flip **exactly 1 byte** in a dm-verity disk image to test your verification path.

## Modes
- `meta1` — flip 1 byte in the **196-byte VERI header** (at `meta_off + 64`).  
  *Expected:* dm table likely fails → early VFS panic (your module may not run).
- `sig1` — flip 1 byte in the **detached PKCS#7 signature** (at `sig_off`).  
  *Expected:* dm table loads; your module rejects PKCS#7 and panics with your message.

## Prereqs
- Image layout from your `generate_verity.sh` (VLOC locator at end of disk).
- Tools: `sudo`, `losetup`, `blockdev`, `python3`, `dd`.
- Symlink: `src/bootloaders/rootfs.img` → your actual image.

## Usage
```bash
# Make script executable
chmod +x src/build/corrupt_rootfs.sh

# Flip 1 byte in metadata header (expect early VFS panic)
src/build/corrupt_rootfs.sh meta1

# Flip 1 byte in signature (expect your module to reject PKCS#7)
src/build/corrupt_rootfs.sh sig1

# Relink back to pristine
src/build/corrupt_rootfs.sh --link-good
```

## Notes
- The script copies to `<image>.bad.img` unless `--inplace` is passed.
- It auto-relinks `src/bootloaders/rootfs.img` unless `--no-link` is passed.
- Verify symlink after corruption:
```bash
readlink -f src/bootloaders/rootfs.img  # should point to ...rootfs.bad.img
```

.
