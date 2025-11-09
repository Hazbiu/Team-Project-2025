# corrupt_rootfs.sh — quick guide

Flip **exactly 1 byte** in the dm-verity disk image to test your verification path.

## Modes

- `meta1` — flip 1 byte in the **196-byte VERI header** (at `meta_off + 64`).  
  **Expected:** dm-verity metadata changes → table/verification likely fails very early.

- `sig1` — flip 1 byte in the **detached PKCS#7 signature** (at `sig_off`).  
  **Expected:** dm-verity parameters still parse, but your module rejects the PKCS7 and panics with your message.

## What it operates on

By default (when run from `src/build`):

- Script path: `src/build/corrupt_rootfs.sh`
- Default image: `src/build/Binaries/rootfs.img`

This is the **same image** your bootloader passes to QEMU via:

```c
realpath("../build/Binaries/rootfs.img", img_abs)
```

So if you corrupt **in place**, the next boot will automatically use the corrupted image.

## Prereqs

- Image created by your `build_rootfs.sh` + `generate_verity.sh` pipeline:
  - Single ext4 filesystem on the whole disk
  - dm-verity hash tree + metadata + VLOC locator at the end
- Tools available:
  - `sudo`, `losetup`, `blockdev`, `python3`, `dd`, `sha256sum`

## Usage

```bash
# Make script executable (once)
chmod +x src/build/corrupt_rootfs.sh
```

### Recommended: corrupt in-place (bootloader picks it up automatically)

From `src/build`:

```bash
# Flip 1 byte in metadata header (VERI header)
# → expect early dm-verity / VFS failure
./corrupt_rootfs.sh meta1 --inplace

# Flip 1 byte in detached PKCS7 signature
# → expect your module to fail PKCS7 verification and panic
./corrupt_rootfs.sh sig1 --inplace
```

Then run your normal unified script / bootloader.  
The bootloader will still realpath `../build/Binaries/rootfs.img`, which is now corrupted.

### Create a separate corrupted copy (without touching the original)

```bash
# Creates Binaries/rootfs.bad.img
./corrupt_rootfs.sh meta1

# Or explicitly:
./corrupt_rootfs.sh sig1 Binaries/rootfs.img
```

In this mode:

- The original `Binaries/rootfs.img` stays pristine.
- The script creates `Binaries/rootfs.bad.img` and corrupts **that**.
- To boot from the corrupted image you would either:
  - Temporarily point QEMU/bootloader to `rootfs.bad.img`, or
  - Manually replace/swap filenames.

## Arguments summary

```text
./corrupt_rootfs.sh <meta1|sig1> [image-path] [--inplace]
```

- `meta1` / `sig1` : corruption mode
- `image-path`     : optional; defaults to `Binaries/rootfs.img` when omitted
- `--inplace`      : corrupt the target image in-place (no `.bad.img` copy)

## What the script actually does

1. Resolves the image path to an absolute path.
2. If not `--inplace`, copies it to `<image>.bad.img`.
3. Attaches the (possibly copied) image as a loop device (whole disk).
4. Reads the last 4 KiB, parses the `VLOC` locator to find:
   - `meta_off` (metadata header offset)
   - `sig_off` / `sig_len` (signature location)
5. Depending on the mode:
   - `meta1`:
     - Flips 1 byte at `meta_off + 64`
     - Prints SHA256 of the first 196 bytes before/after (proof of change)
   - `sig1`:
     - Flips 1 byte at `sig_off`
6. Detaches the loop device and prints the expected behavior at boot.
