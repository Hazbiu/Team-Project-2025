# Whole-Disk dm-verity Demo (No Initramfs, Detached PKCS7)

This repository is a self-contained demo of **whole-disk dm-verity** without an initramfs.

It shows how to:

- Build a Debian root filesystem into a **single ext4 disk image** (no GPT, no partitions).
- Append a **dm-verity Merkle tree** to that disk.
- Generate a **196-byte metadata header**, sign it with **PKCS#7** using an X.509 certificate, and store:
  - header
  - signature
  - a 4 KiB **locator footer** (`VLOC`)
  at the **end of the disk image**.
- Boot a Linux kernel under QEMU via a small **userspace bootloader**.
- Let a built-in **`dm-verity-autoboot` kernel module**:
  - verify the PKCS7 signature against the kernel trusted keyring
  - create a dm-verity mapping using `dm_early_create()`
  - mount `/dev/dm-0` as the read-only **verified root filesystem**.
- Intentionally **corrupt** the image and see verification fail.

> **No initramfs is required**: dm-verity is set up by a kernel module during early boot, directly from the whole-disk image.

---

## 1. High-Level Boot Flow

1. **Userspace bootloader** (QEMU launcher):
   - Locates `rootfs.img` (a whole-disk image containing ext4 + verity data).
   - Launches `qemu-system-x86_64` with:
     - `-kernel kernel_image.bin`
     - `-drive …,file=rootfs.img` as **virtio-blk** (`/dev/vda` in guest)
     - Kernel command line:
       ```text
       console=ttyS0,115200 loglevel=7        dm_verity_autoboot.autoboot_device=/dev/vda        root=/dev/dm-0 rootfstype=ext4 rootwait rootdelay=10
       ```

2. **Kernel + `dm-verity-autoboot` module**:
   - Waits until `/dev/vda` appears.
   - Reads the **last 4 KiB** of the device and examines the magic:
     - `VERI` → legacy attached 4 KiB footer (header + PKCS7 in one block)
     - `VLOC` → **detached footer**: 4 KiB locator pointing to:
       ```text
       [ ext4 data ][ Merkle tree ][ 4K header ][ PKCS7 sig ][ 4K locator ]
       ```
   - Reads the metadata header and PKCS7 signature regions.
   - Verifies the PKCS7 signature against the **kernel trusted keyring**.
   - If verification succeeds, calls `dm_early_create()` to create:
     - name: `"verity_root"`  → usually `/dev/dm-0`
   - The kernel then mounts `root=/dev/dm-0` as **ext4**, read-only, verified.

3. If verification **fails**:
   - The module calls `panic()` with a clear message:
     - e.g. `dm-verity-autoboot: untrusted rootfs footer`
     - or `dm-verity-autoboot: untrusted detached metadata`.

---

## 2. Repository Layout (Assumed)


```text
repo/
  boot/                # signing keys
    bl_private.pem     # private key used to sign verity header
    bl_cert.pem        # certificate trusted by kernel keyring

  bootloaders/
    bootloader.c       # QEMU launcher (user-space "bootloader")
    kernel_image.bin   # Linux kernel image with dm-verity-autoboot built-in
    secondary_bootloader  # compiled binary (bootloader executable)

  build/               # build scripts and output
    launch_boot.sh        # unified boot script (name may differ in your repo)
    build_rootfs.sh
    generate_verity.sh
    corrupt_rootfs.sh
    Binaries/
      rootfs/          # chroot tree for Debian rootfs (debootstrap output)
      rootfs.img       # final disk image (ext4 + hash tree + metadata)
      metadata/        # verity metadata artifacts
```

> If your filenames differ, adjust the commands below accordingly.  
> The scripts themselves are path-relative and assume this kind of layout.

---

## 3. Components

### 3.1 `build_rootfs.sh` — Build the Root Filesystem Image

**Purpose:**  
Create a **single ext4 filesystem** on a raw disk image (`rootfs.img`), without GPT or partitions, and copy a minimal Debian system into it.

**What it does:**

1. **Create base Debian rootfs** (in `Binaries/rootfs`):
   - Uses `debootstrap` for `bookworm` (`amd64`).
   - Installs core packages:
     - `systemd`, `systemd-sysv`, `udev`
     - `passwd`, `login`, `sudo`
     - `net-tools`, `iproute2`, `ifupdown`
     - `openssh-server`
     - `vim`, `less`

2. **Basic configuration inside chroot:**
   - Root password: `root`
   - User:
     - name: `keti`
     - password: `keti`
     - added to `sudo` group.
   - Hostname:
     ```text
     secureboot-demo
     ```
   - Network configuration (`/etc/network/interfaces`):
     ```text
     auto lo
     iface lo inet loopback

     auto eth0
     iface eth0 inet dhcp
     ```

3. **Build the disk image:**
   - Estimates used size (`du`), adds ~20% + 100 MB margin.
   - Adds extra space reserved for:
     - dm-verity Merkle tree
     - metadata header + signature + locator
   - Creates a sparse image:  
     `Binaries/rootfs.img` of size `DISK_SIZE_MB`.
   - Creates an **ext4 filesystem on the whole image** (no partition table):
     ```bash
     mkfs.ext4 -F -L rootfs "$OUTPUT_IMG"
     ```
   - Mounts the image, copies rootfs via `rsync`, then unmounts.

4. Prints summary and reminds you to run the **dm-verity metadata generation** script next.

---

### 3.2 `generate_verity.sh` — Generate dm-verity Metadata

**Purpose:**  
Take `rootfs.img` and:

- Compute **dm-verity Merkle tree** directly on the image.
- Compute the **root hash** and **salt**.
- Build a **196-byte metadata header** (`VERI`).
- Sign it with **PKCS7** using your key pair.
- Write:
  - metadata header
  - PKCS7 signature
  - 4 KiB **VLOC** locator footer
  into the **end of the disk image**.

**Inputs:**

- Disk image: `build/Binaries/rootfs.img`
- Keys:
  - Private key: `../boot/bl_private.pem`
  - Certificate: `../boot/bl_cert.pem`

**Artifacts (output to `build/Binaries/metadata/`):**

- `verity_info.txt` — human-readable `veritysetup format` output.
- `root.hash` — Merkle root hash (hex).
- `verity_header.bin` — 196-byte metadata header.
- `verity_header.sig` — PKCS7 detached signature (DER).
- `verity_locator.bin` — 4 KiB locator footer (`VLOC`).

**On-disk layout (end of the image):**

```text
[ ...ext4 data... ]
[ Merkle hash tree @ HASH_OFFSET ]
[ 4K-aligned metadata header @ META_OFFSET ]
[ PKCS7 detached signature @ SIG_OFFSET ]
[ 4 KiB VLOC locator footer @ LOCATOR_OFFSET = end-of-disk - 4096 ]
```

**Key steps inside the script:**

1. Attach `rootfs.img` as a loop device.
2. Read ext4 geometry via `dumpe2fs`:
   - block size
   - block count
3. Compute how big the **Merkle tree** would be (via Python).
4. Shrink the filesystem (if needed) to make room for the tree + metadata:
   - Uses `e2fsck` and `resize2fs`.
5. Run `veritysetup format` with:
   - `--no-superblock`
   - same device for data and hash device
   - `--hash-offset` pointing after the filesystem data.
6. Extract **root hash** and **salt** from `veritysetup` output.
7. Build the 196-byte `verity_metadata_header` in Python:
   - `magic = "VERI"`
   - `version = 1`
   - `data_blocks`, `hash_start_sector`
   - `data_block_size`, `hash_block_size`
   - `hash_algorithm = "sha256"`
   - `root_hash` (32 bytes)
   - `salt` (up to 64 bytes)
   - `salt_size`
8. Sign the header with `openssl smime -sign` (PKCS7 DETACHED, DER).
9. Compute offsets for:
   - metadata (4K aligned)
   - signature (4K aligned)
   - locator (final 4 KiB)
10. Build `VLOC` (locator) structure in Python:
    - magic = `"VLOC"`
    - version
    - `meta_off`, `meta_len`
    - `sig_off`, `sig_len`
11. `dd` the metadata header, signature, and locator into the correct offsets on the loop device.

---

### 3.3 `bootloader.c` — User-space QEMU Launcher

**Purpose:**  
Minimal userspace “bootloader” that:

- Finds the rootfs disk image.
- Builds the correct `-drive` option for QEMU.
- Passes a kernel command line suitable for **dm-verity-autoboot**.
- Starts QEMU.

**Behavior:**

- Resolves `rootfs.img` absolute path:
  ```c
  realpath("../build/Binaries/rootfs.img", img_abs)
  ```
- Constructs QEMU drive string:
  ```c
  "if=none,id=drv0,format=raw,media=disk,file=%s"
  ```
- Constructs kernel cmdline:
  ```text
  console=ttyS0,115200 loglevel=7   dm_verity_autoboot.autoboot_device=/dev/vda   root=/dev/dm-0 rootfstype=ext4 rootwait rootdelay=10
  ```
- Launches:
  ```c
  const char *argv[] = {
      "qemu-system-x86_64",
      "-m", "1024",
      "-machine", "q35,accel=tcg",
      "-cpu", "max",
      "-nodefaults",
      "-nographic",
      "-serial", "mon:stdio",
      "-d", "guest_errors",
      "-kernel", "kernel_image.bin",
      "-drive",  drive_opt,
      "-device", "virtio-blk-pci,drive=drv0",
      "-append", append,
      NULL
  };
  ```

**Build:**

From the `bootloaders/` directory:

```bash
gcc -O2 -Wall -o secondary_bootloader bootloader.c
```

The unified script assumes the binary is called **`secondary_bootloader`**.

---

### 3.4 `dm-verity-autoboot.c` — Kernel Module

**Purpose:**  
Built-in kernel module that:

- Runs during late init.
- Resolves `dm_verity_autoboot.autoboot_device` (e.g. `/dev/vda`).
- Detects attached vs detached verity footer.
- Verifies PKCS7 signature over the **196-byte metadata header**.
- Calls `dm_early_create()` to create a `verity` dm device (`verity_root`).

**Key points:**

- Parameter:
  ```c
  static char *autoboot_device;
  module_param(autoboot_device, charp, 0);
  ```
- Resolves `/dev/vda` using `block_class` iteration, not `/dev` nodes:
  - Safe for early boot (before udev).
- Two footer modes:
  - **Attached (`VERI`)**:
    - Last 4 KiB is `verity_metadata_ondisk`.
    - Includes header + PKCS7 blob in one block.
  - **Detached (`VLOC`)**:
    - Last 4 KiB is `verity_footer_locator` (VLOC).
    - Points to:
      - `meta_off` / `meta_len` — metadata header region.
      - `sig_off` / `sig_len` — PKCS7 signature region.
- Uses kernel **PKCS7** helpers and `verification.h`:
  - `pkcs7_parse_message`
  - `pkcs7_supply_detached_data` (for detached mode)
  - `pkcs7_verify`
  - `pkcs7_get_digest`
- Verifies that:
  - signature is from a **trusted key** (kernel keyring).
  - digest matches `SHA256(header[0..VERITY_FOOTER_SIGNED_LEN-1])`.

**Creating the dm-verity mapping:**

- Builds dm-verity table params:

  ```text
  <version>
  <data_dev_major:minor> <hash_dev_major:minor>
  <data_block_size> <hash_block_size>
  <num_data_blocks> <hash_start_block>
  <hash_algorithm> <root_hash_hex> <salt_hex>
  ```

- Uses the same device for data + hash:
  - `data` is blocks `[0 .. data_blocks-1]`
  - hash tree starts at `hash_start_block = data_blocks`
- Calls:
  ```c
  dm_early_create(&dmi, spec_array, params_array);
  ```
- Creates device named `"verity_root"`, read-only.
- Root device becomes `/dev/dm-0` (via `root=/dev/dm-0`).

If anything fails, the module logs detailed info and **panics** to abort boot.

---

### 3.5 `corrupt_rootfs.sh` — Verity Corruption Helper

**Purpose:**  
Convenience tool to flip a single byte in the disk image so you can **see dm-verity fail**:

- `meta1` → corrupt metadata header
- `sig1` → corrupt PKCS7 signature

**Usage:**

```bash
./corrupt_rootfs.sh <meta1|sig1> [image-path] [--inplace]
```

- `image-path` (optional): defaults to `./Binaries/rootfs.img` when run from `build/`.
- `--inplace`:
  - if set, modifies the image **in place**.
  - otherwise creates `*.bad.img`:

    - e.g. `rootfs.bad.img`

**How it works:**

1. Finds the **locator footer** (VLOC) at end of disk:
   - `locator_offset = disk_size - 4096`
   - Reads its fields to get:
     - `meta_off`
     - `sig_off`
     - `sig_len`
2. For mode `meta1`:
   - Flips one byte at `META_OFFSET + 64`.
   - Prints SHA256 digest of the 196-byte header **before/after** as proof.
3. For mode `sig1`:
   - Flips one byte at `SIG_OFFSET`.
4. Detaches loop device and prints expectations:
   - `meta1`:
     - header changed → dm-verity parameters / verification should fail early.
   - `sig1`:
     - header unchanged, but PKCS7 signature invalid → **signature verification fails** in module.

To test, you can:

- Either boot the corrupted image directly (with `--inplace`), or
- Point your bootloader to the `*.bad.img` copy.

---

## 4. Unified Boot Script

The first script you pasted is a **unified boot script** that:

1. Builds the root filesystem.
2. Generates dm-verity metadata.
3. Launches the bootloader.

For the README, we’ll call it `launch_boot.sh` (adjust to your actual filename).

**Script responsibilities:**

1. **Build rootfs**:
   ```bash
   [1/3] Building Root Filesystem...
   bash "$BUILD_DIR/build_rootfs.sh"
   ```
2. **Generate dm-verity metadata**:
   ```bash
   [2/3] Generating dm-verity metadata...
   bash "$BUILD_DIR/generate_verity.sh"
   ```
3. **Launch bootloader**:
   - Verifies that `Binaries/rootfs.img` exists.
   - `cd` into `../bootloaders`.
   - Run:
     ```bash
     sudo ./secondary_bootloader
     ```

If any step fails, the script exits with an error message; otherwise it prints that all stages completed and the system is booted.

---

## 5. Prerequisites

On the **host system**, you need:

- **QEMU**:
  - `qemu-system-x86_64`
- **Rootfs and filesystem tools**:
  - `debootstrap`
  - `e2fsprogs` (`mkfs.ext4`, `resize2fs`, `e2fsck`, `dumpe2fs`)
  - `rsync`
- **dm-verity tooling**:
  - `cryptsetup` / `veritysetup`
- **Loop & block tools**:
  - `losetup`
  - `blockdev`
- **Crypto tools**:
  - `openssl`
- **Language runtimes**:
  - `bash`
  - `python3`
- A Linux kernel configured with:
  - Device mapper & dm-verity support
  - Kernel PKCS7 & X.509 signature verification
  - The `dm-verity-autoboot` module built in.

You also need:

- A signing keypair:
  - `boot/bl_private.pem`
  - `boot/bl_cert.pem`
- The certificate must be trusted by the kernel keyring (e.g. built into the kernel or loaded appropriately).

---

## 6. How to Build and Run the Demo

Assuming you’re in the `build/` directory:

### 6.1 One-shot: unified script

```bash
cd build
./launch_boot.sh
```

What it does:

1. `build_rootfs.sh` → creates `Binaries/rootfs.img`.
2. `generate_verity.sh` → appends Merkle tree + metadata + VLOC.
3. Runs `sudo ../bootloaders/secondary_bootloader`, which:
   - Launches QEMU with `kernel_image.bin` + `rootfs.img`.
   - Kernel boots, module verifies, mounts `/dev/dm-0` as root.

### 6.2 Manual step-by-step

If you prefer manual control:

```bash
cd build

# 1) Build root filesystem image
./build_rootfs.sh

# 2) Generate dm-verity metadata, header, signature, locator
./generate_verity.sh

# 3) (In bootloaders/) build the bootloader if not yet done
cd ../bootloaders
gcc -O2 -Wall -o secondary_bootloader bootloader.c

# 4) Run bootloader (QEMU)
sudo ./secondary_bootloader
```

You should see:

- Kernel logs on serial (`ttyS0`).
- `dm-verity-autoboot` logs describing:
  - autodetected footer mode (`VERI` or `VLOC`)
  - parsed metadata
  - PKCS7 verification status
  - dm-verity mapping creation
- Eventually a login prompt on the Debian system (`username: keti`, password `keti`).

---

## 7. Testing Verification Failures

### 7.1 Corrupt metadata header (`meta1`)

From `build/`:

```bash
./corrupt_rootfs.sh meta1 --inplace
```

Then boot:

```bash
cd ../bootloaders
sudo ./secondary_bootloader
```

Expected behavior:

- dm-verity-autoboot will detect that the metadata header digest no longer matches what the signature expects.
- You should see logs indicating failure of signature / digest checks.
- The module calls `panic()` and stops boot.

### 7.2 Corrupt signature (`sig1`)

```bash
cd build
./corrupt_rootfs.sh sig1 --inplace
```

Then boot as before.

Expected behavior:

- The metadata header is unchanged, but the PKCS7 blob is damaged.
- PKCS7 parsing or verification fails.
- Module logs indicate “signer not trusted” / digest mismatch.
- System panics, refusing to boot untrusted rootfs.

Instead of `--inplace`, you can generate a `.bad.img` and temporarily point your bootloader to it (e.g. modify `bootloader.c` path) to keep a pristine image.

---

## 8. Notes & Customization

- Paths (`../build/Binaries/rootfs.img`, `../boot/bl_private.pem`, etc.) are hardcoded in the scripts and bootloader.
  - If you change your directory layout, adjust these constants.
- This demo uses:
  - **Whole disk** as verity target (`/dev/vda`).
  - A single **ext4 filesystem** spanning the data area.
  - A **detached** PKCS7 signature and locator scheme (`VLOC`).
- The module also supports an **attached** 4 KiB footer mode (`VERI`), though your current scripts build the detached layout.
- The root filesystem is intentionally **read-only** due to dm-verity:
  - For changes, you must rebuild the image (`build_rootfs.sh` + `generate_verity.sh`).

---

## 9. Quick Troubleshooting

- **`rootfs.img not found`**:
  - Ensure `build_rootfs.sh` completed successfully and that `Binaries/rootfs.img` exists.
- **`ERROR: bl_private.pem not found` / `bl_cert.pem not found`**:
  - Place your keypair in `boot/` or adjust paths in `generate_verity.sh`.
- **QEMU cannot find kernel**:
  - Ensure `kernel_image.bin` is present in `bootloaders/`.
- **No dm-verity logs in kernel output**:
  - Check that:
    - The module is built in.
    - The kernel cmdline includes `dm_verity_autoboot.autoboot_device=/dev/vda`.
- **Boot hangs waiting for `/dev/dm-0`**:
  - Likely mapping creation failed.
  - Look for `dm-verity-autoboot` messages in the serial output.

---

