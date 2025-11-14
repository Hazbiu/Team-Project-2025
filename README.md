# dm-verity Secure Boot System

A production-ready implementation of dm-verity with PKCS7 signature verification for secure Linux boot environments. This system provides cryptographic verification of the root filesystem before mounting, ensuring boot-time integrity and authenticity.

## Overview

This solution implements a complete secure boot chain where:

1. The host launches QEMU directly with a Linux kernel and a raw disk image.
2. A **modular** in-kernel helper (`dm-verity-autoboot` family) performs dm-verity setup and signature verification.
3. The verified filesystem is mounted as the root device.

The early-boot helper is now split into four logical components:

- `dm-verity-autoboot.c` – orchestration, device discovery, footer detection.
- `metadata_parse.c` – safe parsing and logging of metadata headers.
- `signature_verify.c` – PKCS7 verification for attached/detached metadata.
- `mapping.c` – construction of the dm-verity device-mapper target.

### Key Features

- **Whole-disk dm-verity** – No partition table overhead; entire disk is used efficiently.  
- **Detached PKCS7 signatures** – Metadata and signatures stored separately at disk end.  
- **Built-in kernel verification** – No initramfs required; verification happens in kernel space.  
- **Zero-touch boot** – Fully automated verification and mapping to `/dev/dm-0`.  
- **Modular kernel design** – Clear separation of parsing, verification, and mapping logic.  
- **Robustness suite** – `integrity_tests.sh` to fuzz metadata and test parser hardening.  

---

## Architecture

### On-Disk Layout

```text
[ext4 filesystem data] [dm-verity hash tree] [metadata header] [PKCS7 signature] [VLOC locator]
                                              ↑                 ↑                   ↑
                                              196 bytes         DER format          4 KiB footer
```

The VLOC (Verity LOCator) footer at the end of the disk provides offsets to the metadata and signature regions, enabling the kernel module to locate and verify all components.

### Boot Flow

```text
┌────────────────────┐
│   Host System      │  Runs src/build/launch_qemu.sh
│ (user space)       │  QEMU + kernel + rootfs.img
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│   Linux Kernel     │  Boots, initializes virtio-blk (/dev/vda)
└─────────┬──────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ dm-verity autoboot stack                    │
│  - dm-verity-autoboot.c                     │
│  - metadata_parse.c                         │
│  - signature_verify.c                       │
│  - mapping.c                                │
│                                              │
│ 1. Read tail 4 KiB → detect VERI vs VLOC     │
│ 2. Read metadata + PKCS7 signature           │
│ 3. Verify PKCS7 via kernel trusted keyring   │
│ 4. Create dm-verity mapping (/dev/dm-0)      │
└─────────┬────────────────────────────────────┘
          │
          ▼
┌────────────────────┐
│    Root Mount      │  Kernel mounts /dev/dm-0 as ext4 root
│     (verified)     │  System boots from verified filesystem
└────────────────────┘
```

The kernel command line used by QEMU is:

```text
console=ttyS0 loglevel=7 root=/dev/dm-0 rootfstype=ext4 rootwait dm_verity_autoboot.autoboot_device=/dev/vda dm_verity_autoboot.mode=verify_and_map
```

---

## Prerequisites

### System Requirements

- Linux-based development environment (Ubuntu 20.04+ or Debian 11+ recommended)
- Minimum 4 GB RAM for building
- 10 GB free disk space
- `sudo`/root access for image creation and loop devices

### Software Dependencies

```bash
sudo apt update

# 1. Build tools and essentials
sudo apt install -y     build-essential     git     wget     curl     ca-certificates     pkg-config     libssl-dev

# 2. QEMU virtualization
sudo apt install -y qemu-system-x86 qemu-utils

# 3. Root filesystem tools
sudo apt install -y     debootstrap     e2fsprogs     rsync

# 4. dm-verity tools
sudo apt install -y cryptsetup veritysetup

# 5. Block device utilities
sudo apt install -y util-linux

# 6. Cryptographic tools
sudo apt install -y openssl
```

### Kernel Requirements

The custom kernel helper requires:

- Linux kernel 5.10 or later  
- `CONFIG_DM_VERITY=y` (dm-verity support)  
- `CONFIG_SYSTEM_DATA_VERIFICATION=y` (PKCS7 verification)  
- `CONFIG_CRYPTO_SHA256=y` (SHA-256 hashing)  

The repository expects an in-tree kernel under `linux/`, with the module sources placed in:

```text
linux/drivers/md/dm-verity-autoboot/
    dm-verity-autoboot.c
    mapping.c / mapping.h
    metadata_parse.c / metadata_parse.h
    signature_verify.c / signature_verify.h
    Makefile
```

The built kernel image is exported to `src/bootloaders/kernel_image.bin`.

---

## Project Structure

High-level layout:

```text
.
├── linux/                         # Linux kernel tree (git submodule)
│   └── drivers/md/dm-verity-autoboot/
│       ├── dm-verity-autoboot.c   # Orchestrator (device + footer handling)
│       ├── mapping.c/.h           # dm-verity mapping construction
│       ├── metadata_parse.c/.h    # Safe header parsing + logging
│       ├── signature_verify.c/.h  # PKCS7 verification (attached/detached)
│       └── Makefile
├── rootfs/                        # Rootfs seed/configuration
└── src/
    ├── boot/
    │   ├── bl_private.pem         # Signing private key (generated locally)
    │   └── bl_cert.pem            # Signing certificate
    ├── bootloaders/
    │   ├── bzImage                # Built kernel image
    │   ├── kernel_image.bin       # Copy used by QEMU
    │   └── qemu_main.sh           # (Optional) helper / menu launcher
    └── build/
        ├── Binaries/
        │   ├── rootfs.img         # Final whole-disk ext4 image
        │   └── metadata/          # dm-verity artifacts
        ├── build_artifacts.sh     # Rootfs + verity orchestration
        ├── build_rootfs.sh        # Creates ext4 disk image
        ├── generate_verity.sh     # Builds hash tree + metadata + VLOC
        ├── integrity_tests.sh     # Robustness & fuzz testing suite
        └── launch_qemu.sh         # QEMU launcher (no separate bootloader)
├── Dockerfile
└── README.md
```

---

## Component Details

### 1. `build_rootfs.sh`

Creates a minimal Debian-based root filesystem on a single-disk image without partitions.

**Features:**

- Uses `debootstrap` to create base Debian system.  
- Configures default users and networking.  
- Sizes disk to accommodate filesystem + dm-verity overhead.  
- Creates ext4 directly on the whole disk (no GPT).  

**Output:** `src/build/Binaries/rootfs.img`  

---

### 2. `generate_verity.sh`

Generates dm-verity Merkle tree and cryptographic metadata.

**Process:**

1. Analyzes filesystem geometry.  
2. Allocates space for hash tree.  
3. Generates hash tree with `veritysetup`.  
4. Builds 196-byte metadata header.  
5. Signs header with PKCS7 (detached signature).  
6. Writes metadata, signature, and VLOC locator to disk end.  

**Output (under `src/build/Binaries/metadata/`):**

- `root.hash` – Root hash (hex).  
- `verity_header.bin` – Metadata header (196 bytes).  
- `verity_header.sig` – PKCS7 signature (DER).  
- `verity_locator.bin` – VLOC footer (4 KiB).  
- `verity_info.txt` – Human-readable summary.  

---

### 3. `build_artifacts.sh`

Unified build script for preparing boot artifacts.

**Workflow:**

1. Runs `build_rootfs.sh`.  
2. Runs `generate_verity.sh`.  
3. Verifies that `Binaries/rootfs.img` exists.  

Usage:

```bash
cd src/build/
./build_artifacts.sh
```

This script only prepares artifacts; it does **not** launch QEMU.

---

### 4. `launch_qemu.sh`

QEMU launcher (replaces the older “userspace bootloader”).

**Responsibilities:**

- Uses `src/bootloaders/kernel_image.bin`.  
- Attaches `Binaries/rootfs.img` as virtio-blk.  
- Sets kernel cmdline parameters for dm-verity autoboot.

Excerpt:

```bash
KERNEL="../bootloaders/kernel_image.bin"
ROOTFS="Binaries/rootfs.img"

APPEND_CMD="console=ttyS0 loglevel=7 root=/dev/dm-0 rootfstype=ext4 rootwait dm_verity_autoboot.autoboot_device=/dev/vda dm_verity_autoboot.mode=verify_and_map"

exec qemu-system-x86_64   -kernel "$KERNEL"   -drive if=none,file="$ROOTFS",format=raw,id=hd0   -device virtio-blk-pci,drive=hd0   -append "$APPEND_CMD"   -m 1024M -nographic
```

You can customize RAM, CPUs, and acceleration directly in this script.

---

### 5. `dm-verity-autoboot.c` (orchestrator)

Core early-boot helper, compiled into the kernel:

- Reads kernel command line (`dm_verity_autoboot.autoboot_device` and `mode`).  
- Resolves block device (e.g. `/dev/vda`) *without* depending on `/dev` nodes.  
- Reads last 4 KiB of the device and distinguishes:
  - **VERI** – attached 4 KiB footer with header + PKCS7.  
  - **VLOC** – detached layout with locator referencing metadata + signature.  
- For VERI:
  - Reads and logs attached footer.  
  - Calls `verify_signature_pkcs7_attached()`.  
  - Validates structure via `verity_parse_metadata_header()`.  
  - Calls `verity_create_mapping()` to build dm-verity target.  
- For VLOC:
  - Reads metadata and detached PKCS7 by offsets/lengths.  
  - Calls `verify_signature_pkcs7_detached()`.  
  - Validates structure via `verity_parse_metadata_header()`.  
  - Calls `verity_create_mapping()`.  

On failure, the helper panics the kernel in a **fail-secure** way.

---

### 6. `mapping.c` / `mapping.h`

Responsible for building the device-mapper table and calling `dm_early_create()`.

**Key tasks:**

- Extracts and validates fields from `struct verity_metadata_header`.  
- Enforces supported algorithms (`sha256` only).  
- Computes `num_data_sectors` and hash region offsets.  
- Converts binary `root_hash` and `salt` to ASCII hex.  
- Assembles a dm-verity table like:

  ```text
  <version> <data_dev> <hash_dev> <data_bs> <hash_bs>   <num_blocks> <hash_start_block> <algo> <root_hex> <salt_hex>
  ```

- Calls `dm_early_create()` with a single read-only “verity_root” target.  

---

### 7. `metadata_parse.c` / `metadata_parse.h`

Safe parsing and logging of verity metadata headers.

**Responsibilities:**

- Encodes root hash and salt to hex for debug logging.  
- Computes:
  - `covered_bytes` (approx. filesystem size).  
  - `hash_start_bytes` for sanity checks.  
- Logs all key fields:

  - version  
  - data/hash block sizes  
  - `data_blocks`  
  - `hash_start_sector`  
  - salt size and hex salt  
  - algorithm name  

The parser is used by the orchestrator *after* signature verification to avoid parsing untrusted data.

---

### 8. `signature_verify.c` / `signature_verify.h`

PKCS7 signature verification logic.

**Capabilities:**

- `verify_signature_pkcs7_attached()`:
  - Computes SHA-256 over the first 196 bytes of the footer.
  - Parses attached PKCS7 blob from the footer.
  - Verifies the PKCS7 using the kernel trusted keyring.
  - Extracts the digest from the PKCS7 and compares against local digest.

- `verify_signature_pkcs7_detached()`:
  - Computes SHA-256 over the detached metadata region.  
  - Parses detached PKCS7 buffer.  
  - Supplies metadata as associated data.  
  - Verifies signature and digest equality.  

Both helpers return `0` on success or a negative errno (`-EKEYREJECTED`, `-EINVAL`, etc.) on failure.

---

### 9. `integrity_tests.sh`

Robustness and fuzz-testing suite for dm-verity metadata.

**Purpose:**

- Systematically corrupts verity structures to test:
  - Input sanitization and bounds checking.  
  - Integer overflow protection.  
  - Buffer overflow prevention.  
  - Error handling for malformed on-disk structures.  

**Typical workflow:**

1. Create a test image:

   ```bash
   cd src/build/
   ./integrity_tests.sh <mode>
   ```

2. Boot the kernel under QEMU:

   ```bash
   ./launch_qemu.sh
   ```

3. Use the default image or, if `integrity_tests.sh` created a `rootfs.<mode>.test.img`, adjust your launch script / menu accordingly.  
4. Observe kernel logs for expected failures (verification errors, bounds rejections, etc.).

**Supported modes:**

| Mode         | What it corrupts                                          | Intention                                             |
|--------------|-----------------------------------------------------------|-------------------------------------------------------|
| `meta1`      | Flips one byte in the 196-byte header                    | Tests header integrity & digest mismatch detection    |
| `sig1`       | Flips one byte in PKCS7 signature blob                   | Tests PKCS7 parsing and cryptographic verification    |
| `int_overflow` | Writes wrap-around values into locator fields          | Tests 32/64-bit overflow handling in offset math      |
| `buf_overflow` | Sets metadata length to `0xFFFFFFFF`                   | Tests allocation limits and buffer size validation    |
| `trunc_meta` | Claims metadata extends beyond disk capacity             | Tests truncated reads and bounds checks               |
| `bad_offsets`| Places meta/sig offsets well beyond disk end             | Tests rejection of out-of-bounds offsets              |
| `sanitize`   | Replaces locator with random garbage                     | Tests magic validation and general input sanitization |

**Key options:**

- `--inplace` – Corrupt the original `rootfs.img` (destructive).  
- `--backup` – Create a `.bak` backup when using `--inplace`.  
- `--dry-run` – Print actions without modifying the image.  
- `--verbose` – Extra debug output.  
- `--restore` – Restore from previously created `.bak` backup.  

---

## Usage

### 1. Generate Signing Keys (one-time)

```bash
cd src/boot/

# Private key
openssl genrsa -out bl_private.pem 2048

# Self-signed certificate
openssl req -new -x509 -key bl_private.pem -out bl_cert.pem -days 3650     -subj "/C=US/ST=State/L=City/O=Organization/CN=SecureBoot"
```

Ensure the certificate is built into or enrolled in the kernel trusted keyring.

---

### 2. Quick Start: Build & Boot

```bash
# From repository root
cd src/build/

# Build rootfs + dm-verity metadata
./build_artifacts.sh

# Boot in QEMU
./launch_qemu.sh
```

---

### 3. Running Integrity Tests

Example: corrupt the metadata header in a **copy** of the image.

```bash
cd src/build/

# Create rootfs.meta1.test.img and corrupt its header
./integrity_tests.sh meta1

# Boot (adjust launch script or menu to use the test image)
./launch_qemu.sh
```

Example: in-place corruption with automatic backup:

```bash
./integrity_tests.sh sig1 --inplace --backup --yes
./launch_qemu.sh
```

---

## Verification During Boot

Watch QEMU console output:

```text
[    2.345] verity-autoboot: Footer mode: detached (VLOC)
[    2.367] verity-autoboot: Signature verification PASSED (detached)
[    2.389] verity-mapping: dm-verity mapping created successfully
[    2.421] EXT4-fs (dm-0): mounted filesystem with ordered data mode
```

**Success indicators:**

- `Signature verification PASSED (attached/detached)`  
- `dm-verity mapping created successfully`  
- `EXT4-fs (dm-0): mounted`  
- Regular login prompt appears.  

**Failure indicators (expected during fuzz tests):**

- `signature verification FAILED`  
- `metadata header validation FAILED`  
- `unknown tail magic` / `invalid VLOC magic`  
- `dm-verity mapping creation FAILED`  
- Kernel panic with `dm-verity-autoboot` message.  

---

## Configuration

### Disk Size Tuning

In `src/build/build_rootfs.sh`:

```bash
VERITY_SPACE_MB=$((ROOTFS_SIZE_MB / 5 + 20))
DISK_SIZE_MB=$((ROOTFS_SIZE_MB + VERITY_SPACE_MB))
```

Adjust the formula to increase or reduce space reserved for the Merkle tree and metadata.

### Kernel Parameters

Modify `APPEND_CMD` in `launch_qemu.sh`:

- `console=ttyS0,115200` – Serial console.  
- `loglevel=7` – Verbosity (debug).  
- `rootdelay=10` – Wait for root device.  
- `dm_verity_autoboot.autoboot_device=/dev/vda` – Device to scan.  
- `dm_verity_autoboot.mode=verify_and_map` – Helper behavior.  

### QEMU Configuration

Also in `launch_qemu.sh`, you can adjust:

```bash
-m 1024M              # RAM
-machine q35,accel=tcg
-cpu max
-smp 2                # Number of vCPUs
```

Switch to `accel=kvm` if KVM is available.

---

## Security Considerations

### Key Management

- Keep `bl_private.pem` secret (restrict permissions, consider encryption).  
- Embed `bl_cert.pem` into the kernel trusted keyring.  
- For production, use HSMs or dedicated key management.  
- Plan for regular key rotation and certificate expiry.  

### Threat Model (Covered)

- Unauthorized filesystem modification.  
- Offline tampering with disk images.  
- Hash tree corruption or replacement.  
- Locator/metadata manipulation to redirect hash tree.  

The integrity test suite is specifically designed to validate that the implementation **fails closed** under all of these attack classes.

---

## Appendices

### A. VLOC Footer Format (4096 bytes)

```text
Offset  Size  Field           Description
------  ----  -----           -----------
0x0000  4     magic           0x564C4F43 ("VLOC")
0x0004  4     version         Format version (currently 1)
0x0008  8     meta_off        Offset to metadata header (bytes)
0x0010  4     meta_len        Length of metadata header (196)
0x0014  8     sig_off         Offset to PKCS7 signature (bytes)
0x001C  4     sig_len         Length of PKCS7 signature (varies)
0x0020  4064  reserved        Zero-filled padding
```

### B. Metadata Header Format (196 bytes)

```text
Offset  Size  Field             Description
------  ----  -----             -----------
0x00    4     magic             0x56455249 ("VERI")
0x04    4     version           Format version (1)
0x08    8     data_blocks       Number of data blocks
0x10    8     hash_start_sector Hash tree start (512-byte sectors)
0x18    4     data_block_size   Data block size (bytes)
0x1C    4     hash_block_size   Hash block size (bytes)
0x20    32    hash_algorithm    Algorithm name (null-padded)
0x40    64    root_hash         SHA-256 root hash (zero-padded)
0x80    64    salt              dm-verity salt (zero-padded)
0xC0    4     salt_size         Actual salt length (bytes)
```

### C. Kernel Module Parameters

| Parameter        | Type   | Example              | Description                                  |
|------------------|--------|----------------------|----------------------------------------------|
| `autoboot_device`| string | `/dev/vda`           | Whole-disk block device with verity footer   |
| `mode`           | string | `verify_and_map`     | Behavior (verification + mapping)            |

Example on cmdline:

```text
dm_verity_autoboot.autoboot_device=/dev/vda dm_verity_autoboot.mode=verify_and_map
```
