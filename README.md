# dm-verity Secure Boot System

A production-ready implementation of dm-verity with PKCS7 signature verification for secure Linux boot environments. This system provides cryptographic verification of the root filesystem before mounting, ensuring boot-time integrity and authenticity.

## Overview

This solution implements a complete secure boot chain where:
1. A minimal bootloader launches QEMU with a Linux kernel
2. A custom kernel module (`dm-verity-autoboot`) performs signature verification
3. The verified filesystem is mounted as the root device

### Key Features

- **Whole-disk dm-verity**: No partition table overhead; entire disk is used efficiently
- **Detached PKCS7 signatures**: Metadata and signatures stored separately at disk end
- **Built-in kernel verification**: No initramfs required; verification happens in kernel space
- **Zero-touch boot**: Fully automated verification and mounting
- **Production-ready**: Comprehensive error handling and logging
- **Tamper detection**: Included corruption testing tool for validation

## Architecture

### On-Disk Layout

```
[ext4 filesystem data] [dm-verity hash tree] [metadata header] [PKCS7 signature] [VLOC locator]
                                              ↑                 ↑                   ↑
                                              196 bytes         DER format          4 KiB footer
```

The VLOC (Verity LOCator) footer at the end of the disk provides offsets to the metadata and signature regions, enabling the kernel module to locate and verify all components.

### Boot Flow

```
┌─────────────────┐
│   Bootloader    │  Launches QEMU with kernel cmdline:
│  (user space)   │  dm_verity_autoboot.autoboot_device=/dev/vda
└────────┬────────┘  root=/dev/dm-0
         │
         ▼
┌─────────────────┐
│  Linux Kernel   │  Boots, initializes virtio-blk (/dev/vda)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ dm-verity-      │  1. Read VLOC footer from /dev/vda
│ autoboot module │  2. Read metadata header + PKCS7 signature
│ (kernel space)  │  3. Verify PKCS7 against kernel keyring
└────────┬────────┘  4. Create dm-verity mapping (/dev/dm-0)
         │
         ▼
┌─────────────────┐
│  Root Mount     │  Kernel mounts /dev/dm-0 as ext4 root
│   (verified)    │  System boots from verified filesystem
└─────────────────┘
```

## Prerequisites

### System Requirements

- Linux-based development environment (Ubuntu 20.04+ or Debian 11+ recommended)
- Minimum 4 GB RAM for building
- 10 GB free disk space
- sudo/root access for image creation and loop devices

### Software Dependencies

Install all required packages:

```bash
# Update package lists
sudo apt update

# 1. Build tools and essentials
sudo apt install -y \
    build-essential \
    git \
    wget \
    curl \
    ca-certificates \
    pkg-config \
    libssl-dev

# 2. QEMU virtualization
sudo apt install -y qemu-system-x86 qemu-utils

# 3. Root filesystem tools
sudo apt install -y \
    debootstrap \
    e2fsprogs \
    rsync

# 4. dm-verity tools
sudo apt install -y cryptsetup veritysetup

# 5. Block device utilities
sudo apt install -y util-linux

# 6. Cryptographic tools
sudo apt install -y openssl
```

### Kernel Requirements

The custom kernel module requires:
- Linux kernel 5.10 or later
- `CONFIG_DM_VERITY=y` (dm-verity support)
- `CONFIG_SYSTEM_DATA_VERIFICATION=y` (PKCS7 verification)
- `CONFIG_CRYPTO_SHA256=y` (SHA-256 hashing)

The provided kernel image (`kernel_image.bin`) includes all necessary components built-in.

## Project Structure

```
.
├── boot/
│   ├── bl_private.pem          # Signing private key
│   └── bl_cert.pem             # Signing certificate
├── bootloaders/
│   ├── bootloader.c            # QEMU launcher (C implementation)
│   └── secondary_bootloader    # Compiled bootloader binary
├── build/
│   ├── Binaries/
│   │   ├── rootfs/             # Debian root filesystem tree
│   │   ├── rootfs.img          # Final disk image
│   │   └── metadata/           # dm-verity artifacts
│   ├── build_rootfs.sh         # Creates ext4 disk image
│   ├── generate_verity.sh      # Generates dm-verity metadata + signatures
│   ├── launch_boot.sh          # Master orchestration script
│   └── corrupt_rootfs.sh       # Testing tool for tampering detection
├── kernel/
│   ├── dm-verity-autoboot.c    # Custom kernel module
│   └── kernel_image.bin        # Pre-built kernel with module
└── README.md
```

## Component Details

### 1. build_rootfs.sh

Creates a minimal Debian-based root filesystem on a single-disk image without partitions.

**Features:**
- Uses `debootstrap` to create base Debian system
- Configures default users (root/keti) and networking
- Sizes disk to accommodate filesystem + dm-verity overhead
- Creates ext4 directly on whole disk (no GPT)

**Output:** `build/Binaries/rootfs.img`

**Default Credentials:**
- Root user: `root` / `root`
- Regular user: `keti` / `keti` (sudo enabled)

### 2. generate_verity.sh

Generates dm-verity hash tree and cryptographic metadata.

**Process:**
1. Analyzes filesystem geometry
2. Calculates and allocates space for Merkle tree
3. Generates hash tree with `veritysetup`
4. Creates 196-byte metadata header
5. Signs header with PKCS7 (detached signature)
6. Writes metadata, signature, and VLOC locator to disk end

**Output:** 
- `metadata/root.hash` - Root hash (hex)
- `metadata/verity_header.bin` - Signed metadata (196 bytes)
- `metadata/verity_header.sig` - PKCS7 signature (DER)
- `metadata/verity_locator.bin` - VLOC footer (4 KiB)
- `metadata/verity_info.txt` - Human-readable metadata

### 3. launch_boot.sh

Master orchestration script that automates the entire build and boot process.

**Workflow:**
1. Executes `build_rootfs.sh` to create the filesystem
2. Runs `generate_verity.sh` to generate security metadata
3. Validates all artifacts are present
4. Launches the bootloader with appropriate parameters

**Features:**
- Color-coded output for better readability
- Error handling at each stage
- Automatic cleanup on failure
- Progress indicators

### 4. bootloader.c

Minimal userspace QEMU launcher that:
- Resolves absolute path to `rootfs.img`
- Constructs QEMU command with appropriate virtio-blk configuration
- Passes kernel parameters for dm-verity autoboot
- Launches VM with serial console output

**Kernel Command Line:**
```
dm_verity_autoboot.autoboot_device=/dev/vda root=/dev/dm-0 rootfstype=ext4 rootwait rootdelay=10
```

**Compilation:**
```bash
cd bootloaders/
gcc -O2 -Wall -o secondary_bootloader bootloader.c
```

### 5. dm-verity-autoboot.c

Custom kernel module providing early-boot verification.

**Capabilities:**
- Parses kernel command line for device path
- Detects attached (VERI) vs detached (VLOC) footer formats
- Reads and validates PKCS7 signatures against kernel trusted keyring
- Creates dm-verity mapping via `dm_early_create()`
- Comprehensive logging for debugging

**Security Properties:**
- Verifies signature before any data access
- Uses kernel's built-in PKCS7 verification
- Panics on verification failure (fail-secure)
- No userspace dependencies
- Supports both 196-byte header and full 4K footer layouts

### 6. corrupt_rootfs.sh

Testing utility to validate tamper detection mechanisms.

**Purpose:**
Intentionally corrupts the disk image to verify that the dm-verity system correctly detects and rejects modified filesystems.

**Usage:**
```bash
# Corrupt metadata header (creates copy)
./corrupt_rootfs.sh meta1

# Corrupt PKCS7 signature (creates copy)
./corrupt_rootfs.sh sig1

# Corrupt in-place (affects actual boot image)
./corrupt_rootfs.sh meta1 --inplace

# Specify custom image path
./corrupt_rootfs.sh sig1 /path/to/custom.img
```

**Corruption Modes:**

| Mode | Target | Effect | Expected Result |
|------|--------|--------|-----------------|
| `meta1` | Metadata header | Flips 1 byte at META_OFFSET+64 | Signature verification fails; kernel panics |
| `sig1` | PKCS7 signature | Flips 1 byte at SIG_OFFSET | PKCS7 parsing fails; kernel panics |

**Output:**
- Default: Creates `rootfs.bad.img` (preserves original)
- With `--inplace`: Modifies `rootfs.img` directly (for testing boot failure)

**Workflow for Testing:**
```bash
# 1. Build clean system
cd build/
./launch_boot.sh   # Should boot successfully

# 2. Corrupt the image
./corrupt_rootfs.sh meta1 --inplace

# 3. Attempt to boot (should fail)
cd ../bootloaders/
sudo ./secondary_bootloader

# Expected: Kernel panic with message:
# "dm-verity-autoboot: signature verification FAILED"

# 4. Restore clean image
cd ../build/
./launch_boot.sh  # Regenerate metadata
```

## Usage

### Quick Start

1. **Generate signing keys** (one-time setup):
```bash
cd boot/
# Generate private key
openssl genrsa -out bl_private.pem 2048

# Generate self-signed certificate
openssl req -new -x509 -key bl_private.pem -out bl_cert.pem -days 3650 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=SecureBoot"
```

2. **Build and launch system**:
```bash
cd build/
./launch_boot.sh
```

This master script automatically:
- Builds the root filesystem
- Generates dm-verity metadata and signatures
- Launches the bootloader
- Boots into the verified system

### Manual Workflow

For step-by-step execution or debugging:

```bash
# Step 1: Build rootfs
cd build/
./build_rootfs.sh

# Step 2: Generate dm-verity metadata
./generate_verity.sh

# Step 3: Launch bootloader
cd ../bootloaders/
sudo ./secondary_bootloader
```

### Testing Tamper Detection

```bash
# 1. Verify clean boot works
cd build/
./launch_boot.sh
# (should boot successfully)

# 2. Create corrupted copy
./corrupt_rootfs.sh meta1
# This creates rootfs.bad.img

# 3. Test with corrupted image
# (manually edit bootloader.c to use rootfs.bad.img, or)
mv Binaries/rootfs.img Binaries/rootfs.clean.img
mv Binaries/rootfs.bad.img Binaries/rootfs.img

# 4. Attempt boot (should fail)
cd ../bootloaders/
sudo ./secondary_bootloader
# Expected: Kernel panic due to signature verification failure

# 5. Restore clean image
cd ../build/Binaries/
mv rootfs.clean.img rootfs.img
```

### Verification

During boot, monitor the serial console for verification messages:

```
[    2.345] verity-autoboot: Footer mode: detached (VLOC)
[    2.367] verity-autoboot: Signature verification PASSED (detached)
[    2.389] verity-autoboot: ✓ dm-verity mapping created: name="verity_root"
[    2.421] EXT4-fs (dm-0): mounted filesystem with ordered data mode
```

**Successful Boot Indicators:**
- "Signature verification PASSED"
- "dm-verity mapping created"
- "EXT4-fs (dm-0): mounted"
- Login prompt appears

**Failed Boot Indicators:**
- "signature verification FAILED"
- "digest mismatch"
- "signer NOT trusted"
- Kernel panic message

## Configuration

### Customizing Root Filesystem

Edit `build_rootfs.sh` to modify:
- Base distribution (change `debootstrap` source)
- Installed packages (add to `--include=` list)
- User accounts and passwords
- Network configuration
- Hostname

**Example: Add additional packages:**
```bash
# In build_rootfs.sh, modify:
--include=systemd,systemd-sysv,udev,passwd,login,sudo,net-tools,iproute2,\
ifupdown,openssh-server,vim,less,curl,wget,python3
```

### Adjusting Disk Size

The build script automatically calculates disk size based on filesystem content plus 20% overhead. To manually adjust:

```bash
# In build_rootfs.sh, modify:
VERITY_SPACE_MB=$((ROOTFS_SIZE_MB / 5 + 20))  # Change multiplier or constant
DISK_SIZE_MB=$((ROOTFS_SIZE_MB + VERITY_SPACE_MB))
```

### Kernel Parameters

Modify `bootloader.c` to adjust:
- Console output: `console=ttyS0,115200`
- Log level: `loglevel=7` (7=debug, 4=warning, 1=error)
- Root device wait time: `rootdelay=10`
- Memory allocation: `-m 1024` (in QEMU args)

### QEMU Configuration

Edit `bootloader.c` QEMU arguments:
```c
"-m", "1024",                    // RAM (increase for larger workloads)
"-machine", "q35,accel=tcg",     // Change to accel=kvm for better performance
"-cpu", "max",                   // CPU model
"-smp", "2",                     // Add for multi-core (not in default)
```

## Security Considerations

### Key Management

- **Private key (`bl_private.pem`)**: Keep secure; compromise allows arbitrary filesystem signing
- **Certificate (`bl_cert.pem`)**: Must be enrolled in kernel trusted keyring
- For production: Use hardware security modules (HSM) for key storage
- Consider key rotation policy (recommended: annually)

**Production Key Management:**
```bash
# Store private key with restricted permissions
chmod 600 boot/bl_private.pem
chown root:root boot/bl_private.pem

# Consider using encrypted storage
cryptsetup luksFormat /dev/sdX
cryptsetup luksOpen /dev/sdX secure_keys
mount /dev/mapper/secure_keys /secure/keys
mv boot/bl_private.pem /secure/keys/
```

### Threat Model

**Protected Against:**
- Unauthorized filesystem modifications
- Malicious root filesystem injection
- Boot-time tampering
- Offline disk image modification
- Hash tree corruption
- Metadata manipulation

**Not Protected Against:**
- Compromised signing key
- Physical attacks on hardware (cold boot, DMA)
- Attacks before dm-verity activation
- Runtime memory attacks (consider SELinux/AppArmor)
- Supply chain attacks on build tools
- Side-channel attacks

## Appendix A: File Format Specifications

### VLOC Footer Format (4096 bytes)

```
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

### Metadata Header Format (196 bytes)

```
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

## Appendix B: Kernel Module Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| autoboot_device | string | NULL | Block device path (e.g., /dev/vda) |

Usage:
```bash
# In kernel command line
dm_verity_autoboot.autoboot_device=/dev/vda

# Or via modprobe (if built as module)
modprobe dm-verity-autoboot autoboot_device=/dev/sda
```

## Appendix C: Build Time Estimates

Based on reference hardware (Intel i5-8250U, 8GB RAM, SSD):

| Operation | Time | Notes |
|-----------|------|-------|
| debootstrap | 3-5 minutes | Network dependent |
| mkfs.ext4 | 2-5 seconds | Size dependent |
| File copy (rsync) | 30-60 seconds | ~1GB of data |
| veritysetup format | 10-30 seconds | CPU intensive |
| PKCS7 signing | <1 second | RSA operations |
| Total (clean build) | 5-8 minutes | First run |
| Total (incremental) | 30-60 seconds | Metadata only |

## Appendix D: Disk Space Requirements

For a typical deployment:

| Component | Size | Description |
|-----------|------|-------------|
| Base Debian | 400-600 MB | Minimal system |
| Packages | 200-400 MB | Depends on selection |
| Hash tree | 5-10% | ~50 MB for 1 GB data |
| Metadata | 4 KB | Header (196B) + padding |
| Signature | 1-2 KB | PKCS7 DER (padded to 4KB) |
| Locator | 4 KB | VLOC footer |
| **Total disk** | **~750 MB** | For minimal system |

## Appendix E: Security Checklist

Pre-deployment security verification:

- [ ] Private key stored securely (chmod 600, encrypted storage)
- [ ] Certificate embedded in kernel trusted keyring
- [ ] Root filesystem is read-only (no write access)
- [ ] Signature verification logs to remote syslog
- [ ] Boot process monitored for anomalies
- [ ] Incident response plan documented
- [ ] Key rotation schedule established
- [ ] Backup/recovery procedures tested
- [ ] Corruption test performed successfully
- [ ] Boot time within acceptable limits
- [ ] All dependencies up to date (apt update/upgrade)
- [ ] Compliance requirements documented

## Updates and Patches

To update the system:

1. **Update packages**:
   ```bash
   sudo apt update && sudo apt upgrade
   ```

2. **Rebuild filesystem**:
   ```bash
   cd build/
   ./build_rootfs.sh
   ./generate_verity.sh
   ```

3. **Test thoroughly**:
   ```bash
   # Clean boot
   ./launch_boot.sh
   
   # Corruption detection
   ./corrupt_rootfs.sh meta1
   mv Binaries/rootfs.img Binaries/rootfs.clean.img
   mv Binaries/rootfs.bad.img Binaries/rootfs.img
   cd ../bootloaders/
   sudo ./secondary_bootloader  # Should fail
   ```