# Secure Boot System - Complete Documentation

## 📁 Complete Project Structure

```
src/
├── boot/                          # Boot components directory
│   ├── primary_bootloader.c       # Primary bootloader source code
│   ├── primary_bootloader         # Primary bootloader executable (built)
│   ├── primary_bootloader.exe     # Windows executable
│   ├── secondary_bootloader.c     # Secondary bootloader source code  
│   ├── secondary_bootloader       # Secondary bootloader executable (built)
│   ├── secondary_bootloader.bin   # Secondary bootloader binary
│   ├── secondary_bootloader.sig   # Secondary bootloader signature
│   ├── verify.c                   # Core verification library
│   ├── verify.h                   # Verification header
│   ├── kernel_image.bin           # Kernel binary
│   ├── kernel_image.sig           # Kernel signature
│   ├── rootfs.cpio.gz             # Root filesystem
│   ├── bl_private.pem             # Bootloader private key
│   ├── pl_public.pem              # Platform public key
│   └── rot_public.pem             # Root of Trust public key
├── keys/                          # Cryptographic keys directory
│   ├── rot_private.pem            # Root of Trust private key
│   └── rot_public.pem             # Root of Trust public key
├── test/                          # Testing directory
│   ├── test_verify                # Integration test executable (built)
│   ├── test_verify.c              # Integration test source code
│   ├── run_tests.sh               # Test execution script
│   ├── unit/                      # Unit tests directory
│   │   ├── test_primary_runner    # Primary bootloader unit tests (built)
│   │   ├── test_primary.c         # Primary bootloader test source
│   │   ├── test_secondary_runner  # Secondary bootloader unit tests (built)
│   │   ├── test_secondary.c       # Secondary bootloader test source
│   │   └── unity/                 # Unity test framework
│   │       ├── unity.c
│   │       ├── unity.h
│   │       ├── unity.c.1
│   │       ├── unity.h.1
│   │       └── unity_internals.h
│   └── tmp_test/                  # Temporary test files (created during tests)
├── workspace                      # Workspace configuration
└── run_build.sh                  # Build script
```

## Available Build Commands

### Basic Build Commands
```bash
make boot                    # Build both primary and secondary bootloaders
make all                     # Same as 'make boot'
./run_build.sh               # Uses build script
make clean                   # Remove all built executables and test runners
```

### Testing Commands
```bash
make test                    # Build and run integration tests (test_verify)
make unit-tests              # Run ALL unit tests for both bootloaders
make unit-test-primary       # Run unit tests for PRIMARY bootloader only
make unit-test-secondary     # Run unit tests for SECONDARY bootloader only
```

### Development & Execution Commands
```bash
make bootchain               # Build and start the full secure boot chain
make run                     # Same as bootchain - starts boot process
```

### CI/CD & Verification Commands
```bash
make docker-test             # Build and test for Docker/CI environments
make verify                  # Build and verify everything works
```

## Build Output Locations

### Bootloader Executables (Built Files)
- `src/boot/primary_bootloader` - Primary bootloader executable
- `src/boot/secondary_bootloader` - Secondary bootloader executable

### Test Executables (Built Files)
- `src/test/test_verify` - Integration test executable
- `src/test/unit/test_primary_runner` - Primary bootloader unit tests
- `src/test/unit/test_secondary_runner` - Secondary bootloader unit tests

## Typical Workflows

### First-Time Setup
```bash
# 1. Install dependencies
sudo apt update && sudo apt install -y build-essential openssl libssl-dev qemu-system-x86

# 2. Clone and navigate to project
cd src/

# 3. Build everything
make boot
# And use the build script:
./run_build.sh
```

### Development Workflow
```bash
# Build bootloaders
make boot

# Run tests
make test
make unit-tests

# Test full boot chain
make run
```

### Testing Workflow
```bash
# Comprehensive testing
make unit-tests              # Run all unit tests
make test                   # Run integration tests
make verify                 # Final verification
```

### CI/CD Pipeline
```bash
make docker-test            # Single command for CI environments
```

## Alternative Build Methods

```bash
# All these commands do the same thing - build the bootloaders:
make boot
make all
./run_build.sh
```

## Quick Start Guide

### Step 1: Install Dependencies
```bash
sudo apt update
sudo apt install -y build-essential openssl libssl-dev qemu-system-x86
```

### Step 2: Build the System
```bash
cd src/
make boot
```

### Step 3: Run Tests
```bash
make test
```

### Step 4: Start Boot Chain
```bash
make run
```
## Fastest way
Easiest and fastest way is to use: 
```bash
run_build.sh
```
and then follow either testing or bootchain

## Prerequisites Checklist

- [ ] **gcc compiler** (`gcc --version`)
- [ ] **OpenSSL libraries** (`openssl version`)
- [ ] **QEMU** (for full boot chain testing) (`qemu-system-x86_64 --version`)
- [ ] **Make** (`make --version`)
- [ ] **Bash** (for scripts)

## Troubleshooting

### Common Issues:

**Missing OpenSSL:**
```bash
sudo apt install libssl-dev
```

**Permission Denied:**
```bash
chmod +x run_build.sh
chmod +x test/run_tests.sh
```

**QEMU Not Found:**
```bash
sudo apt install qemu-system-x86
```

**Build Errors:**
```bash
make clean
make boot
```


Use `make help` to see all available commands at any time.

