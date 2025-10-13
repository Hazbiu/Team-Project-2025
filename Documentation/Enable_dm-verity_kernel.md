## Build Linux Kernel with dm-verity support enabled

### Prerequisites
```bash
sudo apt update
sudo apt install -y git build-essential bc libncurses-dev bison flex libssl-dev libelf-dev
````

### Clone the repository

In WSL:

```bash
cd ~
git clone https://github.com/torvalds/linux.git
cd linux
make defconfig  # x86_64 architecture by default
```

### Enable dm-verity support

```bash
scripts/config --enable CONFIG_BLK_DEV_DM
scripts/config --enable CONFIG_DM_VERITY
scripts/config --enable CONFIG_DM_VERITY_FEC
scripts/config --enable CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG
scripts/config --enable CONFIG_CRYPTO_SHA256
scripts/config --enable CONFIG_CRYPTO_SHA1
scripts/config --enable CONFIG_IKCONFIG
scripts/config --enable CONFIG_IKCONFIG_PROC
make olddefconfig
```

### Build the kernel

```bash
make -j$(nproc) bzImage
```

### Copy kernel in our boot chain project

```bash
cp arch/x86/boot/bzImage /mnt/d/Team_project/Team-Project-2025/src/boot/kernel_image.bin
```

### Re-sign using our boot chain project

```bash
cd /mnt/d/Team_project/Team-Project-2025/src
./build.sh
```

### Boot and verify in BusyBox

```bash
zcat /proc/config.gz | grep DM_VERITY
```

### We should see something like this:

```
CONFIG_DM_VERITY=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y
CONFIG_DM_VERITY_FEC=y
```

### Run dm-verity kernel in QEMU

In WSL (opened in src):

```bash
WIP
```



