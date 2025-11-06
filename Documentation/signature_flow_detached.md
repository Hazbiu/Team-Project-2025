# dm-verity Detached Signature Schema
## COMMIT NO: 6ab334c2eaf028877ea41959ff998afad3f5080f

## Purpose
Authenticate the **dm-verity metadata header** (`verity_header.bin`) using a **detached PKCS#7 (DER)** signature verified by the kernel (`dm-verity-autoboot`).  
Ensures the Merkle root and filesystem geometry cannot be tampered.

---

## Signing Flow (`generate_verity.sh`)
```
Inputs:
  rootfs.img        – ext4 partition (data + Merkle tree)
  bl_private.pem    – private key
  bl_cert.pem       – public cert (trusted by kernel)

Steps:
  1. veritysetup format --no-superblock → root.hash, salt
  2. build verity_header.bin (196 bytes)
  3. openssl smime -sign -binary -noattr → verity_header.sig (DER)
  4. create 4K locator footer (VLOC)
  5. write [metadata][signature][locator] at disk end
```

---

## On-Disk Layout (end of disk)
```
 ┌───────────────────────────────────────────────────────────────┐
 │ ext4 data + Merkle tree                                      │
 ├───────────────────────────────────────────────────────────────┤
 │ verity_header.bin   (196 B)   ← signed region (SHA256 input)  │
 ├───────────────────────────────────────────────────────────────┤
 │ verity_header.sig    (~1 KiB) ← PKCS#7 DER signature          │
 ├───────────────────────────────────────────────────────────────┤
 │ verity_locator.bin   (4 KiB)  ← points to meta + sig offsets  │
 └───────────────────────────────────────────────────────────────┘
        ↑HASH_OFFSET       ↑META_OFF   ↑SIG_OFF      ↑LOC_OFF
```

---

## Structures
```c
struct verity_header_196 {
  u32 magic;          // 'VERI'
  u32 version;
  u64 data_blocks;
  u64 hash_start_sector;
  u32 data_bs, hash_bs;
  char algo[32];      // "sha256"
  u8  root_hash[64];
  u8  salt[64];
  u32 salt_size;
};

struct verity_footer_locator {
  u32 magic;          // 'VLOC'
  u32 version;
  u64 meta_off; u32 meta_len;  // header position
  u64 sig_off;  u32 sig_len;   // signature position
};
```

---

## Verification (kernel: `dm-verity-autoboot`)
```
1. Read last 4K → detect VERI (attached) or VLOC (detached)
2. If VLOC:
      read(meta_off, meta_len) → meta_buf
      read(sig_off, sig_len)   → sig_buf
3. digest = SHA256(meta_buf)
4. pkcs7_parse_message(sig_buf)
5. pkcs7_supply_detached_data(meta_buf)
6. pkcs7_verify() using trusted keyring
7. if PKCS7.digest != digest → panic("untrusted rootfs")
```

---

## Results (kernel logs)
| Case | Kernel Log / Behavior |
|------|------------------------|
| Valid signature | “Signature verification PASSED (detached)” |
| Wrong signer |  “signer NOT trusted” → panic |
| Corrupted header |  “digest mismatch” → panic |
| Invalid locator | “unknown tail magic” → fail early |

---

## Trust Model
- Cert `bl_cert.pem` must be present in **kernel trusted keyring**.  
- Digest algorithm: **SHA-256**.  
- Signed region: **exactly 196 bytes** (`verity_header.bin`).  

---

## Boot Verification Flow
```
┌────────────────────────────────────────────────────────────┐
│ secondary_bootloader (userspace)                           │
│   ↳ reads locator (VLOC)                                   │
│   ↳ parses verity_header.bin                               │
│   ↳ builds dm-mod.create= parameter                        │
│   ↳ boots kernel with dm_verity_autoboot.autoboot_device   │
├────────────────────────────────────────────────────────────┤
│ kernel (dm-init)                                           │
│   ↳ creates /dev/dm-0 from mapping                         │
│   ↳ mounts root=/dev/dm-0                                  │
├────────────────────────────────────────────────────────────┤
│ dm-verity-autoboot (late_initcall)                         │
│   ↳ reads VLOC + header + sig                              │
│   ↳ verifies PKCS#7 detached signature                     │
│   ↳ panic("untrusted rootfs") if invalid                   │
│   ↳ continue boot if valid                                 │
└────────────────────────────────────────────────────────────┘
```
