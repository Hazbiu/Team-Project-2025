# dm‑verity Secure Boot Flow (Attached PKCS#7)
## COMMIT NO: 34db2833831da8208171874c7acfc76033fee054

##  Overview
This document describes the **end‑to‑end chain of trust** for dm‑verity with an **embedded PKCS#7 signature**, covering:

1. **Key generation** and signing logic.  
2. **dm‑verity metadata generation** (`generate_verity_metadata.sh`).  
3. **Boot hand‑off** by the `secondary_bootloader`.  
4. **In‑kernel verification** by `dm‑verity‑autoboot`.

The goal: ensure that the **root filesystem and its Merkle tree** are authenticated at boot using cryptographic signatures trusted by the kernel keyring.

---

## PKCS#7 Key Infrastructure

### Key Generation (once per trusted signer)
```bash
# Create private key and X.509 certificate (self‑signed for demo)
openssl req -newkey rsa:2048 -nodes -keyout bl_private.pem     -x509 -days 3650 -out bl_cert.pem     -subj "/CN=SecureBoot Demo/"

# Verify the cert
openssl x509 -in bl_cert.pem -text -noout
```

### Kernel Trust Setup
- The **public certificate (`bl_cert.pem`)** must be built into or imported into the **kernel trusted keyring**.
- At runtime, the kernel validates PKCS#7 signatures using this trusted certificate.

**Trusted anchor:**  
```
CONFIG_SYSTEM_TRUSTED_KEYS="bl_cert.pem"
```

---

## 3️⃣ Metadata Generation (generate_verity_metadata.sh)

### Purpose
Compute dm‑verity metadata, generate a **PKCS#7 (DER, attached)** signature, and embed it directly at the **end of the disk**.

### High‑level Steps
```
1. Attach rootfs.img as loop device
2. Run veritysetup to generate hash tree and root hash
3. Build verity_metadata.bin (4KB footer, unsigned)
4. Sign bytes [0..195] with openssl (PKCS#7, attached)
5. Embed signature and pkcs7_size into metadata
6. Write final 4KB footer to end of disk (/dev/vda)
```

### PKCS#7 Signature Creation
```bash
openssl smime -sign   -binary -noattr -nosmimecap -nodetach   -in header.bin   -signer bl_cert.pem   -inkey bl_private.pem   -outform DER > footer.pkcs7
```

### Footer Structure (embedded mode)
| Field | Size | Description |
|--------|------|-------------|
| magic | 4B | 'VERI' |
| version | 4B | format version |
| data_blocks | 8B | number of filesystem blocks |
| hash_start_sector | 8B | LBA where Merkle tree begins |
| data_block_size | 4B | usually 4096 |
| hash_block_size | 4B | usually 4096 |
| hash_algorithm | 32B | “sha256” |
| root_hash | 64B | Merkle root hash |
| salt | 64B | salt value |
| salt_size | 4B | salt length |
| pkcs7_size | 4B | signature length |
| pkcs7_blob | ≤2048B | PKCS#7 DER blob (attached) |
| reserved | pad to 4096B | |

### Final Disk Layout
```
 ┌─────────────────────────────────────────────────────┐
 │ GPT Partition Table                                 │
 ├─────────────────────────────────────────────────────┤
 │ Partition #1 (ext4 + dm‑verity hash tree)           │
 ├─────────────────────────────────────────────────────┤
 │ 4KB Metadata Footer (VERI header + PKCS#7 blob)     │
 └─────────────────────────────────────────────────────┘
```

---

## Boot Flow (secondary_bootloader)

### Purpose
Launch the kernel **without initramfs**, ensuring it can directly read the disk footer.

### Actions
1. Scans GPT for partition named `"rootfs"`.
2. Boots QEMU with virtio disk (`/dev/vda`).
3. Passes parameters to kernel:
   ```bash
   console=ttyS0    dm_verity_autoboot.autoboot_device=/dev/vda    root=/dev/mapper/verified_root ro rootwait
   ```
4. The kernel will then run `dm‑verity‑autoboot` automatically (late init).

### Flow Diagram
```
┌──────────────────────────────────────────────┐
│ secondary_bootloader                         │
│   ↓                                           │
│ Parse GPT (find 'rootfs')                     │
│   ↓                                           │
│ Launch QEMU with kernel and rootfs.img        │
│   ↓                                           │
│ Kernel boots with dm_verity_autoboot params   │
└──────────────────────────────────────────────┘
```

---

## In‑Kernel Verification (`dm‑verity‑autoboot`)

### Purpose
Validate the authenticity of the verity footer using the embedded PKCS#7 signature.

### Core Verification Logic
```c
1. Read last 4096 bytes of disk (/dev/vda)
2. Check magic = 'VERI'
3. Compute SHA256(meta[0..195])
4. pkcs7_parse_message(pkcs7_blob)
5. pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE)
6. pkcs7_get_digest() → signed_hash
7. Compare signed_hash == computed_digest
8. If mismatch → panic("untrusted rootfs")
```

### Key Point
The signature is **attached**, so `pkcs7_supply_detached_data()` is **not called**.  
This avoids “Data already supplied” errors from earlier detached mode.

### Verification Output
| Stage | Kernel log |
|--------|-------------|
| Read footer | `dm-verity-autoboot: read+dump footer` |
| Verify sig | `==== Step 2: Verifying PKCS7 signature ====` |
| Success | `Digest in PKCS7 matches SHA256(header[0..195])` |
| Failure | `rootfs footer NOT TRUSTED (ret=-EKEYREJECTED)` → panic |

---

## End‑to‑End Trust Flow

```
┌──────────────────────────────────────────────────────────┐
│ Key generation (OpenSSL)                                 │
│   ↳ bl_private.pem / bl_cert.pem                         │
│   ↳ bl_cert.pem → compiled into kernel keyring            │
├──────────────────────────────────────────────────────────┤
│ generate_verity_metadata.sh                               │
│   ↳ builds verity_metadata.bin (4KB)                      │
│   ↳ signs bytes [0..195] with PKCS#7 (DER, attached)      │
│   ↳ embeds into disk end (overwrites GPT backup)          │
├──────────────────────────────────────────────────────────┤
│ secondary_bootloader                                      │
│   ↳ finds GPT partition                                   │
│   ↳ launches kernel + rootfs.img (/dev/vda)               │
│   ↳ passes dm_verity_autoboot.autoboot_device=/dev/vda    │
├──────────────────────────────────────────────────────────┤
│ kernel (dm‑verity‑autoboot)                               │
│   ↳ reads footer                                          │
│   ↳ parses + verifies PKCS#7                              │
│   ↳ compares digest                                       │
│   ↳ authenticates root hash & salt                        │
│   ↳ (future) mount verified root /dev/mapper/verified_root│
└──────────────────────────────────────────────────────────┘
```

---

## Trust Model Summary

| Element | Description |
|----------|--------------|
| **Private key** | Used by signer to produce PKCS#7 signature |
| **Certificate (bl_cert.pem)** | Embedded in kernel trusted keyring |
| **Signed region** | Bytes 0–195 of metadata (root hash, salt, geometry) |
| **Digest algorithm** | SHA‑256 |
| **Signature format** | PKCS#7 DER (attached) |
| **Verifier** | `pkcs7_verify()` in kernel |
| **Failure behavior** | `panic("dm-verity-autoboot: untrusted rootfs footer")` |

---

## Expected Outcomes

### Valid Signature
```
dm-verity-autoboot: Signature verification PASSED (attached)
dm-verity-autoboot: Footer header is AUTHENTIC
dm-verity-autoboot: verified_root mapping ready
```

### Invalid / Corrupted Footer
```
dm-verity-autoboot: rootfs footer NOT TRUSTED (ret=-EKEYREJECTED)
Kernel panic: dm-verity-autoboot: untrusted rootfs footer
```

---

## Version / Credits
**Team A – Kernel Security & Storage Group**  
*Version 2.0 — November 2025*

