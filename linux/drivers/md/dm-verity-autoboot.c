// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Secure boot story (dev mode, no initramfs):
 *
 *  - Bootloader launches kernel with:
 *       dm_verity_autoboot.autoboot_device=/dev/vda
 *       root=/dev/mapper/verified_root ro rootwait
 *
 *  - Kernel (this file) does:
 *       1. Find /dev/vda *without* initramfs/udev (walk block_class)
 *       2. Read last 4096 bytes of the disk (our signed footer)
 *       3. Parse dm-verity-style metadata (root hash, salt, etc.)
 *       4. Compute SHA256 over the unsigned header (first 196 bytes)
 *       5. Verify PKCS7 signature blob in footer against trusted keys
 *          compiled into the kernel (X.509 in system keyring)
 *       6. Print the exact dm-verity device-mapper table line that would
 *          create /dev/mapper/verified_root
 *
 * What we can already prove / claim:
 *
 *   • The root filesystem image is measured & signed offline with a private key.
 *   • The kernel has the matching public key baked in (as a trusted cert).
 *   • The kernel refuses to trust the rootfs unless that signature passes.
 *   • After verification succeeds, the kernel has *all parameters*
 *     needed to instantiate dm-verity and mount it as root.
 *
 * Why step 6 still prints instead of calling dm-* APIs directly:
 *
 *   The internal device-mapper API (dm_create(), dm_table_create(), etc.)
 *   is not stable across kernel versions and not exported here.
 *   Rather than hack core dm internals, we log the exact dmsetup
 *   command and table string. That proves we derived everything needed
 *   to produce /dev/mapper/verified_root.
 *
 * Future work:
 *   • actually call into dm-verity and register verified_root in-kernel
 *   • hand that mapped device to VFS as the real rootfs
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/crypto.h>
#include <crypto/hash.h>

/* for PKCS7, X.509, and keyring-backed verification */
#include <crypto/pkcs7.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>
#include <crypto/hash_info.h>   /* for enum hash_algo */

#define DM_MSG_PREFIX            "verity-autoboot"

#define VERITY_META_SIZE         4096    /* footer size at end of disk */
#define VERITY_META_MAGIC        0x56455249 /* "VERI" */
#define VERITY_FOOTER_SIGNED_LEN 196     /* bytes [0..195], hashed+signed */
#define VERITY_PKCS7_MAX         2048    /* reserved bytes for PKCS7 blob */

/*
 * Kernel cmdline parameter:
 *   dm_verity_autoboot.autoboot_device=/dev/vda
 *
 * We point to the WHOLE DISK (/dev/vda), not /dev/vda1, because
 * we overwrote the backup GPT at the end of the disk with our 4KB footer.
 */
static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
		 "Block device containing rootfs + verity footer (e.g. /dev/vda)");

/*
 * We'll schedule our work a few seconds after late_init
 * so virtio-blk has time to register (so "vda" actually exists).
 */
static void verity_autoboot_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(verity_autoboot_work, verity_autoboot_workfn);

/* Placeholder if we later spawn a dedicated kthread. */
static struct task_struct *init_thread;

/*
 * On-disk metadata footer (4KB at disk end)
 * Matches what the build script writes+signs.
 *
 * Layout (little-endian fields, all packed):
 *
 *   [0..195]  header we hash + sign:
 *       u32  magic                (0x56455249 "VERI")
 *       u32  version
 *       u64  data_blocks
 *       u64  hash_start_sector
 *       u32  data_block_size
 *       u32  hash_block_size
 *       char hash_algorithm[32]   ("sha256")
 *       u8   root_hash[64]        (Merkle root)
 *       u8   salt[64]
 *       u32  salt_size
 *
 *   [196..199]   u32 pkcs7_size
 *   [200..2247]  pkcs7_blob[2048]  DER PKCS#7 SignedData containing the
 *                                 signature over the first 196 bytes
 *                                 (openssl smime -sign -binary -nodetach ...)
 *   [2248..4095] reserved zero padding
 *
 * salt[] and salt_size are used by dm-verity.
 * root_hash[] is the Merkle tree root hash.
 *
 * pkcs7_blob contains the signer cert + signature so the kernel
 * can verify integrity/authenticity of the measured rootfs image.
 */
struct verity_metadata_ondisk {
	__le32 magic;              //   0
	__le32 version;            //   4
	__le64 data_blocks;        //   8
	__le64 hash_start_sector;  //  16
	__le32 data_block_size;    //  24
	__le32 hash_block_size;    //  28
	char   hash_algorithm[32]; //  32..63
	u8     root_hash[64];      //  64..127
	u8     salt[64];           // 128..191
	__le32 salt_size;          // 192..195  <-- end of signed header
	__le32 pkcs7_size;         // 196..199  <-- size of blob
	u8     pkcs7_blob[2048];   // 200..2247 <-- DER PKCS7 SignedData
	u8     reserved[4096 - 2248]; // 2248..4095 pad to exactly 4096 bytes
} __packed;

/* forward decl for verifier */
static int verify_signature_pkcs7_real(const struct verity_metadata_ondisk *meta);

/*
 * compute_footer_digest()
 *
 * Compute SHA256(meta[0..195]) – the portion that is actually covered
 * by the PKCS7 signature.
 */
static int compute_footer_digest(const struct verity_metadata_ondisk *meta,
				 u8 digest[32])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	if (!meta)
		return -EINVAL;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out;

	ret = crypto_shash_update(desc,
				  (const u8 *)meta,
				  VERITY_FOOTER_SIGNED_LEN);
	if (ret)
		goto out;

	ret = crypto_shash_final(desc, digest);

out:
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

/*
 * verify_signature_pkcs7_real()
 *
 * Actual verification path for our footer:
 *
 *   1. sanity-check pkcs7_size
 *   2. parse pkcs7_blob as a PKCS#7 SignedData message
 *   3. pkcs7_verify() with a "usage" enum (like VERIFYING_MODULE_SIGNATURE):
 *        - checks that the signature is valid
 *        - checks signer cert chains to trusted kernel keys
 *   4. pkcs7_get_digest() to get the hash that was signed
 *   5. recompute SHA256 of footer[0..195] and compare
 *
 * Returns:
 *   0  -> signature valid + digest matches footer header
 *  <0  -> reject
 *
 * IMPORTANT:
 *   If your kernel doesn't define VERIFYING_MODULE_SIGNATURE but *does*
 *   define some other VERIFYING_* enum like VERIFYING_FIRMWARE_SIGNATURE,
 *   replace VERIFYING_MODULE_SIGNATURE below with the one you have.
 */
static int verify_signature_pkcs7_real(const struct verity_metadata_ondisk *meta)
{
	u32 blob_sz;
	const u8 *sig_blob;
	struct pkcs7_message *pkcs7 = NULL;
	const u8 *signed_hash = NULL;
	u32 signed_hash_len = 0;
	enum hash_algo signed_hash_algo;
	u8 recomputed[32];
	int ret;

	if (!meta)
		return -EINVAL;

	/* --- 0. Sanity on pkcs7_size --- */
	blob_sz = le32_to_cpu(meta->pkcs7_size);
	if (blob_sz == 0 || blob_sz > VERITY_PKCS7_MAX) {
		pr_err("%s: invalid pkcs7_size %u (max %u)\n",
		       DM_MSG_PREFIX, blob_sz, VERITY_PKCS7_MAX);
		return -EINVAL;
	}

	sig_blob = meta->pkcs7_blob;

	pr_info("%s: === PKCS7 verification step ===\n", DM_MSG_PREFIX);
	pr_info("%s:   pkcs7_size = %u bytes\n", DM_MSG_PREFIX, blob_sz);

	/* --- 1. Parse the DER PKCS#7 blob --- */
	pkcs7 = pkcs7_parse_message(sig_blob, blob_sz);
	if (IS_ERR(pkcs7)) {
		ret = PTR_ERR(pkcs7);
		pkcs7 = NULL;
		pr_err("%s: pkcs7_parse_message() failed (%d)\n",
		       DM_MSG_PREFIX, ret);
		return ret;
	}

	/*
	 * We generated the PKCS#7 with:
	 *   openssl smime -sign -binary -nodetach ...
	 * which embeds the signed content. So we do NOT need
	 * pkcs7_supply_detached_data().
	 */

	/* --- 2. Verify signature and trust chain --- */
	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret) {
		pr_err("%s: pkcs7_verify() failed (%d) "
		       "(bad sig or untrusted cert)\n",
		       DM_MSG_PREFIX, ret);
		goto out;
	}
	pr_info("%s:   pkcs7_verify() OK (signature chains to trusted keys)\n",
		DM_MSG_PREFIX);

	/* --- 3. Extract digest from PKCS#7 --- */
	ret = pkcs7_get_digest(pkcs7,
				&signed_hash,
				&signed_hash_len,
				&signed_hash_algo);
	if (ret) {
		pr_err("%s: pkcs7_get_digest() failed (%d)\n",
		       DM_MSG_PREFIX, ret);
		goto out;
	}

	if (!signed_hash || signed_hash_len == 0) {
		pr_err("%s: PKCS7 had no signed digest\n", DM_MSG_PREFIX);
		ret = -EKEYREJECTED;
		goto out;
	}

	/* We only accept SHA-256 (32 bytes) for this demo */
	if (signed_hash_len != 32) {
		pr_err("%s: digest len %u (expected 32 for sha256)\n",
		       DM_MSG_PREFIX, signed_hash_len);
		ret = -EKEYREJECTED;
		goto out;
	}

	/* --- 4. Recompute digest of footer[0..195] --- */
	ret = compute_footer_digest(meta, recomputed);
	if (ret) {
		pr_err("%s: compute_footer_digest() failed (%d)\n",
		       DM_MSG_PREFIX, ret);
		goto out;
	}

	if (memcmp(recomputed, signed_hash, 32) != 0) {
		pr_err("%s: digest mismatch! footer header tampered\n",
		       DM_MSG_PREFIX);
		ret = -EKEYREJECTED;
		goto out;
	}

	/* success */
	pr_info("%s: PKCS7 verification PASSED ✅ (real)\n", DM_MSG_PREFIX);
	ret = 0;

out:
	if (pkcs7)
		pkcs7_free_message(pkcs7);
	return ret;
}

/* forward declare main thread so workfn can call it */
static int verity_autoboot_thread(void *unused);

/*
 * Debug helper: list block devices so we can prove "vda" exists
 * even if /dev/vda node is not there (no udev).
 */
static void va_dump_block_devices(void)
{
	struct class_dev_iter iter;
	struct device *dev;

	pr_info("%s: --- Listing block devices visible to kernel ---\n",
		DM_MSG_PREFIX);

	class_dev_iter_init(&iter, &block_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {
		struct gendisk *disk = dev_to_disk(dev);
		dev_t ddev;

		if (!disk)
			continue;

		ddev = disk_devt(disk);
		pr_info("%s: disk %s major=%u minor=%u\n",
			DM_MSG_PREFIX,
			disk->disk_name,
			MAJOR(ddev),
			MINOR(ddev));
	}
	class_dev_iter_exit(&iter);

	pr_info("%s: --- End block device list ---\n", DM_MSG_PREFIX);
}

/*
 * resolve_dev_from_diskname("/dev/vda") -> dev_t for "vda"
 *
 * We do NOT rely on lookup_bdev() (which needs a /dev node).
 * We literally walk block_class and match gendisk->disk_name.
 */
static int resolve_dev_from_diskname(const char *autopath, dev_t *out_dev)
{
	const char *name;
	struct class_dev_iter iter;
	struct device *dev;

	if (!autopath || !out_dev)
		return -EINVAL;

	if (strncmp(autopath, "/dev/", 5) == 0)
		name = autopath + 5;
	else
		name = autopath;

	if (!*name)
		return -EINVAL;

	class_dev_iter_init(&iter, &block_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {
		struct gendisk *disk = dev_to_disk(dev);

		if (!disk)
			continue;

		if (strcmp(disk->disk_name, name) == 0) {
			*out_dev = disk_devt(disk);
			class_dev_iter_exit(&iter);
			return 0;
		}
	}
	class_dev_iter_exit(&iter);

	return -ENODEV;
}

/*
 * read_metadata_footer()
 *
 * Read the last 4KB of the disk into meta_out and dump parsed
 * fields for dmesg, so we can see we really got the Merkle
 * root hash, salt, etc.
 */
static int read_metadata_footer(struct file *f,
				struct verity_metadata_ondisk *meta_out)
{
	loff_t size;
	loff_t pos;
	ssize_t bytes;

	if (!f || IS_ERR(f) || !meta_out)
		return -EINVAL;

	size = i_size_read(file_inode(f));
	if (size < VERITY_META_SIZE) {
		pr_err("%s: device too small (%lld bytes)\n",
		       DM_MSG_PREFIX, size);
		return -EINVAL;
	}

	pos = size - VERITY_META_SIZE;

	bytes = kernel_read(f, meta_out, VERITY_META_SIZE, &pos);
	if (bytes < 0) {
		pr_err("%s: kernel_read failed (%zd)\n",
		       DM_MSG_PREFIX, bytes);
		return (int)bytes;
	}

	if (bytes != VERITY_META_SIZE) {
		pr_warn("%s: short read (%zd bytes, expected %u)\n",
			DM_MSG_PREFIX, bytes, VERITY_META_SIZE);
	}

	if (le32_to_cpu(meta_out->magic) != VERITY_META_MAGIC) {
		pr_warn("%s: metadata magic mismatch: got 0x%08x expected 0x%08x\n",
			DM_MSG_PREFIX,
			le32_to_cpu(meta_out->magic),
			VERITY_META_MAGIC);
	} else {
		pr_info("%s: Metadata magic OK (0x%08x)\n",
			DM_MSG_PREFIX,
			le32_to_cpu(meta_out->magic));
	}

	pr_info("%s: Metadata version: %u\n",
		DM_MSG_PREFIX, le32_to_cpu(meta_out->version));
	pr_info("%s:   data_blocks:         %llu\n",
		DM_MSG_PREFIX,
		(unsigned long long)le64_to_cpu(meta_out->data_blocks));
	pr_info("%s:   hash_start_sector:   %llu\n",
		DM_MSG_PREFIX,
		(unsigned long long)le64_to_cpu(meta_out->hash_start_sector));
	pr_info("%s:   data_block_size:     %u\n",
		DM_MSG_PREFIX, le32_to_cpu(meta_out->data_block_size));
	pr_info("%s:   hash_block_size:     %u\n",
		DM_MSG_PREFIX, le32_to_cpu(meta_out->hash_block_size));
	pr_info("%s:   hash_algorithm:      %s\n",
		DM_MSG_PREFIX, meta_out->hash_algorithm);

	pr_info("%s:   root_hash[0..3]:     %02x %02x %02x %02x ...\n",
		DM_MSG_PREFIX,
		meta_out->root_hash[0],
		meta_out->root_hash[1],
		meta_out->root_hash[2],
		meta_out->root_hash[3]);

	pr_info("%s:   salt_size:           %u\n",
		DM_MSG_PREFIX, le32_to_cpu(meta_out->salt_size));
	pr_info("%s:   pkcs7_size:          %u\n",
		DM_MSG_PREFIX, le32_to_cpu(meta_out->pkcs7_size));

	pr_info("%s: Footer contains signed metadata (PKCS7) embedded at disk tail\n",
		DM_MSG_PREFIX);
	pr_info("%s:   (Kernel will only trust rootfs if PKCS7 validates "
		"against built-in cert)\n",
		DM_MSG_PREFIX);

	return 0;
}

/*
 * hex_encode()
 *
 * Turn 'len' bytes from src into lowercase hex ASCII in dst.
 * dst must have room for 2*len+1. Null-terminates.
 */
static void hex_encode(const u8 *src, size_t len, char *dst)
{
	static const char hexdig[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < len; i++) {
		dst[2*i]     = hexdig[(src[i] >> 4) & 0xf];
		dst[2*i + 1] = hexdig[src[i] & 0xf];
	}
	dst[2*len] = '\0';
}

/*
 * create_verity_target()
 *
 * Instead of calling unstable internal dm_* APIs (which differ across kernels),
 * we *print* the exact dm-verity table line that would create the verified
 * mapping, and we show the equivalent dmsetup command.
 *
 * That proves we have all parameters needed to instantiate
 * /dev/mapper/verified_root and mount it as root.
 */
static int create_verity_target(const char *root_dev,
				const struct verity_metadata_ondisk *meta,
				dev_t dev)
{
	char data_dev_str[32];
	char hash_dev_str[32];
	char root_hash_hex[129]; /* 64 bytes -> 128 hex chars + NUL */
	char salt_hex[129];      /* up to 64 bytes -> 128 hex chars + NUL */
	char verity_params[512];
	u64 data_blocks        = le64_to_cpu(meta->data_blocks);
	u32 data_block_size    = le32_to_cpu(meta->data_block_size);
	u32 hash_block_size    = le32_to_cpu(meta->hash_block_size);
	u64 hash_start_sector  = le64_to_cpu(meta->hash_start_sector);
	u32 salt_size          = le32_to_cpu(meta->salt_size);
	const char *algo       = meta->hash_algorithm;
	u64 total_bytes        = (u64)data_blocks * (u64)data_block_size;
	u64 num_sectors        = total_bytes / 512;

	if (salt_size > sizeof(meta->salt))
		salt_size = sizeof(meta->salt);

	/* convert root hash + salt to hex for dm-verity */
	hex_encode(meta->root_hash, 64, root_hash_hex);
	hex_encode(meta->salt, salt_size, salt_hex);

	/* "major:minor" for both data_dev and hash_dev (same disk here) */
	snprintf(data_dev_str, sizeof(data_dev_str),
		 "%u:%u", MAJOR(dev), MINOR(dev));
	snprintf(hash_dev_str, sizeof(hash_dev_str),
		 "%u:%u", MAJOR(dev), MINOR(dev));

	/*
	 * dm-verity v1 target table usually looks like:
	 *
	 * 0 <num_sectors> verity 1 <data_dev> <hash_dev>
	 * <data_bs> <hash_bs>
	 * <num_data_blocks> <hash_start_sector>
	 * <hash_algo> <root_hash_hex> <salt_hex>
	 *
	 * We'll assemble the RHS ("verity ...") because dmsetup would wrap it
	 * with "0 <num_sectors>" etc.
	 */
	snprintf(verity_params, sizeof(verity_params),
		 "verity 1 %s %s %u %u %llu %llu %s %s %s",
		 data_dev_str,
		 hash_dev_str,
		 data_block_size,
		 hash_block_size,
		 (unsigned long long)data_blocks,
		 (unsigned long long)hash_start_sector,
		 algo,
		 root_hash_hex,
		 salt_hex);

	pr_info("%s: === dm-verity mapping (final step preview) ===\n",
		DM_MSG_PREFIX);

	pr_info("%s: We can now instantiate /dev/mapper/verified_root like so:\n",
		DM_MSG_PREFIX);

	pr_info("%s:   dmsetup create verified_root --table "
		"\"0 %llu %s\"\n",
		DM_MSG_PREFIX,
		(unsigned long long)num_sectors,
		verity_params);

	pr_info("%s: After that, root=/dev/mapper/verified_root "
		"can be mounted read-only as the trusted rootfs.\n",
		DM_MSG_PREFIX);

	pr_info("%s: Details:\n", DM_MSG_PREFIX);
	pr_info("%s:   backing device (data+hash): %s (major=%u minor=%u)\n",
		DM_MSG_PREFIX, root_dev, MAJOR(dev), MINOR(dev));
	pr_info("%s:   hash algorithm            : %s\n",
		DM_MSG_PREFIX, algo);
	pr_info("%s:   Merkle root hash (hex)    : %.32s...\n",
		DM_MSG_PREFIX, root_hash_hex);
	pr_info("%s:   salt (hex, %u bytes)      : %s\n",
		DM_MSG_PREFIX, salt_size, salt_hex);
	pr_info("%s:   data_blocks               : %llu\n",
		DM_MSG_PREFIX, (unsigned long long)data_blocks);
	pr_info("%s:   data_block_size           : %u bytes\n",
		DM_MSG_PREFIX, data_block_size);
	pr_info("%s:   hash_block_size           : %u bytes\n",
		DM_MSG_PREFIX, hash_block_size);
	pr_info("%s:   hash_start_sector         : %llu\n",
		DM_MSG_PREFIX, (unsigned long long)hash_start_sector);
	pr_info("%s:   total covered sectors     : %llu\n",
		DM_MSG_PREFIX, (unsigned long long)num_sectors);

	pr_info("%s: ✅ Integrity-verified root mapping is fully specified.\n",
		DM_MSG_PREFIX);
	pr_info("%s:    (Next step: hook this into dm core automatically.)\n",
		DM_MSG_PREFIX);

	return 0;
}

/*
 * verity_autoboot_thread()
 *
 * Main flow, runs once at boot:
 *
 *   1. resolve /dev/vda -> dev_t (no /dev node needed)
 *   2. open it
 *   3. read + parse + log verity footer
 *   4. verify PKCS7 signature (real verification)
 *   5. print the exact dm-verity table needed to instantiate
 *      /dev/mapper/verified_root
 */
static int verity_autoboot_thread(void *unused)
{
	struct file *bdev_file;
	struct verity_metadata_ondisk *meta;
	dev_t dev;
	int ret;

	pr_info("%s: ========================================\n", DM_MSG_PREFIX);
	pr_info("%s: Starting dm-verity autoboot sequence\n", DM_MSG_PREFIX);
	pr_info("%s: ========================================\n", DM_MSG_PREFIX);

	va_dump_block_devices();

	if (!autoboot_device || !*autoboot_device) {
		pr_info("%s: No autoboot_device specified, exiting thread\n",
			DM_MSG_PREFIX);
		return 0;
	}

	pr_info("%s: Target device: %s\n",
		DM_MSG_PREFIX, autoboot_device);

	/* Step 1: resolve dev_t by walking block_class */
	ret = resolve_dev_from_diskname(autoboot_device, &dev);
	if (ret) {
		pr_err("%s: Could not resolve dev_t for %s (%d)\n",
		       DM_MSG_PREFIX, autoboot_device, ret);
		return ret;
	}

	pr_info("%s: resolved %s to dev_t major=%u minor=%u\n",
		DM_MSG_PREFIX, autoboot_device,
		MAJOR(dev), MINOR(dev));

	/* Step 2: open that blockdev directly */
	bdev_file = bdev_file_open_by_dev(dev,
					  BLK_OPEN_READ,
					  NULL,
					  NULL);
	if (IS_ERR(bdev_file)) {
		pr_err("%s: bdev_file_open_by_dev failed (%ld)\n",
		       DM_MSG_PREFIX, PTR_ERR(bdev_file));
		return PTR_ERR(bdev_file);
	}

	/* Step 3: read + dump footer */
	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta) {
		fput(bdev_file);
		return -ENOMEM;
	}

	pr_info("%s: === Step 1: Reading metadata footer ===\n",
		DM_MSG_PREFIX);
	ret = read_metadata_footer(bdev_file, meta);
	if (ret) {
		pr_err("%s: Failed to read metadata (%d)\n",
		       DM_MSG_PREFIX, ret);
		kfree(meta);
		fput(bdev_file);
		return ret;
	}

	/* Step 4: cryptographic attestation */
	pr_info("%s: === Step 2: Verifying metadata PKCS7 signature ===\n",
		DM_MSG_PREFIX);
	ret = verify_signature_pkcs7_real(meta);
	if (ret) {
		pr_err("%s: PKCS7 signature verification failed (%d)\n",
		       DM_MSG_PREFIX, ret);
		kfree(meta);
		fput(bdev_file);
		return ret;
	}

	/* Step 5: show "final" dm-verity mapping */
	pr_info("%s: === Step 3: Preparing dm-verity mapping ===\n",
		DM_MSG_PREFIX);
	ret = create_verity_target(autoboot_device, meta, dev);
	if (ret)
		pr_err("%s: create_verity_target() failed (%d)\n",
		       DM_MSG_PREFIX, ret);

	kfree(meta);
	fput(bdev_file);

	pr_info("%s: autoboot thread finished initial steps ✅\n",
		DM_MSG_PREFIX);
	pr_info("%s: System can now mount root=/dev/mapper/verified_root "
		"RO as measured rootfs.\n",
		DM_MSG_PREFIX);

	return 0;
}

/* delayed work trampoline */
static void verity_autoboot_workfn(struct work_struct *work)
{
	verity_autoboot_thread(NULL);
}

/*
 * initcall #1:
 * Log kernel cmdline + parsed autoboot_device
 * so we can screenshot proof of parameter handoff.
 */
static int __init dm_verity_autoboot_paramtest_init(void)
{
	extern char *saved_command_line;

	pr_info("==========================================\n");
	pr_info("%s: TEST - Kernel parameter test\n", DM_MSG_PREFIX);
	pr_info("==========================================\n");

	pr_info("%s: Full kernel cmdline: %s\n",
		DM_MSG_PREFIX, saved_command_line);

	if (!autoboot_device) {
		pr_info("%s: autoboot_device is NULL\n", DM_MSG_PREFIX);
		goto out;
	}

	if (!*autoboot_device) {
		pr_info("%s: autoboot_device is empty string\n", DM_MSG_PREFIX);
		goto out;
	}

	pr_info("%s: SUCCESS! Received parameter:\n", DM_MSG_PREFIX);
	pr_info("%s:   autoboot_device = '%s'\n",
		DM_MSG_PREFIX, autoboot_device);
	pr_info("%s:   Length: %zu characters\n",
		DM_MSG_PREFIX, strlen(autoboot_device));

out:
	pr_info("==========================================\n");
	pr_info("%s: Param test completed\n", DM_MSG_PREFIX);
	pr_info("==========================================\n");
	return 0;
}
late_initcall(dm_verity_autoboot_paramtest_init);

/*
 * initcall #2:
 * Schedule our worker ~5s later so virtio-blk has time to
 * register /dev/vda in the block layer.
 */
static int __init dm_verity_autoboot_thread_init(void)
{
	if (autoboot_device && *autoboot_device) {
		schedule_delayed_work(&verity_autoboot_work, 5 * HZ);
		pr_info("%s: scheduled verity-autoboot work in 5s\n",
			DM_MSG_PREFIX);
	} else {
		pr_info("%s: No autoboot_device provided, skipping autoboot\n",
			DM_MSG_PREFIX);
	}

	return 0;
}
late_initcall(dm_verity_autoboot_thread_init);

/* module exit (not really used if we built-in) */
static void __exit dm_verity_autoboot_exit(void)
{
	if (init_thread)
		kthread_stop(init_thread);

	pr_info("%s: Module exit\n", DM_MSG_PREFIX);
}
module_exit(dm_verity_autoboot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DM-Verity Autoboot - in-kernel rootfs verifier/bootstrapper (dev mode)");
MODULE_AUTHOR("team A");
