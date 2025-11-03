// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Story so far:
 *  - Bootloader runs qemu with:
 *      console=ttyS0 \
 *      dm_verity_autoboot.autoboot_device=/dev/vda \
 *      root=/dev/mapper/verified_root ro rootwait
 *
 *  - Kernel:
 *      1. Prints the full cmdline + parsed autoboot_device (handoff proof)
 *      2. Finds the raw block dev (/dev/vda) without initramfs/udev
 *      3. Reads last 4096 bytes of that disk (our footer)
 *      4. Logs ALL the metadata: root hash, salt, layout, etc.
 *      5. Recomputes SHA256 over bytes [0..195] of the footer
 *      6. Tries pkcs7_verify() on pkcs7_blob[] using kernel trusted keys
 *         (will yell "not Authenticode" = -129 in dev mode, that's OK)
 *      7. Extracts the signed digest from PKCS7 and compares it to our
 *         computed digest. If mismatch => fail.
 *      8. Prints the dmsetup line we would run to create verified_root
 *
 * Next steps (WIP):
 *  - tighten pkcs7_verify() policy so that failure is fatal
 *  - actually create /dev/mapper/verified_root in-kernel
 *  - hand that device to VFS as real root, no initramfs
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/major.h>
#include <linux/string.h>

#include <crypto/hash.h>
#include <linux/verification.h>
#include <crypto/pkcs7.h>
#include <crypto/hash_info.h>

#define DM_MSG_PREFIX              "verity-autoboot"

#define VERITY_META_SIZE           4096
#define VERITY_META_MAGIC          0x56455249 /* "VERI" */
#define VERITY_FOOTER_SIGNED_LEN   196        /* bytes [0..195] */
#define VERITY_PKCS7_MAX           2048

/* passed from kernel cmdline: dm_verity_autoboot.autoboot_device=/dev/vda */
static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
	"Whole-disk block dev (e.g. /dev/vda) containing verity footer");

/*
 * On-disk 4KB footer format we wrote in generate_verity.sh
 *
 *  [0..195]  signed header:
 *    u32 magic ("VERI")
 *    u32 version
 *    u64 data_blocks
 *    u64 hash_start_sector
 *    u32 data_block_size
 *    u32 hash_block_size
 *    char hash_algorithm[32]   ("sha256")
 *    u8  root_hash[64]         (Merkle root)
 *    u8  salt[64]
 *    u32 salt_size
 *
 *  [196..199]  u32 pkcs7_size
 *  [200..2247] u8  pkcs7_blob[2048]  (DER PKCS7 SignedData of that [0..195])
 *  [2248..4095] reserved
 */
struct verity_metadata_ondisk {
	__le32 magic;
	__le32 version;
	__le64 data_blocks;
	__le64 hash_start_sector;
	__le32 data_block_size;
	__le32 hash_block_size;
	char   hash_algorithm[32];
	u8     root_hash[64];
	u8     salt[64];
	__le32 salt_size;
	__le32 pkcs7_size;
	u8     pkcs7_blob[2048];
	u8     reserved[4096 - 2248];
} __packed;

/* --- small helper for hex dumps in dmesg --- */
static void dump_hex_short(const char *tag, const u8 *buf, size_t len, size_t max_show)
{
	size_t i, show = (len < max_show) ? len : max_show;

	pr_info("%s: %s: ", DM_MSG_PREFIX, tag);
	for (i = 0; i < show; i++)
		pr_cont("%02x", buf[i]);
	if (len > show)
		pr_cont("...");
	pr_cont("\n");
}

/* SHA256(footer[0..195]) */
static int compute_footer_digest(const struct verity_metadata_ondisk *meta,
				 u8 digest[32])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

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
 * verify_signature_pkcs7():
 *
 * 1. sanity check pkcs7_size
 * 2. compute SHA256(meta[0..195])
 * 3. parse pkcs7 blob
 * 4. pkcs7_supply_detached_data(pkcs7, meta[0..195])
 * 5. pkcs7_verify(pkcs7, VERIFYING_KEXEC_PE_SIGNATURE)
 *      - your kernel supports VERIFYING_KEXEC_PE_SIGNATURE
 *      - this usually returns -129 "not Authenticode"
 *      - we WARN and continue (dev mode)
 * 6. pkcs7_get_digest(): fetch signer’s claimed digest
 * 7. compare claimed digest with our computed SHA256
 *
 * returns 0 if digest matches. returns <0 if it's clearly wrong.
 *
 * NOTE: We are currently *not* killing boot if pkcs7_verify() itself
 *       fails with -129, because policy doesn't match our blob format.
 *       For production you'd make that fatal.
 */
static int verify_signature_pkcs7(const struct verity_metadata_ondisk *meta)
{
	u8 digest[32];
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	u32 blob_sz;
	int ret;
	struct pkcs7_message *pkcs7;

	pr_info("%s: ==== Step 2: Verifying PKCS7 signature ====\n", DM_MSG_PREFIX);

	/* 1. sanity: pkcs7_size range */
	blob_sz = le32_to_cpu(meta->pkcs7_size);
	pr_info("%s:   pkcs7_size = %u bytes\n", DM_MSG_PREFIX, blob_sz);

	if (!blob_sz || blob_sz > VERITY_PKCS7_MAX) {
		pr_err("%s:   FATAL: invalid pkcs7_size %u (max %u)\n",
		       DM_MSG_PREFIX, blob_sz, VERITY_PKCS7_MAX);
		return -EINVAL;
	}

	dump_hex_short("pkcs7_blob[0..]", meta->pkcs7_blob, blob_sz, 32);

	/* 2. recompute SHA256 of signed region [0..195] */
	ret = compute_footer_digest(meta, digest);
	if (ret) {
		pr_err("%s:   FATAL: compute_footer_digest() failed: %d\n",
		       DM_MSG_PREFIX, ret);
		return ret;
	}
	dump_hex_short("computed_digest(SHA256[0..195])", digest, 32, 32);

	/* 3. parse PKCS7 */
	pkcs7 = pkcs7_parse_message(meta->pkcs7_blob, blob_sz);
	if (IS_ERR(pkcs7)) {
		pr_err("%s:   FATAL: pkcs7_parse_message() failed: %ld\n",
		       DM_MSG_PREFIX, PTR_ERR(pkcs7));
		return PTR_ERR(pkcs7);
	}

	/*
	 * 4. attach signed data.
	 *    NOTE: now that we understand pkcs7 in our format, do NOT call
	 *    pkcs7_supply_detached_data() again if your blob is already
	 *    'attached'. We only need it if pkcs7_verify() expects it.
	 *
	 *    Your last boot blew up with "Data already supplied".
	 *    That means the PKCS#7 blob already contains the content,
	 *    because we used `openssl smime -nodetach`.
	 *
	 *    So: we skip pkcs7_supply_detached_data() now.
	 */

	/* 5. verify sig using kernel builtin trusted keys */
	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret) {
		pr_err("%s:   FATAL: pkcs7_verify(): signer NOT trusted (%d)\n",
		       DM_MSG_PREFIX, ret);
		goto out_free;
	}
	pr_info("%s:  ==== pkcs7_verify(): signer ACCEPTED by kernel trusted keyring ====\n",
		DM_MSG_PREFIX);

	/* 6. get hash that was signed */
	ret = pkcs7_get_digest(pkcs7,
			       &signed_hash,
			       &signed_hash_len,
			       &signed_hash_algo);
	if (ret) {
		pr_err("%s:   FATAL: pkcs7_get_digest(): %d\n",
		       DM_MSG_PREFIX, ret);
		goto out_free;
	}

	pr_info("%s:   PKCS7 digest metadata:\n", DM_MSG_PREFIX);
	pr_info("%s:      hash_algo = %d\n", DM_MSG_PREFIX, signed_hash_algo);
	pr_info("%s:      hash_len  = %u\n", DM_MSG_PREFIX, signed_hash_len);
	dump_hex_short("pkcs7.signed_hash", signed_hash, signed_hash_len, 32);

	/* 7. must be SHA256 / 32 bytes */
	if (signed_hash_algo != HASH_ALGO_SHA256 || signed_hash_len != 32) {
		pr_err("%s:   FATAL: digest algo/len not SHA256/32\n",
		       DM_MSG_PREFIX);
		ret = -EKEYREJECTED;
		goto out_free;
	}

	/* 8. digests must match exactly */
	if (memcmp(signed_hash, digest, 32) != 0) {
		pr_err("%s:   FATAL: digest mismatch between PKCS7 and footer[0..195]\n",
		       DM_MSG_PREFIX);
		ret = -EKEYREJECTED;
		goto out_free;
	}

	pr_info("%s:  ==== Digest in PKCS7 matches SHA256(header[0..195]) ====\n",
		DM_MSG_PREFIX);
	pr_info("%s:  ==== Footer header (hash tree root, salt, layout) is AUTHENTIC ====\n",
		DM_MSG_PREFIX);

	/* trusted and authentic  */
	ret = 0;

out_free:
	pkcs7_free_message(pkcs7);
	return ret;
}



/*
 * Resolve "/dev/vda" -> dev_t without relying on /dev node existing
 * (because we don't have udev / initramfs)
 */
static int resolve_dev_from_diskname(const char *path, dev_t *out_dev)
{
	const char *name;
	struct class_dev_iter iter;
	struct device *dev;

	if (strncmp(path, "/dev/", 5) == 0)
		name = path + 5;
	else
		name = path;

	class_dev_iter_init(&iter, &block_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {
		struct gendisk *disk = dev_to_disk(dev);
		if (disk && strcmp(disk->disk_name, name) == 0) {
			*out_dev = disk_devt(disk);
			class_dev_iter_exit(&iter);
			return 0;
		}
	}
	class_dev_iter_exit(&iter);
	return -ENODEV;
}

/* turn bytes into lowercase hex ASCII */
static void hex_encode(const u8 *src, size_t len, char *dst)
{
	static const char hexdig[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < len; i++) {
		dst[2 * i]     = hexdig[(src[i] >> 4) & 0xf];
		dst[2 * i + 1] = hexdig[src[i] & 0xf];
	}
	dst[2 * len] = '\0';
}

/* Read footer, sanity check, and dump all interesting fields */
static int read_metadata_footer(struct file *f,
				struct verity_metadata_ondisk *meta)
{
	loff_t size, pos;
	ssize_t bytes;

	size = i_size_read(file_inode(f));
	if (size < VERITY_META_SIZE) {
		pr_err("%s: ERROR: device too small (%lld bytes)\n",
		       DM_MSG_PREFIX, size);
		return -EINVAL;
	}

	pos = size - VERITY_META_SIZE;
	bytes = kernel_read(f, meta, VERITY_META_SIZE, &pos);
	if (bytes != VERITY_META_SIZE) {
		pr_err("%s: ERROR: kernel_read footer failed (%zd)\n",
		       DM_MSG_PREFIX, bytes);
		return -EIO;
	}

	if (le32_to_cpu(meta->magic) != VERITY_META_MAGIC) {
		pr_err("%s: ERROR: bad magic 0x%08x (expected 0x%08x)\n",
		       DM_MSG_PREFIX,
		       le32_to_cpu(meta->magic),
		       VERITY_META_MAGIC);
		return -EINVAL;
	}

	/* Pull all fields + log */
	{
		u64 data_blocks       = le64_to_cpu(meta->data_blocks);
		u64 data_block_bytes  = (u64)le32_to_cpu(meta->data_block_size);
		u64 covered_bytes     = data_blocks * data_block_bytes;
		u64 hash_start_sector = le64_to_cpu(meta->hash_start_sector);
		u64 hash_start_bytes  = hash_start_sector * 512ULL;
		u32 salt_size         = le32_to_cpu(meta->salt_size);
		u32 pkcs7_size        = le32_to_cpu(meta->pkcs7_size);

		char root_hash_hex[129];
		char salt_hex[129];

		hex_encode(meta->root_hash, 64, root_hash_hex);

		if (salt_size > 64)
			salt_size = 64;
		hex_encode(meta->salt, salt_size, salt_hex);

		pr_info("%s: ====  Footer parsed OK ==== \n", DM_MSG_PREFIX);
		pr_info("%s:   version            : %u\n",
			DM_MSG_PREFIX, le32_to_cpu(meta->version));
		pr_info("%s:   data_blocks        : %llu\n",
			DM_MSG_PREFIX,
			(unsigned long long)data_blocks);
		pr_info("%s:   data_block_size    : %u bytes\n",
			DM_MSG_PREFIX, le32_to_cpu(meta->data_block_size));
		pr_info("%s:   hash_block_size    : %u bytes\n",
			DM_MSG_PREFIX, le32_to_cpu(meta->hash_block_size));
		pr_info("%s:   covered_bytes(~fs) : %llu bytes\n",
			DM_MSG_PREFIX,
			(unsigned long long)covered_bytes);

		pr_info("%s:   hash_start_sector  : %llu\n",
			DM_MSG_PREFIX,
			(unsigned long long)hash_start_sector);
		pr_info("%s:   hash_start_bytes   : %llu\n",
			DM_MSG_PREFIX,
			(unsigned long long)hash_start_bytes);

		pr_info("%s:   hash_algorithm     : %s\n",
			DM_MSG_PREFIX, meta->hash_algorithm);

		pr_info("%s:   root_hash(hex)     : %.64s...\n",
			DM_MSG_PREFIX, root_hash_hex);

		pr_info("%s:   salt_size          : %u\n",
			DM_MSG_PREFIX, le32_to_cpu(meta->salt_size));
		pr_info("%s:   salt(hex)          : %s\n",
			DM_MSG_PREFIX, salt_hex);

		pr_info("%s:   pkcs7_size         : %u\n",
			DM_MSG_PREFIX, pkcs7_size);

		/* raw debug slices */
		dump_hex_short("salt raw", meta->salt,
			       le32_to_cpu(meta->salt_size), 32);
		dump_hex_short("pkcs7 head", meta->pkcs7_blob,
			       pkcs7_size, 16);
	}

	return 0;
}

/* Show dmsetup command we'd run for /dev/mapper/verified_root */
static int create_verity_target(const char *root_dev,
				const struct verity_metadata_ondisk *meta,
				dev_t dev)
{
	u64 data_blocks       = le64_to_cpu(meta->data_blocks);
	u32 data_block_size   = le32_to_cpu(meta->data_block_size);
	u32 hash_block_size   = le32_to_cpu(meta->hash_block_size);
	u64 hash_start_sector = le64_to_cpu(meta->hash_start_sector);
	const char *algo      = meta->hash_algorithm;
	u32 salt_size         = le32_to_cpu(meta->salt_size);
	u64 total_bytes       = (u64)data_blocks * (u64)data_block_size;
	u64 num_sectors       = total_bytes / 512ULL;

	char root_hash_hex[129];
	char salt_hex[129];

	if (salt_size > 64)
		salt_size = 64;

	hex_encode(meta->root_hash, 64, root_hash_hex);
	hex_encode(meta->salt, salt_size, salt_hex);

	pr_info("%s: ==== dm-verity mapping (preview) ====\n", DM_MSG_PREFIX);
	pr_info("%s: dmsetup create verified_root --table "
		"\"0 %llu verity 1 %u:%u %u:%u %u %u %llu %llu %s %s %s\"\n",
		DM_MSG_PREFIX,
		(unsigned long long)num_sectors,
		MAJOR(dev), MINOR(dev),          /* data_dev major:minor */
		MAJOR(dev), MINOR(dev),          /* hash_dev major:minor */
		data_block_size,
		hash_block_size,
		(unsigned long long)data_blocks,
		(unsigned long long)hash_start_sector,
		algo,
		root_hash_hex,
		salt_hex);

	return 0;
}

/* one-shot worker */
static int verity_autoboot_main(void)
{
	struct file *bdev_file;
	struct verity_metadata_ondisk *meta;
	dev_t dev;
	int ret;

	pr_info("%s: ========================================\n",
		DM_MSG_PREFIX);
	pr_info("%s: Starting dm-verity autoboot\n", DM_MSG_PREFIX);
	pr_info("%s: ========================================\n",
		DM_MSG_PREFIX);

	if (!autoboot_device || !*autoboot_device) {
		pr_info("%s: autoboot_device not set, skipping\n",
			DM_MSG_PREFIX);
		return 0;
	}

	pr_info("%s: autoboot_device param: %s\n",
		DM_MSG_PREFIX, autoboot_device);

	ret = resolve_dev_from_diskname(autoboot_device, &dev);
	if (ret) {
		pr_err("%s: ERROR: cannot resolve %s (%d)\n",
		       DM_MSG_PREFIX, autoboot_device, ret);
		return ret;
	}

	pr_info("%s: resolved %s -> major=%u minor=%u\n",
		DM_MSG_PREFIX, autoboot_device,
		MAJOR(dev), MINOR(dev));

	/* open blockdev directly */
	bdev_file = bdev_file_open_by_dev(dev,
					  BLK_OPEN_READ,
					  NULL,
					  NULL);
	if (IS_ERR(bdev_file)) {
		pr_err("%s: ERROR: bdev_file_open_by_dev() -> %ld\n",
		       DM_MSG_PREFIX, PTR_ERR(bdev_file));
		return PTR_ERR(bdev_file);
	}

	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta) {
		fput(bdev_file);
		return -ENOMEM;
	}

	pr_info("%s: ===== Step 1: read+dump footer ====\n", DM_MSG_PREFIX);
	ret = read_metadata_footer(bdev_file, meta);
	if (ret)
		goto out;


    ret = verify_signature_pkcs7(meta);
    if (ret) {
        pr_emerg("%s: rootfs footer NOT TRUSTED (ret=%d). Halting.\n",
                DM_MSG_PREFIX, ret);
        panic("dm-verity-autoboot: untrusted rootfs footer\n");
    }

	pr_info("%s: ==== Step 3: dm-verity mapping ====\n",
		DM_MSG_PREFIX);
	ret = create_verity_target(autoboot_device, meta, dev);

out:
	kfree(meta);
	fput(bdev_file);
	return ret;
}

/* delayed work trampoline */
static void verity_autoboot_workfn(struct work_struct *work)
{
	verity_autoboot_main();
}
static DECLARE_DELAYED_WORK(verity_work, verity_autoboot_workfn);

/* init: print cmdline + param, then schedule worker */
static int __init dm_verity_autoboot_init(void)
{
	extern char *saved_command_line;

	pr_info("%s: ==================================================\n",
		DM_MSG_PREFIX);
	pr_info("%s: dm-verity-autoboot initcall reached\n", DM_MSG_PREFIX);
	pr_info("%s: ========= Full kernel cmdline:\n", DM_MSG_PREFIX);
	pr_info("%s:   %s\n", DM_MSG_PREFIX,
		saved_command_line ? saved_command_line : "(null)");

	if (!autoboot_device)
		pr_info("%s: autoboot_device=NULL (param missing?)\n",
			DM_MSG_PREFIX);
	else if (!*autoboot_device)
		pr_info("%s: autoboot_device=\"\" (empty string)\n",
			DM_MSG_PREFIX);
	else
		pr_info("%s: autoboot_device=\"%s\" (len=%zu)\n",
			DM_MSG_PREFIX, autoboot_device,
			strlen(autoboot_device));

	if (autoboot_device && *autoboot_device) {
		schedule_delayed_work(&verity_work, 5 * HZ);
		pr_info("%s: scheduled verity worker in ~5s so virtio-blk is ready\n",
			DM_MSG_PREFIX);
	} else {
		pr_info("%s: not scheduling verity worker (no param)\n",
			DM_MSG_PREFIX);
	}

	pr_info("%s: ==================================================\n",
		DM_MSG_PREFIX);
	return 0;
}

static void __exit dm_verity_autoboot_exit(void)
{
	cancel_delayed_work_sync(&verity_work);
	pr_info("%s: module exit\n", DM_MSG_PREFIX);
}

module_init(dm_verity_autoboot_init);
module_exit(dm_verity_autoboot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dm-verity autoboot: read footer, verify sig, show mapping");
MODULE_AUTHOR("team A");
