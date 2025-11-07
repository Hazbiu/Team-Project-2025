// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot-full.c
 *
 * Complete dm-verity autoboot (no userspace):
 *  1. Read metadata from rootfs partition
 *  2. Verify PKCS7 signature
 *  3. Create dm-verity device mapping in-kernel
 *  4. Allow kernel to mount verified root (at /dev/dm-0)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/device-mapper.h>

#include <crypto/hash.h>
#include <linux/verification.h>
#include <crypto/pkcs7.h>
#include <crypto/hash_info.h>

#define DM_MSG_PREFIX              "verity-autoboot"

#define VERITY_META_SIZE           4096
#define VERITY_META_MAGIC          0x56455249 /* "VERI" */
#define VERITY_FOOTER_SIGNED_LEN   196
#define VERITY_PKCS7_MAX           2048

/* Detached locator footer */
#define VLOC_MAGIC                 0x564C4F43 /* "VLOC" */

static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
	"Block device containing rootfs with verity footer (e.g. /dev/vda1)");

/* On-disk 196-byte header */
struct verity_header_196 {
	__le32 magic;
	__le32 version;
	__le64 data_blocks;
	__le64 hash_start_sector; /* sectors (512B) relative to the partition */
	__le32 data_block_size;
	__le32 hash_block_size;
	char   hash_algorithm[32];
	u8     root_hash[64];
	u8     salt[64];
	__le32 salt_size;
} __packed;

/* Optional 4KB footer: DETACHED mode ("VLOC") */
struct verity_footer_locator {
	__le32 magic;
	__le32 version;
	__le64 meta_off;
	__le32 meta_len;  /* 196 */
	__le64 sig_off;
	__le32 sig_len;
	u8     reserved[4096 - 32];
} __packed;

/* Parsed metadata for dm-verity setup */
struct verity_config {
	u64    data_blocks;
	u64    hash_start_block; /* blocks (data_block_size) */
	u32    data_block_size;
	u32    hash_block_size;
	char   algorithm[32];
	u8     root_hash[64];
	size_t root_hash_len;
	u8     salt[64];
	u32    salt_size;
};

/* --- helpers & logging --- */
static void dump_hex_short(const char *tag, const u8 *buf, size_t len, size_t max_show)
{
	size_t i, show = min(len, max_show);
	pr_info("%s: %s: ", DM_MSG_PREFIX, tag);
	for (i = 0; i < show; i++)
		pr_cont("%02x", buf[i]);
	if (len > show)
		pr_cont("...");
	pr_cont("\n");
}

static int sha256_buf(const u8 *buf, size_t len, u8 digest[32])
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
	ret = crypto_shash_update(desc, buf, len);
	if (ret)
		goto out;
	ret = crypto_shash_final(desc, digest);

out:
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static int read_region(struct file *bdev_file, u64 off, u32 len, u8 **out)
{
	loff_t pos = off;
	ssize_t rd;
	u8 *buf;

	if (!len || len > (8U << 20))
		return -EINVAL;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rd = kernel_read(bdev_file, buf, len, &pos);
	if (rd != len) {
		kfree(buf);
		return rd < 0 ? (int)rd : -EIO;
	}

	*out = buf;
	return 0;
}

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

/* ---- PKCS7 verification (DETACHED) ---- */
static int verify_signature_pkcs7_detached(const u8 *meta_buf, u32 meta_len,
					   const u8 *sig_buf,  u32 sig_len)
{
	struct pkcs7_message *pkcs7;
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	u8 digest[32];
	int ret;

	pr_info("%s: Verifying PKCS7 signature (detached)\n", DM_MSG_PREFIX);
	pr_info("%s:   meta_len = %u, sig_len = %u\n", DM_MSG_PREFIX, meta_len, sig_len);
	dump_hex_short("detached.pkcs7 head", sig_buf, sig_len, 32);

	if (!meta_len || meta_len < VERITY_FOOTER_SIGNED_LEN ||
	    sig_len == 0 || sig_len > VERITY_PKCS7_MAX)
		return -EINVAL;

	ret = sha256_buf(meta_buf, meta_len, digest);
	if (ret) {
		pr_err("%s: sha256(meta_buf) failed: %d\n", DM_MSG_PREFIX, ret);
		return ret;
	}
	dump_hex_short("computed_digest(SHA256[meta_buf])", digest, 32, 32);

	pkcs7 = pkcs7_parse_message(sig_buf, sig_len);
	if (IS_ERR(pkcs7)) {
		pr_err("%s: pkcs7_parse_message(): %ld\n", DM_MSG_PREFIX, PTR_ERR(pkcs7));
		return PTR_ERR(pkcs7);
	}

	ret = pkcs7_supply_detached_data(pkcs7, meta_buf, meta_len);
	if (ret) {
		pr_err("%s: pkcs7_supply_detached_data(): %d\n", DM_MSG_PREFIX, ret);
		goto out_free;
	}

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret) {
		pr_err("%s: pkcs7_verify(): signer NOT trusted (%d)\n", DM_MSG_PREFIX, ret);
		goto out_free;
	}

	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len, &signed_hash_algo);
	if (ret) {
		pr_err("%s: pkcs7_get_digest(): %d\n", DM_MSG_PREFIX, ret);
		goto out_free;
	}

	pr_info("%s:   digest algo = %d, len = %u\n",
		DM_MSG_PREFIX, signed_hash_algo, signed_hash_len);
	dump_hex_short("pkcs7.signed_hash", signed_hash, signed_hash_len, 32);

	if (signed_hash_algo != HASH_ALGO_SHA256 || signed_hash_len != 32) {
		pr_err("%s: digest algo/len not SHA256/32\n", DM_MSG_PREFIX);
		ret = -EKEYREJECTED;
		goto out_free;
	}
	if (memcmp(signed_hash, digest, 32) != 0) {
		pr_err("%s: digest mismatch between PKCS7 and detached metadata\n", DM_MSG_PREFIX);
		ret = -EKEYREJECTED;
		goto out_free;
	}

	pr_info("%s: Signature verification PASSED (detached)\n", DM_MSG_PREFIX);
	ret = 0;

out_free:
	pkcs7_free_message(pkcs7);
	return ret;
}

/* Parse the 196-byte header into verity_config */
static int parse_verity_header(const u8 *meta_buf, struct verity_config *cfg)
{
	const struct verity_header_196 *hdr = (const struct verity_header_196 *)meta_buf;
	u32 magic = le32_to_cpu(hdr->magic);

	if (magic != VERITY_META_MAGIC) {
		pr_err("%s: bad metadata magic 0x%08x\n", DM_MSG_PREFIX, magic);
		return -EINVAL;
	}

	cfg->data_blocks     = le64_to_cpu(hdr->data_blocks);
	cfg->data_block_size = le32_to_cpu(hdr->data_block_size);
	cfg->hash_block_size = le32_to_cpu(hdr->hash_block_size);
	cfg->salt_size       = min_t(u32, le32_to_cpu(hdr->salt_size), (u32)64);

	/* No-superblock layout: hashtree starts right after data blocks. */
	cfg->hash_start_block = cfg->data_blocks;

	memset(cfg->algorithm, 0, sizeof(cfg->algorithm));
	memcpy(cfg->algorithm, hdr->hash_algorithm, 31);
	cfg->algorithm[31] = '\0';

	/* sha256 root hash length = 32 bytes */
	cfg->root_hash_len = 32;
	memcpy(cfg->root_hash, hdr->root_hash, 64);
	memcpy(cfg->salt,      hdr->salt,      64);

	pr_info("%s: Parsed metadata:\n", DM_MSG_PREFIX);
	pr_info("%s:   data_blocks      = %llu\n", DM_MSG_PREFIX, (unsigned long long)cfg->data_blocks);
	pr_info("%s:   hash_start_block = %llu\n", DM_MSG_PREFIX, (unsigned long long)cfg->hash_start_block);
	pr_info("%s:   data_block_size  = %u\n",  DM_MSG_PREFIX, cfg->data_block_size);
	pr_info("%s:   hash_block_size  = %u\n",  DM_MSG_PREFIX, cfg->hash_block_size);
	pr_info("%s:   algorithm        = %s\n",  DM_MSG_PREFIX, cfg->algorithm);
	pr_info("%s:   salt_size        = %u\n",  DM_MSG_PREFIX, cfg->salt_size);

	return 0;
}

/* ---- in-kernel dm-verity device creation (no dmsetup)
 * Use MAJOR:MINOR strings so we don't depend on /dev nodes inside DM.
 */
static int create_dm_verity_device_kernel(const char *dev_spec_mm,
					  const struct verity_config *cfg)
{
	int ret = 0;
	struct mapped_device *md = NULL;
	struct dm_table *table = NULL;
	sector_t start = 0, length;
	u64 sectors_u64;
	char *root_hash_hex = NULL, *salt_hex = NULL, *params = NULL;

	/* compute data-region length (in 512B sectors) */
	sectors_u64 = (cfg->data_blocks * (u64)cfg->data_block_size) / 512;
	length = (sector_t)sectors_u64;

	root_hash_hex = kmalloc(2 * cfg->root_hash_len + 1, GFP_KERNEL);
	salt_hex      = kmalloc(2 * max_t(u32, cfg->salt_size, 1) + 1, GFP_KERNEL);
	if (!root_hash_hex || !salt_hex) { ret = -ENOMEM; goto out_free; }

	hex_encode(cfg->root_hash, cfg->root_hash_len, root_hash_hex);
	if (cfg->salt_size)
		hex_encode(cfg->salt, cfg->salt_size, salt_hex);
	else
		strcpy(salt_hex, "-");

	/* DM verity target parameters; use the same dev for data and hash */
	params = kasprintf(GFP_KERNEL,
	                   "1 %s %s %u %u %llu %llu %s %s %s",
	                   dev_spec_mm,            /* data dev as MAJOR:MINOR */
	                   dev_spec_mm,            /* hash dev (same partition) */
	                   cfg->data_block_size,
	                   cfg->hash_block_size,
	                   (unsigned long long)cfg->data_blocks,
	                   (unsigned long long)cfg->hash_start_block,
	                   cfg->algorithm,
	                   root_hash_hex,
	                   salt_hex);
	if (!params) { ret = -ENOMEM; goto out_free; }

	pr_info("%s: Creating dm target: start=%llu len=%llu, verity %s\n",
		DM_MSG_PREFIX,
		(unsigned long long)start,
		(unsigned long long)length,
		params);

	/* 1) Create md on any minor; /dev/dm-X will be created by devtmpfs */
	ret = dm_create(DM_ANY_MINOR, &md);
	if (ret) {
		pr_err("%s: dm_create failed: %d\n", DM_MSG_PREFIX, ret);
		goto out_free;
	}

	/* 2) Build a table with one target; mode = FMODE_READ for verity */
	ret = dm_table_create(&table, FMODE_READ, 1, md);
	if (ret) {
		pr_err("%s: dm_table_create failed: %d\n", DM_MSG_PREFIX, ret);
		goto out_put_md;
	}

	ret = dm_table_add_target(table, "verity", start, length, params);
	if (ret) {
		pr_err("%s: dm_table_add_target failed: %d\n", DM_MSG_PREFIX, ret);
		goto out_destroy_table;
	}

	ret = dm_table_complete(table);
	if (ret) {
		pr_err("%s: dm_table_complete failed: %d\n", DM_MSG_PREFIX, ret);
		goto out_destroy_table;
	}

	/* 3) Activate: swap in table and resume device */
	dm_swap_table(md, table);   /* ownership of 'table' moves to DM */
	ret = dm_resume(md);
	if (ret) {
		pr_err("%s: dm_resume failed: %d\n", DM_MSG_PREFIX, ret);
		goto out_put_md;
	}

	pr_info("%s: ✓ dm-verity device created (use /dev/dm-0 as root)\n", DM_MSG_PREFIX);

	dm_put(md);
	kfree(params);
	kfree(salt_hex);
	kfree(root_hash_hex);
	return 0;

out_destroy_table:
	if (table)
		dm_table_destroy(table);
out_put_md:
	if (md)
		dm_put(md);
out_free:
	kfree(params);
	kfree(salt_hex);
	kfree(root_hash_hex);
	return ret;
}

/* Read and process metadata from device */
static int read_and_verify_metadata(struct file *bdev_file,
				    struct verity_config *cfg)
{
	u8 *tail = NULL, *meta_buf = NULL, *sig_buf = NULL;
	loff_t sz = i_size_read(file_inode(bdev_file));
	loff_t pos = sz - VERITY_META_SIZE;
	ssize_t got;
	__le32 magic;
	int ret = -ENOMEM;

	pr_info("%s: Reading metadata footer from device (size=%lld)\n",
		DM_MSG_PREFIX, sz);

	tail = kmalloc(VERITY_META_SIZE, GFP_KERNEL);
	if (!tail)
		return -ENOMEM;

	got = kernel_read(bdev_file, tail, VERITY_META_SIZE, &pos);
	if (got != VERITY_META_SIZE) {
		pr_err("%s: read tail failed (%zd)\n", DM_MSG_PREFIX, got);
		ret = -EIO;
		goto out;
	}

	magic = *(__le32 *)tail;

	if (le32_to_cpu(magic) == VLOC_MAGIC) {
		struct verity_footer_locator loc;

		memcpy(&loc, tail, sizeof(loc));
		pr_info("%s: Footer mode: detached (VLOC)\n", DM_MSG_PREFIX);
		pr_info("%s:   meta_off=%llu meta_len=%u sig_off=%llu sig_len=%u\n",
			DM_MSG_PREFIX,
			(unsigned long long)le64_to_cpu(loc.meta_off),
			le32_to_cpu(loc.meta_len),
			(unsigned long long)le64_to_cpu(loc.sig_off),
			le32_to_cpu(loc.sig_len));

		if (le32_to_cpu(loc.meta_len) < VERITY_FOOTER_SIGNED_LEN) {
			pr_err("%s: bad meta_len %u\n", DM_MSG_PREFIX, le32_to_cpu(loc.meta_len));
			ret = -EINVAL;
			goto out;
		}

		ret = read_region(bdev_file, le64_to_cpu(loc.meta_off),
				  le32_to_cpu(loc.meta_len), &meta_buf);
		if (ret) {
			pr_err("%s: reading metadata region: %d\n", DM_MSG_PREFIX, ret);
			goto out;
		}

		ret = read_region(bdev_file, le64_to_cpu(loc.sig_off),
				  le32_to_cpu(loc.sig_len), &sig_buf);
		if (ret) {
			pr_err("%s: reading signature region: %d\n", DM_MSG_PREFIX, ret);
			goto out;
		}

		dump_hex_short("detached.meta head", meta_buf, le32_to_cpu(loc.meta_len), 32);

		ret = verify_signature_pkcs7_detached(meta_buf, le32_to_cpu(loc.meta_len),
						      sig_buf, le32_to_cpu(loc.sig_len));
		if (ret) {
			pr_emerg("%s: SIGNATURE VERIFICATION FAILED\n", DM_MSG_PREFIX);
			panic("dm-verity-autoboot: untrusted rootfs metadata");
		}

		ret = parse_verity_header(meta_buf, cfg);

	} else if (le32_to_cpu(magic) == VERITY_META_MAGIC) {
		pr_err("%s: Attached mode not implemented\n", DM_MSG_PREFIX);
		ret = -ENOSYS;
	} else {
		pr_err("%s: unknown footer magic 0x%08x\n", DM_MSG_PREFIX, le32_to_cpu(magic));
		ret = -EINVAL;
	}

out:
	kfree(sig_buf);
	kfree(meta_buf);
	kfree(tail);
	return ret;
}

/* Main worker function */
static int verity_autoboot_main(void)
{
	struct file *bdev_file = NULL;
	struct verity_config *cfg;
	int ret = 0;
	int retry;
	dev_t opened_devt = 0;
	unsigned int maj = 0, min = 0;
	char dev_spec_mm[32];

	pr_info("%s: ==============================================\n", DM_MSG_PREFIX);
	pr_info("%s: dm-verity autoboot: full initialization\n", DM_MSG_PREFIX);
	pr_info("%s: ==============================================\n", DM_MSG_PREFIX);

	if (!autoboot_device || !*autoboot_device) {
		pr_info("%s: autoboot_device not set — skipping\n", DM_MSG_PREFIX);
		return 0;
	}

	pr_info("%s: Target device: %s\n", DM_MSG_PREFIX, autoboot_device);

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return -ENOMEM;

	/* Robustly wait for the device node to exist and be openable. */
	for (retry = 0; retry < 240; retry++) { /* up to ~120s */
		bdev_file = bdev_file_open_by_path(autoboot_device, FMODE_READ, NULL, NULL);
		if (!IS_ERR(bdev_file)) {
			if (retry)
				pr_info("%s: opened %s after %d attempts\n",
					DM_MSG_PREFIX, autoboot_device, retry + 1);
			break;
		}
		if (retry == 0)
			pr_info("%s: device %s not ready, waiting...\n",
				DM_MSG_PREFIX, autoboot_device);
		msleep(500);
	}

	if (IS_ERR(bdev_file)) {
		ret = PTR_ERR(bdev_file);
		pr_err("%s: cannot open %s after retries: %d\n",
		       DM_MSG_PREFIX, autoboot_device, ret);
		goto out_free_cfg;
	}

	/* Capture dev_t once; we'll use MAJOR:MINOR for DM target args. */
	opened_devt = file_inode(bdev_file)->i_rdev;
	maj = MAJOR(opened_devt);
	min = MINOR(opened_devt);
	snprintf(dev_spec_mm, sizeof(dev_spec_mm), "%u:%u", maj, min);
	pr_info("%s: using device %s (dev %u:%u) for verity mapping\n",
		DM_MSG_PREFIX, autoboot_device, maj, min);

	/* Read + verify metadata */
	ret = read_and_verify_metadata(bdev_file, cfg);
	if (ret) {
		pr_err("%s: metadata read/verify failed: %d\n", DM_MSG_PREFIX, ret);
		goto out_close;
	}

	pr_info("%s: ✓ Metadata verified and parsed successfully\n", DM_MSG_PREFIX);

	/* Done with block file */
	filp_close(bdev_file, NULL);
	bdev_file = NULL;

	/* Create verity mapping in-kernel, using MAJOR:MINOR (not /dev path) */
	ret = create_dm_verity_device_kernel(dev_spec_mm, cfg);
	if (ret) {
		pr_err("%s: failed to create dm device: %d\n", DM_MSG_PREFIX, ret);
		goto out_free_cfg;
	}

	pr_info("%s: ✓ dm-verity device ready. Mount with root=/dev/dm-0\n", DM_MSG_PREFIX);

out_free_cfg:
	kfree(cfg);
	return ret;

out_close:
	if (!IS_ERR_OR_NULL(bdev_file))
		filp_close(bdev_file, NULL);
	goto out_free_cfg;
}

/* Delayed work trampoline */
static void verity_autoboot_workfn(struct work_struct *work)
{
	verity_autoboot_main();
}
static DECLARE_DELAYED_WORK(verity_work, verity_autoboot_workfn);

/* Run very early, but delay a bit to let blk drivers probe */
static int __init dm_verity_autoboot_init(void)
{
	pr_info("%s: Module loaded (autoboot_device=%s)\n", DM_MSG_PREFIX,
		autoboot_device ? autoboot_device : "(null)");

	if (autoboot_device && *autoboot_device) {
		schedule_delayed_work(&verity_work, 2 * HZ);
		pr_info("%s: Scheduled verification in ~2 seconds\n", DM_MSG_PREFIX);
	}

	return 0;
}

static void __exit dm_verity_autoboot_exit(void)
{
	cancel_delayed_work_sync(&verity_work);
	pr_info("%s: Module unloaded\n", DM_MSG_PREFIX);
}

rootfs_initcall(dm_verity_autoboot_init);
module_exit(dm_verity_autoboot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dm-verity autoboot: complete metadata parsing and in-kernel device setup");
MODULE_AUTHOR("Team A");
