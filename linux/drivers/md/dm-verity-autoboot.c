// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Verify dm-verity footer (attached or detached PKCS7) and, if trusted,
 * validate the hash tree location, then allow boot to continue.
 *
 * Device creation itself is done by dm-init via dm-mod.create=
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
#include <linux/cred.h>
#include <linux/sched.h>

#include <crypto/hash.h>
#include <linux/verification.h>
#include <crypto/pkcs7.h>
#include <crypto/hash_info.h>

#define DM_MSG_PREFIX              "verity-autoboot"

#define VERITY_META_SIZE           4096
#define VERITY_META_MAGIC          0x56455249 /* "VERI" */
#define VERITY_FOOTER_SIGNED_LEN   196
#define VERITY_PKCS7_MAX           2048

#define VLOC_MAGIC                 0x564C4F43 /* "VLOC" */

static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
	"Whole-disk block dev (e.g. /dev/vda) containing verity footer");

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

struct verity_footer_locator {
	__le32 magic;
	__le32 version;
	__le64 meta_off;
	__le32 meta_len;
	__le64 sig_off;
	__le32 sig_len;
	u8     reserved[4096 - 32];
} __packed;

/* ---------------------------------------------------------- */
/* Utility Helpers (must be defined before used)               */
/* ---------------------------------------------------------- */

/* SHA256 helper */
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

/* Read region of disk */
static int read_region(struct file *bdev_file, u64 off, u32 len, u8 **out)
{
	loff_t pos = off;
	ssize_t got;
	u8 *buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	got = kernel_read(bdev_file, buf, len, &pos);
	if (got != len) {
		kfree(buf);
		return -EIO;
	}

	*out = buf;
	return 0;
}

/* Lookup block device */
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

/* ---------------------------------------------------------- */
/* Signature Verification                                      */
/* ---------------------------------------------------------- */

static int verify_attached(const struct verity_metadata_ondisk *meta)
{
	struct pkcs7_message *pkcs7;
	u8 digest[32];
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	u32 blob_sz;
	int ret;

	pr_info("%s: [VERIFY] Attached metadata signature verification started\n", DM_MSG_PREFIX);

	blob_sz = le32_to_cpu(meta->pkcs7_size);
	if (!blob_sz || blob_sz > VERITY_PKCS7_MAX)
		return -EINVAL;

	ret = sha256_buf((const u8 *)meta, VERITY_FOOTER_SIGNED_LEN, digest);
	if (ret)
		return ret;

	pkcs7 = pkcs7_parse_message(meta->pkcs7_blob, blob_sz);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		goto out;

	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len, &signed_hash_algo);
	if (ret || signed_hash_algo != HASH_ALGO_SHA256 ||
		signed_hash_len != 32 ||
		memcmp(signed_hash, digest, 32) != 0) {

		pr_err("%s: [VERIFY] Attached signature FAILED\n", DM_MSG_PREFIX);
		ret = -EKEYREJECTED;

	} else {
		pr_info("%s: [VERIFY] Attached signature PASSED ✅\n", DM_MSG_PREFIX);
	}

out:
	pkcs7_free_message(pkcs7);
	return ret;
}

static int verify_detached(const u8 *meta_buf, u32 meta_len,
			   const u8 *sig_buf,  u32 sig_len)
{
	struct pkcs7_message *pkcs7;
	u8 digest[32];
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	int ret;

	pr_info("%s: [VERIFY] Detached metadata signature verification started\n", DM_MSG_PREFIX);

	ret = sha256_buf(meta_buf, meta_len, digest);
	if (ret)
		return ret;

	pkcs7 = pkcs7_parse_message(sig_buf, sig_len);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = pkcs7_supply_detached_data(pkcs7, meta_buf, meta_len);
	if (ret)
		goto out;

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		goto out;

	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len, &signed_hash_algo);
	if (!ret && (signed_hash_algo != HASH_ALGO_SHA256 ||
		     signed_hash_len != 32 ||
		     memcmp(signed_hash, digest, 32) != 0))
		ret = -EKEYREJECTED;

out:
	pkcs7_free_message(pkcs7);

	if (!ret)
		pr_info("%s: [VERIFY] Detached signature PASSED ✅\n", DM_MSG_PREFIX);
	else
		pr_err("%s: [VERIFY] Detached signature FAILED\n", DM_MSG_PREFIX);

	return ret;
}

/* ---------------------------------------------------------- */
/* Metadata Parsing (only runs after verification succeeded!)  */
/* ---------------------------------------------------------- */

static void check_hash_tree_location(const struct verity_metadata_ondisk *m)
{
	u64 data_blocks      = le64_to_cpu(m->data_blocks);
	u32 data_block_size  = le32_to_cpu(m->data_block_size);
	u64 declared_sector  = le64_to_cpu(m->hash_start_sector);
	u64 expected_sector;

	pr_info("%s: [PARSE] Metadata parsed successfully\n", DM_MSG_PREFIX);
	pr_info("  hash algorithm     : %s\n", m->hash_algorithm);
	pr_info("  data block size    : %u bytes\n", data_block_size);
	pr_info("  number of blocks   : %llu\n", (unsigned long long)data_blocks);
	pr_info("  declared hash tree : sector %llu\n", (unsigned long long)declared_sector);
	dump_hex_short("root_hash", m->root_hash, 32, 32);

	if (!data_block_size || (data_block_size % 512)) {
		pr_emerg("%s: INVALID data_block_size %u\n", DM_MSG_PREFIX, data_block_size);
		panic("dm-verity-autoboot: invalid metadata block size");
	}

	expected_sector = data_blocks * (data_block_size / 512ULL);

	if (declared_sector != expected_sector) {
		pr_emerg("%s: HASH TREE LOCATION MISMATCH\n", DM_MSG_PREFIX);
		panic("dm-verity-autoboot: hash tree location mismatch");
	}

	pr_info("%s: Parsing Successful, hash tree location verified ✅ (sector=%llu)\n",
		DM_MSG_PREFIX, (unsigned long long)declared_sector);
}

/* ---------------------------------------------------------- */
/* Main boot-check logic                                      */
/* ---------------------------------------------------------- */

static int verity_autoboot_main(void)
{
	struct file *bdev_file;
	dev_t dev;
	int ret;

	if (!autoboot_device || !*autoboot_device)
		return 0;

	ret = resolve_dev_from_diskname(autoboot_device, &dev);
	if (ret)
		return ret;

	bdev_file = bdev_file_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(bdev_file))
		return PTR_ERR(bdev_file);

	{
		u8 tail[VERITY_META_SIZE];
		loff_t sz = i_size_read(file_inode(bdev_file));
		loff_t pos = sz - VERITY_META_SIZE;
		ssize_t got = kernel_read(bdev_file, tail, VERITY_META_SIZE, &pos);

		if (got != VERITY_META_SIZE) {
			fput(bdev_file);
			return -EIO;
		}

		/* Attached footer */
		if (le32_to_cpu(*(__le32 *)tail) == VERITY_META_MAGIC) {
			struct verity_metadata_ondisk *meta;

			meta = kmalloc(VERITY_META_SIZE, GFP_KERNEL);
			if (!meta) {
				fput(bdev_file);
				return -ENOMEM;
			}

			pr_info("%s: [READ] Found attached metadata footer\n", DM_MSG_PREFIX);

			pos = sz - VERITY_META_SIZE;
			if (kernel_read(bdev_file, meta, VERITY_META_SIZE, &pos) != VERITY_META_SIZE) {
				kfree(meta);
				fput(bdev_file);
				return -EIO;
			}

			/* VERIFY BEFORE PARSE */
			ret = verify_attached(meta);
			if (ret) {
				kfree(meta);
				fput(bdev_file);
				panic("dm-verity-autoboot: attached signature INVALID");
			}

			/* PARSE AFTER SUCCESSFUL VERIFY */
			check_hash_tree_location(meta);

			kfree(meta);
			fput(bdev_file);
			return 0;
		}

		/* Detached footer */
		else if (le32_to_cpu(*(__le32 *)tail) == VLOC_MAGIC) {
			struct verity_footer_locator loc;
			u8 *meta_buf = NULL, *sig_buf = NULL;

			pr_info("%s: [READ] Found detached metadata footer\n", DM_MSG_PREFIX);

			memcpy(&loc, tail, sizeof(loc));

			ret = read_region(bdev_file, le64_to_cpu(loc.meta_off),
					  le32_to_cpu(loc.meta_len), &meta_buf);
			if (ret) {
				fput(bdev_file);
				return ret;
			}

			ret = read_region(bdev_file, le64_to_cpu(loc.sig_off),
					  le32_to_cpu(loc.sig_len), &sig_buf);
			if (ret) {
				kfree(meta_buf);
				fput(bdev_file);
				return ret;
			}

			/* VERIFY BEFORE PARSE */
			ret = verify_detached(meta_buf, le32_to_cpu(loc.meta_len),
					      sig_buf,  le32_to_cpu(loc.sig_len));
			if (ret) {
				kfree(sig_buf);
				kfree(meta_buf);
				fput(bdev_file);
				panic("dm-verity-autoboot: detached signature INVALID");
			}

			/* PARSE AFTER SUCCESSFUL VERIFY */
			check_hash_tree_location((struct verity_metadata_ondisk *)meta_buf);

			kfree(sig_buf);
			kfree(meta_buf);
			fput(bdev_file);
			return 0;
		}

		fput(bdev_file);
		return -EINVAL;
	}
}

static void verity_autoboot_workfn(struct work_struct *work)
{
	verity_autoboot_main();
}

static DECLARE_DELAYED_WORK(verity_work, verity_autoboot_workfn);

static int __init dm_verity_autoboot_init(void)
{
	if (autoboot_device && *autoboot_device)
		schedule_delayed_work(&verity_work, 5 * HZ);
	return 0;
}

static void __exit dm_verity_autoboot_exit(void)
{
	cancel_delayed_work_sync(&verity_work);
}

late_initcall(dm_verity_autoboot_init);
module_exit(dm_verity_autoboot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dm-verity autoboot rootfs authenticity + location enforcement");
MODULE_AUTHOR("team A");
