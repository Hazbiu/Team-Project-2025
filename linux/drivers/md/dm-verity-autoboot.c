// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Verify dm-verity footer (attached or detached PKCS7) and, if trusted,
 * just log success. Device creation is done by dm-init via dm-mod.create=
 * on the kernel command line.
 *
 * Build as built-in or module. Recommended as built-in for early verification.
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

/* Optional detached locator footer */
#define VLOC_MAGIC                 0x564C4F43 /* "VLOC" */

static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
	"Whole-disk block dev (e.g. /dev/vda) containing verity footer");

/* On-disk 4KB footer: ATTACHED mode ("VERI") */
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

/* Optional 4KB footer: DETACHED mode ("VLOC") */
struct verity_footer_locator {
	__le32 magic;
	__le32 version;
	__le64 meta_off;
	__le32 meta_len;
	__le64 sig_off;
	__le32 sig_len;
	u8     reserved[4096 - 32];
} __packed;

/* --- helpers & logging --- */
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

static int compute_footer_digest(const struct verity_metadata_ondisk *meta,
				 u8 digest[32])
{
	return sha256_buf((const u8 *)meta, VERITY_FOOTER_SIGNED_LEN, digest);
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

/* ----- read attached footer ----- */
static int read_metadata_footer_attached(struct file *f,
				struct verity_metadata_ondisk *meta)
{
	loff_t size, pos;
	ssize_t bytes;

	size = i_size_read(file_inode(f));
	if (size < VERITY_META_SIZE) {
		pr_err("%s: device too small (%lld bytes)\n",
		       DM_MSG_PREFIX, size);
		return -EINVAL;
	}

	pos = size - VERITY_META_SIZE;
	bytes = kernel_read(f, meta, VERITY_META_SIZE, &pos);
	if (bytes != VERITY_META_SIZE) {
		pr_err("%s: kernel_read footer failed (%zd)\n",
		       DM_MSG_PREFIX, bytes);
		return -EIO;
	}

	if (le32_to_cpu(meta->magic) != VERITY_META_MAGIC) {
		pr_err("%s: bad magic 0x%08x (expected 0x%08x)\n",
		       DM_MSG_PREFIX,
		       le32_to_cpu(meta->magic),
		       VERITY_META_MAGIC);
		return -EINVAL;
	}

	/* Log parsed fields */
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

		pr_info("%s: ---- Footer parsed ----\n", DM_MSG_PREFIX);
		pr_info("%s:   version            : %u\n",
			DM_MSG_PREFIX, le32_to_cpu(meta->version));
		pr_info("%s:   data_blocks        : %llu\n",
			DM_MSG_PREFIX, (unsigned long long)data_blocks);
		pr_info("%s:   data_block_size    : %u bytes\n",
			DM_MSG_PREFIX, le32_to_cpu(meta->data_block_size));
		pr_info("%s:   hash_block_size    : %u bytes\n",
			DM_MSG_PREFIX, le32_to_cpu(meta->hash_block_size));
		pr_info("%s:   covered_bytes(~fs) : %llu bytes\n",
			DM_MSG_PREFIX, (unsigned long long)covered_bytes);
		pr_info("%s:   hash_start_sector  : %llu\n",
			DM_MSG_PREFIX, (unsigned long long)hash_start_sector);
		pr_info("%s:   hash_start_bytes   : %llu\n",
			DM_MSG_PREFIX, (unsigned long long)hash_start_bytes);
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

		dump_hex_short("salt raw", meta->salt,
			       le32_to_cpu(meta->salt_size), 32);
		dump_hex_short("pkcs7 head", meta->pkcs7_blob,
			       pkcs7_size, 32);
	}

	return 0;
}

/* ---- PKCS7 verification (ATTACHED) ---- */
static int verify_signature_pkcs7_attached(const struct verity_metadata_ondisk *meta)
{
	u8 digest[32];
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	u32 blob_sz;
	int ret;
	struct pkcs7_message *pkcs7;

	pr_info("%s: Verifying PKCS7 signature (attached)\n", DM_MSG_PREFIX);

	blob_sz = le32_to_cpu(meta->pkcs7_size);
	pr_info("%s:   pkcs7_size = %u bytes\n", DM_MSG_PREFIX, blob_sz);

	if (!blob_sz || blob_sz > VERITY_PKCS7_MAX) {
		pr_err("%s: invalid pkcs7_size %u (max %u)\n",
		       DM_MSG_PREFIX, blob_sz, VERITY_PKCS7_MAX);
		return -EINVAL;
	}

	dump_hex_short("pkcs7_blob[0..]", meta->pkcs7_blob, blob_sz, 32);

	ret = compute_footer_digest(meta, digest);
	if (ret) {
		pr_err("%s: compute_footer_digest() failed: %d\n",
		       DM_MSG_PREFIX, ret);
		return ret;
	}
	dump_hex_short("computed_digest(SHA256[0..195])", digest, 32, 32);

	pkcs7 = pkcs7_parse_message(meta->pkcs7_blob, blob_sz);
	if (IS_ERR(pkcs7)) {
		pr_err("%s: pkcs7_parse_message() failed: %ld\n",
		       DM_MSG_PREFIX, PTR_ERR(pkcs7));
		return PTR_ERR(pkcs7);
	}

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret) {
		pr_err("%s: pkcs7_verify(): signer NOT trusted (%d)\n",
		       DM_MSG_PREFIX, ret);
		goto out_free;
	}
	pr_info("%s: signer accepted by kernel trusted keyring\n",
		DM_MSG_PREFIX);

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
		pr_err("%s: digest mismatch between PKCS7 and footer[0..195]\n", DM_MSG_PREFIX);
		ret = -EKEYREJECTED;
		goto out_free;
	}

	pr_info("%s: Digest in PKCS7 matches header digest; footer is authentic\n",
		DM_MSG_PREFIX);
	ret = 0;

out_free:
	pkcs7_free_message(pkcs7);
	return ret;
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

	if (!meta_len || meta_len < VERITY_FOOTER_SIGNED_LEN || sig_len == 0 || sig_len > VERITY_PKCS7_MAX)
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

	pr_info("%s: Digest in PKCS7 matches detached metadata digest\n", DM_MSG_PREFIX);
	return 0;

out_free:
	pkcs7_free_message(pkcs7);
	return ret;
}

/* ----- main worker: verify only ----- */
static int verity_autoboot_main(void)
{
	struct file *bdev_file;
	dev_t dev;
	int ret;

	pr_info("%s: ==============================================\n", DM_MSG_PREFIX);
	pr_info("%s: Start: dm-verity signature verification (verify-only)\n", DM_MSG_PREFIX);
	pr_info("%s: ==============================================\n", DM_MSG_PREFIX);

	if (!autoboot_device || !*autoboot_device) {
		pr_info("%s: autoboot_device not set — skipping verification\n", DM_MSG_PREFIX);
		return 0;
	}

	pr_info("%s: autoboot_device param: %s\n", DM_MSG_PREFIX, autoboot_device);

	ret = resolve_dev_from_diskname(autoboot_device, &dev);
	if (ret) {
		pr_err("%s: cannot resolve %s (%d)\n",
		       DM_MSG_PREFIX, autoboot_device, ret);
		return ret;
	}

	pr_info("%s: resolved %s -> major=%u minor=%u\n",
		DM_MSG_PREFIX, autoboot_device, MAJOR(dev), MINOR(dev));

	/* Open block device by dev_t for footer reads */
	bdev_file = bdev_file_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(bdev_file)) {
		pr_err("%s: bdev_file_open_by_dev() -> %ld\n",
		       DM_MSG_PREFIX, PTR_ERR(bdev_file));
		return PTR_ERR(bdev_file);
	}

	/* Peek last 4 KiB to decide ATTACHED vs DETACHED */
	{
		u8 tail[VERITY_META_SIZE];
		loff_t sz = i_size_read(file_inode(bdev_file));
		loff_t pos = sz - VERITY_META_SIZE;
		ssize_t got = kernel_read(bdev_file, tail, VERITY_META_SIZE, &pos);
		if (got != VERITY_META_SIZE) {
			pr_err("%s: read tail failed (%zd)\n", DM_MSG_PREFIX, got);
			fput(bdev_file);
			return -EIO;
		}

		{
			__le32 magic = *(__le32 *)tail;

			if (le32_to_cpu(magic) == VERITY_META_MAGIC) {
				/* ATTACHED */
				struct verity_metadata_ondisk *meta;

				meta = kmalloc(sizeof(*meta), GFP_KERNEL);
				if (!meta) {
					fput(bdev_file);
					return -ENOMEM;
				}

				pr_info("%s: Footer mode: attached (VERI)\n", DM_MSG_PREFIX);
				ret = read_metadata_footer_attached(bdev_file, meta);
				if (ret) {
					kfree(meta);
					fput(bdev_file);
					return ret;
				}

				ret = verify_signature_pkcs7_attached(meta);
				if (ret) {
					kfree(meta);
					fput(bdev_file);
					pr_emerg("%s: signature verification FAILED (attached), ret=%d\n",
						 DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: untrusted rootfs footer");
				}

				pr_info("%s: Signature verification PASSED (attached)\n", DM_MSG_PREFIX);
				pr_info("%s: dm-init should have already created /dev/mapper/verified_root\n",
					DM_MSG_PREFIX);
				kfree(meta);
				fput(bdev_file);
				return 0;

			} else if (le32_to_cpu(magic) == VLOC_MAGIC) {
				/* DETACHED */
				struct verity_footer_locator loc;
				u8 *meta_buf = NULL, *sig_buf = NULL;

				memcpy(&loc, tail, sizeof(loc));
				pr_info("%s: Footer mode: detached (VLOC)\n", DM_MSG_PREFIX);
				pr_info("%s:   meta_off=%llu meta_len=%u sig_off=%llu sig_len=%u\n",
					DM_MSG_PREFIX,
					(unsigned long long)le64_to_cpu(loc.meta_off),
					le32_to_cpu(loc.meta_len),
					(unsigned long long)le64_to_cpu(loc.sig_off),
					le32_to_cpu(loc.sig_len));

				/* Read regions */
				ret = read_region(bdev_file, le64_to_cpu(loc.meta_off),
						  le32_to_cpu(loc.meta_len), &meta_buf);
				if (ret) {
					pr_err("%s: reading metadata region: %d\n", DM_MSG_PREFIX, ret);
					fput(bdev_file);
					return ret;
				}
				ret = read_region(bdev_file, le64_to_cpu(loc.sig_off),
						  le32_to_cpu(loc.sig_len), &sig_buf);
				if (ret) {
					pr_err("%s: reading signature region: %d\n", DM_MSG_PREFIX, ret);
					kfree(meta_buf);
					fput(bdev_file);
					return ret;
				}

				dump_hex_short("detached.meta head", meta_buf, le32_to_cpu(loc.meta_len), 32);
				dump_hex_short("detached.sig  head", sig_buf,  le32_to_cpu(loc.sig_len),  32);

				/* Verify detached */
				ret = verify_signature_pkcs7_detached(meta_buf, le32_to_cpu(loc.meta_len),
								      sig_buf,  le32_to_cpu(loc.sig_len));
				if (ret) {
					kfree(sig_buf);
					kfree(meta_buf);
					fput(bdev_file);
					pr_emerg("%s: signature verification FAILED (detached), ret=%d\n",
						 DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: untrusted detached metadata");
				}

				pr_info("%s: Signature verification PASSED (detached)\n", DM_MSG_PREFIX);
				pr_info("%s: dm-init should have already created /dev/mapper/verified_root\n",
					DM_MSG_PREFIX);

				kfree(sig_buf);
				kfree(meta_buf);
				fput(bdev_file);
				return 0;

			} else {
				pr_err("%s: unknown tail magic 0x%08x\n",
				       DM_MSG_PREFIX, le32_to_cpu(magic));
				fput(bdev_file);
				return -EINVAL;
			}
		}
	}
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
	pr_info("%s: ===== Kernel cmdline =====\n", DM_MSG_PREFIX);
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
		/* delay a bit so virtio-blk registers and dm_mod param appears */
		schedule_delayed_work(&verity_work, 5 * HZ);
		pr_info("%s: scheduled verification worker in ~5s\n",
			DM_MSG_PREFIX);
	} else {
		pr_info("%s: not scheduling verification (no param)\n",
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

late_initcall(dm_verity_autoboot_init);
module_exit(dm_verity_autoboot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dm-verity autoboot: verify signature only (dm-init creates mapping)");
MODULE_AUTHOR("team A");
