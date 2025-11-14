// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Built-in helper for early-boot dm-verity on a whole-disk image.
 *
 * Boot flow overview:
 *
 *   Bootloader:
 *     - Passes the whole-disk device path via kernel cmdline:
 *
 *         dm_verity_autoboot.autoboot_device=/dev/vda
 *         root=/dev/dm-0 rootfstype=ext4 rootwait ...
 *
 *   This module:
 *     1. Resolves the block device for autoboot_device (e.g. /dev/vda)
 *     2. Reads the last 4 KiB of the device
 *     3. Distinguishes:
 *          - Attached footer ("VERI"): 4 KiB footer = header + PKCS7
 *          - Detached footer ("VLOC"): footer is a locator pointing to:
 *                [ ... data ... ][hash tree][header][signature][locator]
 *     4. Verifies a PKCS7 signature (using the kernel trusted keyring)
 *        over the 196-byte metadata header.
 *     5. Uses dm_early_create() to create a dm-verity mapping:
 *            name="verity_root"  → typically /dev/dm-0
 *   Core kernel:
 *     - Mounts /dev/dm-0 as the ext4 root filesystem.
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
#include <linux/device-mapper.h>
#include <linux/dm-ioctl.h>
#include "signature_verify.h"
#include "metadata_parse.h"
#include "mapping.h"


#define DM_MSG_PREFIX              "verity-autoboot"

#define VERITY_META_SIZE           4096
#define VERITY_META_MAGIC          0x56455249 /* "VERI" */
#define VERITY_FOOTER_SIGNED_LEN   196        /* bytes covered by PKCS7 */
#define VERITY_PKCS7_MAX           2048
#define VLOC_MAGIC                 0x564C4F43 /* "VLOC" */

static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
	"Whole-disk block dev (e.g. /dev/vda) containing verity metadata+locator");

/*
 * Full attached 4K footer ("VERI"):
 *   [header (196 bytes)] [salt_size/pkcs7_size] [PKCS7 DER] [padding]
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

/*
 * Detached locator footer ("VLOC"), always at the last 4 KiB:
 *   - meta_off/meta_len: header region (196 bytes, padded to 4K)
 *   - sig_off/sig_len  : PKCS7 (DER) region
 */
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

/* Compute SHA-256 over the first VERITY_FOOTER_SIGNED_LEN bytes of the footer */
static int compute_footer_digest(const struct verity_metadata_ondisk *meta,
				 u8 digest[32])
{
	return sha256_buf((const u8 *)meta, VERITY_FOOTER_SIGNED_LEN, digest);
}

/*
 * Read an arbitrary region (meta or sig) from the block device file.
 */
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

/*
 * Resolve "/dev/vda" or "vda" to a dev_t by matching gendisk->disk_name.
 * This does NOT depend on /dev/ nodes existing, so it works early in boot.
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

	/* Use centralized metadata parser + logger */
	verity_parse_metadata_header((const struct verity_metadata_header *)meta);

	return 0;
}



/* ----- main worker: verify & create mapping ----- */

static int verity_autoboot_main(void)
{
	struct file *bdev_file;
	dev_t dev;
	int ret;

	pr_info("%s: ==============================================\n", DM_MSG_PREFIX);
	pr_info("%s: Start: dm-verity signature verification + mapping\n",
		DM_MSG_PREFIX);
	pr_info("%s: ==============================================\n", DM_MSG_PREFIX);

	if (!autoboot_device || !*autoboot_device) {
		pr_info("%s: autoboot_device not set — skipping verification\n",
			DM_MSG_PREFIX);
		return 0;
	}

	pr_info("%s: autoboot_device param: %s\n",
		DM_MSG_PREFIX, autoboot_device);

	ret = resolve_dev_from_diskname(autoboot_device, &dev);
	if (ret) {
		pr_err("%s: cannot resolve %s (%d)\n",
		       DM_MSG_PREFIX, autoboot_device, ret);
		return ret;
	}

	pr_info("%s: resolved %s -> major=%u minor=%u\n",
		DM_MSG_PREFIX, autoboot_device, MAJOR(dev), MINOR(dev));

	bdev_file = bdev_file_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(bdev_file)) {
		pr_err("%s: bdev_file_open_by_dev() -> %ld\n",
		       DM_MSG_PREFIX, PTR_ERR(bdev_file));
		return PTR_ERR(bdev_file);
	}

	/* Peek last 4 KiB to detect attached vs detached footer layout */
	{
		u8 tail[VERITY_META_SIZE];
		loff_t sz = i_size_read(file_inode(bdev_file));
		loff_t pos = sz - VERITY_META_SIZE;
		ssize_t got = kernel_read(bdev_file, tail, VERITY_META_SIZE, &pos);

		if (got != VERITY_META_SIZE) {
			pr_err("%s: read tail failed (%zd)\n",
			       DM_MSG_PREFIX, got);
			fput(bdev_file);
			return -EIO;
		}

		{
			__le32 magic = *(__le32 *)tail;

			if (le32_to_cpu(magic) == VERITY_META_MAGIC) {
				/* Attached metadata footer ("VERI") */
				struct verity_metadata_ondisk *meta;
				const struct verity_metadata_header *h;

				meta = kmalloc(sizeof(*meta), GFP_KERNEL);
				if (!meta) {
					fput(bdev_file);
					return -ENOMEM;
				}

				pr_info("%s: Footer mode: attached (VERI)\n",
					DM_MSG_PREFIX);

				ret = read_metadata_footer_attached(bdev_file, meta);
				if (ret) {
					kfree(meta);
					fput(bdev_file);
					return ret;
				}

				pr_info("%s: Attached metadata footer read and parsed successfully\n",
					DM_MSG_PREFIX);

				ret = verify_signature_pkcs7_attached(meta);
				if (ret) {
					kfree(meta);
					fput(bdev_file);
					pr_emerg("%s: signature verification FAILED (attached), ret=%d\n",
						 DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: untrusted rootfs footer");
				}

				pr_info("%s: Signature verification PASSED (attached)\n", DM_MSG_PREFIX);

				h = (const struct verity_metadata_header *)meta;

				//Validate + log metadata fields using separated logic */
				ret = verity_parse_metadata_header(h);
				if (ret) {
					kfree(meta);
					fput(bdev_file);
					pr_emerg("%s: metadata header validation FAILED, ret=%d\n",
							DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: invalid metadata header");
				}


				/*
				 * CRITICAL: Close the underlying block device
				 * before creating the dm-verity mapping.
				 * dm-verity wants exclusive access.
				 */
				fput(bdev_file);
				bdev_file = NULL;

				ret = verity_create_mapping(dev, h);

				if (ret) {
					kfree(meta);
					pr_emerg("%s: dm-verity mapping creation FAILED (attached), ret=%d\n",
						 DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: failed to create dm-verity mapping");
				}

				kfree(meta);
				return 0;

			} else if (le32_to_cpu(magic) == VLOC_MAGIC) {
				/* Detached metadata/signature indicated by VLOC footer */
				struct verity_footer_locator loc;
				u8 *meta_buf = NULL, *sig_buf = NULL;
				const struct verity_metadata_header *h;
				loff_t disk_size;
				u64 meta_end, sig_end;


				memcpy(&loc, tail, sizeof(loc));

	
				disk_size = i_size_read(file_inode(bdev_file));

				pr_info("%s: Footer mode: detached (VLOC)\n",
					DM_MSG_PREFIX);
				pr_info("%s: VALIDATION: disk_size=%lld, checking locator fields...\n",
        		DM_MSG_PREFIX, disk_size);
				pr_info("%s:   meta_off=%llu meta_len=%u sig_off=%llu sig_len=%u\n",
					DM_MSG_PREFIX,
					(unsigned long long)le64_to_cpu(loc.meta_off),
					le32_to_cpu(loc.meta_len),
					(unsigned long long)le64_to_cpu(loc.sig_off),
					le32_to_cpu(loc.sig_len));

				pr_info("%s: DEBUG: meta_off=%llu, meta_len=%u, disk_size=%lld\n",
					DM_MSG_PREFIX,
					(unsigned long long)le64_to_cpu(loc.meta_off),
					le32_to_cpu(loc.meta_len),
					disk_size);
				pr_info("%s: DEBUG: meta_off + meta_len = %llu\n",
					DM_MSG_PREFIX,
					(unsigned long long)(le64_to_cpu(loc.meta_off) + le32_to_cpu(loc.meta_len)));

				pr_info("%s: VALIDATION: checking locator fields...\n", DM_MSG_PREFIX);

		
				/* Validate meta region */
				if (le64_to_cpu(loc.meta_off) >= disk_size) {
					pr_emerg("%s: VALIDATION FAILED: meta_off %llu beyond disk size %lld\n",
            			    DM_MSG_PREFIX,
						(unsigned long long)le64_to_cpu(loc.meta_off),
						disk_size);
					fput(bdev_file);

					return -EINVAL;
				}
				if (le32_to_cpu(loc.meta_len) == 0 || 
					le32_to_cpu(loc.meta_len) > (8U << 20)) { // 8MB sanity limit
					pr_emerg("%s: VALIDATION FAILED: invalid meta_len %u\n",
						DM_MSG_PREFIX, le32_to_cpu(loc.meta_len));
					fput(bdev_file);
					return -EINVAL;
				}

				meta_end = le64_to_cpu(loc.meta_off) + le32_to_cpu(loc.meta_len);
				if (meta_end < le64_to_cpu(loc.meta_off)) {
					// This detects overflow
					pr_emerg("%s: VALIDATION FAILED: meta region overflow (meta_off + meta_len wraps around)\n",
						DM_MSG_PREFIX);
					fput(bdev_file);
					return -EINVAL;
				}
				if (meta_end > disk_size) {
					pr_emerg("%s: VALIDATION FAILED: meta region [%llu, %llu] exceeds disk size %lld\n",
						DM_MSG_PREFIX,
						(unsigned long long)le64_to_cpu(loc.meta_off),
						(unsigned long long)meta_end,
						disk_size);
					fput(bdev_file);
					return -EINVAL;
				}

				/* Validate sig region */
				if (le64_to_cpu(loc.sig_off) >= disk_size) {
					pr_emerg("%s: VALIDATION FAILED: sig_off %llu beyond disk size %lld\n",
						DM_MSG_PREFIX,
						(unsigned long long)le64_to_cpu(loc.sig_off),
						disk_size);
					fput(bdev_file);
					return -EINVAL;
				}
				if (le32_to_cpu(loc.sig_len) == 0 || 
					le32_to_cpu(loc.sig_len) > VERITY_PKCS7_MAX) {
					pr_emerg("%s: VALIDATION FAILED:  invalid sig_len %u\n",
						DM_MSG_PREFIX, le32_to_cpu(loc.sig_len));
					fput(bdev_file);
					return -EINVAL;
				}
				
				sig_end = le64_to_cpu(loc.sig_off) + le32_to_cpu(loc.sig_len);
				if (sig_end < le64_to_cpu(loc.sig_off)) {
					// This detects overflow
					pr_emerg("%s: VALIDATION FAILED: sig region overflow (sig_off + sig_len wraps around)\n",
						DM_MSG_PREFIX);
					fput(bdev_file);
					return -EINVAL;
				}
				if (sig_end > disk_size) {
					pr_emerg("%s: VALIDATION FAILED: sig region [%llu, %llu] exceeds disk size %lld\n",
						DM_MSG_PREFIX,
						(unsigned long long)le64_to_cpu(loc.sig_off),
						(unsigned long long)sig_end,
						disk_size);
					fput(bdev_file);
					return -EINVAL;
				}

				pr_info("%s: VALIDATION PASSED: proceeding with read_region...\n", DM_MSG_PREFIX);
				
				ret = read_region(bdev_file, le64_to_cpu(loc.meta_off),
						  le32_to_cpu(loc.meta_len), &meta_buf);
				if (ret) {
					pr_err("%s: reading metadata region: %d\n",
					       DM_MSG_PREFIX, ret);
					fput(bdev_file);
					return ret;
				}
				ret = read_region(bdev_file, le64_to_cpu(loc.sig_off),
						  le32_to_cpu(loc.sig_len), &sig_buf);
				if (ret) {
					pr_err("%s: reading signature region: %d\n",
					       DM_MSG_PREFIX, ret);
					kfree(meta_buf);
					fput(bdev_file);
					return ret;
				}

				pr_info("%s: Detached metadata and signature regions read successfully\n",
					DM_MSG_PREFIX);

				dump_hex_short("detached.meta head", meta_buf,
					       le32_to_cpu(loc.meta_len), 32);
				dump_hex_short("detached.sig  head", sig_buf,
					       le32_to_cpu(loc.sig_len),  32);

				ret = verify_signature_pkcs7_detached(meta_buf,
							le32_to_cpu(loc.meta_len),
							sig_buf,
							le32_to_cpu(loc.sig_len));
				if (ret) {
					kfree(sig_buf);
					kfree(meta_buf);
					fput(bdev_file);
					pr_emerg("%s: signature verification FAILED (detached), ret=%d\n",
						 DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: untrusted detached metadata");
				}

				pr_info("%s: Signature verification PASSED (detached)\n", DM_MSG_PREFIX);

				h = (const struct verity_metadata_header *)meta_buf;

				/* NEW: Validate + log metadata fields */
				ret = verity_parse_metadata_header(h);
				if (ret) {
					kfree(sig_buf);
					kfree(meta_buf);
					fput(bdev_file);
					pr_emerg("%s: metadata header validation FAILED (detached), ret=%d\n",
							DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: invalid detached metadata header");
				}

				/*
				 * CRITICAL: Close the underlying block device
				 * before creating the dm-verity mapping.
				 */
				fput(bdev_file);
				bdev_file = NULL;

				ret = verity_create_mapping(dev, h);

				if (ret) {
					kfree(sig_buf);
					kfree(meta_buf);
					pr_emerg("%s: dm-verity mapping creation FAILED (detached), ret=%d\n",
						 DM_MSG_PREFIX, ret);
					panic("dm-verity-autoboot: failed to create dm-verity mapping");
				}

				kfree(sig_buf);
				kfree(meta_buf);
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

/*
 * init: print cmdline + param, then schedule the verification/mapping worker
 * a bit later so that the block device (virtio-blk, etc.) has time to appear.
 */
static int __init dm_verity_autoboot_init(void)
{
	extern char *saved_command_line;

	pr_info("%s: ==================================================\n",
		DM_MSG_PREFIX);
	pr_info("%s: dm-verity-autoboot initcall reached\n",
		DM_MSG_PREFIX);
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
		schedule_delayed_work(&verity_work, 5 * HZ);
		pr_info("%s: scheduled verification+mapping worker in ~5s\n",
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
MODULE_DESCRIPTION("dm-verity autoboot: verify PKCS7 + create dm-verity mapping");
MODULE_AUTHOR("team A");
