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
