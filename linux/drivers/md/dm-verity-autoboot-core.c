#include <linux/init.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/fs.h>        // for fput(), file_inode()
#include <linux/blkdev.h>    // for bdev_file_open_by_dev(), BLK_OPEN_READ
#include "dm-verity-autoboot.h"

static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
	"Whole-disk block dev (e.g. /dev/vda) containing verity footer");

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
		u8 tail[4096];
		loff_t sz = i_size_read(file_inode(bdev_file));
		loff_t pos = sz - 4096;
		ssize_t got = kernel_read(bdev_file, tail, 4096, &pos);

		if (got != 4096) {
			fput(bdev_file);
			return -EIO;
		}

		/* Attached footer */
		if (le32_to_cpu(*(__le32 *)tail) == 0x56455249) {
			struct verity_metadata_ondisk *meta;

			meta = kmalloc(4096, GFP_KERNEL);
			if (!meta) {
				fput(bdev_file);
				return -ENOMEM;
			}

			pos = sz - 4096;
			if (kernel_read(bdev_file, meta, 4096, &pos) != 4096) {
				kfree(meta);
				fput(bdev_file);
				return -EIO;
			}

			ret = verify_attached(meta);
			if (ret) {
				kfree(meta);
				fput(bdev_file);
				panic("dm-verity-autoboot: attached signature INVALID");
			}

			check_hash_tree_location(meta);

			kfree(meta);
			fput(bdev_file);
			return 0;
		}

		/* Detached footer */
		else if (le32_to_cpu(*(__le32 *)tail) == 0x564C4F43) {
			struct verity_footer_locator loc;
			u8 *meta_buf = NULL, *sig_buf = NULL;

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

			ret = verify_detached(meta_buf, le32_to_cpu(loc.meta_len),
					      sig_buf,  le32_to_cpu(loc.sig_len));
			if (ret) {
				kfree(sig_buf);
				kfree(meta_buf);
				fput(bdev_file);
				panic("dm-verity-autoboot: detached signature INVALID");
			}

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
