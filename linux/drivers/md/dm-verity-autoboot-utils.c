// dm_verity_autoboot-utils.c
#include "dm-verity-autoboot.h"
#include <linux/slab.h>
#include <crypto/hash.h>
#include <linux/blkdev.h>   // provides struct gendisk, dev_to_disk, disk_devt, block_class


/* ---------------------------------------------------------- */
/* Utility Helpers (must be defined before used)               */
/* ---------------------------------------------------------- */

/* SHA256 helper */
int sha256_buf(const u8 *buf, size_t len, u8 digest[32])
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
int read_region(struct file *bdev_file, u64 off, u32 len, u8 **out)
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
int resolve_dev_from_diskname(const char *path, dev_t *out_dev)
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


void dump_hex_short(const char *tag, const u8 *buf, size_t len, size_t max_show)
{
	size_t i, show = (len < max_show) ? len : max_show;
	pr_info("%s: %s: ", DM_MSG_PREFIX, tag);
	for (i = 0; i < show; i++)
		pr_cont("%02x", buf[i]);
	if (len > show)
		pr_cont("...");
	pr_cont("\n");
}