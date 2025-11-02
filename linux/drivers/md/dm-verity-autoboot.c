// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Flow (dev/demo mode):
 *  - Bootloader passes: dm_verity_autoboot.autoboot_device=/dev/vda
 *  - Kernel initcalls:
 *      1) log the cmdline + param (paramtest)
 *      2) schedule our worker (autoboot_thread_init)
 *  - Worker does:
 *      - find the block device in-kernel (no /dev node, no udev)
 *      - open it by dev_t
 *      - read last 4KB footer (verity metadata blob)
 *      - dump parsed fields
 *      - (future) create dm-verity mapping /dev/mapper/verified_root
 *
 * Notes:
 *  - We no longer rely on /dev/vda1 or partition scan.
 *  - We no longer rely on lookup_bdev("/dev/vda"), because /dev/vda
 *    node does not exist without udev. We instead walk block_class,
 *    match disk->disk_name to "vda", grab its dev_t, and call
 *    bdev_file_open_by_dev().
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

#define DM_MSG_PREFIX          "verity-autoboot"
#define VERITY_META_SIZE       4096    /* footer assumed in last 4KB */
#define VERITY_META_MAGIC      0x56455249 /* "VERI" magic in metadata struct */

/*
 * Kernel cmdline parameter:
 *   dm_verity_autoboot.autoboot_device=/dev/vda
 *
 * In this DEV MODE flow, the verity footer is at the END OF DISK,
 * not at the end of a specific partition. So we just open the base
 * disk ("vda") and read its last 4KB.
 */
static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
		 "Block device containing rootfs + verity footer (e.g. /dev/vda)");

/*
 * delayed_work to run our logic a few seconds after boot
 * (gives virtio time to register the disk)
 */
static void verity_autoboot_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(verity_autoboot_work, verity_autoboot_workfn);

/* kthread handle not strictly needed anymore but keep for symmetry */
static struct task_struct *init_thread;

/*
 * On-disk metadata format.
 * Must match what userspace wrote into last 4096 bytes of the disk image.
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
	__le32 signature_size;
	u8     signature[256];
	u8     reserved[3328]; /* pad so total is 4096 */
} __packed;

/* forward decl of main thread fn so workfn can call it */
static int verity_autoboot_thread(void *unused);

/* ────────────────────────────────────────────────
 * Debug helper: list visible block devices
 * ──────────────────────────────────────────────── */
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

/* ────────────────────────────────────────────────
 * resolve_dev_from_diskname()
 *
 * Input: autoboot_device string like "/dev/vda"
 * Output: dev_t for that disk (NOT partition), by matching disk->disk_name.
 *
 * We intentionally do NOT rely on the existence of a /dev node,
 * and we do NOT call lookup_bdev(). We walk the in-kernel block
 * devices via block_class and find the matching gendisk.
 * ──────────────────────────────────────────────── */
static int resolve_dev_from_diskname(const char *autopath, dev_t *out_dev)
{
	const char *name;
	struct class_dev_iter iter;
	struct device *dev;

	if (!autopath || !out_dev)
		return -EINVAL;

	/* strip "/dev/" prefix if present */
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

/* ────────────────────────────────────────────────
 * Read last VERITY_META_SIZE bytes from open blockdev file
 * ──────────────────────────────────────────────── */
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

	/* Dump fields for debug/demo */
	if (le32_to_cpu(meta_out->magic) != VERITY_META_MAGIC) {
		pr_warn("%s: metadata magic mismatch: got 0x%08x expected 0x%08x\n",
			DM_MSG_PREFIX,
			le32_to_cpu(meta_out->magic),
			VERITY_META_MAGIC);
	} else {
		pr_info("%s: Metadata magic OK (0x%08x)\n",
			DM_MSG_PREFIX, le32_to_cpu(meta_out->magic));
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
	pr_info("%s:   signature_size:      %u\n",
		DM_MSG_PREFIX, le32_to_cpu(meta_out->signature_size));

	return 0;
}

/* ────────────────────────────────────────────────
 * Signature verification placeholder
 * ──────────────────────────────────────────────── */
static int verify_signature(const struct verity_metadata_ondisk *meta)
{
	u32 sig_sz = le32_to_cpu(meta->signature_size);

	pr_info("%s: === Signature verification step ===\n",
		DM_MSG_PREFIX);

	pr_info("%s:   signature_size = %u\n",
		DM_MSG_PREFIX, sig_sz);

	pr_warn("%s: DEV MODE: signature verification NOT enforced yet\n",
		DM_MSG_PREFIX);

	return 0;
}

/* ────────────────────────────────────────────────
 * Placeholder for creating /dev/mapper/verified_root
 * ──────────────────────────────────────────────── */
static int create_verity_target(const char *root_dev,
				const struct verity_metadata_ondisk *meta)
{
	pr_info("%s: === dm-verity mapping (stub) ===\n", DM_MSG_PREFIX);
	pr_info("%s: Would now create /dev/mapper/verified_root\n",
		DM_MSG_PREFIX);
	pr_info("%s:   backing device  : %s\n",
		DM_MSG_PREFIX, root_dev);
	pr_info("%s:   hash algorithm  : %s\n",
		DM_MSG_PREFIX, meta->hash_algorithm);
	pr_info("%s:   root hash (hex) : %02x%02x%02x%02x...\n",
		DM_MSG_PREFIX,
		meta->root_hash[0],
		meta->root_hash[1],
		meta->root_hash[2],
		meta->root_hash[3]);

	return 0;
}

/* ────────────────────────────────────────────────
 * Main worker thread
 * ──────────────────────────────────────────────── */
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

	/*
	 * NEW: resolve dev_t directly from kernel's block list
	 * instead of relying on /dev nodes or lookup_bdev().
	 */
	ret = resolve_dev_from_diskname(autoboot_device, &dev);
	if (ret) {
		pr_err("%s: Could not resolve dev_t for %s (%d)\n",
		       DM_MSG_PREFIX, autoboot_device, ret);
		return ret;
	}

	pr_info("%s: resolved %s to dev_t major=%u minor=%u\n",
		DM_MSG_PREFIX, autoboot_device,
		MAJOR(dev), MINOR(dev));

	/*
	 * Open that block device for read.
	 * No /dev entry is needed for this.
	 */
	bdev_file = bdev_file_open_by_dev(dev,
					  BLK_OPEN_READ,
					  NULL, /* holder */
					  NULL  /* blk_holder_ops */);
	if (IS_ERR(bdev_file)) {
		pr_err("%s: bdev_file_open_by_dev failed (%ld)\n",
		       DM_MSG_PREFIX, PTR_ERR(bdev_file));
		return PTR_ERR(bdev_file);
	}

	/* Read verity footer */
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

	/* Signature verification stub */
	pr_info("%s: === Step 2: Verifying metadata signature (stub) ===\n",
		DM_MSG_PREFIX);
	ret = verify_signature(meta);
	if (ret) {
		pr_err("%s: Signature verification failed (%d)\n",
		       DM_MSG_PREFIX, ret);
		kfree(meta);
		fput(bdev_file);
		return ret;
	}

	/* dm-verity mapping stub */
	pr_info("%s: === Step 3: Creating dm-verity mapping (stub) ===\n",
		DM_MSG_PREFIX);
	ret = create_verity_target(autoboot_device, meta);
	if (ret)
		pr_err("%s: create_verity_target() failed (%d)\n",
		       DM_MSG_PREFIX, ret);

	kfree(meta);
	fput(bdev_file);

	pr_info("%s: autoboot thread finished initial steps ✅\n",
		DM_MSG_PREFIX);
	return 0;
}

/* workqueue trampoline just calls the thread fn */
static void verity_autoboot_workfn(struct work_struct *work)
{
	verity_autoboot_thread(NULL);
}

/* ────────────────────────────────────────────────
 * initcall #1: parameter test logger
 * ──────────────────────────────────────────────── */
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

/* ────────────────────────────────────────────────
 * initcall #2: schedule the worker that does the real work
 * ──────────────────────────────────────────────── */
static int __init dm_verity_autoboot_thread_init(void)
{
	if (autoboot_device && *autoboot_device) {
		/* wait ~5s after late_init to let virtio block register */
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

/* ────────────────────────────────────────────────
 * module exit (in case it's ever a module again)
 * ──────────────────────────────────────────────── */
static void __exit dm_verity_autoboot_exit(void)
{
	if (init_thread)
		kthread_stop(init_thread);

	pr_info("%s: Module exit\n", DM_MSG_PREFIX);
}
module_exit(dm_verity_autoboot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DM-Verity Autoboot - in-kernel rootfs verifier/bootstrapper (dev mode)");
MODULE_AUTHOR("ioana");
