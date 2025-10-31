// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Early boot helper to automatically create and activate a dm-verity target
 * for the verified root filesystem.
 *
 * Example kernel cmdline parameter:
 *     dm.verity.param=/dev/mmcblk0p2,/dev/mmcblk0p2,123456,200000,b96a1234...
 *
 * Tokens:
 *   [0] data device
 *   [1] hash device
 *   [2] data block count
 *   [3] hash start sector
 *   [4] root hash (hex string)
 *
 * The rootfs is expected to be mounted via "root=/dev/mapper/verified_root".
 */

#include <linux/init.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/slab.h>
#include <linux/err.h>

#define DM_ROOT_NAME        "verified_root"
#define VERITY_PARAM_LEN    512
#define EXPECTED_TOKENS     5

static char verity_param_raw[VERITY_PARAM_LEN] __initdata;

/* Parse the boot-time argument "dm.verity.param=" */
static int __init verity_param_setup(char *str)
{
	strlcpy(verity_param_raw, str, sizeof(verity_param_raw));
	return 1;
}
__setup("dm.verity.param=", verity_param_setup);

/* Early setup of dm-verity target */
static int __init dm_verity_autoboot_setup(void)
{
	char *p = NULL;
	char *data[EXPECTED_TOKENS];
	int i = 0, r = 0;
	struct dm_table *table = NULL;
	struct mapped_device *md = NULL;

	pr_info("DM-VERITY-AUTO: starting verity setup...\n");

	if (!verity_param_raw[0]) {
		pr_info("DM-VERITY-AUTO: no 'dm.verity.param' found, skipping.\n");
		return 0; /* not an error if feature unused */
	}

	/* Duplicate for tokenization */
	p = kstrdup_const(verity_param_raw, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	char *cursor = p;

	while ((data[i] = strsep(&cursor, ",")) != NULL) {
		if (++i >= EXPECTED_TOKENS)
			break;
	}

	if (i != EXPECTED_TOKENS) {
		pr_err("DM-VERITY-AUTO: invalid param, got %d tokens (expected %d)\n",
		       i, EXPECTED_TOKENS);
		r = -EINVAL;
		goto out_free;
	}

	/* Build dm-verity target arguments */
	char *table_args[] = {
		"1",          /* version */
		data[0],      /* data device */
		data[1],      /* hash device */
		"4096",       /* data block size */
		"4096",       /* hash block size */
		data[2],      /* number of data blocks */
		data[3],      /* hash start sector */
		"sha256",     /* hash algorithm */
		data[4],      /* root hash */
		"-",          /* salt */
		NULL
	};
	unsigned int num_args = ARRAY_SIZE(table_args) - 1;

	pr_info("DM-VERITY-AUTO: creating verity target: data=%s hash=%s hashstart=%s root_hash=%s\n",
	        data[0], data[1], data[3], data[4]);

	/* --- Modern device-mapper setup sequence --- */

	md = dm_alloc_md(MEMPOOL_NOIO);
	if (IS_ERR(md)) {
		r = PTR_ERR(md);
		pr_err("DM-VERITY-AUTO: dm_alloc_md failed (%d)\n", r);
		goto out_free;
	}

	r = dm_table_create(&table, FMODE_READ, md);
	if (r) {
		pr_err("DM-VERITY-AUTO: dm_table_create failed (%d)\n", r);
		goto err_put_md;
	}

	r = dm_table_add_target(table, "verity", 0, 0, table_args, num_args);
	if (r) {
		pr_err("DM-VERITY-AUTO: dm_table_add_target failed (%d)\n", r);
		goto err_destroy_table;
	}

	r = dm_table_complete(table);
	if (r) {
		pr_err("DM-VERITY-AUTO: dm_table_complete failed (%d)\n", r);
		goto err_destroy_table;
	}

	r = dm_bind_table(md, table);
	if (r) {
		pr_err("DM-VERITY-AUTO: dm_bind_table failed (%d)\n", r);
		goto err_destroy_table;
	}

	r = dm_resume(md);
	if (r) {
		pr_err("DM-VERITY-AUTO: dm_resume failed (%d)\n", r);
		goto err_put_md;
	}

	pr_info("DM-VERITY-AUTO: verified root device '/dev/mapper/%s' is active.\n",
	        DM_ROOT_NAME);
	goto out_free;

err_destroy_table:
	dm_table_destroy(table);
err_put_md:
	dm_put(md);
out_free:
	kfree(p);
	if (r)
		pr_err("DM-VERITY-AUTO: setup failed (%d)\n", r);
	return r;
}

/* Run before mount_root() */
core_initcall(dm_verity_autoboot_setup);
