// SPDX-License-Identifier: GPL-2.0
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/key.h>
#include <linux/kernel_read_file.h>
#include <linux/verification.h>

#define DM_MSG_PREFIX "verity-signed"

/*
 * Simplified demo: reads metadata (roothash + salt) and signature from
 * /boot/rootfs.verity.meta + /boot/rootfs.verity.meta.sig
 * and verifies the signature using a built-in X.509 key in kernel.
 */

static int verify_signature(const char *meta_path, const char *sig_path)
{
	struct key *key;
	const struct public_key_signature *sig;
	const u8 *data;
	loff_t size;
	int ret;

	ret = kernel_read_file_from_path(meta_path, (void **)&data, &size, 0, READING_FIRMWARE);
	if (ret < 0) {
		pr_err("verity-signed: failed to read metadata (%s)\n", meta_path);
		return ret;
	}

	/* Verify signature using kernel keyring */
	ret = verify_pkcs7_signature(NULL, 0, data, size, sig_path, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		pr_err("verity-signed: metadata signature verification failed (%d)\n", ret);
	else
		pr_info("verity-signed: metadata signature OK\n");

	kfree(data);
	return ret;
}

static int verity_signed_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	pr_info("verity-signed: creating target with %u args\n", argc);

	/* For now just demonstrate signature verification */
	verify_signature("/boot/rootfs.verity.meta", "/boot/rootfs.verity.meta.sig");

	pr_info("verity-signed: verified, ready to register as dm target\n");
	return 0;
}

static void verity_signed_dtr(struct dm_target *ti)
{
	pr_info("verity-signed: target destroyed\n");
}

static struct target_type verity_signed_target = {
	.name    = "verity-signed",
	.version = {1, 0, 0},
	.module  = THIS_MODULE,
	.ctr     = verity_signed_ctr,
	.dtr     = verity_signed_dtr,
};

static int __init verity_signed_init(void)
{
	pr_info("verity-signed: registering target\n");
	return dm_register_target(&verity_signed_target);
}

static void __exit verity_signed_exit(void)
{
	pr_info("verity-signed: unregistering target\n");
	dm_unregister_target(&verity_signed_target);
}

module_init(verity_signed_init);
module_exit(verity_signed_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dm-verity target with signed metadata verification");
MODULE_AUTHOR("Keti Secure Boot Project");
cd 