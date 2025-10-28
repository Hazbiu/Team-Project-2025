// SPDX-License-Identifier: GPL-2.0
/*
 * dm-verity-signed: skeleton Device Mapper target that verifies a PKCS#7-
 * signed metadata blob before proceeding (WIP placeholder).
 *
 * NOTE: This builds against your kernel’s verification API:
 *   extern int verify_pkcs7_signature(const void *data, size_t len,
 *                                     const void *raw_pkcs7, size_t pkcs7_len,
 *                                     struct key *trusted_keys,
 *                                     enum key_being_used_for usage,
 *                                     int (*view_content)(void *ctx,
 *                                                         const void *data,
 *                                                         size_t len,
 *                                                         size_t asn1hdrlen),
 *                                     void *ctx);
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/device-mapper.h>
#include <linux/kernel_read_file.h>
#include <linux/verification.h>

#define DM_MSG_PREFIX "verity-signed"

/* Simple helper to read a whole file into a vmalloc buffer */
static int read_whole_file(const char *path, void **buf, size_t *len)
{
	ssize_t ret;
	void *p = NULL;
	size_t file_size = 0;

	*buf = NULL;
	*len = 0;

	ret = kernel_read_file_from_path(path,
					 0,           /* offset */
					 &p,          /* out: vmalloc'd buffer */
					 0,           /* buf_size==0 => allocate as needed */
					 &file_size,  /* out: size */
					 READING_FIRMWARE);
	if (ret < 0)
		return (int)ret;

	/* Some kernels return number of bytes read in ret; trust file_size */
	*buf = p;
	*len = file_size;
	return 0;
}

/*
 * Verify that 'data' (metadata) is signed by a PKCS#7 signature in 'sig',
 * using the kernel trusted keyring.
 *
 * IMPORTANT: 'sig' must be a PKCS#7/CMS DER blob (NOT a raw RSA signature).
 */
static int verify_signature(const void *data, size_t data_len,
			    const void *sig, size_t sig_len)
{
#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
	/* Use only builtin trusted keys: pass NULL per your verification.h */
	struct key *trusted = NULL;

	/*
	 * If you want to accept both builtin and secondary keyrings, use:
	 *   trusted = VERIFY_USE_SECONDARY_KEYRING;
	 * If you also want to allow platform keyring (if configured):
	 *   trusted = VERIFY_USE_PLATFORM_KEYRING;
	 */
	return verify_pkcs7_signature(data, data_len,
				      sig, sig_len,
				      trusted,
				      VERIFYING_FIRMWARE_SIGNATURE,
				      NULL, NULL);
#else
	pr_err(DM_MSG_PREFIX ": CONFIG_SYSTEM_DATA_VERIFICATION=n; PKCS#7 verify not available\n");
	return -EOPNOTSUPP;
#endif
}

struct verity_signed_c {
	char *meta_path;
	char *sig_path;
	/* Future: parsed verity params go here */
};

static int verity_signed_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct verity_signed_c *vc;
	void *meta = NULL, *sig = NULL;
	size_t meta_len = 0, sig_len = 0;
	int r;

	/* --- Log what we received from dm-mod.create --- */
	pr_info(DM_MSG_PREFIX ": target constructor called, argc=%u\n", argc);
	for (unsigned int i = 0; i < argc; i++)
		pr_info(DM_MSG_PREFIX ": argv[%u] = '%s'\n", i, argv[i]);

	/* Optional: show the kernel cmdline for debugging */
#if defined(CONFIG_PRINTK)
	extern char *saved_command_line;
	pr_info("Kernel cmdline: %s\n", saved_command_line);
	pr_info(DM_MSG_PREFIX ": full cmdline: %s\n", saved_command_line);
#endif

	/* --- Usage check --- */
	if (argc < 2) {
		ti->error = "Usage: verity-signed <meta_path> <sig_path>";
		return -EINVAL;
	}

	/* --- Allocate context --- */
	vc = kzalloc(sizeof(*vc), GFP_KERNEL);
	if (!vc)
		return -ENOMEM;

	vc->meta_path = kstrdup(argv[0], GFP_KERNEL);
	vc->sig_path  = kstrdup(argv[1], GFP_KERNEL);
	if (!vc->meta_path || !vc->sig_path) {
		r = -ENOMEM;
		goto err_free_ctx;
	}

	/* --- Print parameters clearly --- */
	DMINFO("received parameters:");
	DMINFO("  meta_path = '%s'", vc->meta_path);
	DMINFO("  sig_path  = '%s'", vc->sig_path);

	/* --- Read and verify files --- */
	r = read_whole_file(vc->meta_path, &meta, &meta_len);
	if (r) {
		DMERR("failed to read metadata '%s': %d", vc->meta_path, r);
		goto err_free_ctx;
	}

	r = read_whole_file(vc->sig_path, &sig, &sig_len);
	if (r) {
		DMERR("failed to read signature '%s': %d", vc->sig_path, r);
		goto err_free_meta;
	}

	r = verify_signature(meta, meta_len, sig, sig_len);
	if (r) {
		DMERR("PKCS#7 verification failed for '%s' (sig '%s'): %d",
		      vc->meta_path, vc->sig_path, r);
		goto err_free_sig;
	}

	DMINFO("metadata verified successfully (PKCS#7). meta='%s' sig='%s' size=%zu/%zu",
	       vc->meta_path, vc->sig_path, meta_len, sig_len);

	vfree(sig);
	vfree(meta);
	ti->private = vc;
	return 0;

err_free_sig:
	vfree(sig);
err_free_meta:
	vfree(meta);
err_free_ctx:
	kfree(vc->sig_path);
	kfree(vc->meta_path);
	kfree(vc);
	return r;
}


static void verity_signed_dtr(struct dm_target *ti)
{
	struct verity_signed_c *vc = ti->private;

	if (!vc)
		return;

	kfree(vc->sig_path);
	kfree(vc->meta_path);
	kfree(vc);
}

static struct target_type verity_signed_target = {
	.name    = "verity-signed",
	.version = { 1, 0, 0 },
	.module  = THIS_MODULE,
	.ctr     = verity_signed_ctr,
	.dtr     = verity_signed_dtr,
	/* map/end_io/etc. to be added once we wrap/chain to core dm-verity */
};


static int __init verity_signed_init(void)
{
    pr_info("verity-signed: Kernel cmdline: %s\n", saved_command_line);

    /* Example: parse the key or root device later if you need */
    if (strstr(saved_command_line, "verity_key="))
        pr_info("verity-signed: found verity_key parameter\n");

    return dm_register_target(&verity_signed_target);
}


static void __exit verity_signed_exit(void)
{
	dm_unregister_target(&verity_signed_target);
	pr_info(DM_MSG_PREFIX ": unregistered\n");
}

module_init(verity_signed_init);
module_exit(verity_signed_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("dm-verity target with signed metadata verification (PKCS#7)");
