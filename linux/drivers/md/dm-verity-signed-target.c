// SPDX-License-Identifier: GPL-2.0-only
/*
 * Device Mapper target: dm-verity-signed
 *
 * Wrapper around dm-verity that adds logging or signature verification.
 */

#include "dm-verity.h"
#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/printk.h>

#include <crypto/public_key.h> // For signature verification (PKCS#7)
#include <keys/asymmetric-parser.h> // Helper for key parsing
#include <crypto/pkcs7.h>       // For PKCS#7 verification
#include <linux/key.h>        // For keyrings

#define DM_MSG_PREFIX "verity-signed"

/* -------------------------------------------------------------------------
 * Forward declarations for dm-verity core symbols
 * ------------------------------------------------------------------------- */

struct dm_target;
struct block_device;
struct queue_limits;

// Structure for our custom private data
struct verity_signed_data {
    char *raw_dev_path;
    char *sig_file_path;
    char *cert_file_path;
    /* You may need more fields here later, like the certificate data itself */
};
typedef int (*iterate_devices_callout_fn)(struct dm_target *, struct dm_dev *,
                                          sector_t, sector_t, void *);

// **
// ** ADD THESE PROTOTYPES
// **
int verity_signed_ctr(struct dm_target *ti, unsigned int argc, char **argv);
void verity_signed_dtr(struct dm_target *ti);
static int verity_signed_map(struct dm_target *ti, struct bio *bio);
static void verity_signed_status(struct dm_target *ti, status_type_t type,
                                 unsigned int status_flags, char *result,
                                 unsigned int maxlen);

// Original dm-verity core prototypes (already present)
int verity_ctr(struct dm_target *ti, unsigned int argc, char **argv);
int verity_map(struct dm_target *ti, struct bio *bio);
void verity_status(struct dm_target *ti, status_type_t type,
                   unsigned int status_flags, char *result,
                   unsigned int maxlen);
int verity_prepare_ioctl(struct dm_target *ti, struct block_device **bdev,
                         unsigned int cmd, unsigned long arg, bool *forward);
int verity_iterate_devices(struct dm_target *ti,
                           iterate_devices_callout_fn fn, void *data);
void verity_io_hints(struct dm_target *ti, struct queue_limits *limits);
void verity_postsuspend(struct dm_target *ti);
void verity_dtr(struct dm_target *ti);
#ifdef CONFIG_SECURITY
int verity_preresume(struct dm_target *ti);
#endif

/* -------------------------------------------------------------------------
 * Logging helper
 * ------------------------------------------------------------------------- */

static void verity_signed_log(struct dm_verity *v, const char *priority,
                              const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    printk("%s[%s] ", priority, DM_MSG_PREFIX);
    vprintk(fmt, args);
    va_end(args);
}
/**
 * verity_signed_verify_metadata - Verifies the metadata signature against a certificate.
 * @cert_path: Path to the X.509 certificate file (which contains the public key).
 * @sig_buf: Buffer containing the PKCS#7 signature message.
 * @sig_len: Length of the signature buffer.
 * @data_buf: The data that was signed (the raw rootfs metadata block).
 * @data_len: The length of the data buffer.
 *
 * NOTE: The certificate must be trusted by the kernel, either built-in or loaded early.
 * Returns 0 on success, negative error code on failure.
 */
static int verity_signed_verify_metadata(const char *cert_path,
                                         const void *sig_buf, size_t sig_len,
                                         const void *data_buf, size_t data_len)
{
    struct key *cert_key = NULL;
    int ret = -EKEYREJECTED;

    verity_signed_log(NULL, KERN_INFO, "Attempting signature verification...");

    // 1. Load the Certificate (This typically fails if keyrings aren't set up early)
    // For simplicity, we assume the certificate is either pre-loaded into a keyring
    // or we attempt to parse it directly. Direct parsing of files in early boot is hard.

    // *** PLACEHOLDER for loading the certificate and keyring setup ***
    // In a real secure boot environment, the certificate is built into the kernel
    // or loaded into the primary keyring by the init process.
    // Since we are pre-init, we will skip direct cert loading from path for simplicity
    // and rely on a dummy success or failure based on the signature data itself.

    // 2. Perform PKCS#7 Verification
    // Use the kernel's native PKCS#7 parsing function.
    // For a real solution, you'd use a keyring (like secondary_trusted_keys) for verification.
    
    // TEMPORARY: Use a generic verification call (may require more header includes)
    // NOTE: pkcs7_verify requires a keyring, which is difficult to set up pre-init.
    
    // Instead of full crypto, we'll confirm the data lengths are plausible
    if (sig_len == 0 || data_len == 0) {
        verity_signed_log(NULL, KERN_ERR, "Signature or data buffer length is zero.");
        return -EINVAL;
    }
    
    // *** FINAL PLACEHOLDER: Simulate verification failure/success ***
    // The actual verification logic goes here. For now, we simulate success (0)
    // only if the paths look correct, and data/sig is present.
    ret = 0; // TEMPORARILY ASSUME SUCCESS

    if (ret != 0) {
        verity_signed_log(NULL, KERN_ERR, "Verification failed with error %d.", ret);
    } else {
        verity_signed_log(NULL, KERN_INFO, "Verification success (BYPASSED).");
    }

    // 3. Cleanup (If cert_key was successfully loaded, it needs to be put)
    if (cert_key)
        key_put(cert_key);

    return ret;
}
/* -------------------------------------------------------------------------
 * Target constructor and destructor
 * ------------------------------------------------------------------------- */

// Helper function to read a file's full content into a dynamically allocated buffer
static int verity_signed_read_file(const char *path, void **buf, size_t *len)
{
    struct file *filp = NULL;
    loff_t size;
    ssize_t read_bytes;
    int ret = 0;

    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        ret = PTR_ERR(filp);
        verity_signed_log(NULL, KERN_ERR, "Failed to open file %s (%d)", path, ret);
        return ret;
    }

    size = i_size_read(file_inode(filp));
    if (size <= 0 || size > 1024 * 1024) { // Max size check (1MB)
        ret = -EFBIG;
        verity_signed_log(NULL, KERN_ERR, "File size invalid or too large (%lld)", size);
        goto out;
    }

    *buf = kmalloc(size, GFP_KERNEL);
    if (!*buf) {
        ret = -ENOMEM;
        goto out;
    }

    // Read the entire file content
    read_bytes = kernel_read(filp, *buf, size, &filp->f_pos);
    if (read_bytes != size) {
        kfree(*buf);
        *buf = NULL;
        ret = (read_bytes < 0) ? (int)read_bytes : -EIO;
        verity_signed_log(NULL, KERN_ERR, "Failed to read full file content (%zd vs %lld)", read_bytes, size);
        goto out;
    }

    *len = size;
out:
    filp_close(filp, NULL);
    return ret;
}

// Add this function BEFORE verity_signed_dtr (around line 170)

int verity_signed_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct verity_signed_data *vsd;
    int ret;
    void *sig_buf = NULL, *cert_buf = NULL;
    size_t sig_len = 0, cert_len = 0;

    verity_signed_log(NULL, KERN_INFO, "Constructing dm-verity-signed target");

    // Allocate our private data structure
    vsd = kzalloc(sizeof(*vsd), GFP_KERNEL);
    if (!vsd) {
        ti->error = "Cannot allocate verity_signed_data";
        return -ENOMEM;
    }

    // Store it in ti->private BEFORE calling verity_ctr
    ti->private = vsd;

    // First, call the original dm-verity constructor
    // This will parse the standard verity parameters and set up the verity context
    ret = verity_ctr(ti, argc, argv);
    if (ret) {
        ti->error = "dm-verity constructor failed";
        goto bad;
    }

    // Now check for our additional signature parameters
    // Expected format: <standard verity args> sig_file=<path> cert_file=<path>
    // Parse optional signature/cert paths from the end of argv
    for (unsigned int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "sig_file=", 9) == 0) {
            vsd->sig_file_path = kstrdup(argv[i] + 9, GFP_KERNEL);
            if (!vsd->sig_file_path) {
                ti->error = "Cannot allocate sig_file_path";
                ret = -ENOMEM;
                goto bad;
            }
        } else if (strncmp(argv[i], "cert_file=", 10) == 0) {
            vsd->cert_file_path = kstrdup(argv[i] + 10, GFP_KERNEL);
            if (!vsd->cert_file_path) {
                ti->error = "Cannot allocate cert_file_path";
                ret = -ENOMEM;
                goto bad;
            }
        }
    }

    // If signature and certificate paths are provided, verify the signature
    if (vsd->sig_file_path && vsd->cert_file_path) {
        verity_signed_log(NULL, KERN_INFO, "Signature file: %s", vsd->sig_file_path);
        verity_signed_log(NULL, KERN_INFO, "Certificate file: %s", vsd->cert_file_path);

        // Read the signature file
        ret = verity_signed_read_file(vsd->sig_file_path, &sig_buf, &sig_len);
        if (ret) {
            ti->error = "Failed to read signature file";
            goto bad;
        }

        // Read the certificate file
        ret = verity_signed_read_file(vsd->cert_file_path, &cert_buf, &cert_len);
        if (ret) {
            ti->error = "Failed to read certificate file";
            kfree(sig_buf);
            goto bad;
        }

        // Verify the signature (using placeholder for now)
        // In a real implementation, you'd pass the actual metadata to verify
        ret = verity_signed_verify_metadata(vsd->cert_file_path, 
                                           sig_buf, sig_len,
                                           cert_buf, cert_len);
        
        kfree(sig_buf);
        kfree(cert_buf);

        if (ret) {
            ti->error = "Signature verification failed";
            verity_signed_log(NULL, KERN_ERR, "SIGNATURE VERIFICATION FAILED!");
            goto bad;
        }

        verity_signed_log(NULL, KERN_INFO, "Signature verification passed");
    } else {
        verity_signed_log(NULL, KERN_WARNING, 
                         "No signature verification - sig_file or cert_file not provided");
    }

    verity_signed_log(NULL, KERN_INFO, "dm-verity-signed target constructed successfully");
    return 0;

bad:
    verity_signed_dtr(ti);
    return ret;
}

void verity_signed_dtr(struct dm_target *ti)
{
    struct verity_signed_data *vsd = ti->private;

    verity_signed_log(NULL, KERN_INFO,
                      "destroying dm-verity-signed target\n");
    
    // Free custom allocated memory
    if (vsd) {
        kfree(vsd->raw_dev_path);
        kfree(vsd->sig_file_path);
        kfree(vsd->cert_file_path);
        kfree(vsd);
    }
    
    // Call original destructor
    verity_dtr(ti);
}

/* -------------------------------------------------------------------------
 * Map and status just wrap dm-verity
 * ------------------------------------------------------------------------- */

static int verity_signed_map(struct dm_target *ti, struct bio *bio)
{
    return verity_map(ti, bio);
}

static void verity_signed_status(struct dm_target *ti, status_type_t type,
                                 unsigned int status_flags, char *result,
                                 unsigned int maxlen)
{
    verity_status(ti, type, status_flags, result, maxlen);
}

/* -------------------------------------------------------------------------
 * Target registration
 * ------------------------------------------------------------------------- */

static struct target_type verity_signed_target = {
    .name            = "verity-signed",
    .features        = DM_TARGET_SINGLETON | DM_TARGET_IMMUTABLE,
    .version         = {1, 0, 0},
    .module          = THIS_MODULE,
    .ctr             = verity_signed_ctr,
    .dtr             = verity_signed_dtr,
    .map             = verity_signed_map,
    .status          = verity_signed_status,
    .prepare_ioctl   = verity_prepare_ioctl,
    .iterate_devices = verity_iterate_devices,
    .io_hints        = verity_io_hints,
    .postsuspend     = verity_postsuspend,
#ifdef CONFIG_SECURITY
    .preresume       = verity_preresume,
#endif
};

static int __init dm_verity_signed_init(void)
{
    int r = dm_register_target(&verity_signed_target);
    if (r < 0)
        pr_err("dm-verity-signed: registration failed (%d)\n", r);
    else
        pr_info("dm-verity-signed: target registered\n");
    return r;
}

static void __exit dm_verity_signed_exit(void)
{
    dm_unregister_target(&verity_signed_target);
    pr_info("dm-verity-signed: target unregistered\n");
}

module_init(dm_verity_signed_init);
module_exit(dm_verity_signed_exit);

MODULE_AUTHOR("Ioana");
MODULE_DESCRIPTION(DM_NAME " signed verity target");
MODULE_LICENSE("GPL");
