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

#define DM_MSG_PREFIX "verity-signed"

/* -------------------------------------------------------------------------
 * Forward declarations for dm-verity core symbols
 * ------------------------------------------------------------------------- */



extern int dm_verity_ctr(struct dm_target *ti, unsigned int argc, char **argv);
extern int verity_map(struct dm_target *ti, struct bio *bio);
extern void verity_status(struct dm_target *ti, status_type_t type,
                          unsigned int status_flags, char *result,
                          unsigned int maxlen);

struct dm_target;
struct block_device;
struct queue_limits;
typedef int (*iterate_devices_callout_fn)(struct dm_target *, struct dm_dev *,
                                          sector_t, sector_t, void *);

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

/* -------------------------------------------------------------------------
 * Target constructor and destructor
 * ------------------------------------------------------------------------- */

static int verity_signed_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    int r;

    verity_signed_log(NULL, KERN_INFO, "creating dm-verity-signed target\n");

    /* Call verity_ctr directly */
    r = verity_ctr(ti, argc, argv);
    if (r) {
        verity_signed_log(NULL, KERN_ERR,
                          "verity ctr failed (%d)\n", r);
        return r;
    }

    verity_signed_log(ti->private, KERN_INFO,
                      "dm-verity-signed target initialized\n");
    return 0;
}

static void verity_signed_dtr(struct dm_target *ti)
{
    verity_signed_log(NULL, KERN_INFO,
                      "destroying dm-verity-signed target\n");
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
