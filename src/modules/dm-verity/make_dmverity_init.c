#include <linux/module.h>
#include <linux/init.h>
#include <linux/device-mapper.h>

static int __init make_dmverity_init(void)
{
    const struct target_type *verity_target;

    pr_info("dm-verity-init: Initializing dm-verity verification layer...\n");

    /* Check if dm-verity target is available */
    verity_target = dm_get_target_type("verity");
    if (!verity_target) {
        pr_err("dm-verity-init: ERROR — dm-verity target not found! "
               "Ensure CONFIG_DM_VERITY is enabled in the kernel.\n");
        return -ENODEV;
    }

    pr_info("dm-verity-init: dm-verity target found [%s], version %u.%u.%u\n",
            verity_target->name,
            verity_target->version[0],
            verity_target->version[1],
            verity_target->version[2]);

    pr_info("dm-verity-init: Kernel is ready to verify rootFS integrity via metadata tree.\n");

    dm_put_target_type(verity_target); 

    return 0;
}

static void __exit make_dmverity_exit(void)
{
    pr_info("dm-verity-init: Exiting dm-verity check module.\n");
}

module_init(make_dmverity_init);
module_exit(make_dmverity_exit);

MODULE_AUTHOR("Hazbiu @ Team-Project-2025");
MODULE_DESCRIPTION("dm-verity verification initialization and availability check");
MODULE_LICENSE("GPL");
