// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Automatically creates a dm-verity mapping from a device passed
 * by the bootloader (e.g., "dm_verity_autoboot.autoboot_device=/dev/vda")
 *
 * Example kernel command line:
 *   console=ttyS0 root=/dev/mapper/verified_root ro rootwait \
 *   dm_verity_autoboot.autoboot_device=/dev/vda
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/fs.h>
#include <linux/string.h>

#define DM_MSG_PREFIX "verity-autoboot"

static char *autoboot_device;
module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device,
	"Device containing the rootfs with verity metadata footer");

/*
 * Step 1: Log what we received from the kernel cmdline
 */
static void log_received_param(void)
{
	extern char *saved_command_line;

	pr_info("==========================================\n");
	pr_info("%s: Starting dm-verity autoboot\n", DM_MSG_PREFIX);
	pr_info("==========================================\n");
	pr_info("%s: Full kernel cmdline: %s\n", DM_MSG_PREFIX, saved_command_line);

	if (!autoboot_device || !*autoboot_device)
		pr_warn("%s: autoboot_device not provided!\n", DM_MSG_PREFIX);
	else
		pr_info("%s: autoboot_device = '%s'\n", DM_MSG_PREFIX, autoboot_device);
}

/*
 * Step 2: Create dm-verity mapping for /dev/mapper/verified_root
 */
static int create_verified_mapping(void)
{
#ifdef CONFIG_DM_INIT
	struct dm_ioctl io;
	struct dm_target_spec *spec = NULL;
	char *params = NULL;   // correct 3rd argument type
	int r;

	memset(&io, 0, sizeof(io));
	io.version[0] = DM_VERSION_MAJOR;
	io.version[1] = DM_VERSION_MINOR;
	io.version[2] = DM_VERSION_PATCHLEVEL;
	io.data_size = sizeof(io);
	io.data_start = sizeof(io);

	pr_info("%s: Creating mapping 'verified_root' for %s\n",
	        DM_MSG_PREFIX, autoboot_device);

	r = dm_early_create(&io, &spec, &params);
	if (r)
		pr_err("%s: dm_early_create failed (%d)\n", DM_MSG_PREFIX, r);
	else
		pr_info("%s: dm_early_create succeeded!\n", DM_MSG_PREFIX);

	return r;
#else
	pr_warn("%s: CONFIG_DM_INIT not enabled, cannot create early mapping\n", DM_MSG_PREFIX);
	return -ENODEV;
#endif
}


/*
 * Step 3: Initialization entry point
 */
static int __init dm_verity_autoboot_init(void)
{
	int r = 0;

	log_received_param();

	if (!autoboot_device || !*autoboot_device)
		return 0;

	r = create_verified_mapping();
	if (r)
		pr_err("%s: Failed to create verified_root mapping (%d)\n",
		       DM_MSG_PREFIX, r);
	else
		pr_info("%s: Verified mapping created successfully\n", DM_MSG_PREFIX);

	pr_info("==========================================\n");
	pr_info("%s: Autoboot init complete\n", DM_MSG_PREFIX);
	pr_info("==========================================\n");

	return 0;
}

/*
 * Step 4: Run late in boot (after device discovery but before root mount)
 */
late_initcall(dm_verity_autoboot_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DM-Verity Autoboot - Automatically create verified_root mapping");
MODULE_AUTHOR("Tomislav Tomov");
