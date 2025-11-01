// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-autoboot.c
 *
 * Step 0: Test that kernel receives parameter from bootloader
 * 
 * Bootloader passes: dm.verity.autoboot=/dev/vdaX
 * This code just logs what it receives
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define DM_MSG_PREFIX "verity-autoboot"

static char *autoboot_device;

/**
 * Test initialization - just log what we receive
 */
static int __init dm_verity_autoboot_init(void)
{
	pr_info("==========================================\n");
	pr_info("%s: TEST - Kernel parameter test\n", DM_MSG_PREFIX);
	pr_info("==========================================\n");

    extern char *saved_command_line;
	pr_info("%s: Full kernel cmdline: %s\n", DM_MSG_PREFIX, saved_command_line);

	/* Check if we have a device parameter */
	if (!autoboot_device) {
		pr_info("%s: autoboot_device is NULL\n", DM_MSG_PREFIX);
		pr_info("%s: No dm.verity.autoboot parameter received\n", DM_MSG_PREFIX);
		return 0;
	}

	if (!*autoboot_device) {
		pr_info("%s: autoboot_device is empty string\n", DM_MSG_PREFIX);
		return 0;
	}

	/* We got something! */
	pr_info("%s: SUCCESS! Received parameter:\n", DM_MSG_PREFIX);
	pr_info("%s:   autoboot_device = '%s'\n", DM_MSG_PREFIX, autoboot_device);
	pr_info("%s:   Length: %zu characters\n", DM_MSG_PREFIX, strlen(autoboot_device));

	pr_info("==========================================\n");
	pr_info("%s: Test completed - parameter received OK\n", DM_MSG_PREFIX);
	pr_info("==========================================\n");

	return 0;
}

/*
 * Use late_initcall to run after device discovery
 */
late_initcall(dm_verity_autoboot_init);

module_param(autoboot_device, charp, 0);
MODULE_PARM_DESC(autoboot_device, 
                 "Device containing rootfs with verity metadata");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DM-Verity Autoboot - Parameter test");