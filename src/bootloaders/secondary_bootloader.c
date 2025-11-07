// Build: gcc -O2 -Wall -Wextra -o simple_bootloader simple_bootloader.c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Simplified bootloader — only passes the rootfs partition path to the kernel.
 *
 * The kernel module (dm-verity-autoboot-full) will:
 *  1) Read dm-verity metadata from the given partition
 *  2) Verify the detached PKCS7 signature
 *  3) Create the dm-verity mapping in-kernel (no userspace)
 *  4) Let the kernel mount the verified root
 */

static const char *KERNEL_IMG = "kernel_image.bin";
static const char *ROOTFS_IMG = "../build/Binaries/rootfs.img";

static int boot_qemu(const char *kernel, const char *rootfs_img)
{
    char append[1024];

    /*
     * Kernel command line:
     *  - Pass the exact partition that contains ext4 + hashtree + detached footer
     *  - root=/dev/mapper/verity_root (created in-kernel by our module)
     *  - Keep rootwait to let the block device probe complete
     */
    snprintf(append, sizeof(append),
        "console=ttyS0,115200 "
        "loglevel=7 "
        "dm_verity_autoboot.autoboot_device=/dev/vda1 "
        "root=/dev/dm-0 "
        "rootfstype=ext4 "
        "rootwait");

    printf("=== Kernel command line ===\n%s\n\n", append);

    char drive[256];
    snprintf(drive, sizeof(drive), "file=%s,format=raw,if=virtio", rootfs_img);

    const char *argv[] = {
        "qemu-system-x86_64",
        "-m", "1024",
        "-kernel", kernel,
        "-drive", drive,
        "-append", append,
        "-nographic",
        NULL
    };

    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], (char * const *)argv);
        _exit(127);
    }

    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

int main(void)
{
    printf("=====================================\n");
    printf("   Simple Bootloader\n");
    printf("   (Kernel handles verity & mount)\n");
    printf("=====================================\n\n");

    printf("This bootloader only:\n");
    printf("  1. Loads kernel and rootfs image\n");
    printf("  2. Passes the partition path via kernel parameter\n\n");

    printf("The kernel module will:\n");
    printf("  1. Read dm-verity metadata from /dev/vda1\n");
    printf("  2. Verify PKCS7 signature\n");
    printf("  3. Parse metadata (root hash, salt, etc.)\n");
    printf("  4. Create dm-verity device mapping (in-kernel)\n");
    printf("  5. Allow kernel to mount verified root\n\n");

    printf("Press ENTER to boot...\n");
    getchar();

    printf("\n=== Launching QEMU ===\n");
    printf("Kernel: %s\n", KERNEL_IMG);
    printf("Rootfs: %s (as /dev/vda with partition p1)\n\n", ROOTFS_IMG);

    int rc = boot_qemu(KERNEL_IMG, ROOTFS_IMG);
    printf("QEMU exited with code %d\n", rc);
    return rc;
}
