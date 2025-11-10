// Build: gcc -O2 -Wall -o bootloader bootloader.c
//
// Minimal userspace bootloader for the dm-verity demo.
//
// Responsibilities:
//   - Resolve the absolute path to the GPT disk image (rootfs.img)
//   - Start QEMU with:
//       * the Linux kernel image (kernel_image.bin)
//       * the disk image attached as a virtio-blk drive (/dev/vda in guest)
//       * a kernel cmdline that:
//           - tells dm-verity-autoboot which disk to verify (/dev/vda)
//           - sets root=/dev/dm-0 so the kernel mounts the dm-verity device
//
// All security logic (dm-verity tree, detached PKCS7 verification,
// dm-verity mapping creation, and mounting the verified rootfs) happens
// entirely inside the kernel.

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void)
{
    char img_abs[PATH_MAX];
    char drive_opt[PATH_MAX + 128];
    char append[1024];

    // Resolve the absolute path for the disk image (GPT disk with ext4 + verity)
    if (!realpath("../build/Binaries/rootfs.img", img_abs)) {  
        perror("realpath(rootfs.img)");
        return 1;
    }

    // QEMU -drive option: attach the image as a raw, whole disk.
    // Inside the guest this shows up as /dev/vda.
    snprintf(drive_opt, sizeof(drive_opt),
             "if=none,id=drv0,format=raw,media=disk,file=%s",
             img_abs);

    // Kernel command line:
    //   - console/loglevel       : serial logging
    //   - dm_verity_autoboot.*   : tell our built-in module which whole disk to verify
    //   - root=/dev/dm-0         : root filesystem must come from the dm-verity mapping
    //   - rootfstype=ext4        : ext4 filesystem inside the verified mapping
    //   - rootwait/rootdelay     : wait for /dev/dm-0 to appear
    snprintf(append, sizeof(append),
             "console=ttyS0,115200 "
             "loglevel=7 "
             "dm_verity_autoboot.autoboot_device=/dev/vda "
             "root=/dev/dm-0 rootfstype=ext4 rootwait rootdelay=10");

    printf("================================================\n");
    printf("  SIMPLE dm-verity BOOTLOADER (QEMU launcher)\n");
    printf("  Kernel does all verification + mapping\n");
    printf("================================================\n\n");

    printf("Using disk image (whole GPT disk):\n  %s\n\n", img_abs);
    printf("QEMU -drive argument:\n  %s\n\n", drive_opt);

    printf("This bootloader ONLY:\n");
    printf("  - Loads the Linux kernel image\n");
    printf("  - Attaches the rootfs disk as a virtio-blk drive (/dev/vda)\n");
    printf("  - Passes the kernel command line with:\n");
    printf("      * dm_verity_autoboot.autoboot_device=/dev/vda\n");
    printf("      * root=/dev/dm-0 (ext4, verified)\n\n");

    printf("Inside the guest, the kernel + dm-verity-autoboot will:\n");
    printf("  1. Bring up virtio-blk and expose /dev/vda (whole disk)\n");
    printf("  2. Read the dm-verity locator + metadata + PKCS7 signature\n");
    printf("     from the end of /dev/vda\n");
    printf("  3. Verify the PKCS7 signature against the kernel trusted keyring\n");
    printf("  4. Create a read-only dm-verity mapping over /dev/vda\n");
    printf("     (device name \"verity_root\", typically /dev/dm-0)\n");
    printf("  5. Let the kernel mount /dev/dm-0 as the ext4 root filesystem\n\n");

    printf("Press ENTER to boot QEMU...\n");
    getchar();

    const char *argv[] = {
        "qemu-system-x86_64",
        "-m", "1024",
        "-machine", "q35,accel=tcg",
        "-cpu", "max",
        "-nodefaults",
        "-nographic",
        "-serial", "mon:stdio",
        "-d", "guest_errors",

        "-kernel", "kernel_image.bin",

        // Attach the whole disk image as a virtio-blk device (/dev/vda in guest)
        "-drive",  drive_opt,
        "-device", "virtio-blk-pci,drive=drv0",

        // Pass the kernel command line constructed above
        "-append", append,
        NULL
    };

    printf("\n=== Launching QEMU ===\n");
    printf("Kernel cmdline:\n  %s\n\n", append);

    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], (char * const *)argv);
        perror("execvp(qemu-system-x86_64)");
        _exit(1);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFEXITED(status))
        printf("\nQEMU exited with status: %d\n", WEXITSTATUS(status));
    else
        printf("\nQEMU exited abnormally (status=0x%x)\n", status);

    return 0;
}
