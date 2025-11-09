// Build: gcc -O2 -Wall -o bootloader bootloader.c

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

    if (!realpath("../build/Binaries/rootfs.img", img_abs)) {
        perror("realpath(rootfs.img)");
        return 1;
    }

    // EXACTLY the same drive option as your working manual test,
    // just with an absolute path substituted.
    snprintf(drive_opt, sizeof(drive_opt),
             "if=none,id=drv0,format=raw,media=disk,file=%s",
             img_abs);

    snprintf(append, sizeof(append),
             "console=ttyS0,115200 "
             "loglevel=7 "
             "dm_verity_autoboot.autoboot_device=/dev/vda "
             "root=/dev/dm-0 rootfstype=ext4 rootwait rootdelay=10");

    printf("================================================\n");
    printf(" SIMPLE BOOTLOADER\n");
    printf(" (Kernel does ALL the work)\n");
    printf("================================================\n\n");

    printf("Using disk image: %s\n", img_abs);
    printf("QEMU -drive: %s\n\n", drive_opt);

    printf("This bootloader ONLY:\n");
    printf("  - Loads kernel and disk image\n");
    printf("  - Passes device path parameter\n\n");

    printf("The kernel module will:\n");
    printf("  1. Wait for /dev/vda to appear\n");
    printf("  2. Read metadata from end of disk\n");
    printf("  3. Verify PKCS7 signature\n");
    printf("  4. Create /dev/dm-0 device\n");
    printf("  5. Kernel mounts /dev/dm-0 as root\n\n");

    printf("Press ENTER to boot...\n");
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

        // ONE argument to -drive, exactly like your working manual command
        "-drive",  drive_opt,
        "-device", "virtio-blk-pci,drive=drv0",

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
