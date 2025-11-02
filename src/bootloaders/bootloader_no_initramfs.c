#include <stdio.h>
#include <stdlib.h>

#define KERNEL_IMG   "/home/keti/Team-Project-2025/linux/kernel_image.bin"
#define INITRAMFS    "/home/keti/Team-Project-2025/src/Binaries/initramfs.cpio.gz"
#define ROOTFS_IMG   "/home/keti/Team-Project-2025/rootfs.img"

int main(void) {
    printf("=====================================\n");
    printf("   Bootloader (Initramfs Boot Mode)\n");
    printf("=====================================\n");

    printf("Press ENTER to boot...\n");
    getchar();

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "qemu-system-x86_64 "
        "-m 2G "
        "-kernel %s "
        "-initrd %s "
        "-drive file=%s,format=raw "
        "-append \"root=/dev/sda rw console=ttyS0 systemd.unified_cgroup_hierarchy=1\" "
        "-nographic",
        KERNEL_IMG, INITRAMFS, ROOTFS_IMG
    );

    printf("Running:\n%s\n\n", cmd);
    return system(cmd);
}
