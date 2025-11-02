#include <stdio.h>
#include <stdlib.h>

#define KERNEL_IMG   "../bootloaders/kernel_image.bin"
#define INITRAMFS    "../Binaries/initramfs.cpio.gz"
#define ROOTFS_IMG   "../rootfs.img"

int main(void) {
    printf("=====================================\n");
    printf("         Automated QEMU Boot Tool    \n");
    printf("=====================================\n");
    printf("Kernel   : %s\n", KERNEL_IMG);
    printf("Initramfs: %s\n", INITRAMFS);
    printf("Rootfs   : %s\n", ROOTFS_IMG);
    printf("-------------------------------------\n");
    printf("Press ENTER to boot...\n");
    getchar();

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "qemu-system-x86_64 "
        "-m 2G -smp 2 "
        "-kernel %s "
        "-initrd %s "
        "-drive file=%s,format=raw "
        "-append \"root=/dev/sda1 rw console=ttyS0\" "
        "-nic user,model=virtio-net-pci "
        "-nographic",
        KERNEL_IMG, INITRAMFS, ROOTFS_IMG
    );

    printf("\nRunning QEMU:\n%s\n\n", cmd);
    return system(cmd);
}
