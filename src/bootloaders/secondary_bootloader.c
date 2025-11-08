// secondary_bootloader.c
// Secure second-stage bootloader that (currently) skips dm-verity mapping
// Build: gcc -O2 -Wall -Wextra -o secondary_bootloader secondary_bootloader.c -lcrypto

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>

// ---------- Artifacts ----------
static const char *KERNEL_IMG   = "kernel_image.bin";
static const char *ROOTFS_IMG   = "rootfs.img";

// ---------- dm-verity metadata structures (RETAINED - DO NOT REMOVE) ----------
#pragma pack(push,1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t data_blocks;
    uint64_t hash_start_sector;
    uint32_t data_block_size;
    uint32_t hash_block_size;
    char     hash_algorithm[32];
    uint8_t  root_hash[64];
    uint8_t  salt[64];
    uint32_t salt_size;
    uint32_t pkcs7_size;
    uint8_t  pkcs7_blob[2048];
    uint8_t  reserved[1848];
} verity_metadata_ondisk;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t meta_off;
    uint32_t meta_len;
    uint64_t sig_off;
    uint32_t sig_len;
    uint8_t  reserved[4064];
} verity_footer_locator;
#pragma pack(pop)

// (REMOVED GPT + metadata parsing - but structs are preserved.)

// ---------- QEMU Boot WITHOUT dm-verity device mapper ----------
static int boot_qemu(const char *kernel, const char *rootfs_img) {

    char drive[256];
    snprintf(drive, sizeof drive,
             "file=%s,format=raw,if=virtio",
             rootfs_img);

    // No dm-verity → normal direct root mount
    const char *append =
        "console=ttyS0 "
        "root=/dev/vda1 ro rootwait";

    printf("\n=== Kernel command line: ===\n%s\n\n", append);

    const char *argv[] = {
        "qemu-system-x86_64",
        "-m","1024",
        "-kernel",kernel,
        "-drive",drive,
        "-append",append,
        "-nographic",
        NULL
    };

    pid_t pid=fork();
    if(pid==0){ execvp(argv[0],(char*const*)argv); _exit(127); }
    int st; waitpid(pid,&st,0);
    return WIFEXITED(st)?WEXITSTATUS(st):1;
}

// ---------- Main ----------
int main(void) {
    printf("=====================================\n");
    printf("   Bootloader (SIGNING STILL PRESENT)\n");
    printf("   dm-verity MAPPING REMOVED         \n");
    printf("=====================================\n");

    printf("Skipping signature verification (DEV MODE, signing fields kept).\n");
    printf("Skipping GPT scan.\n");
    printf("Skipping dm-verity footer parsing.\n");
    printf("Skipping dmsetup verification mapping.\n");

    printf("\nPress ENTER to boot kernel...\n");
    getchar();

    printf("\n=== ABOUT TO LAUNCH QEMU ===\n");
    printf("Kernel: %s\n", KERNEL_IMG);
    printf("Rootfs image (virtio as /dev/vda): %s\n", ROOTFS_IMG);
    printf("Direct boot WITHOUT dm-verity mapper\n");
    printf("\nPress ENTER again to continue to QEMU...\n");
    getchar();

    int rc = boot_qemu(KERNEL_IMG, ROOTFS_IMG);
    printf("QEMU exited with code %d\n", rc);
    return rc;
}
