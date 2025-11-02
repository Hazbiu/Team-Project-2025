// secondary_bootloader.c
// Secure second-stage bootloader (DEV MODE, no signature, no initramfs).
// Build: gcc -O2 -Wall -Wextra -o secondary_bootloader secondary_bootloader.c -lcrypto

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

// ---------- Artifacts ----------
static const char *KERNEL_IMG   = "/home/tomislav/Team-Project-2025/src/bootloaders/kernel_image.bin";
static const char *ROOTFS_IMG   = "/home/tomislav/Team-Project-2025/src/bootloaders/rootfs.img";
static const char *VERITY_META  = "/home/tomislav/Team-Project-2025/src/bootloaders/rootfs.verity.meta"; // optional

// ---------- GPT RootFS Detection ----------
#pragma pack(push,1)
typedef struct {
    char signature[8];
    uint32_t rev, header_size, hdr_crc, res;
    uint64_t cur, bak, first, last;
    uint8_t guid[16];
    uint64_t ent_lba;
    uint32_t count, entsz, arr_crc;
} GPTHeader;

typedef struct {
    uint8_t type[16], id[16];
    uint64_t first, last, attrs;
    uint16_t name[36];
} GPTEntry;
#pragma pack(pop)

static int read_exact(FILE *f, void *buf, size_t n, uint64_t off) {
    fseeko(f, off, SEEK_SET);
    return fread(buf, 1, n, f) == n;
}

#include <endian.h>    // for le32toh/le64toh

static int gpt_find_rootfs_partition(const char *img) {
    FILE *f = fopen(img, "rb");
    if (!f) return 0;

    GPTHeader h;
    if (fseeko(f, 512, SEEK_SET) || fread(&h, 1, sizeof h, f) != sizeof h) { fclose(f); return 0; }
    if (memcmp(h.signature, "EFI PART", 8) != 0) { fclose(f); return 0; }

    uint32_t count  = le32toh(h.count);
    uint32_t entsz  = le32toh(h.entsz);
    uint64_t ent_lba= le64toh(h.ent_lba);
    if (entsz < 128 || entsz > 1024 || count > 512) { fclose(f); return 0; } // sanity

    // (Optional) validate header/array CRCs here

    // Read entries one by one (handle entsz >= sizeof(GPTEntry))
    uint8_t buf[1024];
    for (uint32_t i = 0; i < count && i < 128; ++i) {
        off_t off = (off_t)ent_lba * 512 + (off_t)i * entsz;
        if (fseeko(f, off, SEEK_SET) || fread(buf, 1, entsz, f) != entsz) break;

        const GPTEntry *e = (const GPTEntry*)buf;
        uint64_t first = le64toh(e->first), last = le64toh(e->last);
        if (!first && !last) continue;

        // Convert UTF-16LE name to ASCII for "rootfs"
        char name[37] = {0};
        for (int k = 0; k < 36; ++k) {
            uint16_t ch = ((const uint16_t*)e->name)[k];
            ch = le16toh(ch);
            if (!ch) break;
            name[k] = (ch < 0x80) ? (char)ch : '?';
        }
        if (strcmp(name, "rootfs") == 0) { fclose(f); return (int)(i + 1); }
    }
    fclose(f);
    return 0;
}

// ---------- QEMU Boot ----------
static int boot_qemu(const char *kernel, const char *rootfs_img, const char *root_dev) {

    char drive[256];
    snprintf(drive, sizeof drive,
             "file=%s,format=raw,if=virtio",
             rootfs_img);

    char append[512];
    snprintf(append, sizeof append,
            "console=ttyS0 dm_verity_autoboot.autoboot_device=/dev/vda root=/dev/mapper/verified_root ro rootwait",
            root_dev);



    printf("DEBUG: Kernel command line will be:\n  %s\n", append);

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
    printf("   Bootloader (NO INITRAMFS MODE)    \n");
    printf("=====================================\n");

    printf("Skipping signature verification (DEV MODE).\n");

    const char *root_dev = "/dev/vda";
    int part = gpt_find_rootfs_partition(ROOTFS_IMG);
    if (part > 0) {
        static char devbuf[32];
        snprintf(devbuf, sizeof devbuf, "/dev/vda%d", part);
        root_dev = devbuf;
        printf("Detected GPT rootfs partition: %s\n", root_dev);
    } else {
        printf("No GPT partition named 'rootfs' found. Using raw image as /dev/vda.\n");
    }

    printf("Press ENTER to boot kernel...\n");
    getchar();

    int rc = boot_qemu(KERNEL_IMG, ROOTFS_IMG, root_dev);
    printf("QEMU exited with code %d\n", rc);
    return rc;
}
