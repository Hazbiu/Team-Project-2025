// secondary_bootloader.c
// Secure second-stage bootloader (NO INITRAMFS MODE, plain ext4 rootfs)
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
static const char *ROOTFS_IMG   = "../build/Binaries/rootfs.img";
static const char *ROOT_HASH    = "../build/Binaries/metadata/root.hash";


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

static int gpt_find_rootfs_partition(const char *img) {
    FILE *f = fopen(img, "rb");
    if (!f) return 0;

    GPTHeader h;
    if (fseeko(f, 512, SEEK_SET) || fread(&h, 1, sizeof h, f) != sizeof h) {
        fclose(f);
        return 0;
    }
    if (memcmp(h.signature, "EFI PART", 8) != 0) {
        fclose(f);
        return 0;
    }

    uint32_t count  = le32toh(h.count);
    uint32_t entsz  = le32toh(h.entsz);
    uint64_t ent_lba= le64toh(h.ent_lba);
    if (entsz < 128 || entsz > 1024 || count > 512) {
        fclose(f);
        return 0;
    }

    uint8_t buf[1024];
    for (uint32_t i = 0; i < count && i < 128; ++i) {
        off_t off = (off_t)ent_lba * 512 + (off_t)i * entsz;
        if (fseeko(f, off, SEEK_SET) || fread(buf, 1, entsz, f) != entsz) break;

        const GPTEntry *e = (const GPTEntry*)buf;
        uint64_t first = le64toh(e->first), last = le64toh(e->last);
        if (!first && !last) continue;

        char name[37] = {0};
        for (int k = 0; k < 36; ++k) {
            uint16_t ch = ((const uint16_t*)e->name)[k];
            ch = le16toh(ch);
            if (!ch) break;
            name[k] = (ch < 0x80) ? (char)ch : '?';
        }

        if (strcmp(name, "rootfs") == 0) {
            fclose(f);
            return (int)(i + 1);
        }
    }
    fclose(f);
    return 0;
}


// ---------- Helpers ----------
static void read_root_hash(char *buf, size_t sz) {
    FILE *f = fopen(ROOT_HASH, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", ROOT_HASH);
        exit(1);
    }
    if (!fgets(buf, sz, f)) {
        fprintf(stderr, "ERROR: Cannot read root hash\n");
        fclose(f);
        exit(1);
    }
    fclose(f);
    buf[strcspn(buf, "\n")] = 0; // strip newline
}


// ---------- QEMU Boot ----------
static int boot_qemu(const char *kernel, const char *rootfs_img, const char *root_dev, const char *root_hash) {
    char drive[256];
    snprintf(drive, sizeof drive,
             "file=%s,format=raw,if=virtio", rootfs_img);

    // ✅ Plain ext4 rootfs boot (NO dm-verity)
    char append[1024];
    snprintf(append, sizeof append,
        "console=ttyS0 root=%s rw rootfstype=ext4 init=/init",
        root_dev
    );

    printf("\n[BOOT CMDLINE]\n%s\n\n", append);

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
    if (pid == 0) { execvp(argv[0], (char *const *)argv); _exit(127); }
    int st; waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}



// ---------- Main ----------
int main(void) {
    printf("=====================================\n");
    printf("   Bootloader (NO INITRAMFS MODE)\n");
    printf("=====================================\n");

    char root_hash[128] = {0};
    read_root_hash(root_hash, sizeof(root_hash));

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

    printf("Root hash: %s\n", root_hash);
    printf("Press ENTER to boot kernel...\n");
    getchar();

    int rc = boot_qemu(KERNEL_IMG, ROOTFS_IMG, root_dev, root_hash);
    printf("QEMU exited with code %d\n", rc);
    return rc;
}
