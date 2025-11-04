// secondary_bootloader.c
// Secure second-stage bootloader that reads dm-verity metadata and passes to kernel
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

// ---------- dm-verity metadata structures ----------
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
    uint32_t magic;            /* "VLOC" */
    uint32_t version;
    uint64_t meta_off;
    uint32_t meta_len;
    uint64_t sig_off;
    uint32_t sig_len;
    uint8_t  reserved[4064];
} verity_footer_locator;
#pragma pack(pop)

#define VERITY_META_MAGIC  0x56455249  /* "VERI" */
#define VLOC_MAGIC         0x564C4F43  /* "VLOC" */

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
        fclose(f); return 0; 
    }
    if (memcmp(h.signature, "EFI PART", 8) != 0) { 
        fclose(f); return 0; 
    }

    uint32_t count  = le32toh(h.count);
    uint32_t entsz  = le32toh(h.entsz);
    uint64_t ent_lba= le64toh(h.ent_lba);
    if (entsz < 128 || entsz > 1024 || count > 512) { 
        fclose(f); return 0; 
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
            fclose(f); return (int)(i + 1); 
        }
    }
    fclose(f);
    return 0;
}

// ---------- Read dm-verity metadata ----------
static void hex_encode(const uint8_t *src, size_t len, char *dst) {
    static const char hexdig[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[2*i]     = hexdig[(src[i] >> 4) & 0xf];
        dst[2*i + 1] = hexdig[src[i] & 0xf];
    }
    dst[2*len] = '\0';
}

static int read_verity_metadata(const char *img, 
                                char *root_hash_hex, 
                                char *salt_hex,
                                uint64_t *data_blocks,
                                uint64_t *hash_start_sector,
                                uint32_t *data_block_size,
                                uint32_t *hash_block_size) {
    FILE *f = fopen(img, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", img);
        return -1;
    }

    // Get file size
    fseeko(f, 0, SEEK_END);
    off_t size = ftello(f);
    
    // Read last 4KB
    uint8_t tail[4096];
    fseeko(f, size - 4096, SEEK_SET);
    if (fread(tail, 1, 4096, f) != 4096) {
        fprintf(stderr, "ERROR: Cannot read footer\n");
        fclose(f);
        return -1;
    }

    uint32_t magic = le32toh(*(uint32_t*)tail);

    if (magic == VERITY_META_MAGIC) {
        // ATTACHED mode
        verity_metadata_ondisk *meta = (verity_metadata_ondisk*)tail;
        
        *data_blocks = le64toh(meta->data_blocks);
        *hash_start_sector = le64toh(meta->hash_start_sector);
        *data_block_size = le32toh(meta->data_block_size);
        *hash_block_size = le32toh(meta->hash_block_size);
        
        uint32_t salt_size = le32toh(meta->salt_size);
        if (salt_size > 64) salt_size = 64;
        
        hex_encode(meta->root_hash, 64, root_hash_hex);
        hex_encode(meta->salt, salt_size, salt_hex);
        
        printf("Found ATTACHED dm-verity metadata\n");
        
    } else if (magic == VLOC_MAGIC) {
        // DETACHED mode
        verity_footer_locator *loc = (verity_footer_locator*)tail;
        
        uint64_t meta_off = le64toh(loc->meta_off);
        uint32_t meta_len = le32toh(loc->meta_len);
        
        // Read metadata region
        uint8_t meta_buf[256];
        fseeko(f, meta_off, SEEK_SET);
        if (fread(meta_buf, 1, meta_len, f) != meta_len) {
            fprintf(stderr, "ERROR: Cannot read detached metadata\n");
            fclose(f);
            return -1;
        }
        
        verity_metadata_ondisk *meta = (verity_metadata_ondisk*)meta_buf;
        
        *data_blocks = le64toh(meta->data_blocks);
        *hash_start_sector = le64toh(meta->hash_start_sector);
        *data_block_size = le32toh(meta->data_block_size);
        *hash_block_size = le32toh(meta->hash_block_size);
        
        uint32_t salt_size = le32toh(meta->salt_size);
        if (salt_size > 64) salt_size = 64;
        
        hex_encode(meta->root_hash, 64, root_hash_hex);
        hex_encode(meta->salt, salt_size, salt_hex);
        
        printf("Found DETACHED dm-verity metadata\n");
        
    } else {
        fprintf(stderr, "ERROR: Unknown footer magic 0x%08x\n", magic);
        fclose(f);
        return -1;
    }

    fclose(f);
    
    printf("  root_hash: %.64s...\n", root_hash_hex);
    printf("  salt: %s\n", salt_hex);
    printf("  data_blocks: %llu\n", (unsigned long long)*data_blocks);
    printf("  hash_start_sector: %llu\n", (unsigned long long)*hash_start_sector);
    
    return 0;
}

// ---------- QEMU Boot ----------
static int boot_qemu(const char *kernel, const char *rootfs_img,
                    const char *root_hash, const char *salt,
                    uint64_t data_blocks, uint64_t hash_start_sector,
                    uint32_t data_block_size, uint32_t hash_block_size) {

    char drive[256];
    snprintf(drive, sizeof drive,
             "file=%s,format=raw,if=virtio",
             rootfs_img);

    // Build dm-mod.create= parameter
    char dm_create[2048];
    uint64_t num_sectors = (data_blocks * data_block_size) / 512;
    
    snprintf(dm_create, sizeof dm_create,
             "verified_root,,,ro,0 %llu verity 1 253:0 253:0 %u %u %llu %llu sha256 %s %s",
             num_sectors,
             data_block_size,
             hash_block_size,
             data_blocks,
             hash_start_sector,
             root_hash,
             salt);

    char append[4096];
    snprintf(append, sizeof append,
         "console=ttyS0 "
         "dm_verity_autoboot.autoboot_device=/dev/vda "
         "root=/dev/mapper/verified_root ro rootwait",
         dm_create);

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
    printf("   Bootloader (dm-init MODE)         \n");
    printf("=====================================\n");

    printf("Skipping signature verification (DEV MODE).\n");

    // Scan GPT
    int part = gpt_find_rootfs_partition(ROOTFS_IMG);
    if (part > 0) {
        printf("Found GPT partition named 'rootfs' (partition %d).\n", part);
    } else {
        printf("No GPT partition named 'rootfs' found.\n");
    }

    // Read dm-verity metadata
    char root_hash_hex[129], salt_hex[129];
    uint64_t data_blocks, hash_start_sector;
    uint32_t data_block_size, hash_block_size;
    
    printf("\nReading dm-verity metadata from disk...\n");
    if (read_verity_metadata(ROOTFS_IMG, root_hash_hex, salt_hex,
                            &data_blocks, &hash_start_sector,
                            &data_block_size, &hash_block_size) != 0) {
        fprintf(stderr, "FATAL: Cannot read dm-verity metadata\n");
        return 1;
    }

    printf("\nPress ENTER to boot kernel...\n");
    getchar();

    printf("\n=== ABOUT TO LAUNCH QEMU ===\n");
    printf("Kernel: %s\n", KERNEL_IMG);
    printf("Rootfs image (virtio as /dev/vda): %s\n", ROOTFS_IMG);
    printf("dm-init will create /dev/mapper/verified_root at boot\n");
    printf("\nPress ENTER again to continue to QEMU...\n");
    getchar();

    int rc = boot_qemu(KERNEL_IMG, ROOTFS_IMG, root_hash_hex, salt_hex,
                      data_blocks, hash_start_sector,
                      data_block_size, hash_block_size);
    printf("QEMU exited with code %d\n", rc);
    return rc;
}