// Build: gcc -O2 -Wall -Wextra -o secondary_bootloader secondary_bootloader.c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <ctype.h>

/*
 * This bootloader does 3 things:
 *   1. Reads/verifies the dm-verity metadata header structure from the image
 *      (for logging / sanity; not enforcing trust here).
 *   2. Builds the correct dm-mod.create= line for dm-init.
 *   3. Launches QEMU with that kernel cmdline.
 *
 * The rootfs layout we assume (what generate_verity.sh produced):
 *   - Single GPT partition "rootfs" (vda1 in the guest)
 *   - ext4 data blocks [0 .. BLOCK_COUNT-1]
 *   - dm-verity Merkle tree immediately after that, same partition
 *   - No verity superblock
 *   - Detached 196-byte header + PKCS7 signature + locator at very end of disk
 *
 * The dm target must use:
 *   data_dev = /dev/vda1
 *   hash_dev = /dev/vda1
 *
 *   <num_data_blocks>      = BLOCK_COUNT
 *   <hash_start_block>     = BLOCK_COUNT
 *
 * And the mapping is exposed as /dev/dm-0 (forced minor 0).
 *
 * Your kernel module:
 *   - Runs after dm-init (late_initcall)
 *   - Reads locator/footer, verifies signature authenticity
 *   - If verification fails: panic("untrusted rootfs")
 *   - If it passes: we keep going and mount /dev/dm-0
 */

static const char *KERNEL_IMG   = "kernel_image.bin";
static const char *ROOTFS_IMG   = "rootfs.img";

/* --- on-disk dm-verity metadata header (first 196 bytes of VERI) --- */
#pragma pack(push,1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t data_blocks;        /* number of filesystem data blocks */
    uint64_t hash_start_sector;  /* 512-byte sectors from start of partition (info / logging) */
    uint32_t data_block_size;    /* bytes */
    uint32_t hash_block_size;    /* bytes */
    char     hash_algorithm[32]; /* "sha256" etc (not guaranteed to be NUL, we'll sanitize) */
    uint8_t  root_hash[64];      /* up to sha512 */
    uint8_t  salt[64];
    uint32_t salt_size;
    /* then would come pkcs7_size + pkcs7_blob..., but we don't read past 196 here */
} verity_header_196;

/* Locator footer ("VLOC") at last 4K of disk */
typedef struct {
    uint32_t magic;     /* "VLOC" */
    uint32_t version;
    uint64_t meta_off;  /* byte offset of 196-byte header in disk image */
    uint32_t meta_len;  /* should be 196 */
    uint64_t sig_off;   /* byte offset of PKCS7 signature blob */
    uint32_t sig_len;   /* length of PKCS7 */
    uint8_t  reserved[4096 - 32];
} verity_footer_locator;
#pragma pack(pop)

#define VERITY_META_MAGIC  0x56455249  /* "VERI" */
#define VLOC_MAGIC         0x564C4F43  /* "VLOC" */

static void hex_encode_n(const uint8_t *src, size_t len, char *dst) {
    static const char hexdig[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[2*i]     = hexdig[(src[i] >> 4) & 0xf];
        dst[2*i + 1] = hexdig[src[i] & 0xf];
    }
    dst[2*len] = '\0';
}

static void to_lower_str(char *s) {
    for (; *s; ++s)
        *s = (char)tolower((unsigned char)*s);
}

/*
 * Read the locator (last 4K of disk), then read the 196-byte metadata header
 * it points to. This mirrors what your kernel module does: it first grabs
 * the locator footer ("VLOC"), then uses that to find meta + sig.
 *
 * We only consume the header fields we need to build dm-mod.create.
 */
static int read_verity_header_from_image(const char *img,
                                         uint64_t *data_blocks,
                                         uint32_t *data_block_size,
                                         uint32_t *hash_block_size,
                                         char     *algo_out,       /* out: algo string */
                                         char     *root_hash_hex,  /* out: hex digest */
                                         char     *salt_hex)       /* out: hex salt or "-" */
{
    FILE *f = fopen(img, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: cannot open %s: %s\n", img, strerror(errno));
        return -1;
    }

    /* Find image size */
    if (fseeko(f, 0, SEEK_END) != 0) {
        fclose(f);
        fprintf(stderr, "ERROR: ftello fail\n");
        return -1;
    }
    off_t disk_size = ftello(f);
    if (disk_size < 4096) {
        fclose(f);
        fprintf(stderr, "ERROR: image too small\n");
        return -1;
    }

    /* Read last 4K = locator */
    off_t locator_off = disk_size - 4096;
    if (fseeko(f, locator_off, SEEK_SET) != 0) {
        fclose(f);
        fprintf(stderr, "ERROR: seek locator failed\n");
        return -1;
    }

    verity_footer_locator loc;
    if (fread(&loc, 1, sizeof(loc), f) != sizeof(loc)) {
        fclose(f);
        fprintf(stderr, "ERROR: read locator failed\n");
        return -1;
    }

    if (le32toh(loc.magic) != VLOC_MAGIC) {
        fclose(f);
        fprintf(stderr, "ERROR: locator magic mismatch (0x%08x)\n",
                le32toh(loc.magic));
        return -1;
    }
    if (le32toh(loc.version) != 1) {
        fclose(f);
        fprintf(stderr, "ERROR: unsupported locator version %u\n",
                le32toh(loc.version));
        return -1;
    }

    uint64_t meta_off = le64toh(loc.meta_off);
    uint32_t meta_len = le32toh(loc.meta_len);

    if (meta_len < sizeof(verity_header_196)) {
        fclose(f);
        fprintf(stderr, "ERROR: meta_len %u too small\n", meta_len);
        return -1;
    }

    /* Read the 196-byte verity header */
    if (fseeko(f, (off_t)meta_off, SEEK_SET) != 0) {
        fclose(f);
        fprintf(stderr, "ERROR: seek meta_off failed\n");
        return -1;
    }

    verity_header_196 vh;
    if (fread(&vh, 1, sizeof(vh), f) != sizeof(vh)) {
        fclose(f);
        fprintf(stderr, "ERROR: read verity header failed\n");
        return -1;
    }

    if (le32toh(vh.magic) != VERITY_META_MAGIC) {
        fclose(f);
        fprintf(stderr, "ERROR: VERI magic mismatch (0x%08x)\n",
                le32toh(vh.magic));
        return -1;
    }

    /* Pull out fields we care about */
    *data_blocks     = le64toh(vh.data_blocks);
    *data_block_size = le32toh(vh.data_block_size);
    *hash_block_size = le32toh(vh.hash_block_size);

    /* hash_algorithm[32], sanitize to printable lowercase and NUL-term */
    char algo_local[33];
    memset(algo_local, 0, sizeof(algo_local));
    memcpy(algo_local, vh.hash_algorithm, 32);
    for (int i = 0; i < 32; i++) {
        unsigned char c = algo_local[i];
        if (!c) break;
        if (c < 32 || c > 126) { algo_local[i] = 0; break; }
    }
    to_lower_str(algo_local);
    strncpy(algo_out, algo_local, 32);
    algo_out[32] = 0;

    /* root_hash -> hex, but we don't know digest length from header directly.
     * We assume sha256 (32 bytes) because that's what generate_verity.sh forces.
     * If you switch to sha512 later, update this to 64.
     */
    size_t digest_len = 32; /* sha256 */
    hex_encode_n(vh.root_hash, digest_len, root_hash_hex);

    /* salt_hex -> hex string */
    uint32_t salt_size = le32toh(vh.salt_size);
    if (salt_size > 64) salt_size = 64;
    if (salt_size == 0) {
        salt_hex[0] = '-';
        salt_hex[1] = 0;
    } else {
        char *p = salt_hex;
        for (uint32_t i = 0; i < salt_size; i++) {
            sprintf(p, "%02x", vh.salt[i]);
            p += 2;
        }
        *p = 0;
    }

    /* Log (purely informational / debugging output) */
    printf("=== Parsed dm-verity header ===\n");
    printf("  data_blocks        = %llu\n",
           (unsigned long long)*data_blocks);
    printf("  data_block_size    = %u\n", *data_block_size);
    printf("  hash_block_size    = %u\n", *hash_block_size);
    printf("  algo               = %s\n", algo_out);
    printf("  root_hash          = %.64s...\n", root_hash_hex);
    printf("  salt_hex           = %s\n", salt_hex);
    printf("  hash_start_sector  = %llu (info only)\n",
           (unsigned long long)le64toh(vh.hash_start_sector));

    fclose(f);
    return 0;
}

/*
 * Launch QEMU:
 *   - Build dm-mod.create="..." so dm-init creates /dev/dm-0.
 *   - root=/dev/dm-0 so kernel mounts verity-protected FS as root.
 *   - Pass dm_verity_autoboot.autoboot_device=/dev/vda so your kernel module
 *     finds the disk and verifies the PKCS7 signature after dm-init.
 */
static int boot_qemu(const char *kernel,
                     const char *rootfs_img,
                     uint64_t data_blocks,
                     uint32_t data_block_size,
                     uint32_t hash_block_size,
                     const char *algo,
                     const char *root_hash_hex,
                     const char *salt_hex)
{
    /* Sanity: calculate mapping length in 512-byte sectors.
     * num_sectors = (data_blocks * data_block_size) / 512.
     * This must be integer or dm will complain.
     */
    uint64_t bytes_total = data_blocks * (uint64_t)data_block_size;
    if (bytes_total % 512ULL) {
        fprintf(stderr,
            "FATAL: data_blocks*data_block_size not 512B-aligned (%llu bytes)\n",
            (unsigned long long)bytes_total);
        return 1;
    }
    uint64_t num_sectors = bytes_total / 512ULL;

    /* In our layout the Merkle tree starts immediately after the data area,
     * and we used --no-superblock and --hash-offset=<DATA_SIZE>.
     * dm-verity wants <hash_start_block> in units of hash_block_size.
     * Because hash starts right after data and data_block_size == hash_block_size,
     * <hash_start_block> = data_blocks.
     */
    uint64_t hash_start_block = data_blocks;

    /* Build dm-mod.create= argument.
     *
     * dm-mod.create format:
     *   <name>,<uuid>,<minor>,<flags>,<table...>
     *
     * table:
     *   0 <num_sectors> verity 1 <data_dev> <hash_dev>
     *                   <data_bs> <hash_bs>
     *                   <num_data_blocks> <hash_start_block>
     *                   <algo> <root_digest_hex> <salt_hex_or_dash>
     *
     * We pin minor=0 so the device appears as /dev/dm-0 predictably.
     *
     * Both data_dev and hash_dev are /dev/vda1.
     */
    const char *data_dev = "/dev/vda1";
    const char *hash_dev = "/dev/vda1";

    char dm_create[2048];
    snprintf(dm_create, sizeof dm_create,
        "verified_root,,0,ro,"
        "0 %llu verity 1 %s %s %u %u %llu %llu %s %s %s",
        (unsigned long long)num_sectors,
        data_dev, hash_dev,
        data_block_size, hash_block_size,
        (unsigned long long)data_blocks,
        (unsigned long long)hash_start_block,
        algo,
        root_hash_hex,
        (salt_hex && salt_hex[0]) ? salt_hex : "-");

    /* Print it so we can see exactly what kernel will get */
    printf("\n=== dm-mod.create argument ===\n%s\n\n", dm_create);

    /* Now assemble kernel cmdline.
     *
     * dm-init parses dm-mod.create and creates /dev/dm-0.
     * We then say root=/dev/dm-0 so kernel mounts that.
     * Your module will later verify the PKCS7 and panic if bad.
     */
    char append[4096];
    snprintf(append, sizeof append,
        "console=ttyS0,115200 "
        "loglevel=7 "
        "initcall_debug "
        "rootfstype=ext4 "
        // "dm-mod.create=\"%s\" "
        "dm_verity_autoboot.autoboot_device=/dev/vda "
        "root=/dev/dm-0 ro rootwait",
        dm_create);

    printf("=== Kernel command line ===\n%s\n\n", append);

    /* Build QEMU argv */
    char drive[256];
    snprintf(drive, sizeof drive,
             "file=%s,format=raw,if=virtio", rootfs_img);

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
    printf("   secondary_bootloader (dm-init mode)\n");
    printf("=====================================\n");

    /* Pull verity header from disk image so we know:
     *   - data_blocks
     *   - block sizes
     *   - algo / root hash / salt (for dm table)
     */
    uint64_t data_blocks = 0;
    uint32_t data_bs = 0;
    uint32_t hash_bs = 0;
    char algo[33] = {0};
    char root_hash_hex[129] = {0}; /* big enough for sha512 if needed */
    char salt_hex[129] = {0};

    if (read_verity_header_from_image(
            ROOTFS_IMG,
            &data_blocks,
            &data_bs,
            &hash_bs,
            algo,
            root_hash_hex,
            salt_hex) != 0) {
        fprintf(stderr, "FATAL: could not parse verity header from %s\n",
                ROOTFS_IMG);
        return 1;
    }

    printf("\nPress ENTER to boot kernel...\n");
    getchar();

    printf("\n=== Launching QEMU ===\n");
    printf("Kernel image : %s\n", KERNEL_IMG);
    printf("Rootfs image : %s (as virtio /dev/vda)\n", ROOTFS_IMG);
    printf("dm-init will create /dev/dm-0 before mount\n");
    printf("Your kernel module will verify signature and panic if untrusted\n\n");

    int rc = boot_qemu(
        KERNEL_IMG,
        ROOTFS_IMG,
        data_blocks,
        data_bs,
        hash_bs,
        algo,
        root_hash_hex,
        salt_hex
    );

    printf("QEMU exited with code %d\n", rc);
    return rc;
}
