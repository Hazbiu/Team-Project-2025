// secondary_bootloader.c
// Secure second-stage bootloader: verify all artifacts, detect rootfs, boot kernel.
// Build: gcc -O2 -Wall -Wextra -o secondary_bootloader secondary_bootloader.c -lcrypto

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

// ---------- Config: artifact paths (keep in sync with build.sh) ----------
static const char *PUBKEY_PATH  = "bl_public.pem";
static const char *KERNEL_IMG   = "kernel_image.bin";
static const char *KERNEL_SIG   = "kernel_image.sig";
static const char *INITRD_IMG   = "initramfs.cpio.gz";    // build.sh outputs this name
static const char *INITRD_SIG   = "rootfs.cpio.gz.sig";   // signature for initramfs
static const char *ROOTFS_IMG   = "rootfs.img";
static const char *ROOTFS_SIG   = "rootfs.img.sig";
static const char *VERITY_META  = "rootfs.verity.meta";
static const char *VERITY_SIG   = "rootfs.verity.meta.sig";

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf,1,2)));
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static int file_exists(const char *p) {
    struct stat st; return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

// ---------- Signature verification (streamed) ----------
static int verify_signature(const char *image, const char *sig, const char *pubkey_path) {
    FILE *imgf = fopen(image, "rb");
    if (!imgf) { perror(image); return 0; }

    FILE *sigf = fopen(sig, "rb");
    if (!sigf) { perror(sig); fclose(imgf); return 0; }

    if (fseek(sigf, 0, SEEK_END) != 0) { perror("fseek(sig)"); fclose(imgf); fclose(sigf); return 0; }
    long L = ftell(sigf);
    if (L <= 0 || L > (64 * 1024)) { fprintf(stderr, "Bad sig size for %s: %ld\n", sig, L); fclose(imgf); fclose(sigf); return 0; }
    rewind(sigf);

    unsigned char *sig_buf = (unsigned char*)malloc((size_t)L);
    if (!sig_buf) { perror("malloc(sig_buf)"); fclose(imgf); fclose(sigf); return 0; }
    size_t r = fread(sig_buf, 1, (size_t)L, sigf);
    fclose(sigf);
    if (r != (size_t)L) { fprintf(stderr, "Short read on %s\n", sig); free(sig_buf); fclose(imgf); return 0; }

    FILE *pubf = fopen(pubkey_path, "r");
    if (!pubf) { perror(pubkey_path); free(sig_buf); fclose(imgf); return 0; }
    EVP_PKEY *pkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
    fclose(pubf);
    if (!pkey) {
        fprintf(stderr, "Failed to parse public key: %s\n", pubkey_path);
        ERR_print_errors_fp(stderr);
        free(sig_buf); fclose(imgf); return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { perror("EVP_MD_CTX_new"); EVP_PKEY_free(pkey); free(sig_buf); fclose(imgf); return 0; }

    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        goto out;
    }
    // Prefer RSA-PSS if key type is RSA
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) != 1) {
            fprintf(stderr, "Warning: couldn't enforce RSA-PSS (using key default).\n");
            ERR_print_errors_fp(stderr);
        }
    }

    unsigned char buf[4096];
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, imgf);
        if (n > 0) {
            if (EVP_DigestVerifyUpdate(ctx, buf, n) != 1) {
                ERR_print_errors_fp(stderr);
                goto out;
            }
        }
        if (n < sizeof buf) {
            if (ferror(imgf)) { perror("fread(image)"); goto out; }
            break; // EOF
        }
    }

    if (EVP_DigestVerifyFinal(ctx, sig_buf, (size_t)L) == 1) ok = 1;
    else {
        fprintf(stderr, "Signature verification failed for %s\n", image);
        ERR_print_errors_fp(stderr);
    }

out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sig_buf);
    fclose(imgf);
    return ok;
}

// ---------- Tiny GPT reader: find partition named "rootfs" ----------
#pragma pack(push,1)
typedef struct {
    char     signature[8];    // "EFI PART"
    uint32_t revision, header_size, header_crc32, reserved;
    uint64_t current_lba, backup_lba, first_usable_lba, last_usable_lba;
    uint8_t  disk_guid[16];
    uint64_t part_entry_lba;
    uint32_t num_part_entries, size_part_entry, part_array_crc32;
} GPTHeader;

typedef struct {
    uint8_t  type_guid[16], uniq_guid[16];
    uint64_t first_lba, last_lba, attrs;
    uint16_t name_utf16[36]; // UTF-16LE
} GPTEntry;
#pragma pack(pop)

static int read_exact(FILE *f, void *buf, size_t n, uint64_t off) {
    if (fseeko(f, (off_t)off, SEEK_SET) != 0) return 0;
    return fread(buf, 1, n, f) == n;
}

// returns 1-based partition index with GPT name "rootfs", else 0
static int gpt_find_rootfs_partition(const char *img_path) {
    FILE *f = fopen(img_path, "rb");
    if (!f) { perror(img_path); return 0; }

    // read GPT header at LBA1 (offset 512)
    GPTHeader hdr;
    if (!read_exact(f, &hdr, sizeof hdr, 512) || memcmp(hdr.signature, "EFI PART", 8) != 0) {
        fclose(f);
        return 0;
    }
    if (hdr.size_part_entry < sizeof(GPTEntry) || hdr.num_part_entries > 512) {
        fclose(f);
        return 0;
    }

    const uint64_t entry_off = hdr.part_entry_lba * 512ULL;
    for (uint32_t i = 0; i < hdr.num_part_entries && i < 128; ++i) {
        GPTEntry e;
        if (!read_exact(f, &e, sizeof e, entry_off + (uint64_t)i * hdr.size_part_entry)) break;
        if (e.first_lba == 0 && e.last_lba == 0) continue; // unused

        // Convert UTF-16LE name → ASCII (lossy)
        char name[73] = {0};
        for (int k = 0; k < 36; ++k) {
            uint16_t ch = e.name_utf16[k];
            if (!ch) break;
            name[k] = (char)(ch & 0xFF);
        }
        if (strcmp(name, "rootfs") == 0) {
            fclose(f);
            return (int)(i + 1); // 1-based index
        }
    }

    fclose(f);
    return 0;
}

// ---------- Metadata parser (roothash, salt, offset) ----------
typedef struct {
    char roothash[129];
    char salt[129];
    unsigned long long offset;
} VerityMeta;

static int parse_verity_metadata(const char *path, VerityMeta *out) {
    FILE *f = fopen(path, "r"); if (!f) return 0;
    char key[64], val[256];
    while (fscanf(f, "%63[^=]=%255s\n", key, val) == 2) {
        if (strcmp(key, "roothash") == 0)
            strncpy(out->roothash, val, sizeof(out->roothash)-1);
        else if (strcmp(key, "salt") == 0)
            strncpy(out->salt, val, sizeof(out->salt)-1);
        else if (strcmp(key, "offset") == 0)
            out->offset = strtoull(val, NULL, 10);
    }
    fclose(f);
    return out->roothash[0] != 0;
}

// ---------- QEMU launcher (no shell) ----------
static int boot_qemu(const char *kernel, const char *initrd, const char *rootfs_img,
                     const char *root_dev, const VerityMeta *meta) {
    // Build -drive arg
    char drive[256];
    snprintf(drive, sizeof drive, "file=%s,format=raw,if=virtio,readonly=on", rootfs_img);

    // Build -append cmdline
    char append[768];
    if (meta && meta->roothash[0]) {
        snprintf(append, sizeof append,
                 "console=ttyS0 rdinit=/init root=%s ro verity=1 verity.hash_alg=sha256 roothash=%s verity.salt=%s verity.hashstart=%llu",
                 root_dev, meta->roothash, meta->salt, meta->offset);
    } else {
        snprintf(append, sizeof append,
                 "console=ttyS0 rdinit=/init root=%s ro verity=1",
                 root_dev);
    }

    const char *argv[32];
    int i = 0;
    argv[i++] = "qemu-system-x86_64";
    argv[i++] = "-m";      argv[i++] = "1024";
    argv[i++] = "-kernel"; argv[i++] = kernel;
    argv[i++] = "-initrd"; argv[i++] = initrd;
    argv[i++] = "-drive";  argv[i++] = drive;
    argv[i++] = "-append"; argv[i++] = append;
    argv[i++] = "-nographic";
    argv[i++] = NULL;

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        execvp(argv[0], (char * const *)argv);
        perror("execvp");
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

int main(void) {
    printf("=====================================\n");
    printf("   Secure Secondary Bootloader v2    \n");
    printf("=====================================\n");

    // OpenSSL init (best-effort; modern OpenSSL is auto-initializing)
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1) Verify artifacts
    printf("Verifying artifacts with %s ...\n", PUBKEY_PATH);
    int ok = 1;

    ok &= verify_signature(KERNEL_IMG, KERNEL_SIG, PUBKEY_PATH);
    printf("  kernel:   %s\n", ok ? "OK" : "FAIL");

    ok &= verify_signature(INITRD_IMG, INITRD_SIG, PUBKEY_PATH);
    printf("  initrd:   %s\n", ok ? "OK" : "FAIL");

    ok &= verify_signature(ROOTFS_IMG, ROOTFS_SIG, PUBKEY_PATH);
    printf("  rootfs:   %s\n", ok ? "OK" : "FAIL");

    ok &= verify_signature(VERITY_META, VERITY_SIG, PUBKEY_PATH);
    printf("  verity:   %s\n", ok ? "OK" : "FAIL");

    if (!ok) die("Verification FAILED. Aborting.");

    // 2) Detect rootfs partition by GPT label "rootfs"
    const char *root_dev = "/dev/vda"; // fallback if image is an unpartitioned FS
    int part = gpt_find_rootfs_partition(ROOTFS_IMG);
    if (part > 0) {
        static char devbuf[32];
        snprintf(devbuf, sizeof devbuf, "/dev/vda%d", part);
        root_dev = devbuf;
        printf("Detected rootfs partition: %s\n", root_dev);
    } else {
        printf("No GPT 'rootfs' label detected; using %s\n", root_dev);
    }

    // 3) Parse metadata (roothash, salt, offset)
    VerityMeta meta = {0};
    if (parse_verity_metadata(VERITY_META, &meta)) {
        printf("Found metadata:\n");
        printf("  roothash: %s\n", meta.roothash);
        printf("  salt:     %s\n", meta.salt);
        printf("  offset:   %llu\n", meta.offset);
    } else {
        printf("No metadata found; proceeding without it.\n");
    }

    // 4) Boot
    printf("\nAll artifacts verified. Ready to boot.\n");
    printf("Press ENTER to continue to kernel boot...\n");
    fflush(stdout);
    (void)getchar();

    int rc = boot_qemu(KERNEL_IMG, INITRD_IMG, ROOTFS_IMG, root_dev, &meta);
    printf("QEMU exited with status %d\n", rc);

    // Cleanup (optional with modern OpenSSL)
    EVP_cleanup();
    ERR_free_strings();
    return rc;
}
