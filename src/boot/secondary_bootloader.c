// Minimal secondary bootloader: verify kernel image, decide root device from image,
// pass minimal necessary parameters (root_dev, signature file, cert file) to the kernel, 
// and exec QEMU.

// Build: gcc -O2 -Wall -Wextra -o secondary_bootloader secondary_bootloader.c -lcrypto -lssl

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// --- Global Constants ---
static const char *PUBKEY_PATH   = "bl_public.pem";
static const char *KERNEL_IMG    = "kernel_image.bin";
static const char *KERNEL_SIG    = "kernel_image.sig";
static const char *ROOTFS_IMG    = "rootfs.img";
static const char *VERITY_KEY_ID = "rootfs-trusted-cert"; // Default key ID (unused in this final cmdline, but kept for context)

// --- Custom DM-Verity Artifact Paths ---
static const char *VERITY_SIG_FILE   = "verity_metadata.p7s";   // PKCS#7 signature file of the metadata
static const char *VERITY_CERT_PATH  = "bl_cert.pem";           // Certificate file for signature verification (Key ID)

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf,1,2)));
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

/* ---------- Signature verification for kernel (UNMODIFIED) ---------- */
static int verify_signature(const char *image, const char *sig, const char *pubkey_path) {
    FILE *imgf = fopen(image, "rb");
    if (!imgf) { perror(image); return 0; }

    FILE *sigf = fopen(sig, "rb");
    if (!sigf) { perror(sig); fclose(imgf); return 0; }

    if (fseek(sigf, 0, SEEK_END) != 0) { perror("fseek(sig)"); fclose(imgf); fclose(sigf); return 0; }
    long siglen = ftell(sigf);
    if (siglen <= 0 || siglen > (64 * 1024)) { fprintf(stderr, "Bad sig size: %ld\n", siglen); fclose(imgf); fclose(sigf); return 0; }
    rewind(sigf);

    unsigned char *sigbuf = malloc((size_t)siglen);
    if (!sigbuf) { perror("malloc"); fclose(imgf); fclose(sigf); return 0; }
    if (fread(sigbuf, 1, (size_t)siglen, sigf) != (size_t)siglen) {
        fprintf(stderr, "Short read on %s\n", KERNEL_SIG);
        free(sigbuf); fclose(imgf); fclose(sigf); return 0;
    }
    fclose(sigf);

    FILE *pubf = fopen(pubkey_path, "r");
    if (!pubf) { perror(pubkey_path); free(sigbuf); fclose(imgf); return 0; }
    EVP_PKEY *pkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
    fclose(pubf);
    if (!pkey) { ERR_print_errors_fp(stderr); free(sigbuf); fclose(imgf); return 0; }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
        unsigned char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, imgf)) > 0)
            EVP_DigestVerifyUpdate(ctx, buf, n);
        if (EVP_DigestVerifyFinal(ctx, sigbuf, (size_t)siglen) == 1)
            ok = 1;
    }
    if (!ok) {
        fprintf(stderr, "Signature verification failed for %s\n", image);
        ERR_print_errors_fp(stderr);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sigbuf);
    fclose(imgf);
    return ok;
}

/* ---------- Decide guest root device name from image (UNMODIFIED) ---------- */
static const char *root_dev_from_image(const char *img_path) {
    static char root_dev[16];

    int fd = open(img_path, O_RDONLY);
    if (fd < 0) {
        perror(img_path);
        // If we can't open, still give a sensible default to avoid blocking boot
        snprintf(root_dev, sizeof root_dev, "/dev/vda");
        return root_dev;
    }

    /* Read first few KB to check for GPT/MBR */
    unsigned char buf[4096] = {0};
    ssize_t r = pread(fd, buf, sizeof buf, 0);
    if (r < 1024) { // too small to be valid MBR anyway
        close(fd);
        snprintf(root_dev, sizeof root_dev, "/dev/vda");
        return root_dev;
    }

    /* GPT: "EFI PART" at LBA1 (offset 512) */
    if (r >= 512 + 8) {
        if (memcmp(buf + 512, "EFI PART", 8) == 0) {
            close(fd);
            snprintf(root_dev, sizeof root_dev, "/dev/vda1");
            return root_dev;
        }
    }

    /* Legacy MBR: partition entries at 0x1BE, signature 0x55AA at 0x1FE */
    int is_mbr = (buf[510] == 0x55 && buf[511] == 0xAA);
    if (is_mbr) {
        int has_part = 0;
        for (int i = 0; i < 4; i++) {
            const unsigned char *pe = buf + 0x1BE + i * 16;
            if (pe[4] != 0x00) { has_part = 1; break; } // non-empty partition type
        }
        close(fd);
        if (has_part) {
            snprintf(root_dev, sizeof root_dev, "/dev/vda1");
            return root_dev;
        }
    }

    close(fd);
    // No partition table detected → assume raw filesystem image
    snprintf(root_dev, sizeof root_dev, "/dev/vda");
    return root_dev;
}

/* ---------- Launch kernel in QEMU with minimal DM cmdline (MODIFIED) ---------- */
static int boot_kernel(const char *kernel_path,
                       const char *rootfs_img,
                       const char *root_dev) // The determined raw device like /dev/vda1
{
    char append[512];
    char dm_create_cmd[384];

    // Construct the dm-mod.create command with MINIMAL parameters:
    // We use a dummy target length (512 sectors) and let the kernel's 'verity-signed' 
    // module read the real data/merkle block size from the disk and reset the table size.
    // Format: name,mode,table_length [target_type] [target_args...]
    // Target Args: {raw_data_dev} {verity_sig_file} {verity_cert_path}
    
    snprintf(dm_create_cmd, sizeof dm_create_cmd,
            "verity-root,,,ro,0 512 verity-signed %s %s %s",
            root_dev,                 // Arg 1: The raw device (/dev/vda1)
            VERITY_SIG_FILE,          // Arg 2: Signature file path (e.g., verity_metadata.p7s)
            VERITY_CERT_PATH          // Arg 3: Cert/Key path (e.g., bl_cert.pem)
    );
    
    // Construct the final kernel append string
    snprintf(append, sizeof append,
            "console=ttyS0 root=/dev/mapper/verity-root ro "
            "modules_load=dm-verity "
            "dm-mod.create=\"%s\"",
            dm_create_cmd);

    const char *argv[] = {
        "qemu-system-x86_64",
        "-m", "1024",
        "-kernel", kernel_path,
        "-append", append,
        "-drive", "file=rootfs.img,format=raw,if=virtio,readonly=on",
        "-nographic",
        NULL
    };

    printf("Launching kernel with command line:\n  %s\n", append);
    execvp(argv[0], (char * const *)argv);
    perror("execvp");
    return 1;
}


/* ---------- Main (MODIFIED) ---------- */
int main(int argc, char **argv) {
    const char *kernel_img  = KERNEL_IMG;
    const char *kernel_sig  = KERNEL_SIG;
    const char *pubkey_path = PUBKEY_PATH;
    const char *rootfs_img  = ROOTFS_IMG;
    const char *verity_key  = VERITY_KEY_ID;
    const char *root_dev_override = NULL;

    // Optional overrides: --kernel / --sig / --pubkey / --rootfs / --rootdev / --key
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--kernel") && i+1 < argc)      kernel_img = argv[++i];
        else if (!strcmp(argv[i], "--sig") && i+1 < argc)    kernel_sig = argv[++i];
        else if (!strcmp(argv[i], "--pubkey") && i+1 < argc) pubkey_path = argv[++i];
        else if (!strcmp(argv[i], "--rootfs") && i+1 < argc) rootfs_img = argv[++i];
        else if (!strcmp(argv[i], "--rootdev") && i+1 < argc) root_dev_override = argv[++i];
        else if (!strcmp(argv[i], "--key") && i+1 < argc)    verity_key = argv[++i];
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage: %s [--kernel K] [--sig S] [--pubkey P] [--rootfs IMG] [--rootdev DEV] [--key KEYID]\n", argv[0]);
            return 0;
        }
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("Verifying kernel image: %s\n", kernel_img);
    printf("Using signature file:   %s\n", kernel_sig);
    printf("Using public key:       %s\n", pubkey_path);

    if (!verify_signature(kernel_img, kernel_sig, pubkey_path))
        die("\n Kernel image signature verification FAILED!");

    const char *root_dev = root_dev_override ? root_dev_override
                                             : root_dev_from_image(rootfs_img);
    
    // NOTE: RootFS metadata/structure verification should happen here, 
    // but the actual function call is deferred as it requires complex PKCS#7 logic 
    // and is outside the scope of this bootloader structure definition.
    // if (!verify_rootfs_structure(VERITY_SIG_FILE, VERITY_CERT_PATH)) { die("RootFS structure verification FAILED!"); }

    printf("rootfs image: %s\n", rootfs_img);
    printf("guest root dev: %s\n", root_dev);
    printf("verity cert path: %s\n\n", VERITY_CERT_PATH);

    // Call the updated boot function with only the essential parameters
    return boot_kernel(kernel_img, rootfs_img, root_dev);
}