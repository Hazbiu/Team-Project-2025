#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// Verify signature of a file with a given public key
int verify_signature(const char *image, const char *sig, const char *pubkey_path) {
    FILE *imgf = fopen(image, "rb");
    if (!imgf) {
        perror("image");
        return 0;
    }

    FILE *sigf = fopen(sig, "rb");
    if (!sigf) {
        perror("sig");
        fclose(imgf);
        return 0;
    }

    fseek(sigf, 0, SEEK_END);
    long sig_len = ftell(sigf);
    fseek(sigf, 0, SEEK_SET);

    unsigned char *sig_buf = malloc(sig_len);
    if (!sig_buf) {
        perror("malloc");
        fclose(imgf);
        fclose(sigf);
        return 0;
    }

    fread(sig_buf, 1, sig_len, sigf);
    fclose(sigf);

    FILE *pubf = fopen(pubkey_path, "r");
    if (!pubf) {
        perror("pubkey");
        fclose(imgf);
        free(sig_buf);
        return 0;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
    fclose(pubf);
    if (!pkey) {
        fprintf(stderr, "Failed to parse public key: %s\n", pubkey_path);
        fclose(imgf);
        free(sig_buf);
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        perror("EVP_MD_CTX_new");
        EVP_PKEY_free(pkey);
        fclose(imgf);
        free(sig_buf);
        return 0;
    }

    int ret = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
        unsigned char buf[4096];
        size_t n;

        while ((n = fread(buf, 1, sizeof(buf), imgf)) > 0) {
            if (EVP_DigestVerifyUpdate(ctx, buf, n) != 1) {
                ret = 0;
                goto cleanup;
            }
        }

        ret = (EVP_DigestVerifyFinal(ctx, sig_buf, sig_len) == 1);
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sig_buf);
    fclose(imgf);

    return ret;
}

int main(void) {
    printf("=====================================\n");
    printf("   Secondary Bootloader Simulation   \n");
    printf("=====================================\n");

    const char *kernel_path   = "kernel_image.bin";
    const char *sig_path      = "kernel_image.sig";
    const char *pubkey_path   = "bl_public.pem";

    printf("Verifying kernel image: %s\n", kernel_path);
    printf("Using signature file:   %s\n", sig_path);
    printf("Using public key:       %s\n", pubkey_path);

    if (verify_signature(kernel_path, sig_path, pubkey_path)) {
        printf("\n Kernel image verified successfully!\n");
        printf("Ready to boot kernel with rootfs.cpio.gz\n");
        printf("Press ENTER to continue to kernel boot...\n");
        getchar(); // Wait for user to press ENTER

        // Launch kernel via QEMU (replace with real boot in HW)
        system("qemu-system-x86_64 -m 1024 "
               "-kernel kernel_image.bin "
               "-initrd rootfs.cpio.gz "
               "-append \"console=ttyS0 rdinit=/init\" "
               "-nographic");
    } else {
        printf("\n Kernel image signature verification FAILED!\n");
    }

    return 0;
}
