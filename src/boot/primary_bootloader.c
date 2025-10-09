#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// Verify a file against a signature using a given public key
int verify_signature(const char *image, const char *sig, const char *pubkey_path) {
    // Load the public key
    FILE *pubf = fopen(pubkey_path, "r");
    if (!pubf) {
        perror("pubkey");
        return 0;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
    fclose(pubf);
    if (!pkey) {
        fprintf(stderr, "Failed to parse public key: %s\n", pubkey_path);
        return 0;
    }

    // Load the signature
    FILE *sigf = fopen(sig, "rb");
    if (!sigf) {
        perror("sig");
        EVP_PKEY_free(pkey);
        return 0;
    }
    fseek(sigf, 0, SEEK_END);
    long sig_len = ftell(sigf);
    fseek(sigf, 0, SEEK_SET);
    unsigned char *sig_buf = malloc(sig_len);
    if (!sig_buf) {
        perror("malloc");
        fclose(sigf);
        EVP_PKEY_free(pkey);
        return 0;
    }
    fread(sig_buf, 1, sig_len, sigf);
    fclose(sigf);

    // Prepare verification context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        perror("EVP_MD_CTX_new");
        EVP_PKEY_free(pkey);
        free(sig_buf);
        return 0;
    }

    int ret = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
        // Feed the image file contents
        FILE *imgf = fopen(image, "rb");
        if (!imgf) {
            perror("image");
        } else {
            unsigned char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), imgf)) > 0) {
                EVP_DigestVerifyUpdate(ctx, buf, n);
            }
            fclose(imgf);

            // Final check
            ret = (EVP_DigestVerifyFinal(ctx, sig_buf, sig_len) == 1);
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sig_buf);

    return ret;
}

int main(void) {
    printf("=====================================\n");
    printf("        Primary Bootloader v1.0      \n");
    printf("=====================================\n\n");

    const char *image_path = "secondary_bootloader.bin";
    const char *sig_path   = "secondary_bootloader.sig";
    const char *pubkey_path = "../keys/rot_public.pem";

    printf("Verifying secondary bootloader...\n");

    if (verify_signature(image_path, sig_path, pubkey_path)) {
        printf("\nPrimary Bootloader: Signature verified successfully!\n");
        printf("Ready to execute secondary bootloader.\n");
        printf("Press ENTER to continue...\n");
        getchar(); // Wait for user input
        system("./secondary_bootloader");
    } else {
        printf("\nPrimary Bootloader: Signature verification FAILED!\n");
    }

    return 0;
}
