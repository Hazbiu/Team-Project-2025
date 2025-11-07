#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* Verify PKCS#7 detached signature */
static int verify_kernel(const char *kernel, const char *sig, const char *cert)
{
    BIO *bio_kernel = NULL, *bio_sig = NULL, *bio_cert = NULL;
    X509 *x509 = NULL;
    STACK_OF(X509) *trusted = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = -1;

    bio_kernel = BIO_new_file(kernel, "rb");
    bio_sig    = BIO_new_file(sig, "rb");
    bio_cert   = BIO_new_file(cert, "rb");
    if (!bio_kernel || !bio_sig || !bio_cert) {
        printf("❌ Unable to open kernel / sig / cert file.\n");
        goto out;
    }

    x509 = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL);
    if (!x509) {
        printf("❌ Failed to read certificate.\n");
        goto out;
    }

    trusted = sk_X509_new_null();
    sk_X509_push(trusted, x509); // stack owns cert now

    cms = d2i_CMS_bio(bio_sig, NULL);
    if (!cms) {
        printf("❌ Invalid PKCS#7 signature format.\n");
        goto out;
    }

    BIO_reset(bio_kernel);

    if (CMS_verify(cms, trusted, NULL, bio_kernel, NULL,
                   CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) != 1) {
        printf("❌ Signature mismatch.\n");
        goto out;
    }

    printf("✅ Signature verified.\n");
    ret = 0;

out:
    if (cms)        CMS_ContentInfo_free(cms);
    if (trusted)    sk_X509_pop_free(trusted, X509_free);
    if (bio_kernel) BIO_free(bio_kernel);
    if (bio_sig)    BIO_free(bio_sig);
    if (bio_cert)   BIO_free(bio_cert);
    return ret;
}





int main(int argc, char **argv)
{
    if (argc < 6) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <kernel> <kernel.p7s> <trusted_cert.pem> <rootfs.img> \"<cmdline>\"\n\n"
            "Example:\n"
            "  ./secondary_bootloader bzImage bzImage.p7s cert.pem rootfs.img "
            "\"console=ttyS0 root=/dev/vda1 rw\"\n",
            argv[0]);
        return 1;
    }

    const char *kernel  = argv[1];
    const char *sig     = argv[2];
    const char *cert    = argv[3];
    const char *rootfs  = argv[4];
    const char *cmdline = argv[5];

    printf("[secondary_bootloader] Verifying kernel signature...\n");
    if (verify_kernel(kernel, sig, cert) != 0) {
        printf("[secondary_bootloader] ❌ Verification FAILED — boot aborted.\n");
        return 1;
    }

    printf("[secondary_bootloader] ✅ Kernel signature verified.\n");
    printf("[secondary_bootloader] Booting kernel...\n");

    char drive_arg[256];
    snprintf(drive_arg, sizeof(drive_arg),
             "file=%s,format=raw,if=virtio", rootfs);

    execlp("qemu-system-x86_64",
           "qemu-system-x86_64",
           "-m", "1024",
           "-kernel", kernel,
           "-drive", drive_arg,
           "-append", cmdline,
           "-nographic",
           (char*)NULL);

    perror("exec qemu failed");
    return 1;
}
