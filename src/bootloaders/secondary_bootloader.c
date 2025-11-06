/* verify_kernel():
 *   Verifies that the kernel binary has a valid PKCS#7 signature using the provided trusted certificate.
 */

/* main():
 *   Verifies the kernel image and, only if the signature is valid, executes QEMU to boot it with the supplied kernel cmdline.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

static int verify_kernel(const char *kernel, const char *sig, const char *cert)
{
    BIO *bio_kernel = NULL, *bio_sig = NULL, *bio_cert = NULL;
    X509 *x509 = NULL;
    STACK_OF(X509) *x509_stack = NULL;
    CMS_ContentInfo *cms = NULL;
    int ok = -1;

    bio_kernel = BIO_new_file(kernel, "rb");
    bio_sig    = BIO_new_file(sig,    "rb");
    bio_cert   = BIO_new_file(cert,   "rb");
    if (!bio_kernel || !bio_sig || !bio_cert)
        goto out;

    x509 = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL);
    if (!x509)
        goto out;

    x509_stack = sk_X509_new_null();
    sk_X509_push(x509_stack, x509);

    cms = d2i_CMS_bio(bio_sig, NULL);
    if (!cms)
        goto out;

  
    if (CMS_verify(cms, x509_stack, NULL, bio_kernel, NULL, CMS_BINARY) == 1)
        ok = 0; 

out:
    if (cms)        CMS_ContentInfo_free(cms);
    if (x509_stack) sk_X509_pop_free(x509_stack, X509_free);
    if (bio_kernel) BIO_free(bio_kernel);
    if (bio_sig)    BIO_free(bio_sig);
    if (bio_cert)   BIO_free(bio_cert);

    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <kernel> <kernel.p7s> <trusted_cert.pem> \"<cmdline>\"\n\n"
            "Example:\n"
            "  ./secondary_bootloader bzImage bzImage.p7s cert.pem "
            "\"console=ttyS0 root=/dev/dm-0 ro\"\n",
            argv[0]);
        return 1;
    }

    const char *kernel  = argv[1];
    const char *sig     = argv[2];
    const char *cert    = argv[3];
    const char *cmdline = argv[4];

    printf("[secondary_bootloader] Verifying kernel signature...\n");
    if (verify_kernel(kernel, sig, cert) != 0) {
        printf("[secondary_bootloader] Verification FAILED, refusing to boot.\n");
        return 1;
    }

    printf("[secondary_bootloader] Kernel signature verified, booting kernel.\n");
    printf("[secondary_bootloader] Passing cmdline:\n    %s\n", cmdline);

    execlp("qemu-system-x86_64",
           "qemu-system-x86_64",
           "-m", "1024",
           "-kernel", kernel,
           "-append", cmdline,
           "-nographic",
           (char*)NULL);

    perror("exec qemu failed");
    return 1;
}
