#ifndef _SIGNATURE_VERIFY_H
#define _SIGNATURE_VERIFY_H
#include <linux/types.h>

struct verity_metadata_ondisk;

int verify_signature_pkcs7_attached(const struct verity_metadata_ondisk *meta);
int verify_signature_pkcs7_detached(const u8 *meta_buf, u32 meta_len,
                                    const u8 *sig_buf, u32 sig_len);

#endif
