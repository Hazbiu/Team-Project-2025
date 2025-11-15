/**
 * @file signature_verify.c
 * @author Team A
 * @brief PKCS7 signature verification for dm-verity metadata.
 *
 * This module verifies digital signatures attached to or detached from
 * dm-verity metadata. It computes SHA-256 digests of the metadata region
 * and checks them against the digest embedded in the PKCS7 signature using
 * the kernel’s trusted keyring.
 *
 * @version 0.1
 * @date 2025-11-12
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#include <linux/kernel.h>
#include <crypto/hash.h>
#include <crypto/pkcs7.h>
#include <crypto/hash_info.h>
#include <linux/verification.h>
#include "signature_verify.h"
#include "dm-verity-autoboot.h" 

#define DM_MSG_PREFIX              "verity-autoboot"
#define VERITY_FOOTER_SIGNED_LEN   196
#define VERITY_PKCS7_MAX           2048


/* External helpers defined in dm-verity-autoboot.c */
extern int compute_footer_digest(const struct verity_metadata_ondisk *meta,
                                 u8 digest[32]);
extern int sha256_buf(const u8 *buf, size_t len, u8 digest[32]);

/**
 * @brief Verify an attached PKCS7 signature in the dm-verity footer.
 * 
 * This function validates the PKCS7 signature embedded directly in
 * the verity metadata footer. It computes a SHA-256 digest of the
 * first 196 bytes (the signed portion) and compares it with the
 * digest stored in the PKCS7 structure.
 *
 * @param meta Pointer to a metadata footer.
 * @return 0 on success, negative errno on failure.
 */
int verify_signature_pkcs7_attached(const struct verity_metadata_ondisk *meta)
{
	u8 digest[32];
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	u32 blob_sz;
	int ret;
	struct pkcs7_message *pkcs7;

	blob_sz = le32_to_cpu(meta->pkcs7_size);
	if (!blob_sz || blob_sz > VERITY_PKCS7_MAX)
		return -EINVAL;

	ret = compute_footer_digest(meta, digest);
	if (ret)
		return ret;

	pkcs7 = pkcs7_parse_message(meta->pkcs7_blob, blob_sz);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		goto out_free;

	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len, &signed_hash_algo);
	if (ret)
		goto out_free;

	if (signed_hash_algo != HASH_ALGO_SHA256 || signed_hash_len != 32 ||
	    memcmp(signed_hash, digest, 32) != 0)
		ret = -EKEYREJECTED;

out_free:
	pkcs7_free_message(pkcs7);
	return ret;
}

/**
 * @brief Verify a detached PKCS7 signature for dm-verity metadata.
 * 
 * This function handles detached signatures, where the metadata and
 * signature are stored separately. It computes a SHA-256 digest over
 * the metadata region and checks it against the PKCS7-provided digest
 * after signature verification using the trusted keyring.
 *
 * @param meta_buf Pointer to the metadata buffer.
 * @param meta_len Length of the metadata buffer in bytes.
 * @param sig_buf Pointer to the PKCS7 signature buffe.
 * @param sig_len Length of the PKCS7 signature in bytes.
 * @return 0 on success, negative errno on failure.
 */
int verify_signature_pkcs7_detached(const u8 *meta_buf, u32 meta_len,
				    const u8 *sig_buf,  u32 sig_len)
{
	u8 digest[32];
	struct pkcs7_message *pkcs7;
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	int ret;

	if (!meta_len || sig_len > VERITY_PKCS7_MAX)
		return -EINVAL;

	ret = sha256_buf(meta_buf, meta_len, digest);
	if (ret)
		return ret;

	pkcs7 = pkcs7_parse_message(sig_buf, sig_len);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = pkcs7_supply_detached_data(pkcs7, meta_buf, meta_len);
	if (ret)
		goto out_free;

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		goto out_free;

	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len, &signed_hash_algo);
	if (ret)
		goto out_free;

	if (signed_hash_algo != HASH_ALGO_SHA256 || signed_hash_len != 32 ||
	    memcmp(signed_hash, digest, 32) != 0)
		ret = -EKEYREJECTED;

out_free:
	pkcs7_free_message(pkcs7);
	return ret;
}
