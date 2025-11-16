/**
 * @file signature_verify.c
 * @author Team A
 * @brief PKCS7 signature verification for dm-verity metadata.
 *
 * This module verifies digital signatures (currently: detached PKCS7)
 * for dm-verity metadata. It computes a SHA-256 digest of the metadata
 * region and checks it against the digest embedded in the PKCS7
 * structure using the kernel’s trusted keyring.
 *
 * @version 0.1
 * @date 2025-11-12
 *
 * Copyright (c) 2025
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/hash.h>
#include <crypto/pkcs7.h>
#include <crypto/hash_info.h>
#include <linux/verification.h>
#include "signature_verify.h"

#define DM_MSG_PREFIX              "verity-autoboot"
#define VERITY_FOOTER_SIGNED_LEN   196
#define VERITY_PKCS7_MAX           2048

/* -------------------------------------------------------------------- */
/* Local helpers                                                        */
/* -------------------------------------------------------------------- */

/**
 * @brief Compute SHA-256 over an arbitrary buffer.
 *
 * @param buf Pointer to input data.
 * @param len Data length in bytes.
 * @param digest Output buffer (32 bytes).
 * @return 0 on success, negative error code on failure.
 */
static int sha256_buf(const u8 *buf, size_t len, u8 digest[32])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out;

	ret = crypto_shash_update(desc, buf, len);
	if (ret)
		goto out;

	ret = crypto_shash_final(desc, digest);

out:
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

/* -------------------------------------------------------------------- */
/* Detached PKCS7 verification                                          */
/* -------------------------------------------------------------------- */

/**
 * @brief Verify a detached PKCS7 signature for dm-verity metadata.
 *
 * This function handles detached signatures, where the metadata and
 * signature are stored separately. It computes a SHA-256 digest over
 * the metadata region and checks it against the digest provided by the
 * PKCS7 structure after signature verification using the trusted keyring.
 *
 * @param meta_buf Pointer to the metadata buffer.
 * @param meta_len Length of the metadata buffer in bytes.
 * @param sig_buf  Pointer to the PKCS7 signature buffer.
 * @param sig_len  Length of the PKCS7 signature in bytes.
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

	if (!meta_len || !sig_len || sig_len > VERITY_PKCS7_MAX)
		return -EINVAL;

	/* Compute digest over metadata region */
	ret = sha256_buf(meta_buf, meta_len, digest);
	if (ret)
		return ret;

	/* Parse PKCS7 structure */
	pkcs7 = pkcs7_parse_message(sig_buf, sig_len);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	/* Attach detached data and verify signature chain */
	ret = pkcs7_supply_detached_data(pkcs7, meta_buf, meta_len);
	if (ret)
		goto out_free;

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		goto out_free;

	/* Extract digest from PKCS7 and compare with our SHA-256 */
	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len,
			       &signed_hash_algo);
	if (ret)
		goto out_free;

	if (signed_hash_algo != HASH_ALGO_SHA256 ||
	    signed_hash_len != 32 ||
	    memcmp(signed_hash, digest, 32) != 0)
		ret = -EKEYREJECTED;

out_free:
	pkcs7_free_message(pkcs7);
	return ret;
}
