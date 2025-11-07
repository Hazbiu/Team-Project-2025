// dm_verity_autoboot-verity.c


#include "dm-verity-autoboot.h"
#include <crypto/pkcs7.h>


/* ---------------------------------------------------------- */
/* Signature Verification                                      */
/* ---------------------------------------------------------- */

int verify_attached(const struct verity_metadata_ondisk *meta)
{
	struct pkcs7_message *pkcs7;
	u8 digest[32];
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	u32 blob_sz;
	int ret;

	pr_info("%s: [VERIFY] Attached metadata signature verification started\n", DM_MSG_PREFIX);

	blob_sz = le32_to_cpu(meta->pkcs7_size);
	if (!blob_sz || blob_sz > VERITY_PKCS7_MAX)
		return -EINVAL;

	ret = sha256_buf((const u8 *)meta, VERITY_FOOTER_SIGNED_LEN, digest);
	if (ret)
		return ret;

	pkcs7 = pkcs7_parse_message(meta->pkcs7_blob, blob_sz);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		goto out;

	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len, &signed_hash_algo);
	if (ret || signed_hash_algo != HASH_ALGO_SHA256 ||
		signed_hash_len != 32 ||
		memcmp(signed_hash, digest, 32) != 0) {

		pr_err("%s: [VERIFY] Attached signature FAILED\n", DM_MSG_PREFIX);
		ret = -EKEYREJECTED;

	} else {
		pr_info("%s: [VERIFY] Attached signature PASSED ✅\n", DM_MSG_PREFIX);
	}

out:
	pkcs7_free_message(pkcs7);
	return ret;
}




int verify_detached(const u8 *meta_buf, u32 meta_len,
			   const u8 *sig_buf,  u32 sig_len)
{
	struct pkcs7_message *pkcs7;
	u8 digest[32];
	const u8 *signed_hash;
	u32 signed_hash_len;
	enum hash_algo signed_hash_algo;
	int ret;

	pr_info("%s: [VERIFY] Detached metadata signature verification started\n", DM_MSG_PREFIX);

	ret = sha256_buf(meta_buf, meta_len, digest);
	if (ret)
		return ret;

	pkcs7 = pkcs7_parse_message(sig_buf, sig_len);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = pkcs7_supply_detached_data(pkcs7, meta_buf, meta_len);
	if (ret)
		goto out;

	ret = pkcs7_verify(pkcs7, VERIFYING_MODULE_SIGNATURE);
	if (ret)
		goto out;

	ret = pkcs7_get_digest(pkcs7, &signed_hash, &signed_hash_len, &signed_hash_algo);
	if (!ret && (signed_hash_algo != HASH_ALGO_SHA256 ||
		     signed_hash_len != 32 ||
		     memcmp(signed_hash, digest, 32) != 0))
		ret = -EKEYREJECTED;

out:
	pkcs7_free_message(pkcs7);

	if (!ret)
		pr_info("%s: [VERIFY] Detached signature PASSED ✅\n", DM_MSG_PREFIX);
	else
		pr_err("%s: [VERIFY] Detached signature FAILED\n", DM_MSG_PREFIX);

	return ret;
}