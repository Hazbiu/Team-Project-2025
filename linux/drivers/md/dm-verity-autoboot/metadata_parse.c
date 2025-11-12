/**
 * @file metadata_parse.c
 * @author Team A
 * @brief Verity metadata header parsing and logging.
 *
 * This module provides helper functions to read and display information
 * from the dm-verity metadata header. It extracts block sizes, offsets, salt, and hash values, 
 * then logs them for easier debugging and verification.
 *
 * @version 0.1
 * @date 2025-11-12
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "metadata_parse.h"
#include "signature_verify.h"


#define DM_MSG_PREFIX "verity-autoboot"


/**
 * @brief Encode binary data into a lowercase hexadecimal string.
 *
 * @param src Pointer to the source buffer.
 * @param len Number of bytes to convert.
 * @param dst Destination buffer (must be at least len*2 + 1 bytes).
 */
static void hex_encode(const u8 *src, size_t len, char *dst)
{
	static const char hexdig[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		dst[2 * i]     = hexdig[(src[i] >> 4) & 0xf];
		dst[2 * i + 1] = hexdig[src[i] & 0xf];
	}
	dst[2 * len] = '\0';
}



/**
 * @brief Parse and display a dm-verity metadata header.
 * 
 * This function extracts key information from a verified verity_metadata_header, such as data and hash block sizes,
 * number of data blocks, salt, and algorithm name. It also prints this information to the kernel log for debugging and verification.
 *
 * @param h Pointer to a verified metadata header describing data and hash layout.
 * @return 0 on success, negative error code on failure.
 */
int verity_parse_metadata_header(const struct verity_metadata_header *h)
{
	char algo[33];
	char root_hash_hex[129];
	char salt_hex[129];
	u64 data_blocks, data_block_bytes, covered_bytes;
	u64 hash_start_sector, hash_start_bytes;
	u32 salt_size;

	data_blocks       = le64_to_cpu(h->data_blocks);
	hash_start_sector = le64_to_cpu(h->hash_start_sector);
	data_block_bytes  = (u64)le32_to_cpu(h->data_block_size);
	covered_bytes     = data_blocks * data_block_bytes;
	hash_start_bytes  = hash_start_sector * 512ULL;
	salt_size         = le32_to_cpu(h->salt_size);

	memcpy(algo, h->hash_algorithm, 32);
	algo[32] = '\0';

	hex_encode(h->root_hash, 32, root_hash_hex);

	if (salt_size > 64)
		salt_size = 64;
	hex_encode(h->salt, salt_size, salt_hex);

	pr_info("%s: ---- Metadata Header ----\n", DM_MSG_PREFIX);
	pr_info("%s:   version            : %u\n",
		DM_MSG_PREFIX, le32_to_cpu(h->version));
	pr_info("%s:   data_blocks        : %llu\n",
		DM_MSG_PREFIX, (unsigned long long)data_blocks);
	pr_info("%s:   data_block_size    : %u bytes\n",
		DM_MSG_PREFIX, le32_to_cpu(h->data_block_size));
	pr_info("%s:   hash_block_size    : %u bytes\n",
		DM_MSG_PREFIX, le32_to_cpu(h->hash_block_size));
	pr_info("%s:   covered_bytes(~fs) : %llu bytes\n",
		DM_MSG_PREFIX, (unsigned long long)covered_bytes);
	pr_info("%s:   hash_start_sector  : %llu\n",
		DM_MSG_PREFIX, (unsigned long long)hash_start_sector);
	pr_info("%s:   hash_start_bytes   : %llu\n",
		DM_MSG_PREFIX, (unsigned long long)hash_start_bytes);
	pr_info("%s:   hash_algorithm     : %s\n", DM_MSG_PREFIX, algo);
	pr_info("%s:   salt_size          : %u\n", DM_MSG_PREFIX, salt_size);
	pr_info("%s:   salt(hex)          : %s\n", DM_MSG_PREFIX, salt_hex);

	return 0;
}
