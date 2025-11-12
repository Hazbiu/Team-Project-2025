/**
 * @file mapping.c
 * @author Team A
 * @brief dm-verity mapping creation logic for verified metadata headers.
 *
 * This module builds a dm-verity device-mapper target using a verified and parsed metadata header. 
 * It converts on-disk metadata (hash algorithm, salt, root hash, block sizes) into a device-mapper
 * table and uses dm_early_create() to instantiate the mapping early in the kernel boot sequence.
 *
 * @version 0.1
 * @date 2025-11-12
 * @copyright Copyright (c) 2025
 * 
 */
#include <linux/device-mapper.h>
#include <linux/dm-ioctl.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include "mapping.h"
#include "metadata_parse.h"

#define DM_MSG_PREFIX "verity-mapping"

/**
 * @brief Encode a binary buffer into lowercase hexadecimal ASCII string.
 *
 *
 * This function converts each byte of @p src into two ASCII hex digits and stores
 * the result in @p dst. The resulting string is null-terminated.
 * 
 * @param src Pointer to source buffer.
 * @param len Length of the source buffer in bytes.
 * @param dst Destination buffer (must be at least @c len*2+1 bytes).
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
 * @brief Create a dm-verity mapping from verified metadata.
 * 
 *
 * This function constructs and installs a device-mapper target, based on a verified verity_metadata_header structure.
 *
 * It performs the following steps:
 * - Extracts and validates fields from the metadata header.
 * - Converts binary root hash and salt to ASCII-encoded parameters.
 * - Formats a dm-verity table string.
 * - Invokes dm_early_create() to instantiate the mapping.
 *   
 *
 * @param data_dev The device identifier for the block device that holds the verified filesystem data.
 *
 * @param h Pointer to a verified metadata header describing data and hash layout.
 * @return Returns 0 if the dm-verity mapping was created successfully.
 *         On failure, returns a negative error code.
 */
int verity_create_mapping(dev_t data_dev, const struct verity_metadata_header *h)
{
	struct dm_ioctl dmi;
	struct dm_target_spec *spec;
	struct dm_target_spec *spec_array[1];
	char *params = NULL;
	char *params_array[1];
	char algo[33];
	char root_hex[129];
	char salt_hex[129];
	u32 version, data_bs, hash_bs, salt_size;
	u64 data_blocks, hash_start_sector;
	u64 hash_start_block;
	u32 sectors_per_block;
	sector_t num_data_sectors;
	int ret;

	version           = le32_to_cpu(h->version);
	data_blocks       = le64_to_cpu(h->data_blocks);
	hash_start_sector = le64_to_cpu(h->hash_start_sector);
	data_bs           = le32_to_cpu(h->data_block_size);
	hash_bs           = le32_to_cpu(h->hash_block_size);
	salt_size         = le32_to_cpu(h->salt_size);

	memcpy(algo, h->hash_algorithm, 32);
	algo[32] = '\0';

	pr_info("%s: Preparing dm-verity mapping:\n", DM_MSG_PREFIX);
	pr_info("%s:   version=%u, data_blocks=%llu, data_bs=%u, hash_bs=%u\n",
		DM_MSG_PREFIX, version,
		(unsigned long long)data_blocks, data_bs, hash_bs);
	pr_info("%s:   hash_start_sector=%llu, salt_size=%u, algo=%s\n",
		DM_MSG_PREFIX,
		(unsigned long long)hash_start_sector, salt_size, algo);

	if (strcmp(algo, "sha256") != 0) {
		pr_err("%s: only sha256 supported (algo=%s)\n", DM_MSG_PREFIX, algo);
		return -EINVAL;
	}

	if (!data_blocks || !data_bs || !hash_bs)
		return -EINVAL;

	if (data_bs != hash_bs)
		return -EINVAL;

	if (data_bs < 512 || (data_bs & 511)) {
		pr_err("%s: data_block_size must be multiple of 512\n", DM_MSG_PREFIX);
		return -EINVAL;
	}

	if (salt_size > 64)
		salt_size = 64;

	sectors_per_block = data_bs >> 9; /* /512 */
	num_data_sectors  = (sector_t)data_blocks * sectors_per_block;
	hash_start_block  = data_blocks;

	hex_encode(h->root_hash, 32, root_hex);
	hex_encode(h->salt, salt_size, salt_hex);

	params = kasprintf(GFP_KERNEL,
			   "%u %u:%u %u:%u %u %u %llu %llu %s %s %s",
			   version,
			   MAJOR(data_dev), MINOR(data_dev),
			   MAJOR(data_dev), MINOR(data_dev),
			   data_bs, hash_bs,
			   (unsigned long long)data_blocks,
			   (unsigned long long)hash_start_block,
			   algo, root_hex, salt_hex);
	if (!params)
		return -ENOMEM;

	pr_info("%s: dm-verity table params: \"%s\"\n", DM_MSG_PREFIX, params);

	memset(&dmi, 0, sizeof(dmi));
	dmi.version[0]   = DM_VERSION_MAJOR;
	dmi.version[1]   = DM_VERSION_MINOR;
	dmi.version[2]   = DM_VERSION_PATCHLEVEL;
	dmi.data_size    = sizeof(dmi);
	dmi.data_start   = sizeof(dmi);
	dmi.target_count = 1;
	dmi.flags        = DM_READONLY_FLAG;
	strscpy(dmi.name, "verity_root", sizeof(dmi.name));

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		kfree(params);
		return -ENOMEM;
	}

	spec->sector_start = 0;
	spec->length       = (u64)num_data_sectors;
	spec->next         = 0;
	strscpy(spec->target_type, "verity", sizeof(spec->target_type));

	spec_array[0] = spec;
	params_array[0] = params;

	ret = dm_early_create(&dmi, spec_array, params_array);
	kfree(spec);
	kfree(params);

	if (ret) {
		pr_err("%s: dm_early_create() failed: %d\n", DM_MSG_PREFIX, ret);
		return ret;
	}

	pr_info("%s: dm-verity mapping created successfully\n", DM_MSG_PREFIX);
	return 0;
}
