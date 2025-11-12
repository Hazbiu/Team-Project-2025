#ifndef _VERITY_METADATA_PARSE_H
#define _VERITY_METADATA_PARSE_H

#include <linux/types.h>

struct verity_metadata_header {
	__le32 magic;
	__le32 version;
	__le64 data_blocks;
	__le64 hash_start_sector;
	__le32 data_block_size;
	__le32 hash_block_size;
	char   hash_algorithm[32];
	u8     root_hash[64];
	u8     salt[64];
	__le32 salt_size;
} __packed;

int verity_parse_metadata_header(const struct verity_metadata_header *h);

#endif 
