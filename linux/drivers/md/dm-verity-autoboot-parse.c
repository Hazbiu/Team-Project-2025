// dm_verity_autoboot-prase.c


#include "dm-verity-autoboot.h"
// move check_hash_tree_location() here

/* ---------------------------------------------------------- */
/* Metadata Parsing (only runs after verification succeeded!)  */
/* ---------------------------------------------------------- */

void check_hash_tree_location(const struct verity_metadata_ondisk *m)
{
	u64 data_blocks      = le64_to_cpu(m->data_blocks);
	u32 data_block_size  = le32_to_cpu(m->data_block_size);
	u64 declared_sector  = le64_to_cpu(m->hash_start_sector);
	u64 expected_sector;

	pr_info("%s: [PARSE] Metadata parsed successfully\n", DM_MSG_PREFIX);
	pr_info("  hash algorithm     : %s\n", m->hash_algorithm);
	pr_info("  data block size    : %u bytes\n", data_block_size);
	pr_info("  number of blocks   : %llu\n", (unsigned long long)data_blocks);
	pr_info("  declared hash tree : sector %llu\n", (unsigned long long)declared_sector);
	dump_hex_short("root_hash", m->root_hash, 32, 32);

	if (!data_block_size || (data_block_size % 512)) {
		pr_emerg("%s: INVALID data_block_size %u\n", DM_MSG_PREFIX, data_block_size);
		panic("dm-verity-autoboot: invalid metadata block size");
	}

	expected_sector = data_blocks * (data_block_size / 512ULL);

	if (declared_sector != expected_sector) {
		pr_emerg("%s: HASH TREE LOCATION MISMATCH\n", DM_MSG_PREFIX);
		panic("dm-verity-autoboot: hash tree location mismatch");
	}

	pr_info("%s: Parsing Successful, hash tree location verified ✅ (sector=%llu)\n",
		DM_MSG_PREFIX, (unsigned long long)declared_sector);
}