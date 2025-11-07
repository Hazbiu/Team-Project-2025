#ifndef DM_VERITY_AUTOBOOT_H
#define DM_VERITY_AUTOBOOT_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/device.h>

/* Shared prefix for kernel logs */
#define DM_MSG_PREFIX "verity-autoboot"

/* Shared constants (moved from original single .c) */
#define VERITY_META_SIZE           4096
#define VERITY_META_MAGIC          0x56455249 /* "VERI" */
#define VERITY_FOOTER_SIGNED_LEN   196
#define VERITY_PKCS7_MAX           2048

#define VLOC_MAGIC                 0x564C4F43 /* "VLOC" */

/* Shared metadata structs */
struct verity_metadata_ondisk {
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
	__le32 pkcs7_size;
	u8     pkcs7_blob[2048];
	u8     reserved[4096 - 2248];
} __packed;

struct verity_footer_locator {
	__le32 magic;
	__le32 version;
	__le64 meta_off;
	__le32 meta_len;
	__le64 sig_off;
	__le32 sig_len;
	u8     reserved[4096 - 32];
} __packed;

/* Function prototypes */
int verify_attached(const struct verity_metadata_ondisk *meta);
int verify_detached(const u8 *meta_buf, u32 meta_len,
                    const u8 *sig_buf, u32 sig_len);

void check_hash_tree_location(const struct verity_metadata_ondisk *m);

int resolve_dev_from_diskname(const char *path, dev_t *out_dev);
int read_region(struct file *bdev_file, u64 off, u32 len, u8 **out);
int sha256_buf(const u8 *buf, size_t len, u8 digest[32]);
void dump_hex_short(const char *tag, const u8 *buf, size_t len, size_t max_show);

#endif /* DM_VERITY_AUTOBOOT_H */
