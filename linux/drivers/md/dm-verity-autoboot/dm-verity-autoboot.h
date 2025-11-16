#ifndef DM_VERITY_AUTOBOOT_H
#define DM_VERITY_AUTOBOOT_H

#include <linux/types.h>

/**
 * @brief Layout of a full attached 4 KiB dm-verity metadata footer.
 * 
 * This footer resides at the last 4096 bytes of the disk when "VERI"-style
 * attached metadata is used.
 */
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


/**
 * @brief  Locator footer for detached metadata/signature ("VLOC").
 * 
 * Located at the final 4 KiB of the device.
 */
struct verity_footer_locator {
    __le32 magic;
    __le32 version;
    __le64 meta_off;
    __le32 meta_len;
    __le64 sig_off;
    __le32 sig_len;
    u8     reserved[4096 - 32];
} __packed;

int compute_footer_digest(const struct verity_metadata_ondisk *meta,
                          u8 digest[32]);

int sha256_buf(const u8 *buf, size_t len, u8 digest[32]);

#endif /* DM_VERITY_AUTOBOOT_H */
