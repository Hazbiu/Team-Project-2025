// SPDX-License-Identifier: GPL-2.0-only
#ifndef _DM_VERITY_METADATA_PARSE_H_
#define _DM_VERITY_METADATA_PARSE_H_

#include <linux/types.h>

struct verity_metadata_header;

/*
 * Parse and log the metadata header (first 196 bytes).
 * Returns 0 on success, -EINVAL if the header is inconsistent.
 */
int verity_parse_metadata_header(const struct verity_metadata_header *h);

#endif
