#ifndef _VERITY_MAPPING_H
#define _VERITY_MAPPING_H

#include <linux/types.h>

struct verity_metadata_header;

int verity_create_mapping(dev_t data_dev, const struct verity_metadata_header *h);

#endif
