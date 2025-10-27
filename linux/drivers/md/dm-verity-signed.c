// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-verity-signed: Kernel-managed metadata verification
 * Bootloader only provides rootfs location, kernel handles everything else
 */

#include "dm-verity.h"
#include "dm-verity-fec.h"
#include "dm-verity-verify-sig.h"
#include "dm-audit.h"
#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/verification.h>
#include <keys/asymmetric-type.h>
#include <crypto/pkcs7.h>
#include <linux/parser.h>
#include <linux/blkdev.h>

#define DM_MSG_PREFIX "verity-signed"

/* 
 * Metadata stored alongside rootfs (e.g., in superblock or dedicated area)
 * Kernel reads this from the data device itself
 */
struct verity_kernel_metadata {
	u32 magic;                    /* Magic: "VRKM" = 0x564B524D */
	u32 version;                  /* Metadata version */
	u32 metadata_size;            /* Size of this structure */
	
	/* Hash tree configuration */
	u32 hash_algorithm;           /* e.g., SHA256 */
	u32 data_block_size;
	u32 hash_block_size;
	u64 data_blocks;
	u64 hash_start_block;
	
	/* Root hash and signature */
	u32 root_hash_size;
	u8 root_hash[64];
	u32 salt_size;
	u8 salt[64];
	
	/* PKCS#7 signature over root_hash */
	u32 signature_size;
	u8 signature[1024];           /* Flexible, can be larger */
	
	/* Additional verification data */
	u32 flags;
	u64 timestamp;                /* When metadata was created */
	u8 reserved[128];             /* Future use */
} __packed;

#define VERITY_KERNEL_MAGIC 0x564B524D  /* "VRKM" */
#define VERITY_KERNEL_VERSION_1 1

/* Metadata location strategies */
enum metadata_location_type {
	META_LOCATION_SUPERBLOCK,     /* In filesystem superblock area */
	META_LOCATION_DEDICATED,      /* Dedicated metadata partition */
	META_LOCATION_END_OF_DEVICE,  /* At end of data device */
	META_LOCATION_CMDLINE,        /* Specified in kernel cmdline */
};

/* Extended verity structure */
struct dm_verity_signed {
	struct dm_verity base;
	
	/* Metadata management */
	struct verity_kernel_metadata *metadata;
	enum metadata_location_type meta_location_type;
	sector_t meta_offset;         /* Where metadata was found */
	bool metadata_verified;
	
	/* Signature verification */
	char *keyring_name;           /* Keyring to use for verification */
	
	/* Logging */
	struct workqueue_struct *log_wq;
	atomic_t log_sequence;        /* Sequential log counter */
	
	/* Statistics */
	atomic64_t blocks_verified;
	atomic64_t verification_errors;
	ktime_t init_time;
};

/* Logging work structure */
struct verity_log_work {
	struct work_struct work;
	struct dm_verity_signed *vs;
	char msg[512];
	int priority;
	u64 sequence;
	ktime_t timestamp;
};

/* ==================== Logging Subsystem ==================== */

static void verity_log_worker(struct work_struct *work)
{
	struct verity_log_work *log_work = 
		container_of(work, struct verity_log_work, work);
	struct dm_verity_signed *vs = log_work->vs;
	
	/* Format with timestamp and sequence */
	printk(log_work->priority, "%s: [%llu] %lld.%06lld: %s\n",
	       DM_MSG_PREFIX,
	       log_work->sequence,
	       (s64)ktime_to_ms(log_work->timestamp) / 1000,
	       (s64)ktime_to_ms(log_work->timestamp) % 1000,
	       log_work->msg);
	
	/* Could add:
	 * - dm_audit_log_target() for audit subsystem
	 * - Write to persistent log partition
	 * - Send to userspace via netlink
	 */
	
	kfree(log_work);
}

static void verity_signed_log(struct dm_verity_signed *vs, 
			      int priority, 
			      const char *fmt, ...)
{
	struct verity_log_work *log_work;
	va_list args;
	
	log_work = kmalloc(sizeof(*log_work), GFP_ATOMIC);
	if (!log_work)
		return;
	
	log_work->vs = vs;
	log_work->priority = priority;
	log_work->sequence = atomic_inc_return(&vs->log_sequence);
	log_work->timestamp = ktime_get();
	
	va_start(args, fmt);
	vsnprintf(log_work->msg, sizeof(log_work->msg), fmt, args);
	va_end(args);
	
	INIT_WORK(&log_work->work, verity_log_worker);
	queue_work(vs->log_wq, &log_work->work);
}

/* ==================== Metadata Discovery ==================== */

/*
 * Strategy 1: Look for metadata at well-known locations
 * Order of preference:
 * 1. Superblock area (first few blocks)
 * 2. End of device
 * 3. Kernel command line specified location
 */
static int verity_find_metadata_superblock(struct dm_verity_signed *vs,
					   struct block_device *bdev)
{
	struct page *page;
	void *buffer;
	struct verity_kernel_metadata *meta;
	sector_t sectors_to_check[] = {0, 1, 2, 8, 16}; /* Common locations */
	int i, r = -ENOENT;
	struct dm_io_request io_req;
	struct dm_io_region io_loc;
	
	verity_signed_log(vs, KERN_INFO, 
			 "Searching for metadata in superblock area");
	
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	
	buffer = page_to_virt(page);
	
	io_req.bi_opf = REQ_OP_READ;
	io_req.mem.type = DM_IO_KMEM;
	io_req.mem.ptr.addr = buffer;
	io_req.notify.fn = NULL;
	io_req.client = vs->base.io;
	io_loc.bdev = bdev;
	io_loc.count = 8; /* 4KB */
	
	for (i = 0; i < ARRAY_SIZE(sectors_to_check); i++) {
		io_loc.sector = sectors_to_check[i];
		
		r = dm_io(&io_req, 1, &io_loc, NULL, IOPRIO_DEFAULT);
		if (r)
			continue;
		
		meta = (struct verity_kernel_metadata *)buffer;
		
		if (meta->magic == VERITY_KERNEL_MAGIC &&
		    meta->version == VERITY_KERNEL_VERSION_1) {
			/* Found it! */
			vs->metadata = kmalloc(sizeof(*meta), GFP_KERNEL);
			if (!vs->metadata) {
				r = -ENOMEM;
				break;
			}
			
			memcpy(vs->metadata, meta, sizeof(*meta));
			vs->meta_offset = sectors_to_check[i];
			vs->meta_location_type = META_LOCATION_SUPERBLOCK;
			
			verity_signed_log(vs, KERN_INFO,
					 "Found metadata at sector %llu",
					 (unsigned long long)sectors_to_check[i]);
			r = 0;
			break;
		}
	}
	
	__free_page(page);
	return r;
}

static int verity_find_metadata_end_of_device(struct dm_verity_signed *vs,
					      struct block_device *bdev)
{
	struct page *page;
	void *buffer;
	struct verity_kernel_metadata *meta;
	sector_t device_size, meta_sector;
	int r;
	struct dm_io_request io_req;
	struct dm_io_region io_loc;
	
	device_size = get_capacity(bdev->bd_disk);
	
	/* Try last few blocks */
	meta_sector = device_size - 8;
	
	verity_signed_log(vs, KERN_INFO,
			 "Searching for metadata at end of device (sector %llu)",
			 (unsigned long long)meta_sector);
	
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	
	buffer = page_to_virt(page);
	
	io_req.bi_opf = REQ_OP_READ;
	io_req.mem.type = DM_IO_KMEM;
	io_req.mem.ptr.addr = buffer;
	io_req.notify.fn = NULL;
	io_req.client = vs->base.io;
	io_loc.bdev = bdev;
	io_loc.sector = meta_sector;
	io_loc.count = 8;
	
	r = dm_io(&io_req, 1, &io_loc, NULL, IOPRIO_DEFAULT);
	if (r)
		goto out;
	
	meta = (struct verity_kernel_metadata *)buffer;
	
	if (meta->magic == VERITY_KERNEL_MAGIC &&
	    meta->version == VERITY_KERNEL_VERSION_1) {
		vs->metadata = kmalloc(sizeof(*meta), GFP_KERNEL);
		if (!vs->metadata) {
			r = -ENOMEM;
			goto out;
		}
		
		memcpy(vs->metadata, meta, sizeof(*meta));
		vs->meta_offset = meta_sector;
		vs->meta_location_type = META_LOCATION_END_OF_DEVICE;
		
		verity_signed_log(vs, KERN_INFO,
				 "Found metadata at end of device");
		r = 0;
	} else {
		r = -ENOENT;
	}
	
out:
	__free_page(page);
	return r;
}

static int verity_discover_metadata(struct dm_verity_signed *vs,
				    struct block_device *bdev)
{
	int r;
	
	verity_signed_log(vs, KERN_INFO, "Beginning metadata discovery");
	
	/* Try superblock area first */
	r = verity_find_metadata_superblock(vs, bdev);
	if (r == 0)
		return 0;
	
	/* Try end of device */
	r = verity_find_metadata_end_of_device(vs, bdev);
	if (r == 0)
		return 0;
	
	verity_signed_log(vs, KERN_ERR, 
			 "Metadata not found in any known location");
	return -ENOENT;
}

/* ==================== Metadata Validation ==================== */

static int verity_validate_metadata_fields(struct dm_verity_signed *vs)
{
	struct verity_kernel_metadata *meta = vs->metadata;
	
	verity_signed_log(vs, KERN_INFO, "Validating metadata fields");
	
	/* Check version */
	if (meta->version != VERITY_KERNEL_VERSION_1) {
		verity_signed_log(vs, KERN_ERR,
				 "Unsupported metadata version: %u", meta->version);
		return -EINVAL;
	}
	
	/* Validate sizes */
	if (meta->root_hash_size > sizeof(meta->root_hash)) {
		verity_signed_log(vs, KERN_ERR,
				 "Invalid root hash size: %u", meta->root_hash_size);
		return -EINVAL;
	}
	
	if (meta->salt_size > sizeof(meta->salt)) {
		verity_signed_log(vs, KERN_ERR,
				 "Invalid salt size: %u", meta->salt_size);
		return -EINVAL;
	}
	
	if (meta->signature_size > sizeof(meta->signature)) {
		verity_signed_log(vs, KERN_ERR,
				 "Invalid signature size: %u", meta->signature_size);
		return -EINVAL;
	}
	
	/* Validate block sizes are power of 2 */
	if (!meta->data_block_size || (meta->data_block_size & (meta->data_block_size - 1))) {
		verity_signed_log(vs, KERN_ERR,
				 "Invalid data block size: %u", meta->data_block_size);
		return -EINVAL;
	}
	
	if (!meta->hash_block_size || (meta->hash_block_size & (meta->hash_block_size - 1))) {
		verity_signed_log(vs, KERN_ERR,
				 "Invalid hash block size: %u", meta->hash_block_size);
		return -EINVAL;
	}
	
	verity_signed_log(vs, KERN_INFO,
			 "Metadata validated: algo=%u, data_blocks=%llu, hash_start=%llu",
			 meta->hash_algorithm, meta->data_blocks, meta->hash_start_block);
	
	return 0;
}

/* ==================== Signature Verification ==================== */

static const char *verity_get_algorithm_name(u32 algo_id)
{
	switch (algo_id) {
	case 0: return "sha256";
	case 1: return "sha512";
	case 2: return "sha1";
	default: return NULL;
	}
}

static int verity_verify_signature(struct dm_verity_signed *vs)
{
	struct verity_kernel_metadata *meta = vs->metadata;
	int r;
	
	verity_signed_log(vs, KERN_INFO,
			 "Verifying signature (size=%u) using keyring: %s",
			 meta->signature_size,
			 vs->keyring_name ?: "system");
	
	if (meta->signature_size == 0) {
		verity_signed_log(vs, KERN_WARNING,
				 "No signature present - proceeding without verification");
		return 0;
	}
	
	/* Use kernel's signature verification */
	r = verify_pkcs7_signature(meta->root_hash,
				   meta->root_hash_size,
				   meta->signature,
				   meta->signature_size,
				   NULL, /* Use system trusted keyring */
				   VERIFYING_MODULE_SIGNATURE,
				   NULL, NULL);
	
	if (r < 0) {
		verity_signed_log(vs, KERN_ERR,
				 "Signature verification FAILED: error %d", r);
		atomic64_inc(&vs->verification_errors);
		return r;
	}
	
	verity_signed_log(vs, KERN_INFO,
			 "Signature verification PASSED");
	vs->metadata_verified = true;
	
	return 0;
}

/* ==================== Build dm-verity Parameters ==================== */

static char **verity_build_argv_from_metadata(struct dm_verity_signed *vs,
					      unsigned int *argc)
{
	struct verity_kernel_metadata *meta = vs->metadata;
	char **argv;
	const char *algo_name;
	int idx = 0;
	
	/* Allocate argv array for verity_ctr */
	argv = kmalloc_array(10, sizeof(char *), GFP_KERNEL);
	if (!argv)
		return NULL;
	
	/* Allocate individual argument strings */
	#define ALLOC_ARG(size) ({ \
		char *arg = kmalloc(size, GFP_KERNEL); \
		if (!arg) goto cleanup; \
		argv[idx++] = arg; \
		arg; \
	})
	
	/* argv[0]: version */
	snprintf(ALLOC_ARG(16), 16, "%u", meta->version);
	
	/* argv[1]: data device - will be filled by caller */
	ALLOC_ARG(256);
	
	/* argv[2]: hash device - will be filled by caller */
	ALLOC_ARG(256);
	
	/* argv[3]: data block size */
	snprintf(ALLOC_ARG(16), 16, "%u", meta->data_block_size);
	
	/* argv[4]: hash block size */
	snprintf(ALLOC_ARG(16), 16, "%u", meta->hash_block_size);
	
	/* argv[5]: number of data blocks */
	snprintf(ALLOC_ARG(32), 32, "%llu", meta->data_blocks);
	
	/* argv[6]: hash start block */
	snprintf(ALLOC_ARG(32), 32, "%llu", meta->hash_start_block);
	
	/* argv[7]: algorithm */
	algo_name = verity_get_algorithm_name(meta->hash_algorithm);
	if (!algo_name)
		goto cleanup;
	snprintf(ALLOC_ARG(16), 16, "%s", algo_name);
	
	/* argv[8]: root digest (hex) */
	{
		char *hex = ALLOC_ARG(meta->root_hash_size * 2 + 1);
		bin2hex(hex, meta->root_hash, meta->root_hash_size);
	}
	
	/* argv[9]: salt (hex or "-") */
	if (meta->salt_size > 0) {
		char *hex = ALLOC_ARG(meta->salt_size * 2 + 1);
		bin2hex(hex, meta->salt, meta->salt_size);
	} else {
		snprintf(ALLOC_ARG(2), 2, "-");
	}
	
	*argc = idx;
	return argv;
	
cleanup:
	while (idx > 0)
		kfree(argv[--idx]);
	kfree(argv);
	return NULL;
}

static void verity_free_argv(char **argv, unsigned int argc)
{
	unsigned int i;
	
	if (!argv)
		return;
	
	for (i = 0; i < argc; i++)
		kfree(argv[i]);
	kfree(argv);
}

/* ==================== Enhanced Verity Callbacks ==================== */

static int verity_signed_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_verity_signed *vs = ti->private;
	int r;
	
	/* Call standard verity map */
	r = verity_map(ti, bio);
	
	if (r == DM_MAPIO_SUBMITTED)
		atomic64_inc(&vs->blocks_verified);
	
	return r;
}

static void verity_signed_status(struct dm_target *ti, status_type_t type,
				 unsigned int status_flags, char *result,
				 unsigned int maxlen)
{
	struct dm_verity_signed *vs = ti->private;
	unsigned int sz = 0;
	
	/* First call base status */
	verity_status(ti, type, status_flags, result, maxlen);
	sz = strlen(result);
	
	/* Add our extended information */
	if (type == STATUSTYPE_INFO) {
		DMEMIT(" verified=%llu errors=%llu uptime=%lld metadata_verified=%d",
		       (unsigned long long)atomic64_read(&vs->blocks_verified),
		       (unsigned long long)atomic64_read(&vs->verification_errors),
		       (s64)ktime_ms_delta(ktime_get(), vs->init_time),
		       vs->metadata_verified);
	}
}

/* ==================== Constructor ==================== */

/*
 * Simplified constructor - bootloader only provides device paths
 * Format: <data_device> <hash_device> [keyring_name]
 * 
 * Everything else is discovered from metadata on the device
 */
static int verity_signed_ctr(struct dm_target *ti, 
			     unsigned int argc, char **argv)
{
	struct dm_verity_signed *vs;
	struct dm_dev *data_dev, *hash_dev;
	char **verity_argv;
	unsigned int verity_argc;
	int r;
	
	verity_signed_log(NULL, KERN_INFO,
			 "Initializing verity-signed target (argc=%u)", argc);
	
	if (argc < 1) {
		ti->error = "Not enough arguments (need: data_device hash_device [keyring])";
		return -EINVAL;
	}
	
	// Determine device paths and optional keyring name
    data_path = argv[0];
    
    if (argc >= 2 && dm_is_valid_name(argv[1])) {
        // Two device paths provided: data_device hash_device
        hash_path = argv[1];
        if (argc >= 3)
            vs->keyring_name = kstrdup(argv[2], GFP_KERNEL);
    } else {
        // One device path provided: Integrated metadata (data_device is also the hash_device)
        hash_path = argv[0]; 
        if (argc >= 2)
            vs->keyring_name = kstrdup(argv[1], GFP_KERNEL);
    }
	/* Allocate our structure */
	vs = kzalloc(sizeof(*vs), GFP_KERNEL);
	if (!vs) {
		ti->error = "Cannot allocate verity-signed structure";
		return -ENOMEM;
	}
	
	ti->private = vs;
	vs->base.ti = ti;
	vs->init_time = ktime_get();
	atomic_set(&vs->log_sequence, 0);
	atomic64_set(&vs->blocks_verified, 0);
	atomic64_set(&vs->verification_errors, 0);
	
	/* Create logging workqueue */
	vs->log_wq = alloc_workqueue("verity_signed_log", WQ_UNBOUND, 0);
	if (!vs->log_wq) {
		ti->error = "Cannot allocate logging workqueue";
		r = -ENOMEM;
		goto bad;
	}
	
	/* Optional keyring name */
	if (argc >= 3) {
		vs->keyring_name = kstrdup(argv[2], GFP_KERNEL);
	}
	
	verity_signed_log(vs, KERN_INFO,
			 "Data device: %s, Hash device: %s",
			 argv[0], argv[1]);
	
	/* Open devices temporarily to discover metadata */
	r = dm_get_device(ti, argv[0], BLK_OPEN_READ, &data_dev);
	if (r) {
		ti->error = "Data device lookup failed";
		verity_signed_log(vs, KERN_ERR, "Cannot open data device: %d", r);
		goto bad;
	}
	
	r = dm_get_device(ti, argv[1], BLK_OPEN_READ, &hash_dev);
	if (r) {
		ti->error = "Hash device lookup failed";
		verity_signed_log(vs, KERN_ERR, "Cannot open hash device: %d", r);
		dm_put_device(ti, data_dev);
		goto bad;
	}
	
	/* Initialize dm-io client for metadata reading */
	vs->base.io = dm_io_client_create();
	if (IS_ERR(vs->base.io)) {
		r = PTR_ERR(vs->base.io);
		vs->base.io = NULL;
		ti->error = "Cannot create dm-io client";
		goto bad_cleanup_devs;
	}
	
	/* Discover metadata from the device */
	r = verity_discover_metadata(vs, data_dev->bdev);
	if (r) {
		ti->error = "Metadata discovery failed";
		goto bad_cleanup_devs;
	}
	
	/* Validate metadata fields */
	r = verity_validate_metadata_fields(vs);
	if (r) {
		ti->error = "Metadata validation failed";
		goto bad_cleanup_devs;
	}
	
	/* Verify signature */
	r = verity_verify_signature(vs);
	if (r) {
		ti->error = "Signature verification failed";
		goto bad_cleanup_devs;
	}
	
	/* Build argv for standard verity constructor */
	verity_argv = verity_build_argv_from_metadata(vs, &verity_argc);
	if (!verity_argv) {
		ti->error = "Cannot build verity arguments";
		r = -ENOMEM;
		goto bad_cleanup_devs;
	}
	
	/* Fill in device names */
	strncpy(verity_argv[1], argv[0], 255);
	strncpy(verity_argv[2], argv[1], 255);
	
	/* Log what we're passing to verity */
	verity_signed_log(vs, KERN_INFO,
			 "Initializing dm-verity with discovered metadata");
	
	/* Release temporary device references */
	dm_put_device(ti, data_dev);
	dm_put_device(ti, hash_dev);
	
	/* Call standard verity constructor */
	r = verity_ctr(ti, verity_argc, verity_argv);
	verity_free_argv(verity_argv, verity_argc);
	
	if (r) {
		verity_signed_log(vs, KERN_ERR,
				 "Base verity initialization failed: %d", r);
		goto bad;
	}
	
	verity_signed_log(vs, KERN_INFO,
			 "Target initialized successfully - signature verified, ready for I/O");
	
	dm_audit_log_ctr(DM_MSG_PREFIX, ti, 1);
	return 0;

bad_cleanup_devs:
	dm_put_device(ti, data_dev);
	dm_put_device(ti, hash_dev);
bad:
	if (vs->base.io)
		dm_io_client_destroy(vs->base.io);
	if (vs->metadata)
		kfree(vs->metadata);
	if (vs->keyring_name)
		kfree(vs->keyring_name);
	if (vs->log_wq)
		destroy_workqueue(vs->log_wq);
	kfree(vs);
	dm_audit_log_ctr(DM_MSG_PREFIX, ti, 0);
	return r;
}

/* ==================== Destructor ==================== */

static void verity_signed_dtr(struct dm_target *ti)
{
	struct dm_verity_signed *vs = ti->private;
	
	if (!vs)
		return;
	
	verity_signed_log(vs, KERN_INFO,
			 "Destroying target - verified %llu blocks, %llu errors",
			 (unsigned long long)atomic64_read(&vs->blocks_verified),
			 (unsigned long long)atomic64_read(&vs->verification_errors));
	
	/* Call base destructor first */
	verity_dtr(ti);
	
	/* Clean up our additions */
	if (vs->metadata)
		kfree(vs->metadata);
	if (vs->keyring_name)
		kfree(vs->keyring_name);
	
	if (vs->log_wq) {
		flush_workqueue(vs->log_wq);
		destroy_workqueue(vs->log_wq);
	}
	
	kfree(vs);
}

/* ==================== Module Registration ==================== */

static struct target_type verity_signed_target = {
	.name		= "verity-signed",
	.features	= DM_TARGET_SINGLETON | DM_TARGET_IMMUTABLE,
	.version	= {1, 2, 0},
	.module		= THIS_MODULE,
	.ctr		= verity_signed_ctr,
	.dtr		= verity_signed_dtr,
	.map		= verity_signed_map,
	.status		= verity_signed_status,
	.prepare_ioctl	= verity_prepare_ioctl,
	.iterate_devices = verity_iterate_devices,
	.io_hints	= verity_io_hints,
	.postsuspend	= verity_postsuspend,
#ifdef CONFIG_SECURITY
	.preresume	= verity_preresume,
#endif
};

static int __init dm_verity_signed_init(void)
{
	int r;
	
	r = dm_register_target(&verity_signed_target);
	if (r < 0) {
		DMERR("register failed %d", r);
	} else {
		DMINFO("version %u.%u.%u loaded - kernel-managed metadata verification",
		       verity_signed_target.version[0],
		       verity_signed_target.version[1],
		       verity_signed_target.version[2]);
	}
	
	return r;
}

static void __exit dm_verity_signed_exit(void)
{
	dm_unregister_target(&verity_signed_target);
	DMINFO("unloaded");
}

module_init(dm_verity_signed_init);
module_exit(dm_verity_signed_exit);

MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION(DM_NAME " kernel-managed signed verification target");
MODULE_LICENSE("GPL");