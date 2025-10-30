// init/verity_autoconfig.c
// SPDX-License-Identifier: GPL-2.0-only
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/verification.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/init.h>

extern char *saved_command_line;
extern unsigned int saved_command_line_len;
/* We'll also update static_command_line in main.c via a helper */
void __init verity_autoconfig_cmdline_append(const char *extra);

static int parse_kv_line(const char *s, const char *key, char *out, size_t outlen)
{
	size_t klen = strlen(key);
	if (strncmp(s, key, klen) == 0 && s[klen] == '=') {
		strscpy(out, s + klen + 1, outlen);
		return 0;
	}
	return -ENOENT;
}

static int read_at(struct file *filp, loff_t pos, void *buf, size_t len)
{
    ssize_t r = kernel_read(filp, buf, len, &pos);
    if (r < 0)
        return r;
    if (r != len)
        return -EIO;
    return 0;
}


static int __init verity_autoconfig_run(void)
{
	struct file *rootf = NULL;
	loff_t sz, foot_off;
	u8 *page = NULL, *meta = NULL, *p7s = NULL;
	char roothash[129] = {0}, salt[129] = {0}, offset_str[64] = {0};
	char *cmd_root = NULL, *devpath = NULL;
	int ret = 0;

	/* 1) Find root device from the original cmdline (expect root=/dev/vda2) */
	{
		const char *cmd = saved_command_line;
		const char *root_eq = strstr(cmd, "root=");
		if (!root_eq) {
			pr_info("[verity] no root= found; skipping kernel verity auto-setup\n");
			return 0;
		}
		root_eq += 5;
		const char *sp = strpbrk(root_eq, " \t");
		size_t n = sp ? (size_t)(sp - root_eq) : strlen(root_eq);
		cmd_root = kzalloc(n + 1, GFP_KERNEL);
		if (!cmd_root) return -ENOMEM;
		memcpy(cmd_root, root_eq, n);
	}

	/* If user already set root=/dev/mapper/..., do nothing */
	if (strstr(cmd_root, "/dev/mapper/")) {
		pr_info("[verity] root already mapper device; skipping\n");
		goto out;
	}

	/* 2) Open the root block device node */
	devpath = cmd_root;
	rootf = filp_open(devpath, O_RDONLY | O_LARGEFILE, 0);
	if (IS_ERR(rootf)) {
		pr_err("[verity] cannot open %s\n", devpath);
		ret = PTR_ERR(rootf);
		rootf = NULL;
		goto out;
	}

	/* 3) Read 4K footer at end of device */
	{
		sz = i_size_read(file_inode(rootf));
		if (sz < 4096) { ret = -EINVAL; goto out; }
		foot_off = sz - 4096;
		page = kzalloc(4096, GFP_KERNEL);
		if (!page) { ret = -ENOMEM; goto out; }
		ret = read_at(rootf, foot_off, page, 4096);
		if (ret) goto out;

		if (memcmp(page, "VERITYMETA1", 11) != 0) {
			pr_info("[verity] metadata footer magic not found; skipping\n");
			ret = 0; goto out;
		}
		__le32 *hdr = (__le32 *)(page + 12); /* meta_len, p7s_len, reserved */
		u32 meta_len = le32_to_cpu(hdr[0]);
		u32 p7s_len  = le32_to_cpu(hdr[1]);

		if (meta_len + p7s_len > 4096 - 16) { ret = -EINVAL; goto out; }
		meta = kzalloc(meta_len + 1, GFP_KERNEL);
		p7s  = kzalloc(p7s_len, GFP_KERNEL);
		if (!meta || !p7s) { ret = -ENOMEM; goto out; }

		memcpy(meta, page + 16, meta_len);
		memcpy(p7s,  page + 16 + meta_len, p7s_len);

		/* 4) Verify PKCS#7 over the plain-text metadata using system keyring */
		ret = verify_pkcs7_signature(meta, meta_len, p7s, p7s_len, NULL,
					     VERIFYING_UNSPECIFIED_SIGNATURE,
					     NULL, NULL);
		if (ret) {
			pr_err("[verity] PKCS#7 verification FAILED (%d)\n", ret);
			goto out;
		}

		/* 5) Parse lines: roothash=…, salt=…, offset=… */
		{
			char *line, *cur = meta, *end = meta + meta_len;
			while (cur < end && (line = strsep(&cur, "\n"))) {
				parse_kv_line(line, "roothash", roothash, sizeof(roothash));
				parse_kv_line(line, "salt",     salt,     sizeof(salt));
				parse_kv_line(line, "offset",   offset_str, sizeof(offset_str));
			}
			if (!roothash[0] || !salt[0] || !offset_str[0]) {
				pr_err("[verity] metadata missing fields\n");
				ret = -EINVAL; goto out;
			}
		}
	}

	/* 6) Build dm-mod.create and root override and inject into cmdline */
	{
		/* dm-mod.create="verity-root,,,ro,0 <offset> verity-signed <dev> <roothash> <salt>" */
		char buf[1024];
		snprintf(buf, sizeof(buf),
		         " dm-mod.create=\"verity-root,,,ro,0 %s verity %s %s %s\""
		         " root=/dev/mapper/verity-root ro",
		         offset_str, devpath, roothash, salt);
		pr_info("[verity] enabling kernel dm-verity for %s\n", devpath);
		verity_autoconfig_cmdline_append(buf);
	}

out:
	if (rootf) filp_close(rootf, NULL);
	kfree(page);
	kfree(meta);
	kfree(p7s);
	kfree(cmd_root);
	return 0;
}

/* Called from start_kernel() after setup_command_line() but before parsing */
void __init verity_autoconfig(void)
{
	(void) verity_autoconfig_run();
}
