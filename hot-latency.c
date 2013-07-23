#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

#include <linux/blkdev.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <scsi/scsi_device.h>

#include "hotfixes.h"
#include "hash_table.h"

#define HOTFIX_PEEK_REQUEST	0
#define HOTFIX_END_BIDI_REQUEST	1

#define HASH_MAX_REQUEST_QUEUE	100

static struct proc_dir_entry *proc_hot_latency;
static struct class *sd_disk_class;
static struct hash_table *request_queue_list;

static struct request* (*p_blk_peek_request)(struct request_queue *q);
bool (*p_blk_end_bidi_request)(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes);

struct scsi_disk {
	struct scsi_driver *driver;	/* always &sd_template */
	struct scsi_device *device;
	struct device	dev;
	struct gendisk	*disk;
	atomic_t	openers;
	sector_t	capacity;	/* size in 512-byte sectors */
	u32		max_ws_blocks;
	u32		max_unmap_blocks;
	u32		unmap_granularity;
	u32		unmap_alignment;
	u32		index;
	unsigned int	physical_block_size;
	unsigned int	max_medium_access_timeouts;
	unsigned int	medium_access_timed_out;
	u8		media_present;
	u8		write_prot;
	u8		protection_type;/* Data Integrity Field */
	u8		provisioning_mode;
	unsigned	ATO : 1;	/* state of disk ATO bit */
	unsigned	cache_override : 1; /* temp override of WCE,RCD */
	unsigned	WCE : 1;	/* state of disk WCE bit */
	unsigned	RCD : 1;	/* state of disk RCD bit, unused */
	unsigned	DPOFUA : 1;	/* state of disk DPOFUA bit */
	unsigned	first_scan : 1;
	unsigned	lbpme : 1;
	unsigned	lbprz : 1;
	unsigned	lbpu : 1;
	unsigned	lbpws : 1;
	unsigned	lbpws10 : 1;
	unsigned	lbpvpd : 1;
	unsigned	ws10 : 1;
	unsigned	ws16 : 1;
};

static struct ali_sym_addr hot_latency_sym_addr_list[] = {
	ALI_DEFINE_SYM_ADDR(blk_peek_request),
	ALI_DEFINE_SYM_ADDR(blk_end_bidi_request),
	{},
};

static struct request* overwrite_blk_peek_request(struct request_queue *q);
static bool overwrite_blk_end_bidi_request(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes);

static struct ali_hotfix_desc hot_latency_hotfix_list[] = {

	[HOTFIX_PEEK_REQUEST] = ALI_DEFINE_HOTFIX( \
			"block: blk_peek_request", \
			"blk_peek_request", \
			overwrite_blk_peek_request),

	[HOTFIX_END_BIDI_REQUEST] = ALI_DEFINE_HOTFIX( \
			"block: blk_end_bidi_request", \
			"blk_end_bidi_request", \
			overwrite_blk_end_bidi_request),

	{},
};

static struct request* (*orig_blk_peek_request)(struct request_queue *q);
static struct request* overwrite_blk_peek_request(struct request_queue *q)
{
	struct request *req;
	orig_blk_peek_request =
		ali_hotfix_orig_func(&hot_latency_hotfix_list[HOTFIX_PEEK_REQUEST]);
	req = orig_blk_peek_request(q);
	if (req)
		printk("peek %p\n", req);
	return req;
}

static bool (*orig_blk_end_bidi_request)(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes);
static bool overwrite_blk_end_bidi_request(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes)
{
	struct hash_node *nd;
	orig_blk_end_bidi_request =
		ali_hotfix_orig_func(
			&hot_latency_hotfix_list[HOTFIX_END_BIDI_REQUEST]);
	if (req) {
		printk("end %p %p\n", req, req->q);
		nd = hash_table_find(request_queue_list,
				(unsigned long)(req->q));
		if (nd)
			nd->value++;
	}
	return orig_blk_end_bidi_request(req, error, nr_bytes, bidi_bytes);
}

void *PDE_DATA(const struct inode *inode)
{
	return container_of(inode, struct proc_inode, vfs_inode)->pde->data;
}

static void *io_latency_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? NULL : SEQ_START_TOKEN;
}

static void *io_latency_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

static void io_latency_seq_stop(struct seq_file *seq, void *v)
{
}

static int io_latency_seq_show(struct seq_file *seq, void *v)
{
	struct request_queue *q = seq->private;
	struct hash_node *nd;

	nd = hash_table_find(request_queue_list, (unsigned long)q);
	if (!nd)
		seq_puts(seq, "none");
	else
		seq_printf(seq, "%lu\n", nd->value);
	return 0;
}

static const struct seq_operations io_latency_seq_ops = {
	.start  = io_latency_seq_start,
	.next   = io_latency_seq_next,
	.stop   = io_latency_seq_stop,
	.show   = io_latency_seq_show,
};

static int proc_io_latency_open(struct inode *inode, struct file *file)
{
	int res;
	res = seq_open(file, &io_latency_seq_ops);
	if (res == 0) {
		struct seq_file *m = file->private_data;
		m->private = PDE_DATA(inode);
	}
	return res;
}

static const struct file_operations proc_io_latency = {
	.owner		= THIS_MODULE,
	.open		= proc_io_latency_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int create_procfs(void)
{
	struct class_dev_iter iter;
	struct device *dev;
	struct scsi_disk *sd;
	struct proc_dir_entry *proc_node;

	proc_hot_latency = proc_mkdir("hot-latency", NULL);
	if (!proc_hot_latency)
		goto err1;

	class_dev_iter_init(&iter, sd_disk_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {
		sd = container_of(dev, struct scsi_disk, dev);
		proc_node = proc_mkdir(sd->disk->disk_name, proc_hot_latency);
		if (!proc_node)
			printk("%s create fail\n", sd->disk->disk_name);
		proc_create_data("io_latency_ms", 0, proc_node,
				&proc_io_latency, sd->device->request_queue);
		/*
		sprintf(node_name, "%s/io_latency_reset", dev_name);
		proc_create_data(node_name, 0, NULL, proc_io_latency_reset,
				sd->device->request_queue);*/
		hash_table_insert(request_queue_list,
				(unsigned long)(sd->device->request_queue),
				0);
		printk("queue:%p\n", sd->device->request_queue);
	}
	class_dev_iter_exit(&iter);

	return 0;
err1:
	return -ENOMEM;
}

static void delete_procfs(void)
{
	if (proc_hot_latency) {
		proc_hot_latency = NULL;
		remove_proc_entry("hot-latency", NULL);
	}
}

static int __init hot_latency_init(void)
{
	int r;

	if (ali_get_symbol_address_list(hot_latency_sym_addr_list, &r)) {
		printk("Can't get address of %s\n",
				hot_latency_sym_addr_list[r].name);
		return -EINVAL;
	}

	r = ali_hotfix_register_list(hot_latency_hotfix_list);
	if (r)
		return r;

	if (!ali_hotfix_orig_func(
			&hot_latency_hotfix_list[HOTFIX_END_BIDI_REQUEST])) {
		printk("Register fail\n");
		ali_hotfix_unregister_list(hot_latency_hotfix_list);
		return -ENODEV;
	}

	sd_disk_class = (struct class *)kallsyms_lookup_name("sd_disk_class");
	if (!sd_disk_class) {
		ali_hotfix_unregister_list(hot_latency_hotfix_list);
		return -EINVAL;
	}

	request_queue_list = create_hash_table(HASH_MAX_REQUEST_QUEUE);
	if (!request_queue_list) {
		ali_hotfix_unregister_list(hot_latency_hotfix_list);
		return -ENOMEM;
	}
	/* create /proc/hot-latency/ */
	r = create_procfs();
	if (r)
		return r;

	return 0;
}

static void __exit hot_latency_exit(void)
{
	delete_procfs();
	destroy_hash_table(request_queue_list);
	ali_hotfix_unregister_list(hot_latency_hotfix_list);
}

module_init(hot_latency_init)
module_exit(hot_latency_exit)
MODULE_AUTHOR("Robin Dong <sanbai@taobao.com>");
MODULE_DESCRIPTION("Collect statistics about io-latency");
MODULE_LICENSE("GPL");
