#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

#include <linux/blkdev.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <scsi/scsi_device.h>

#include "hotfixes.h"
#include "hash_table.h"
#include "latency_stats.h"

#define HOTFIX_PEEK_REQUEST	0
#define HOTFIX_END_BIDI_REQUEST	1

#define MAX_REQUEST_QUEUE	100
#define MAX_REQUESTS		10000

/* /proc/io-latency/sda/
 * /proc/io-latency/sda/io_latency_s
 * /proc/io-latency/sda/io_latency_ms
 * /proc/io-latency/sda/io_latency_us
 * /proc/io-latency/sda/io_latency_reset
 */
#define NR_PROC_TYPE		5

static struct proc_dir_entry *proc_io_latency;
static struct class *sd_disk_class;
static struct hash_table *request_queue_table;
static struct hash_table *request_table;

struct proc_entry_name {
	struct proc_dir_entry *entry;
	struct proc_dir_entry *parent;
	char name[64];
};

static struct proc_entry_name *dir_proc_list;
static int nr_dir_proc;

static void add_proc_node(const char *name, struct proc_dir_entry *node,
			struct proc_dir_entry *parent)
{
	dir_proc_list[nr_dir_proc].entry = node;
	dir_proc_list[nr_dir_proc].parent = parent;
	strncpy(dir_proc_list[nr_dir_proc].name, name, 64);
	nr_dir_proc++;
}

static void delete_procfs(void);

static struct request* (*p_blk_peek_request)(struct request_queue *q);
static bool (*p_blk_end_bidi_request)(struct request *req, int error,
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

static struct ali_sym_addr io_latency_sym_addr_list[] = {
	ALI_DEFINE_SYM_ADDR(blk_peek_request),
	ALI_DEFINE_SYM_ADDR(blk_end_bidi_request),
	{},
};

static struct request* overwrite_blk_peek_request(struct request_queue *q);
static bool overwrite_blk_end_bidi_request(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes);

static struct ali_hotfix_desc io_latency_hotfix_list[] = {

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
		ali_hotfix_orig_func(&io_latency_hotfix_list[HOTFIX_PEEK_REQUEST]);
	req = orig_blk_peek_request(q);
	if (req)
		hash_table_insert(request_table, (unsigned long)req, jiffies);
	return req;
}

static bool (*orig_blk_end_bidi_request)(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes);
static bool overwrite_blk_end_bidi_request(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes)
{
	struct hash_node *nd;
	struct latency_stats *lstats;
	unsigned long stime;
	int res;

	orig_blk_end_bidi_request =
		ali_hotfix_orig_func(
			&io_latency_hotfix_list[HOTFIX_END_BIDI_REQUEST]);
	if (req) {
		res = hash_table_find_and_remove(request_table,
				(unsigned long)req, &stime);
		if (!res) {
			nd = hash_table_find(request_queue_table,
					(unsigned long)(req->q));
			if (nd) {
				lstats = (struct latency_stats *)nd->value;
				update_latency_stats(lstats, stime);
			}
		}
	}
	return orig_blk_end_bidi_request(req, error, nr_bytes, bidi_bytes);
}

static void *PDE_DATA(const struct inode *inode)
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

static ssize_t io_latency_ms_show(struct latency_stats *lstats, char *buf)
{
	int slot_base = 0;
	int i, nr, ptr;

	for (ptr = 0, i = 0; i < IO_LATENCY_STATS_MS_NR; i++) {
		nr = sprintf(buf + ptr,
			"%d-%d(ms):%d\n",
			slot_base,
			slot_base + IO_LATENCY_STATS_MS_GRAINSIZE - 1,
			atomic_read(&(lstats->latency_stats_ms[i])));
		if (nr < 0)
			break;

		slot_base += IO_LATENCY_STATS_MS_GRAINSIZE;
		ptr += nr;
	}

	return strlen(buf);
}

static int io_latency_seq_show(struct seq_file *seq, void *v)
{
	struct request_queue *q = seq->private;
	struct latency_stats *lstats;
	struct hash_node *nd;
	static char buf[4096];

	nd = hash_table_find(request_queue_table, (unsigned long)q);
	if (!nd)
		seq_puts(seq, "none");
	else {
		lstats = (struct latency_stats *)nd->value;
		io_latency_ms_show(lstats, buf);
		seq_puts(seq, buf);
	}
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

static const struct file_operations proc_io_latency_fops = {
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
	struct proc_dir_entry *proc_node, *proc_dir;
	struct latency_stats *lstats;

	proc_io_latency = proc_mkdir("io-latency", NULL);
	if (!proc_io_latency)
		goto err;

	dir_proc_list = kzalloc(sizeof(struct proc_entry_name) *
			MAX_REQUEST_QUEUE * NR_PROC_TYPE, GFP_KERNEL);
	if (!dir_proc_list)
		goto err;

	class_dev_iter_init(&iter, sd_disk_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {
		sd = container_of(dev, struct scsi_disk, dev);
		proc_dir = proc_mkdir(sd->disk->disk_name, proc_io_latency);
		if (!proc_dir)
			goto err;
		add_proc_node(sd->disk->disk_name, proc_dir, proc_io_latency);
		proc_node = proc_create_data("io_latency_ms", 0, proc_dir,
					&proc_io_latency_fops,
					sd->device->request_queue);
		add_proc_node("io_latency_ms", proc_node, proc_dir);
		/*
		sprintf(node_name, "%s/io_latency_reset", dev_name);
		proc_create_data(node_name, 0, NULL, proc_io_latency_reset,
				sd->device->request_queue);*/
		lstats = create_latency_stats();
		hash_table_insert(request_queue_table,
				(unsigned long)(sd->device->request_queue),
				(unsigned long)lstats);
	}
	class_dev_iter_exit(&iter);

	return 0;
err:
	delete_procfs();
	if (proc_io_latency)
		remove_proc_entry("io-latency", NULL);
	return -ENOMEM;
}

int free_io_latency_stats(struct hash_node *nd)
{
	struct latency_stats *lstats = (struct latency_stats *)nd->value;
	destroy_latency_stats(lstats);
	nd->value = 0;
	return 0;
}

void delete_procfs(void)
{
	struct proc_dir_entry *proc_node;
	int i;

	if (dir_proc_list) {
		for (i = MAX_REQUEST_QUEUE * NR_PROC_TYPE - 1; i >= 0; i--) {
			proc_node = dir_proc_list[i].entry;
			if (proc_node) {
				remove_proc_entry(dir_proc_list[i].name,
						dir_proc_list[i].parent);
				printk("remove %s %p\n", dir_proc_list[i].name,
						dir_proc_list[i].parent);
			}
			memset(dir_proc_list + i, 0,
					sizeof(struct proc_entry_name));
		}
	}
	if (proc_io_latency) {
		proc_io_latency = NULL;
		remove_proc_entry("io-latency", NULL);
	}
	if (request_queue_table)
		call_for_each_hash_node(request_queue_table,
				free_io_latency_stats);
}

static int __init io_latency_init(void)
{
	int res;

	if (ali_get_symbol_address_list(io_latency_sym_addr_list, &res)) {
		printk("Can't get address of %s\n",
				io_latency_sym_addr_list[res].name);
		return -EINVAL;
	}

	res = ali_hotfix_register_list(io_latency_hotfix_list);
	if (res)
		return res;

	if (!ali_hotfix_orig_func(
			&io_latency_hotfix_list[HOTFIX_END_BIDI_REQUEST])) {
		printk("Register fail\n");
		res = -ENODEV;
		goto err;
	}

	sd_disk_class = (struct class *)kallsyms_lookup_name("sd_disk_class");
	if (!sd_disk_class) {
		res = -EINVAL;
		goto err;
	}

	request_queue_table = create_hash_table("request_queue_table",
						MAX_REQUEST_QUEUE);
	if (!request_queue_table) {
		res = -ENOMEM;
		goto err;
	}

	request_table = create_hash_table("request_table", MAX_REQUESTS);
	if (!request_table) {
		res = -ENOMEM;
		goto err;
	}

	res = init_latency_stats();
	if (res)
		goto err;

	/* create /proc/io-latency/ */
	res = create_procfs();
	if (res)
		goto err;

	return 0;
err:
	ali_hotfix_unregister_list(io_latency_hotfix_list);
	return res;
}

static void __exit io_latency_exit(void)
{
	delete_procfs();
	exit_latency_stats();
	destroy_hash_table(request_table);
	destroy_hash_table(request_queue_table);
	ali_hotfix_unregister_list(io_latency_hotfix_list);
}

module_init(io_latency_init)
module_exit(io_latency_exit)
MODULE_AUTHOR("Robin Dong <sanbai@taobao.com>");
MODULE_DESCRIPTION("Collect statistics about io-latency");
MODULE_LICENSE("GPL");