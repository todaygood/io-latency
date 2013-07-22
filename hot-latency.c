#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/blkdev.h>

#include "hotfixes.h"

#define HOTFIX_PEEK_REQUEST	0
#define HOTFIX_END_BIDI_REQUEST	1

static struct request* (*p_blk_peek_request)(struct request_queue *q);
bool (*p_blk_end_bidi_request)(struct request *req, int error,
		unsigned int nr_bytes, unsigned int bidi_bytes);

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
	orig_blk_end_bidi_request =
		ali_hotfix_orig_func(
			&hot_latency_hotfix_list[HOTFIX_END_BIDI_REQUEST]);
	if (req)
		printk("end %p\n", req);
	return orig_blk_end_bidi_request(req, error, nr_bytes, bidi_bytes);
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
	return 0;
}

static void __exit hot_latency_exit(void)
{
	ali_hotfix_unregister_list(hot_latency_hotfix_list);
}

module_init(hot_latency_init)
module_exit(hot_latency_exit)
MODULE_AUTHOR("Robin Dong <sanbai@taobao.com>");
MODULE_DESCRIPTION("Collect statistics about io-latency");
MODULE_LICENSE("GPL");
