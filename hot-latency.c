#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/blkdev.h>

#include "hotfixes.h"

#define HOTFIX_PEEK_REQUEST	0
#define HOTFIX_PUT_REQUEST	1

static struct request* (*p_blk_peek_request)(struct request_queue *q);
void (*p_blk_put_request)(struct request *req);

static struct ali_sym_addr hot_latency_sym_addr_list[] = {
	ALI_DEFINE_SYM_ADDR(blk_peek_request),
	ALI_DEFINE_SYM_ADDR(blk_put_request),
	{},
};

static struct request* overwrite_blk_peek_request(struct request_queue *q);
static void overwrite_blk_put_request(struct request *req);

static struct ali_hotfix_desc hot_latency_hotfix_list[] = {

	[HOTFIX_PEEK_REQUEST] = ALI_DEFINE_HOTFIX(\
			"block: blk_peek_request", \
			"blk_peek_request", \
			overwrite_blk_peek_request),

	[HOTFIX_PUT_REQUEST] = ALI_DEFINE_HOTFIX(\
			"block: blk_put_request", \
			"blk_put_request", \
			overwrite_blk_put_request),

	{},
};

static struct request* (*orig_blk_peek_request)(struct request_queue *q);
static struct request* overwrite_blk_peek_request(struct request_queue *q)
{
	struct request *req;
	orig_blk_peek_request =
		ali_hotfix_orig_func(&hot_latency_hotfix_list[HOTFIX_PEEK_REQUEST]);
	req = orig_blk_peek_request(q);
	printk("%p\n", req);
	return req;
}

static void (*orig_blk_put_request)(struct request *req);
static void overwrite_blk_put_request(struct request *req)
{
	printk("%p\n", req);
	orig_blk_put_request =
		ali_hotfix_orig_func(&hot_latency_hotfix_list[HOTFIX_PUT_REQUEST]);
	orig_blk_put_request(req);
}

static int __init hot_latency_init(void)
{
	int r;

	if (ali_get_symbol_address_list(hot_latency_sym_addr_list, &r)) {
		printk("Can't get address of %s\n", hot_latency_sym_addr_list[r].name);
		return -EINVAL;
	}

	r = ali_hotfix_register_list(hot_latency_hotfix_list);
	if (r)
		return r;

	if (!ali_hotfix_orig_func(&hot_latency_hotfix_list[HOTFIX_PUT_REQUEST])) {
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
MODULE_LICENSE("GPL");
