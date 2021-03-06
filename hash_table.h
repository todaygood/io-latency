#ifndef _IO_LATENCY_HASH_TABLE_H_
#define _IO_LATENCY_HASH_TABLE_H_

#include <linux/slab.h>

#define MAX_HASH_TABLE_NAME_LEN		64

struct hash_table {
	struct hlist_head *tbl;
	struct kmem_cache *cache;
	char name[MAX_HASH_TABLE_NAME_LEN];
	int nr_ent;
	int nr_node;
};

struct hash_node {
	struct hlist_node node;
	unsigned long key;
	unsigned long value;
};

struct hash_table *create_hash_table(const char *name, int nr_ent);
void destroy_hash_table(struct hash_table *table);

int hash_table_insert(struct hash_table *table, unsigned long key,
			unsigned long value);
int hash_table_remove(struct hash_table *table, unsigned long key);

struct hash_node *hash_table_find(struct hash_table *table, unsigned long key);
int hash_table_find_and_remove(struct hash_table *table, unsigned long key,
				unsigned long *value);

void call_for_each_hash_node(struct hash_table *table,
			int (*func)(struct hash_node *nd));

#endif
