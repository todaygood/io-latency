#ifndef _IO_LATENCY_HASH_TABLE_H_
#define _IO_LATENCY_HASH_TABLE_H_

#include <linux/slab.h>

struct hash_table {
	struct hlist_head *tbl;
	struct kmem_cache *cache;
	int nr_ent;
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
#endif
