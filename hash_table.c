#include "hash_table.h"

static int compute_hash(struct hash_table *table, unsigned long key)
{
	return (int)(key % table->nr_ent);
}

struct hash_node *hash_table_find(struct hash_table *table, unsigned long key)
{
	struct hlist_head *hp;
	struct hlist_node *hn;
	struct hash_node *nd;

	hp = &(table->tbl[compute_hash(table, key)]);
	hlist_for_each_entry(nd, hn, hp, node) {
		if (nd->key == key)
			return nd;
	}
	return NULL;
}

struct hash_table *create_hash_table(int nr_ent)
{
	struct hash_table *table;

	table = kzalloc(sizeof(struct hash_table), GFP_KERNEL);
	if (!table)
		return NULL;

	table->tbl = kzalloc(sizeof(struct hlist_head) * nr_ent, GFP_KERNEL);
	if (!table->tbl) {
		kfree(table);
		return NULL;
	}

	table->cache = kmem_cache_create("hot-latency-hash-table",
				sizeof(struct hash_node), 0, 0, NULL);
	if (!table->cache) {
		kfree(table->tbl);
		kfree(table);
		return NULL;
	}
	table->nr_ent = nr_ent;
	return table;
}

void destroy_hash_table(struct hash_table *table)
{
	if (table->cache)
		kmem_cache_destroy(table->cache);
	kfree(table->tbl);
	kfree(table);
}

int hash_table_insert(struct hash_table *table, unsigned long key,
			unsigned long value)
{
	struct hlist_head *hp;
	struct hash_node *nd;
	nd = hash_table_find(table, key);

	if (nd)
		return -EEXIST;

	nd = kmem_cache_zalloc(table->cache, GFP_KERNEL);
	if (!nd)
		return -ENOMEM;

	hp = &table->tbl[compute_hash(table, key)];
	nd->key = key;
	nd->value = value;
	hlist_add_head(&nd->node, hp);
	return 0;
}

int hash_table_remove(struct hash_table *table, unsigned long key)
{
	struct hash_node *nd;
	nd = hash_table_find(table, key);

	if (!nd)
		return -ENODEV;
	hlist_del_init(&nd->node);
	kmem_cache_free(table->cache, nd);
	return 0;
}

int hash_table_find_and_remove(struct hash_table *table, unsigned long key,
				unsigned long *value)
{
	struct hash_node *nd;
	nd = hash_table_find(table, key);
	if (!nd)
		return -ENODEV;
	if (value)
		*value = nd->value;
	hlist_del_init(&nd->node);
	kmem_cache_free(table->cache, nd);
	return 0;
}
