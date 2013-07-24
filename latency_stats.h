#ifndef _HOT_LATENCY_STATS_H_
#define _HOT_LATENCY_STATS_H_

#include <linux/types.h>

/* 300s is max disk I/O latency which application may accept */
#define HOT_LATENCY_STATS_S_NR		100
#define HOT_LATENCY_STATS_S_GRAINSIZE	(1000/HOT_LATENCY_STATS_S_NR)
#define HOT_LATENCY_STATS_MS_NR		100
#define HOT_LATENCY_STATS_MS_GRAINSIZE	(1000/HOT_LATENCY_STATS_MS_NR)

struct latency_stats {
	/* latency statistic buckets */
	atomic_t latency_stats_s[HOT_LATENCY_STATS_S_NR];
	atomic_t latency_stats_ms[HOT_LATENCY_STATS_MS_NR];
};

int init_latency_stats(void);
void exit_latency_stats(void);

struct latency_stats *create_latency_stats(void);
void destroy_latency_stats(struct latency_stats *lstats);

void update_latency_stats(struct latency_stats *lstats, unsigned long stime);

#endif
