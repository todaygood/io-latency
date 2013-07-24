#ifndef _IO_LATENCY_STATS_H_
#define _IO_LATENCY_STATS_H_

#include <linux/types.h>

/* 300s is max disk I/O latency which application may accept */
#define IO_LATENCY_STATS_S_NR		100
#define IO_LATENCY_STATS_S_GRAINSIZE	(1000/IO_LATENCY_STATS_S_NR)
#define IO_LATENCY_STATS_MS_NR		100
#define IO_LATENCY_STATS_MS_GRAINSIZE	(1000/IO_LATENCY_STATS_MS_NR)

struct latency_stats {
	/* latency statistic buckets */
	atomic_t latency_stats_s[IO_LATENCY_STATS_S_NR];
	atomic_t latency_stats_ms[IO_LATENCY_STATS_MS_NR];
};

int init_latency_stats(void);
void exit_latency_stats(void);

struct latency_stats *create_latency_stats(void);
void destroy_latency_stats(struct latency_stats *lstats);

void update_latency_stats(struct latency_stats *lstats, unsigned long stime);

#endif
