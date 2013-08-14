#ifndef _IO_LATENCY_STATS_H_
#define _IO_LATENCY_STATS_H_

#include <linux/types.h>

/* 300s is max disk I/O latency which application may accept */
#define IO_LATENCY_STATS_S_NR		100
#define IO_LATENCY_STATS_S_GRAINSIZE	(1000/IO_LATENCY_STATS_S_NR)
#define IO_LATENCY_STATS_MS_NR		100
#define IO_LATENCY_STATS_MS_GRAINSIZE	(1000/IO_LATENCY_STATS_MS_NR)
#define IO_LATENCY_STATS_US_NR		100
#define IO_LATENCY_STATS_US_GRAINSIZE	(1000/IO_LATENCY_STATS_S_NR)

#define IO_SIZE_MAX			(1024 * 1024)
#define IO_SIZE_STATS_GRAINSIZE		4096
#define IO_SIZE_STATS_NR		(IO_SIZE_MAX / IO_SIZE_STATS_GRAINSIZE)

struct latency_stats {
	/* latency statistic buckets */
	unsigned long latency_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long latency_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long latency_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long latency_read_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long latency_read_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long latency_read_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long latency_write_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long latency_write_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long latency_write_stats_us[IO_LATENCY_STATS_US_NR];
	/* latency statistic for block-layer buckets */
	unsigned long soft_latency_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long soft_latency_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long soft_latency_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long soft_latency_read_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long soft_latency_read_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long soft_latency_read_stats_us[IO_LATENCY_STATS_US_NR];
	unsigned long soft_latency_write_stats_s[IO_LATENCY_STATS_S_NR];
	unsigned long soft_latency_write_stats_ms[IO_LATENCY_STATS_MS_NR];
	unsigned long soft_latency_write_stats_us[IO_LATENCY_STATS_US_NR];
	/* io size statistic buckets */
	unsigned long io_size_stats[IO_SIZE_STATS_NR];
	unsigned long io_read_size_stats[IO_SIZE_STATS_NR];
	unsigned long io_write_size_stats[IO_SIZE_STATS_NR];
};

int init_latency_stats(void);
void exit_latency_stats(void);

struct latency_stats __percpu *create_latency_stats(void);
void destroy_latency_stats(struct latency_stats __percpu *lstats);

void update_latency_stats(struct latency_stats *lstats, unsigned long stime,
			unsigned long now, int soft, int rw);
void update_io_size_stats(struct latency_stats *lstats, unsigned long size,
			int rw);
void reset_latency_stats(struct latency_stats __percpu *lstats);
#endif
