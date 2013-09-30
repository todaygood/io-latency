/*
 * latency_stats.c
 *
 * informations for IO latency and size
 *
 * Copyright (C) 2013,  Coly Li <i@coly.li>
 * 			Robin Dong <sanbai@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License, version 2,  as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#include <asm-generic/div64.h>
#include <linux/slab.h>
#include <linux/clocksource.h>
#include <linux/percpu.h>

#include "latency_stats.h"

static struct kmem_cache *latency_stats_cache;

static unsigned long long us2msecs(unsigned long long usec)
{
	usec += 500;
	do_div(usec, 1000);
	return usec;
}

static unsigned long long us2secs(unsigned long long usec)
{
	usec += 500;
	do_div(usec, 1000);
	usec += 500;
	do_div(usec, 1000);
	return usec;
}

/*
static unsigned long long ms2secs(unsigned long long msec)
{
	msec += 500;
	do_div(msec, 1000);
	return msec;
}*/

int init_latency_stats(void)
{
	latency_stats_cache = kmem_cache_create("io-latency-stats",
			sizeof(struct latency_stats), 0, 0, NULL);
	if (!latency_stats_cache)
		return -ENOMEM;
	return 0;
}

void exit_latency_stats(void)
{
	if (latency_stats_cache) {
		kmem_cache_destroy(latency_stats_cache);
		latency_stats_cache = NULL;
	}
}

void reset_latency_stats(struct latency_stats __percpu *lstats)
{
	int r, cpu;
	struct latency_stats *pstats;

	for_each_possible_cpu(cpu) {
		pstats = per_cpu_ptr(lstats, cpu);
		/* reset latency stats buckets */
		for (r = 0; r < IO_LATENCY_STATS_S_NR; r++) {
			pstats->latency_stats_s[r] = 0;
			pstats->latency_read_stats_s[r] = 0;
			pstats->latency_write_stats_s[r] = 0;
			pstats->soft_latency_stats_s[r] = 0;
			pstats->soft_latency_read_stats_s[r] = 0;
			pstats->soft_latency_write_stats_s[r] = 0;
		}
		for (r = 0; r < IO_LATENCY_STATS_MS_NR; r++) {
			pstats->latency_stats_ms[r] = 0;
			pstats->latency_read_stats_ms[r] = 0;
			pstats->latency_write_stats_ms[r] = 0;
			pstats->soft_latency_stats_ms[r] = 0;
			pstats->soft_latency_read_stats_ms[r] = 0;
			pstats->soft_latency_write_stats_ms[r] = 0;
		}
		for (r = 0; r < IO_LATENCY_STATS_US_NR; r++) {
			pstats->latency_stats_us[r] = 0;
			pstats->latency_read_stats_us[r] = 0;
			pstats->latency_write_stats_us[r] = 0;
			pstats->soft_latency_stats_us[r] = 0;
			pstats->soft_latency_read_stats_us[r] = 0;
			pstats->soft_latency_write_stats_us[r] = 0;
		}
		for (r = 0; r < IO_SIZE_STATS_NR; r++) {
			pstats->io_size_stats[r] = 0;
			pstats->io_read_size_stats[r] = 0;
			pstats->io_write_size_stats[r] = 0;
		}
	}
}

struct latency_stats __percpu *create_latency_stats(void)
{
	return alloc_percpu(struct latency_stats);
}

void destroy_latency_stats(struct latency_stats __percpu *lstats)
{
	if (lstats)
		free_percpu(lstats);
}

#define INC_LATENCY(lstats, idx, soft, rw, grain)			\
do {									\
									\
if (soft) {								\
	lstats->soft_latency_stats_##grain[idx]++;			\
	if (rw)								\
		lstats->soft_latency_write_stats_##grain[idx]++;	\
	else								\
		lstats->soft_latency_read_stats_##grain[idx]++;		\
} else {								\
	lstats->latency_stats_##grain[idx]++;				\
	if (rw)								\
		lstats->latency_write_stats_##grain[idx]++;		\
	else								\
		lstats->latency_read_stats_##grain[idx]++;		\
}									\
									\
} while (0)

void update_latency_stats(struct latency_stats *lstats, unsigned long stime,
			unsigned long now, int soft, int rw)
{
	unsigned long latency;
	int idx;

	/*
	 * if now <= io->start_time_usec, it means counter
	 * in ktime_get() over flows, just ignore this I/O
	*/
	if (unlikely(now <= stime))
		return;

	latency = now - stime;
#ifndef USE_US
	latency *= 1000;
#endif
	if (latency < 1000) {
		/* microseconds */
		idx = latency/IO_LATENCY_STATS_US_GRAINSIZE;
		if (idx > (IO_LATENCY_STATS_US_NR - 1))
			idx = IO_LATENCY_STATS_US_NR - 1;
		INC_LATENCY(lstats, idx, soft, rw, us);
	} else if (latency < 1000000) {
		/* milliseconds */
		idx = us2msecs(latency)/IO_LATENCY_STATS_MS_GRAINSIZE;
		if (idx > (IO_LATENCY_STATS_MS_NR - 1))
			idx = IO_LATENCY_STATS_MS_NR - 1;
		INC_LATENCY(lstats, idx, soft, rw, ms);
	} else {
		/* seconds */
		idx = us2secs(latency)/IO_LATENCY_STATS_S_GRAINSIZE;
		if (idx > (IO_LATENCY_STATS_S_NR - 1))
			idx = IO_LATENCY_STATS_S_NR - 1;
		INC_LATENCY(lstats, idx, soft, rw, s);
	}
}

void update_io_size_stats(struct latency_stats *lstats, unsigned long size,
				int rw)
{
	int idx;

	if (size < IO_SIZE_MAX) {
		idx = size/IO_SIZE_STATS_GRAINSIZE;
		if (idx > (IO_SIZE_STATS_NR - 1))
			idx = IO_SIZE_STATS_NR - 1;
		lstats->io_size_stats[idx]++;
		if (rw)
			lstats->io_write_size_stats[idx]++;
		else
			lstats->io_read_size_stats[idx]++;
	}
}
