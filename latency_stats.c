#include <asm-generic/div64.h>
#include <linux/slab.h>
#include <linux/clocksource.h>

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

struct latency_stats *create_latency_stats(void)
{
	struct latency_stats *lstats;
	int r;

	lstats = kmem_cache_zalloc(latency_stats_cache, GFP_KERNEL);
	if (!lstats)
		return (struct latency_stats *)-ENOMEM;

	/* initial latency stats buckets */
	for (r = 0; r < IO_LATENCY_STATS_S_NR; r++)
		atomic_set(&(lstats->latency_stats_s[r]), 0);
	for (r = 0; r < IO_LATENCY_STATS_MS_NR; r++)
		atomic_set(&(lstats->latency_stats_ms[r]), 0);

	return lstats;
}

void destroy_latency_stats(struct latency_stats *lstats)
{
	if (lstats)
		kmem_cache_free(latency_stats_cache, lstats);
}

void update_latency_stats(struct latency_stats *lstats, unsigned long stime,
			unsigned long now)
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
	if (latency < 1000) {
		/* microseconds */
		idx = latency/IO_LATENCY_STATS_US_GRAINSIZE;
		if (idx > (IO_LATENCY_STATS_US_NR - 1))
			idx = IO_LATENCY_STATS_US_NR - 1;
		atomic_inc(&(lstats->latency_stats_us[idx]));
	} else if (latency < 1000000) {
		/* milliseconds */
		idx = us2msecs(latency)/IO_LATENCY_STATS_MS_GRAINSIZE;
		if (idx > (IO_LATENCY_STATS_MS_NR - 1))
			idx = IO_LATENCY_STATS_MS_NR - 1;
		atomic_inc(&(lstats->latency_stats_ms[idx]));
	} else {
		/* seconds */
		idx = us2secs(latency)/IO_LATENCY_STATS_S_GRAINSIZE;
		if (idx > (IO_LATENCY_STATS_S_NR - 1))
			idx = IO_LATENCY_STATS_S_NR - 1;
		atomic_inc(&(lstats->latency_stats_s[idx]));
	}
}
