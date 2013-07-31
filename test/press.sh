DEV=sdb

run_io()
{
	for i in `seq 1 10`; do
		dd if=/dev/$DEV of=/dev/null iflag=direct skip=$i count=1 bs=1M
	done
}

while [ 1 ]; do
	make setup
	run_io
	cat /proc/io-latency/$DEV/io_latency_us
	cat /proc/io-latency/$DEV/io_latency_ms
	cat /proc/io-latency/$DEV/io_latency_s
	echo "" > /proc/io-latency/$DEV/io_stats_reset
	make unsetup
done
