
run_io()
{
    fio test/pure.fio &
}

while [ 1 ]; do
	make setup
	run_io
    sleep 60
    for DEV in sdb sdc sdd sde sdf sdg sdh sdi; do
        cat /proc/io-latency/$DEV/soft_io_latency_us > /dev/null
        cat /proc/io-latency/$DEV/read_io_latency_ms > /dev/null
        cat /proc/io-latency/$DEV/io_latency_s > /dev/null
        echo "1" > /proc/io-latency/$DEV/io_stats_reset
    done
	make unsetup
done
