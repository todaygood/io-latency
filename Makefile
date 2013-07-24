obj-m += io-latency.o
io-latency-objs +=  io_latency.o hash_table.o latency_stats.o
obj-m += hotfixes.o

KERNEL_DEVEL_DIR=/lib/modules/`uname -r`/build

all:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` modules

clean:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` clean

unsetup:
	rmmod io-latency
	rmmod hotfixes
setup:
	insmod hotfixes.ko
	insmod io-latency.ko
