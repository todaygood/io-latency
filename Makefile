obj-m += latency.o
latency-objs +=  hot-latency.o hash_table.o
obj-m += hotfixes.o

KERNEL_DEVEL_DIR=/lib/modules/`uname -r`/build

all:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` modules

clean:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` clean

unsetup:
	rmmod latency
	rmmod hotfixes
setup:
	insmod hotfixes.ko
	insmod latency.ko
