obj-m += hot-latency.o
obj-m += hotfixes.o

KERNEL_DEVEL_DIR=/lib/modules/`uname -r`/build

all:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` modules

clean:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` clean
