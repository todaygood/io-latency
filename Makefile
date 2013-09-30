obj-m += io-latency.o
io-latency-objs += io_latency.o hash_table.o latency_stats.o
obj-m += hotfixes.o

KERNEL_DEVEL_DIR=/lib/modules/`uname -r`/build
ifdef USE_US
	US_CONFIG="\#define USE_US 1"
endif

XEN=$(shell uname -r|grep "2.6.32.*xen"|wc -l)
ifeq (${XEN}, 1)
	HT_CONFIG="\#define USE_HASH_TABLE 1"
endif

ifdef USE_HASH_TABLE
	HT_CONFIG="\#define USE_HASH_TABLE 1"
endif

all:
	touch config.h
	echo $(US_CONFIG) > config.h
	echo $(HT_CONFIG) >> config.h
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` modules

clean:
	make -C ${KERNEL_DEVEL_DIR} M=`pwd` clean

unsetup:
	- rmmod io-latency
	- rmmod hotfixes
setup:
	insmod hotfixes.ko
	insmod io-latency.ko
