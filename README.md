io-latency
===========
io-latency is a kernel module used for collecting statistics information about
response-time(RT) of IO on linux.

0. Prerequisite

	linux kernel version: 2.6.32

	Installed kernel-devel package

1. How to install

	wget "https://github.com/RobinDong/io-latency/archive/v1.1.1.zip"

	unzip v1.1.1

	cd io-latency-v1.1.1/

	make

	make setup

	If want to collect microsecond(default is millisecond) granularity
	response-time, you could use 'make USE_US=1' to compile code.

	You can also copy hotfixes.ko and io-latency.ko to machies with equally
	kernel version and use

		insmod hotfixes.ko

		insmod io-latency.ko

	to install it.

2. How to use it

	After install io-latency, you can use:
		
		cat /proc/io-latency/sdx/io_latency_ms

	to see the RT of IO on /dev/sdx by granularity of microsecond.

	'/proc/io-latency/sdx/read_io_latency_ms' show the RT of read IO

	'/proc/io-latency/sdx/io_write_size' shows the IO-size of write.

	'soft_io_latency_xxx'(enabled by default, you can use

	'echo 0 > /proc/io-latency/sdx/enable_soft_latency' to disable it) show
	the RT of IO in software layer--mainly in kernel block layer\io-scheduler.

	'io_latency_xxx' show the RT of IO in hardware layer.

	To reset all the statistics info to zero, you can use

	'enable 1 > /proc/io-latency/sdx/io_stats_reset'



io-latency
===========
io-latency是一个统计linux里IO延时信息的内核模块

0. 安装前需要确认

	linux内核版本是2.6.32

	已经安装了 kernel-devel 包

1. 如何安装io-latency

	wget "https://github.com/RobinDong/io-latency/archive/v1.1.1.zip"

	unzip v1.1.1

	cd io-latency-v1.1.1/

	make

	make setup

	如果想将统计时间的粒度变为微秒（默认为毫秒），可以在编译时使用

    		make USE_US=1

	您也可以将编译好的 hotfixes.ko 和 io-latency.ko 拷贝到内核版本完全一致的

	其它服务器上，然后：

		insmod hotfixes.ko

		insmod io-latency.ko

	来安装io-latency.

2. 如何使用io-latency

	安装完成后可以用：
		
		cat /proc/io-latency/sdx/io_latency_ms

	查看IO的延时，单位是毫秒

	'/proc/io-latency/sdx/read_io_latency_xx' 显示了读IO的延时统计

	'io_write_size' 显示了IO大小的统计

	'soft_io_latency_xxx'(默认是开启的，可以用
	'echo 0 > /proc/io-latency/sdx/enable_soft_latency'关闭此项统计) 显示了
	IO在软件层的延时——主要是内核的块设备层和IO调度器里的延时

	'io_latency_xxx' 显示了IO在硬件层的延时

	如果要重置所有统计信息，可以用

	'enable 1 > /proc/io-latency/sdx/io_stats_reset'

