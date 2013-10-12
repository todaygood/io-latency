%define _io_latency_version %(grep "define IO_LATENCY_VERSION" %{_sourcedir}io_latency.c|awk -F'\"' '{print $(NF-1)}')
%define _release %(date +"%Y%m%d_%H%M")
%define _sharedir /usr/local/share/io_latency/

Summary:	Kernel Module to monitor latency of system IO
Name:		io-latency
Version:	%{_io_latency_version}
Release:	%{_release}
Group:		Alibaba
Buildroot:      %{_tmppath}/%{name}-%{version}-%{release}-root/
License:	GPL/OSL
Requires:	kernel-devel

%description
io-latency is a kernel module used for collecting statistics
information about response-time(RT) of IO on linux.

%install
mkdir -p %{buildroot}%{_sharedir}

install %{_sourcedir}hotfixes.ko %{buildroot}/%{_sharedir}hotfixes.ko
install %{_sourcedir}io-latency.ko %{buildroot}/%{_sharedir}/io-latency.ko

%clean
rm -rf %{buildroot}/%{_sharedir}

%files
%defattr(-,root,root)
%{_sharedir}
%{_sharedir}/hotfixes.ko
%{_sharedir}/io-latency.ko

%post

if [ `lsmod|grep hotfixes|wc -l` == 0 ]; then
	insmod %{_sharedir}hotfixes.ko
fi

if [ `lsmod|grep io_latency|wc -l` == 0 ]; then
	insmod %{_sharedir}io-latency.ko
fi

%postun

if [ `lsmod|grep io_latency|wc -l` != 0 ]; then
	rmmod io-latency.ko
fi

if [ `lsmod|grep hotfixes|wc -l` != 0 ]; then
	rmmod hotfixes.ko
fi

%changelog
* Thu Oct 11 2013 Robin Dong <sanbai@taobao.com>
- Add new disk to hash_table for monitor when plug new disk into system.
