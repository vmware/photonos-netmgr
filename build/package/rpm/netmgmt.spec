Name:    netmgmt
Summary: Network Management Utilities
Version: 1.0.4
Release: 0
Group:   Applications/System
Vendor:  VMware, Inc.
License: VMware
URL:     http://www.vmware.com
BuildArch: x86_64

%description
Network Management Utilities

%build
cd build
autoreconf -mif ..
../configure \
    --prefix=%{_prefix} \
    --libdir=%{_lib64dir}

make

%install

[ %{buildroot} != "/" ] && rm -rf %{buildroot}/*
cd build && make install DESTDIR=$RPM_BUILD_ROOT

%post

    /sbin/ldconfig

    # First argument is 1 => New Installation
    # First argument is 2 => Upgrade

%files
%defattr(-,root,root)
%{_bindir}/netmgr
%{_lib64dir}/libnetmgr.so*
%{_lib64dir}/libnetmgrcli.so*

%exclude %{_lib64dir}/libnetmgr.a
%exclude %{_lib64dir}/libnetmgr.la
%exclude %{_lib64dir}/libnetmgrcli.a
%exclude %{_lib64dir}/libnetmgrcli.la
%exclude %{_includedir}/*

# %doc ChangeLog README COPYING

%changelog

