#
# Copyright © 2016-2018 VMware, Inc.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the “License”); you may not
# use this file except in compliance with the License.  You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an “AS IS” BASIS, without
# warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
# License for the specific language governing permissions and limitations
# under the License.
#

Summary: Photon OS Network Configuration Manager
Name:    netmgmt
Version: 1.1.0
Release: 1
Group:   Applications/System
Vendor:  VMware, Inc.
License: Apache2.0
URL:     http://www.vmware.com
BuildArch: %{_arch}

%description
This is a utility to easily configure network settings for PhotonOS or any OS that uses systemd-networkd.

%package devel
Summary: netmgmt development headers and libraries
Group: Development/Libraries
Requires: netmgmt = %{version}-%{release}

%description devel
header files and libraries for netmgmt

%package cli-devel
Summary: netmgmt development cli headers and libraries
Group: Development/Libraries
Requires: netmgmt = %{version}-%{release}

%description cli-devel
header files and libraries for netmgmt cli

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

%files devel
%{_includedir}/netmgmt/netmgr.h
%{_lib64dir}/libnetmgr.a
%{_lib64dir}/libnetmgr.la

%files cli-devel
%{_includedir}/netmgmt/netmgrcli.h
%{_lib64dir}/libnetmgrcli.so*
%{_lib64dir}/libnetmgrcli.a
%{_lib64dir}/libnetmgrcli.la

# %doc ChangeLog README COPYING

%changelog
*   Sun Mar 05 2017 Vinay Kulkarni <kulkarniv@vmware.com> 1.1.0-1
-   Bump version to 1.1.0
*   Wed Nov 02 2016 Vinay Kulkarni <kulkarniv@vmware.com> 1.0.5-1
-   netmgr version 1.0.5
