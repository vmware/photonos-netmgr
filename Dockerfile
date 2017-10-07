FROM vmware/photon

ARG ARCH=x86_64
ARG NMROOT=/root/netmgmt/
ENV container docker
ENV LC_ALL C

# Copying netmgr rpms and tests..
ADD ./build/rpmbuild/RPMS/$ARCH/*.rpm /netmgr/rpms/
ADD ./tests/files/10-eth0.network /etc/systemd/network/
ADD ./tests/files/run_tests.sh /netmgr/unittest/
ADD ./tests/clitest/testsuite /netmgr/unittest/clitest/
ADD ./tests/clitest/*.at /netmgr/unittest/clitest/
ADD ./build/tests/apitest/* /netmgr/unittest/apitest/
ADD ./build/ $NMROOT/build/

# Install systemd, netmgr, and other supporting rpms..
RUN tdnf install -y systemd
RUN tdnf install -y sed gawk diffutils iproute2 iputils net-tools dbus ntp iptables
RUN tdnf install -y gcc binutils glibc-devel pcre-devel glib-devel check
RUN rpm -Uvh --force /netmgr/rpms/*.rpm

# Create SystemCtl Config File
RUN echo "net.ipv4.tcp_syncookies=1\nnet.ipv4.ip_dynaddr=2 " > /etc/sysctl.d/99-sysctl.conf

# Debug
#RUN tdnf install -y gdb make rpm-build libtool automake autoconf cpio strace
#ADD ./nm.tar /root/

RUN cd /lib/systemd/system/sysinit.target.wants/; \
ls | grep -v systemd-tmpfiles-setup | xargs rm -f $1 \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*; \
rm -f /lib/systemd/system/plymouth*; \
rm -f /lib/systemd/system/systemd-update-utmp*; \
rm -f /etc/systemd/network/10-dhcp-en.network

RUN chmod 644 /etc/systemd/network/10-eth0.network
RUN sed -i s/#DNS=/DNS=10.10.10.250/ /etc/systemd/resolved.conf
RUN mkdir -p /tools/netmgr
RUN ln -s /usr/bin/netmgr /tools/netmgr/netmgr

RUN sed -i "s/^ExecStart=/ExecStartPre=\/usr\/sbin\/ip addr flush dev eth0\nExecStartPre=\/usr\/bin\/sleep 2\nExecStart=/" /usr/lib/systemd/system/systemd-networkd.service
RUN systemctl set-default multi-user.target

ENV init /lib/systemd/systemd

VOLUME [ "/sys/fs/cgroup" ]

ENTRYPOINT ["/lib/systemd/systemd"]

