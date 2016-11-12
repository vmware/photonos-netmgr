FROM vmware/photon

ENV container docker
ENV LC_ALL C

# Copying netmgr rpms and tests..
ADD ./build/rpmbuild/RPMS/x86_64 /netmgr/unittests/rpms
ADD ./tests/testsuite /netmgr/unittests/tests/
ADD ./tests/*.at /netmgr/unittests/tests/
ADD ./tests/files/10-eth0.network /etc/systemd/network/
ADD ./tests/files/run_tests.sh /netmgr/

# Install systemd, netmgr, and other supporting rpms..
RUN tdnf install -y systemd
RUN tdnf install -y sed gawk diffutils iproute2
RUN rpm -Uvh --force /netmgr/unittests/rpms/*.rpm

# Debug
#RUN tdnf install -y gdb gcc binutils make rpm-build libtool pcre pcre-devel
#RUN tdnf install -y automake autoconf glibc glibc-devel tar glib glib-devel
#RUN tdnf install -y cpio
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

CMD umount /etc/resolv.conf
CMD rm -f /etc/resolv.conf
CMD ln -f -s /run/systemd/resolve/resolv.conf /etc/resolv.conf

ENTRYPOINT ["/lib/systemd/systemd"]

