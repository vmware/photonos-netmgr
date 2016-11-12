#!/bin/bash

if mount | grep resolv > /dev/null
  then
    umount /etc/resolv.conf
    rm -f /etc/resolv.conf
    ln -f -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
    ip addr flush dev eth0
    systemctl start systemd-networkd
    systemctl start systemd-resolved
fi

cd /netmgr/unittests && ./tests/testsuite

