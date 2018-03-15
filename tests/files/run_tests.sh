#!/bin/bash

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

if mount | grep resolv > /dev/null
  then
    umount /etc/resolv.conf
    rm -f /etc/resolv.conf
    ln -f -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
    ip addr flush dev eth0
    systemctl start systemd-networkd
    systemctl start systemd-resolved
fi

cd /netmgr/unittest/clitest && ./testsuite
cd /netmgr/unittest/apitest && ./testutils
cd /netmgr/unittest/apitest && ./testnetmgr

