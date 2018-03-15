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

lib_LTLIBRARIES = libnetmgrcli.la

libnetmgrcli_la_SOURCES = \
    netmgrcli.c

libnetmgrcli_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/include/public

libnetmgrcli_la_LIBADD = \
    @top_builddir@/common/libcommon.la
