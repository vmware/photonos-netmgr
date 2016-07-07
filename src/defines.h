/*
 * Copyright © 2016 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#define IsNullOrEmptyString(str) (!(str) || !(*str))

#ifndef __DEFINES_H__
#define __DEFINES_H__


#define MAX_LINE                       512

#define SYSTEMD_PATH                   "/etc/systemd/"
#define SYSTEMD_NET_PATH               "/etc/systemd/network/"

#define SECTION_RESOLVE                "Resolve"
#define SECTION_NETWORK                "Network"
#define SECTION_DHCP                   "DHCP"

#define KEY_IAID                       "IAID"
#define KEY_DUID_TYPE                  "DUIDType"
#define KEY_DUID_RAWDATA               "DUIDRawData"
#define KEY_DNS                        "DNS"
#define KEY_USE_DNS                    "UseDNS"


#define bail_on_error(errcode) \
    do { \
       if (errcode) { \
          goto error; \
       } \
    } while(0)

#endif /* __DEFINES_H__ */
