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

#ifndef __DEFINES_H__
#define __DEFINES_H__


#define MAX_LINE                       512
#define NM_LOCK_FILENAME               "/run/lock/netmgr.lck"

#define SYSTEMD_PATH                   "/etc/systemd/"
#define SYSTEMD_NET_PATH               "/etc/systemd/network/"

#define ARPING_COMMAND                 "/sbin/arping"
#define ARPING_DUP_ADDR_CHECK_CMDOPT   "-D -q -c 2"
#define ARPING_UPDATE_NEIGHBOR_CMDOPT  "-A -c 3"

#define SECTION_RESOLVE                "Resolve"
#define SECTION_NETWORK                "Network"
#define SECTION_DHCP                   "DHCP"
#define SECTION_ROUTE                  "Route"
#define SECTION_LINK                   "Link"

#define KEY_ADDRESS                    "Address"
#define KEY_GATEWAY                    "Gateway"
#define KEY_DEST                       "Destination"
#define KEY_SRC                        "Source"
#define KEY_METRIC                     "Metric"
#define KEY_SCOPE                      "Scope"
#define KEY_DHCP                       "DHCP"
#define KEY_DNS                        "DNS"
#define KEY_USE_DNS                    "UseDNS"
#define KEY_DOMAINS                    "Domains"
#define KEY_USE_DOMAINS                "UseDomains"
#define KEY_IAID                       "IAID"
#define KEY_DUID_TYPE                  "DUIDType"
#define KEY_DUID_RAWDATA               "DUIDRawData"
#define KEY_MTU                        "MTUBytes"
#define KEY_MAC_ADDRESS                "MACAddress"

#define SECTION_KEY_DELIM              "_"


#define RESOLV_CONF_FILENAME           "/etc/resolv.conf"
#define NTP_CONF_FILENAME              "/etc/ntp.conf"
#define STR_NAMESERVER                 "nameserver"
#define STR_SEARCH                     "search"
#define STR_SERVER                     "server"


#define fDHCP_IPV4         0x00000001
#define fDHCP_IPV6         0x00000010
#define fAUTO_IPV6         0x00000020


#define bail_on_error(errcode) \
    do { \
       if (errcode) { \
          goto error; \
       } \
    } while(0)

#endif /* __DEFINES_H__ */
