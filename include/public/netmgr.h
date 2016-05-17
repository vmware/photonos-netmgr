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

#ifndef __NETMGR_H__
#define __NETMGR_H__

typedef struct _NETMGR_INTERFACE
{
    char* pszName;
    struct _NETMGR_INTERFACE* pNext;
}NETMGR_INTERFACE, *PNETMGR_INTERFACE;

uint32_t
enum_interfaces(
    int nFamily,
    PNETMGR_INTERFACE* ppInterface
    );

void
free_interface(
    PNETMGR_INTERFACE pInterface
    );

uint32_t
ifup(
    const char *pszInterfaceName
    );

uint32_t
ifdown(
    const char * pszInterfaceName
    );

int
set_iaid(
    const char *pszInterfaceName,
    const uint32_t iaid
);

int
get_iaid(
    const char *pszInterfaceName,
    uint32_t *iaid
);

int
set_duid(
    const char *pszInterfaceName,
    const char *pszDuid
);

int
get_duid(
    const char *pszInterfaceName,
    char *pszDuid
);

int
set_dns_servers(
    const char *pszInterfaceName,
    const char *pszDnsServers
);

int
get_dns_servers(
    const char *pszInterfaceName,
    char *pszDnsServers
);

#endif /* __NETMGR_H__ */

