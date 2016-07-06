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


/*
 * Interface configuration APIs
 */

typedef enum _NET_LINK_MODE
{
    LINK_AUTO = 0,
    LINK_MANUAL,
} NET_LINK_MODE;

typedef enum _NET_LINK_STATE
{
    LINK_DOWN = 0,
    LINK_UP,
    LINK_UNKNOWN,
} NET_LINK_STATE;

typedef struct _NET_LINK_INFO
{
    char *pszInterfaceName;
    char *pszMacAddress;
    uint32_t mtu;
    NET_LINK_MODE mode;
    NET_LINK_STATE state;
} NET_LINK_INFO;

// Override the 'factory/nvram' mac address. mtu=0 -> use default 1500
int
set_link_info(
    const char *pszInterfaceName,
    const char *pszMacAddress,
    uint32_t mtu
);

int
set_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE mode
);

int
set_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE state
);

int
get_link_info(
    const char *pszInterfaceName,
    size_t *pCount,
    NET_LINK_INFO **ppLinkInfo
);


/*
 * IP Address configuration APIs
 */

//TODO: Support address for virtual interface e.g. "eth1:0"
int
set_static_ipv4_addr(
    const char *pszInterfaceName,
    const char *pszIPv4Addr,
    uint8_t prefix,
    uint32_t flags
);

int
delete_static_ipv4_addr(
    const char *pszInterfaceName
);

#define fCLEAR_IPV6_ADDR_LIST     0x00000001
int
add_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6Addr,
    uint8_t prefix,
    uint32_t flags
);

int
delete_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6Addr,
    uint8_t prefix,
    uint32_t flags
);

#define fDHCP_IPV4         0x00000001
#define fDHCP_IPV6         0x00000010
#define fAUTO_IPV6         0x00000020
//[3 - dhcp=yes], [4 - dhcp=no, autoconf=1], [1 - dhcp=ipv4, autoconf=0], [2 - dhcp=ipv6, autoconf=0]
int
set_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t dhcpModeFlags
);

typedef enum _NET_ADDR_TYPE
{
    STATIC_IPV4  =  0x00000001,
    STATIC_IPV6  =  0x00000002,
    DHCP_IPV4    =  0x00000010,
    DHCP_IPV6    =  0x00000020,
    AUTO_IPV6    =  0x00000040,
} NET_ADDR_TYPE;

//#define ALL_IP_ADDR = or of all the above enum values
typedef struct _NET_IP_ADDR
{
    NET_ADDR_TYPE type;
    char *pszIPAddr;
    uint8_t prefix;
} NET_IP_ADDR;

int
get_ip_addr_info(
    const char *pszInterfaceName,
    uint32_t flags,
    size_t *pCount,
    NET_IP_ADDR **ppAddrList
);


/*
 * Route configuration APIs
 */

typedef enum _NET_ROUTE_TYPE
{
    GLOBAL_ROUTE,
    LINK_ROUTE,
    HOST_ROUTE,
} NET_ROUTE_TYPE;

typedef struct _NET_IP_ROUTE
{
    char *pszInterfaceName;
    char *pszDestAddr;
    uint8_t prefix;
    char *pszGateway;
    NET_ROUTE_TYPE type;
} NET_IP_ROUTE;

#define fCLEAR_ROUTES_LIST     0x00000001
#define fSCOPE_HOST            0x00000010
int
set_ip_route(
    const char *pszInterfaceName,
    const char *pszDestAddr,
    uint8_t prefix,
    const char *pszGateway,
    uint32_t metric,
    uint32_t flags
);

int
delete_ip_route(
    const char *pszInterfaceName,
    const char *pszDestAddr,
    uint8_t prefix,
    uint32_t flags
);

int
get_ip_route_info(
    size_t *pCount,
    NET_IP_ROUTE **ppRouteList
);


/*
 * DNS configuration APIs
 */

typedef enum _NET_DNS_MODE
{
    STATIC_DNS = 0,
    DHCP_DNS,
} NET_DNS_MODE;

#define fAPPEND_DNS_SERVERS_LIST       0x00000001
int
set_dns_servers_v2(
    const char *pszInterfaceName,
    NET_DNS_MODE mode,
    size_t count,
    const char **ppDnsServers,
    uint32_t flags
);

#define fRESOLVED_CONF_DNS_SERVERS
int
get_dns_servers_v2(
    const char *pszInterfaceName,
    uint32_t flags,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***ppDnsServers
);

#define fAPPEND_DNS_DOMAINS_LIST       0x00000001
int
set_dns_domains(
    const char *pszInterfaceName,
    size_t count,
    const char **ppDnsDomains,
    uint32_t flags
);

#define fRESOLVED_CONF_DNS_DOMAINS     0x00000001
int
get_dns_domains(
    const char *pszInterfaceName,
    uint32_t flags,
    size_t *pCount,
    char **ppDnsDomains
);


/*
 * DHCP options, DUID, IAID configuration APIs
 */

int
set_iaid(
    const char *pszInterfaceName,
    uint32_t iaid
);

int
get_iaid(
    const char *pszInterfaceName,
    uint32_t *pIaid
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

