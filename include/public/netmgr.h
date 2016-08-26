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

#define SET_FLAG(v, f) (v) = ((v) | (f))
#define CLEAR_FLAG(v, f) (v) = ((v) & ~(f))
#define TEST_FLAG(v, f) (((v) & (f)) != 0)


#define fNO_RESTART        0x00000001


/*
 * Interface configuration structs
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


/*
 * IP Address configuration structs
 */
#define fDHCP_IPV4         0x00000001
#define fDHCP_IPV6         0x00000010
#define fAUTO_IPV6         0x00000020

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


/*
 * Route configuration structs
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


/*
 * DNS configuration structs
 */
typedef enum _NET_DNS_MODE
{
    DNS_MODE_INVALID = 0,
    STATIC_DNS,
    DHCP_DNS,
    DNS_MODE_MAX,
} NET_DNS_MODE;


typedef struct _NETMGR_INTERFACE
{
    char* pszName;
    struct _NETMGR_INTERFACE* pNext;
} NETMGR_INTERFACE, *PNETMGR_INTERFACE;

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

//[3 - dhcp=yes], [4 - dhcp=no, autoconf=1], [1 - dhcp=ipv4, autoconf=0], [2 - dhcp=ipv6, autoconf=0]
int
set_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t dhcpModeFlags
);

int
get_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t *pDhcpModeFlags
);

int
get_static_ip_addr(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    char ***ppszAddrList
);


/*
 * Route configuration APIs
 */
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
int
set_dns_servers(
    const char *pszInterfaceName,
    NET_DNS_MODE mode,
    size_t count,
    const char **ppszDnsServers,
    uint32_t flags
);

int
add_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer,
    uint32_t flags
);

int
delete_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer,
    uint32_t flags
);

int
get_dns_servers(
    const char *pszInterfaceName,
    uint32_t flags,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***pppszDnsServers
);

int
set_dns_domains(
    const char *pszInterfaceName,
    size_t count,
    const char **ppszDnsDomains,
    uint32_t flags
);

int
add_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain,
    uint32_t flags
);

int
delete_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain,
    uint32_t flags
);

int
get_dns_domains(
    const char *pszInterfaceName,
    uint32_t flags,
    size_t *pCount,
    char ***pppszDnsDomains
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
    char **ppszDuid
);


/*
 * DHCP options, DUID, IAID configuration APIs
 */
int
stop_network_service();

int
restart_network_service();

int
stop_dns_service();

int
restart_dns_service();


#endif /* __NETMGR_H__ */

