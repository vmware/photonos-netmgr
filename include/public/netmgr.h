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
    LINK_MODE_UNKNOWN
} NET_LINK_MODE;

typedef enum _NET_LINK_STATE
{
    LINK_DOWN = 0,
    LINK_UP,
    LINK_STATE_UNKNOWN,
} NET_LINK_STATE;

typedef struct _NET_LINK_INFO
{
    struct _NET_LINK_INFO *pNext;
    char *pszInterfaceName;
    char *pszMacAddress;
    uint32_t mtu;
    NET_LINK_MODE mode;
    NET_LINK_STATE state;
} NET_LINK_INFO;


/*
 * IP Address configuration structs
 */
typedef enum _NET_IPV4_ADDR_MODE
{
    IPV4_ADDR_MODE_NONE = 0,
    IPV4_ADDR_MODE_STATIC,
    IPV4_ADDR_MODE_DHCP,
    IPV4_ADDR_MODE_MAX
} NET_IPV4_ADDR_MODE;

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
typedef enum _NET_ROUTE_SCOPE
{
    GLOBAL_ROUTE = 0,
    LINK_ROUTE,
    HOST_ROUTE,
    NET_ROUTE_SCOPE_MAX
} NET_ROUTE_SCOPE;

typedef struct _NET_IP_ROUTE
{
    char *pszInterfaceName;
    char *pszDestNetwork;
    char *pszSourceNetwork;
    char *pszGateway;
    NET_ROUTE_SCOPE scope;
    uint32_t metric;
    uint32_t table;
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

uint32_t
get_interface_ipaddr(
    const char *pszInterfaceName,
    NET_ADDR_TYPE addrType,
    size_t *pCount,
    char ***pppszIpAddress
);

/*
 * Interface configuration APIs
 */
// Override the 'factory/nvram' mac address. mtu=0 -> use default 1500
uint32_t
set_link_mac_addr(
    const char *pszInterfaceName,
    const char *pszMacAddress
);

uint32_t
set_link_mtu(
    const char *pszInterfaceName,
    uint32_t mtu
);

uint32_t
set_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE mode
);

uint32_t
set_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE state
);

uint32_t
get_link_info(
    const char *pszInterfaceName,
    size_t *pCount,
    NET_LINK_INFO **ppLinkInfo
);


/*
 * IP Address configuration APIs
 */
uint32_t
get_static_ip_addr(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    char ***pppszIpAddrList
);

//TODO: Support address for virtual interface e.g. "eth1:0"
uint32_t
set_ipv4_addr_gateway(
    const char *pszInterfaceName,
    NET_IPV4_ADDR_MODE mode,
    const char *pszIPv4AddrPrefix,
    const char *pszIPv4Gateway,
    uint32_t flags
);

uint32_t
get_ipv4_addr_gateway(
    const char *pszInterfaceName,
    NET_IPV4_ADDR_MODE *pMode,
    char **ppszIPv4AddrPrefix,
    char **ppszIPv4Gateway
);

uint32_t
add_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6AddrPrefix,
    uint32_t flags
);

uint32_t
delete_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6AddrPrefix,
    uint32_t flags
);

uint32_t
set_ipv6_addr_mode(
    const char *pszInterfaceName,
    uint32_t enableDhcp,
    uint32_t enableAutoconf
);

uint32_t
get_ipv6_addr_mode(
    const char *pszInterfaceName,
    uint32_t *pDhcpEnabled,
    uint32_t *pAutoconfEnabled
);

uint32_t
set_ipv6_gateway(
    const char *pszInterfaceName,
    const char *pszIPv6Gateway,
    uint32_t flags
);

uint32_t
get_ipv6_gateway(
    const char *pszInterfaceName,
    char **ppszIPv6Gateway
);


/*
 * Route configuration APIs
 */
uint32_t
add_static_ip_route(
    NET_IP_ROUTE *pRoute,
    uint32_t flags
);

uint32_t
delete_static_ip_route(
    NET_IP_ROUTE *pRoute,
    uint32_t flags
);

uint32_t
get_static_ip_routes(
    const char *pszInterfaceName,
    size_t *pCount,
    NET_IP_ROUTE ***pppRouteList
);


/*
 * DNS configuration APIs
 */
uint32_t
set_dns_servers(
    const char *pszInterfaceName,
    NET_DNS_MODE mode,
    size_t count,
    const char **ppszDnsServers,
    uint32_t flags
);

uint32_t
add_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer,
    uint32_t flags
);

uint32_t
delete_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer,
    uint32_t flags
);

uint32_t
get_dns_servers(
    const char *pszInterfaceName,
    uint32_t flags,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***pppszDnsServers
);

uint32_t
set_dns_domains(
    const char *pszInterfaceName,
    size_t count,
    const char **ppszDnsDomains,
    uint32_t flags
);

uint32_t
add_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain,
    uint32_t flags
);

uint32_t
delete_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain,
    uint32_t flags
);

uint32_t
get_dns_domains(
    const char *pszInterfaceName,
    uint32_t flags,
    size_t *pCount,
    char ***pppszDnsDomains
);


/*
 * DHCP options, DUID, IAID configuration APIs
 */
uint32_t
set_iaid(
    const char *pszInterfaceName,
    uint32_t iaid
);

uint32_t
get_iaid(
    const char *pszInterfaceName,
    uint32_t *pIaid
);

uint32_t
set_duid(
    const char *pszInterfaceName,
    const char *pszDuid
);

uint32_t
get_duid(
    const char *pszInterfaceName,
    char **ppszDuid
);


/*
 * Misc APIs
 */
uint32_t
wait_for_ip(
    const char *pszInterfaceName,
    uint32_t timeout,
    NET_ADDR_TYPE addrTypes
);


/*
 * Service management APIs
 */
uint32_t
stop_network_service();

uint32_t
restart_network_service();

uint32_t
stop_dns_service();

uint32_t
restart_dns_service();


#endif /* __NETMGR_H__ */

