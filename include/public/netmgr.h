/*
 * Copyright © 2016-2018 VMware, Inc.  All Rights Reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

#define SET_FLAG(v, f) (v) = ((v) | (f))
#define CLEAR_FLAG(v, f) (v) = ((v) & ~(f))
#define TEST_FLAG(v, f) (((v) & (f)) != 0)

#define IPV4       4
#define IPV6       6


/*
 * Error codes
 */
#define NM_BASE_ERROR                          4096U
#define NM_ERR_INVALID_PARAMETER               (NM_BASE_ERROR + 1)
#define NM_ERR_NOT_SUPPORTED                   (NM_BASE_ERROR + 2)
#define NM_ERR_OUT_OF_MEMORY                   (NM_BASE_ERROR + 3)
#define NM_ERR_VALUE_NOT_FOUND                 (NM_BASE_ERROR + 4)
#define NM_ERR_VALUE_EXISTS                    (NM_BASE_ERROR + 5)
#define NM_ERR_INVALID_INTERFACE               (NM_BASE_ERROR + 6)
#define NM_ERR_INVALID_ADDRESS                 (NM_BASE_ERROR + 7)
#define NM_ERR_INVALID_MODE                    (NM_BASE_ERROR + 8)
#define NM_ERR_BAD_CONFIG_FILE                 (NM_BASE_ERROR + 9)
#define NM_ERR_WRITE_FAILED                    (NM_BASE_ERROR + 10)
#define NM_ERR_TIME_OUT                        (NM_BASE_ERROR + 11)
#define NM_ERR_DHCP_TIME_OUT                   (NM_BASE_ERROR + 12)
#define NM_MAX_ERROR                           (NM_BASE_ERROR + 100)


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
} NET_LINK_INFO, *PNET_LINK_INFO;


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

typedef enum _NET_ADDR_TYPE
{
    STATIC_IPV4        =  0x00000001,
    STATIC_IPV6        =  0x00000002,
    DHCP_IPV4          =  0x00000010,
    DHCP_IPV6          =  0x00000020,
    AUTO_IPV6          =  0x00000040,
    LINK_LOCAL_IPV6    =  0x00000080,
} NET_ADDR_TYPE;

#define NET_ADDR_IPV4     STATIC_IPV4 | DHCP_IPV4
#define NET_ADDR_IPV6     STATIC_IPV6 | DHCP_IPV6 | AUTO_IPV6

//TODO: #define ALL_IP_ADDR = or of all the above enum values

typedef struct _NET_IP_ADDR
{
    char *pszInterfaceName;
    NET_ADDR_TYPE type;
    char *pszIPAddrPrefix;
} NET_IP_ADDR, *PNET_IP_ADDR;


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
} NET_IP_ROUTE, *PNET_IP_ROUTE;


/*
 * DNS configuration structs
 */
typedef enum _NET_DNS_MODE
{
    DNS_MODE_UNKNOWN = 0,
    STATIC_DNS,
    DHCP_DNS,
    DNS_MODE_MAX,
} NET_DNS_MODE;


/*
 * Firewall configuration structs
 */
typedef enum _NET_FW_RULE_TYPE
{
    FW_RAW = 0,
    FW_POLICY,
    FW_RULE_TYPE_MAX
} NET_FW_RULE_TYPE;

typedef struct _NET_FW_RULE
{
    uint8_t ipVersion;
    NET_FW_RULE_TYPE type;
    union
    {
        struct
        {
            char *pszTable;
            char *pszChain;
            char *pszIfName;
            char *pszProto;
            char *srcIp;
            char *dstIp;
            uint16_t srcPort;
            uint16_t dstPort;
            char *pszTarget;
        };
        char *pszRawFwRule;     // e.g. -A INPUT  -i lo -j ACCEPT
    };
} NET_FW_RULE, *PNET_FW_RULE;


typedef struct _NET_INTERFACE
{
    char *pszName;
    struct _NET_INTERFACE *pNext;
} NET_INTERFACE, *PNET_INTERFACE;


const char *
nm_link_state_to_string(
    NET_LINK_STATE state
);

const char *
nm_ip_addr_type_to_string(
    NET_ADDR_TYPE addrType
);

const char *
nm_link_mode_to_string(
    NET_LINK_MODE mode
);

const char *
nm_get_error_info(
    uint32_t nmErrCode
);

uint32_t
nm_touch_network_conf_file(
    const char *pszInterfaceName,
    char **ppszFilename);

/*
 * Interface configuration APIs
 */
// Override the 'factory/nvram' mac address. mtu=0 -> use default 1500
uint32_t
nm_set_link_mac_addr(
    const char *pszInterfaceName,
    const char *pszMacAddress
);

uint32_t
nm_get_link_mac_addr(
    const char *pszInterfaceName,
    char **ppszMacAddress
);

uint32_t
nm_set_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE mode
);

uint32_t
nm_get_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE *pLinkMode
);

uint32_t
nm_set_link_mtu(
    const char *pszInterfaceName,
    uint32_t mtu
);

uint32_t
nm_get_link_mtu(
    const char *pszInterfaceName,
    uint32_t *pMtu
);

uint32_t
nm_set_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE state
);

uint32_t
nm_get_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE *pLinkState
);

uint32_t
nm_ifup(
    const char *pszInterfaceName
);

uint32_t
nm_ifdown(
    const char *pszInterfaceName
);

uint32_t
nm_get_link_info(
    const char *pszInterfaceName,
    NET_LINK_INFO **ppLinkInfo
);

void
nm_free_link_info(
    NET_LINK_INFO *pNetLinkInfo
);


/*
 * IP Address configuration APIs
 */
//TODO: Support address for virtual interface e.g. "eth1:0"
uint32_t
nm_set_ipv4_addr_gateway(
    const char *pszInterfaceName,
    NET_IPV4_ADDR_MODE mode,
    const char *pszIPv4AddrPrefix,
    const char *pszIPv4Gateway
);

uint32_t
nm_get_ipv4_addr_gateway(
    const char *pszInterfaceName,
    NET_IPV4_ADDR_MODE *pMode,
    char **ppszIPv4AddrPrefix,
    char **ppszIPv4Gateway
);

uint32_t
nm_add_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6AddrPrefix
);

uint32_t
nm_delete_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6AddrPrefix
);

uint32_t
nm_set_ipv6_addr_mode(
    const char *pszInterfaceName,
    uint32_t enableDhcp,
    uint32_t enableAutoconf
);

uint32_t
nm_get_ipv6_addr_mode(
    const char *pszInterfaceName,
    uint32_t *pDhcpEnabled,
    uint32_t *pAutoconfEnabled
);

uint32_t
nm_get_ip_addr(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    NET_IP_ADDR ***pppIpAddrList
);

uint32_t
nm_set_ipv6_gateway(
    const char *pszInterfaceName,
    const char *pszIPv6Gateway
);

uint32_t
nm_get_ipv6_gateway(
    const char *pszInterfaceName,
    char **ppszIPv6Gateway
);


/*
 * Route configuration APIs
 */
uint32_t
nm_add_static_ip_route(
    NET_IP_ROUTE *pRoute
);

uint32_t
nm_delete_static_ip_route(
    NET_IP_ROUTE *pRoute
);

uint32_t
nm_get_static_ip_routes(
    const char *pszInterfaceName,
    size_t *pCount,
    NET_IP_ROUTE ***pppRouteList
);


/*
 * DNS configuration APIs
 */
uint32_t
nm_set_dns_servers(
    const char *pszInterfaceName,
    NET_DNS_MODE mode,
    size_t count,
    const char **ppszDnsServers
);

uint32_t
nm_add_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer
);

uint32_t
nm_delete_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer
);

uint32_t
nm_get_dns_servers(
    const char *pszInterfaceName,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***pppszDnsServers
);

uint32_t
nm_set_dns_domains(
    const char *pszInterfaceName,
    size_t count,
    const char **ppszDnsDomains
);

uint32_t
nm_add_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain
);

uint32_t
nm_delete_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain
);

uint32_t
nm_get_dns_domains(
    const char *pszInterfaceName,
    size_t *pCount,
    char ***pppszDnsDomains
);


/*
 * DHCP options, DUID, IAID configuration APIs
 */
uint32_t
nm_set_iaid(
    const char *pszInterfaceName,
    uint32_t iaid
);

uint32_t
nm_get_iaid(
    const char *pszInterfaceName,
    uint32_t *pIaid
);

uint32_t
nm_set_duid(
    const char *pszInterfaceName,
    const char *pszDuid
);

uint32_t
nm_get_duid(
    const char *pszInterfaceName,
    char **ppszDuid
);


/*
 * NTP configuration APIs
 */
uint32_t
nm_set_ntp_servers(
    size_t count,
    const char **ppszNtpServers
);

uint32_t
nm_add_ntp_servers(
    size_t count,
    const char **ppszNtpServers
);

uint32_t
nm_delete_ntp_servers(
    size_t count,
    const char **ppszNtpServers
);

uint32_t
nm_get_ntp_servers(
    size_t *pCount,
    char ***pppszNtpServers
);


/*
 * Firewall configuration APIs
 */
uint32_t
nm_set_firewall_policy(
    const char *pszTable,
    const char *pszChain,
    const char *pszPolicy
);

uint32_t
nm_get_firewall_policy(
    const char *pszTable,
    const char *pszChain,
    char **ppszPolicy
);

uint32_t
nm_add_firewall_rule(
    NET_FW_RULE *pNetFwRule
);

uint32_t
nm_delete_firewall_rule(
    NET_FW_RULE *pNetFwRule
);

uint32_t
nm_get_firewall_rules(
    size_t *pCount,
    NET_FW_RULE ***pppNetFwRules
);


/*
 * Misc APIs
 */
uint32_t
nm_set_hostname(
    const char *pszHostname
);

uint32_t
nm_get_hostname(
    char **ppszHostname
);

uint32_t
nm_wait_for_link_up(
    const char *pszInterfaceName,
    uint32_t timeout
);

uint32_t
nm_wait_for_ip(
    const char *pszInterfaceName,
    uint32_t timeout,
    NET_ADDR_TYPE addrTypes
);

uint32_t
nm_set_network_param(
    const char *pszObjectName,
    const char *pszParamName,
    const char *pszParamValue
);

uint32_t
nm_get_network_param(
    const char *pszObjectName,
    const char *pszParamName,
    char **ppszParamValue
);


/*
 * Service management APIs
 */
uint32_t
nm_stop_network_service();

uint32_t
nm_restart_network_service();

uint32_t
nm_stop_dns_service();

uint32_t
nm_restart_dns_service();

uint32_t
nm_stop_ntp_service();

uint32_t
nm_restart_ntp_service();

uint32_t
nm_reload_firewall_config();

#ifdef __cplusplus
}
#endif

#endif /* __NETMGR_H__ */

