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

#include "includes.h"

static uint32_t
alloc_conf_filename(
    char **ppszFilename,
    const char *pszPath,
    const char *pszFname)
{
    uint32_t err = 0;
    size_t len = 0;
    char *pszFilename = NULL;

    if (!ppszFilename || !pszPath || !pszFname)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    len = strlen(pszPath) + strlen (pszFname) + 1;
    err = netmgr_alloc(len, (void **)&pszFilename);
    bail_on_error(err);

    sprintf(pszFilename, "%s%s", pszPath, pszFname);

    *ppszFilename = pszFilename;

cleanup:
    return err;
error:
    netmgr_free(pszFilename);
    if (ppszFilename != NULL)
    {
        *ppszFilename = NULL;
    }
    goto cleanup;
}

static uint32_t
get_networkd_conf_filename(
    char **ppszFilename)
{
    return alloc_conf_filename(ppszFilename, SYSTEMD_PATH, "networkd.conf");
}

static uint32_t
get_network_conf_filename(
    char **ppszFilename,
    const char *pszIfname)
{
    uint32_t err = 0;
    char fname[MAX_LINE];
    if (pszIfname == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    sprintf(fname, "10-%s.network", pszIfname);
    err = alloc_conf_filename(ppszFilename, SYSTEMD_NET_PATH, fname);
error:
    return err;
}

static uint32_t
get_resolved_conf_filename(
    char **ppszFilename)
{
    return alloc_conf_filename(ppszFilename, SYSTEMD_PATH, "resolved.conf");
}

uint32_t
enum_interfaces(
    int nFamily,
    PNETMGR_INTERFACE* ppInterfaces
    )
{
    uint32_t err = 0;
    int fd = 0;
    int i = 0;
    struct ifreq *pIFReq;
    struct ifconf stIFConf;
    char szBuff[1024];
    size_t nLen;
    PNETMGR_INTERFACE pInterfaces = NULL;
    PNETMGR_INTERFACE pInterface = NULL;

    if(nFamily != PF_INET && nFamily != PF_INET6 && !ppInterfaces)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    fd = socket(nFamily, SOCK_DGRAM, 0);
    if(fd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    stIFConf.ifc_len = sizeof(szBuff);
    stIFConf.ifc_buf = szBuff;
    if(ioctl(fd, SIOCGIFCONF, &stIFConf) != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    pIFReq = stIFConf.ifc_req;
    for(i = 0; i < stIFConf.ifc_len;)
    {
        err = netmgr_alloc(sizeof(NETMGR_INTERFACE), (void**)&pInterface);
        bail_on_error(err);

        err = netmgr_alloc_string(pIFReq->ifr_name, &pInterface->pszName);
        bail_on_error(err);

        nLen = sizeof(*pIFReq);
        pIFReq = (struct ifreq*)((char*)pIFReq + nLen);
        i += nLen;

        pInterface->pNext = pInterfaces;
        pInterfaces = pInterface;
        pInterface = NULL;
    }

    *ppInterfaces = pInterfaces;

clean:
    if(fd >= 0)
    {
       close(fd);
    }
    return err;
error:
    if(ppInterfaces)
    {
        *ppInterfaces = NULL;
    }
    if(pInterfaces)
    {
        free_interface(pInterfaces);
    }
    if(pInterface)
    {
        free_interface(pInterface);
    }
    goto clean;
}

void
free_interface(
    PNETMGR_INTERFACE pInterface
    )
{
    while(pInterface)
    {
        PNETMGR_INTERFACE pCurrent = pInterface;
        pInterface = pCurrent->pNext;

        if(pCurrent->pszName)
        {
            netmgr_free(pCurrent->pszName);
        }
        netmgr_free(pCurrent);
    }
}


uint32_t
ifup(
    const char *pszInterfaceName
    )
{
    uint32_t err = 0;

    if (IsNullOrEmptyString(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }


cleanup:
    return err;

error:
    goto cleanup;
}

uint32_t
ifdown(
    const char *pszInterfaceName
    )
{
    uint32_t err = 0;
    if (IsNullOrEmptyString(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

cleanup:
    return err;

error:
    goto cleanup;
}

int
set_link_info(
    const char *pszInterfaceName,
    const char *pszMacAddress,
    uint32_t mtu
)
{
    return 0;
}

int
set_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE mode
)
{
    return 0;
}

int
set_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE state
)
{
    return 0;
}

int
get_link_info(
    const char *pszInterfaceName,
    size_t *pCount,
    NET_LINK_INFO **ppLinkInfo
)
{
    return 0;
}


/*
 * IP Address configuration APIs
 */

static uint32_t
is_ipv4_addr(const char *pszIpAddr)
{
    struct sockaddr_in sa;
    return (inet_pton(AF_INET, pszIpAddr, &(sa.sin_addr)) != 0);
}

static uint32_t
is_ipv6_addr(const char *pszIpAddr)
{
    struct sockaddr_in6 sa;
    return (inet_pton(AF_INET6, pszIpAddr, &(sa.sin6_addr)) != 0);
}

int
set_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t dhcpModeFlags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL, szDhcpValue[] = "ipv4";

    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    if (TEST_FLAG(dhcpModeFlags, fDHCP_IPV4) && TEST_FLAG(dhcpModeFlags, fDHCP_IPV6))
    {
        strcpy(szDhcpValue, "yes");
    }
    else if (TEST_FLAG(dhcpModeFlags, fDHCP_IPV6))
    {
        strcpy(szDhcpValue, "ipv6");
    }
    else if (TEST_FLAG(dhcpModeFlags, fDHCP_IPV4))
    {
        strcpy(szDhcpValue, "ipv4");
    }
    else if (dhcpModeFlags == 0)
    {
        strcpy(szDhcpValue, "no");
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = set_key_value(pszCfgFileName, SECTION_NETWORK, KEY_DHCP, szDhcpValue, 0);
    bail_on_error(err);

    /* TODO: set  autoconf setting */

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
get_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t *pDhcpModeFlags
)
{
    uint32_t err = 0, mode = 0;
    char *pszCfgFileName = NULL;
    char *pszDhcpValue = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pDhcpModeFlags)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, SECTION_NETWORK, KEY_DHCP, &pszDhcpValue);
    if ((err == ENOENT) || !strcmp(pszDhcpValue, "no"))
    {
        mode = 0;
        err = 0;
    }
    else if (!strcmp(pszDhcpValue, "ipv4"))
    {
        mode = fDHCP_IPV4;
    }
    else if (!strcmp(pszDhcpValue, "ipv6"))
    {
        mode = fDHCP_IPV6;
    }
    else if (!strcmp(pszDhcpValue, "yes"))
    {
        mode = (fDHCP_IPV4 | fDHCP_IPV6);
    }
    else
    {
        err = EINVAL;
    }
    bail_on_error(err);

    /* TODO: query autoconf setting */

    *pDhcpModeFlags = mode;
cleanup:
    if (pszDhcpValue != NULL)
    {
        netmgr_free(pszDhcpValue);
    }
    netmgr_free(pszCfgFileName);
    return err;
error:
    if (pDhcpModeFlags != NULL)
    {
        *pDhcpModeFlags = 0;
    }
    goto cleanup;
}

int
set_static_ipv4_addr(
    const char *pszInterfaceName,
    const char *pszIPv4Addr,
    uint8_t prefix,
    uint32_t flags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL, szIpAddr[MAX_LINE];

    /* TODO: Handle eth0:0 virtual interfaces */
    if (IS_NULL_OR_EMPTY(pszInterfaceName) || IS_NULL_OR_EMPTY(pszIPv4Addr))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (!is_ipv4_addr(pszIPv4Addr) || (prefix > 32))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    sprintf(szIpAddr, "%s/%hhu", pszIPv4Addr, prefix);

    err = delete_static_ipv4_addr(pszInterfaceName);
    bail_on_error(err);

    err = add_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS, szIpAddr, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
delete_static_ipv4_addr(
    const char *pszInterfaceName
)
{
    uint32_t err = 0;
    size_t i, count = 0;
    char *pszCfgFileName = NULL, **ppszAddrList = NULL;

    /* TODO: Handle eth0:0 virtual interfaces */
    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    err = get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &count,
                             &ppszAddrList);
    bail_on_error(err);
    if (count > 1)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (count)
    {
        err = delete_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS,
                               ppszAddrList[0], 0);
        bail_on_error(err);
    }

cleanup:
    if (ppszAddrList != NULL)
    {
        for (i = 0; i < count; i++)
        {
            netmgr_free(ppszAddrList[i]);
        }
        netmgr_free(ppszAddrList);
    }
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
add_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6Addr,
    uint8_t prefix,
    uint32_t flags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL, szIpAddr[MAX_LINE];

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || IS_NULL_OR_EMPTY(pszIPv6Addr))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (!is_ipv6_addr(pszIPv6Addr) || (prefix > 128))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    sprintf(szIpAddr, "%s/%hhu", pszIPv6Addr, prefix);

    err = add_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS, szIpAddr, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
delete_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6Addr,
    uint8_t prefix,
    uint32_t flags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL, szIpAddr[MAX_LINE];

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || IS_NULL_OR_EMPTY(pszIPv6Addr))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (!is_ipv6_addr(pszIPv6Addr) || (prefix > 128))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    sprintf(szIpAddr, "%s/%hhu", pszIPv6Addr, prefix);
    err = delete_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS, szIpAddr, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
get_static_ip_addr(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    char ***pppszAddrList
)
{
    uint32_t err = 0, dwNumSections = 0, nCount = 0, i = 0, prefix;
    char *pszCfgFileName = NULL, ipAddr[INET6_ADDRSTRLEN];
    char **ppszAddrList = NULL;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pKeyValue = NULL, pNextKeyValue = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pCount || !pppszAddrList)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    err = ini_cfg_read(pszCfgFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, SECTION_NETWORK, &ppSections,
                                &dwNumSections);
    bail_on_error(err);

    if (dwNumSections > 1)
    {
        /* TODO: Log error */
        err = EINVAL;
        bail_on_error(err);
    }
    else if (dwNumSections == 0)
    {
        err = ENOENT;
        bail_on_error(err);
    }
    pSection = ppSections[0];

    /* Static IP addresses */
    do
    {
        pNextKeyValue = ini_cfg_find_next_key(pSection, pKeyValue, KEY_ADDRESS);
        if (pNextKeyValue == NULL)
        {
            break;
        }
        if (sscanf(pNextKeyValue->pszValue, "%[^/]/%u", ipAddr, &prefix) < 2)
        {
            err = EINVAL;
            bail_on_error(err);
        }
        if (TEST_FLAG(addrTypes, STATIC_IPV4) && is_ipv4_addr(ipAddr))
        {
            nCount++;
        }
        else if (TEST_FLAG(addrTypes, STATIC_IPV6) && is_ipv6_addr(ipAddr))
        {
            nCount++;
        }
        pKeyValue = pNextKeyValue;
    } while (pNextKeyValue != NULL);

    if (nCount > 0)
    {
        err = netmgr_alloc((nCount * sizeof(char *)), (void *)&ppszAddrList);
        bail_on_error(err);

        pKeyValue = NULL;
        do
        {
            pNextKeyValue = ini_cfg_find_next_key(pSection, pKeyValue,
                                                  KEY_ADDRESS);
            if (pNextKeyValue == NULL)
            {
                break;
            }
            sscanf(pNextKeyValue->pszValue, "%[^/]/%u", ipAddr, &prefix);
            if ((TEST_FLAG(addrTypes, STATIC_IPV4) && is_ipv4_addr(ipAddr)) ||
                (TEST_FLAG(addrTypes, STATIC_IPV6) && is_ipv6_addr(ipAddr)))
            {
                err = netmgr_alloc_string(pNextKeyValue->pszValue,
                                          &(ppszAddrList[i++]));
                bail_on_error(err);
            }
            pKeyValue = pNextKeyValue;
        } while (pNextKeyValue != NULL);
    }

    /* TODO: Implement get for DHCPv4, DHCPv6 and AutoV6 */

    *pCount = i;
    *pppszAddrList = ppszAddrList;

cleanup:
    if (ppSections != NULL)
    {
        ini_cfg_free_sections(ppSections, dwNumSections);
    }
    if (pConfig != NULL)
    {
        ini_cfg_free_config(pConfig);
    }
    netmgr_free(pszCfgFileName);
    return err;
error:
    if (ppszAddrList != NULL)
    {
        netmgr_free(ppszAddrList);
    }
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppszAddrList != NULL)
    {
        *pppszAddrList = NULL;
    }
    goto cleanup;
}

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
)
{
    return 0;
}

int
delete_ip_route(
    const char *pszInterfaceName,
    const char *pszDestAddr,
    uint8_t prefix,
    uint32_t flags
)
{
    return 0;
}

int
get_ip_route_info(
    size_t *pCount,
    NET_IP_ROUTE **ppRouteList
)
{
    return 0;
}


/*
 * DNS configuration APIs
 */

static int
space_delimited_string_append(
    size_t count,
    const char **ppszStrings,
    const char *pszCurrentString,
    char **ppszNewString
)
{
    uint32_t err = 0;
    size_t i, bytes = 0;
    char *pszNewString = NULL;

    if (ppszNewString == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (count > 0)
    {
        if (ppszStrings == NULL)
        {
            err = EINVAL;
            bail_on_error(err);
        }
        for (i = 0; i < count; i++)
        {
            bytes += strlen(ppszStrings[i]) + 1;
        }

        if (!IS_NULL_OR_EMPTY(pszCurrentString))
        {
            bytes += strlen(pszCurrentString) + 1;
        }
        err = netmgr_alloc(bytes, (void *)&pszNewString);
        bail_on_error(err);

        if (!IS_NULL_OR_EMPTY(pszCurrentString))
        {
            strcpy(pszNewString, pszCurrentString);
        }
        for (i = 0; i < count; i++)
        {
            /* TODO: Eliminate duplicates */
            if (strlen(pszNewString) > 0)
            {
                strcat(pszNewString, " ");
            }
            strcat(pszNewString, ppszStrings[i]);
        }
    }

    *ppszNewString = pszNewString;

cleanup:
    return err;

error:
    if (pszNewString != NULL)
    {
        netmgr_free(pszNewString);
    }
    if (ppszNewString == NULL)
    {
        *ppszNewString = NULL;
    }
    goto cleanup;
}

static int
get_dns_mode(
    const char *pszInterfaceName,
    NET_DNS_MODE *pMode
)
{
    uint32_t err = 0;
    NET_DNS_MODE mode;
    char *pszCfgFileName = NULL;
    char *pszUseDnsValue = NULL;

    if (pMode == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, SECTION_DHCP, KEY_USE_DNS, &pszUseDnsValue);
    if ((err == ENOENT) || !strcmp(pszUseDnsValue, "true"))
    {
        mode = DHCP_DNS;
        err = 0;
    }
    else if (!strcmp(pszUseDnsValue, "false"))
    {
        mode = STATIC_DNS;
    }
    else
    {
        err = EINVAL;
    }
    bail_on_error(err);
    *pMode = mode;
cleanup:
    if (pszUseDnsValue != NULL)
    {
        netmgr_free(pszUseDnsValue);
    }
    netmgr_free(pszCfgFileName);
    return err;
error:
    if (pMode != NULL)
    {
        *pMode = DNS_MODE_INVALID;
    }
    goto cleanup;
}

int
add_dns_servers(
    const char *pszInterfaceName,
    size_t count,
    const char **ppszDnsServers
)
{
    uint32_t err = 0;
    NET_DNS_MODE mode;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsServers = NULL;
    char *pszNewDnsServersValue = NULL;

    if ((count == 0) || (ppszDnsServers == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* TODO: Check DNS server IP addresses are valid. */

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = get_dns_mode("eth0", &mode);
    bail_on_error(err);

    if (mode == DHCP_DNS)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                        &pszCurrentDnsServers);
    if (err != ENOENT)
    {
        bail_on_error(err);
    }

    err = space_delimited_string_append(count, ppszDnsServers,
                                        pszCurrentDnsServers,
                                        &pszNewDnsServersValue);
    bail_on_error(err);

    err = set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                        pszNewDnsServersValue, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCurrentDnsServers);
    netmgr_free(pszNewDnsServersValue);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
delete_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer
)
{
    uint32_t err = 0;
    NET_DNS_MODE mode;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsServers = NULL, *pszMatch, *pszNext;
    char *pszNewDnsServersValue = NULL;

    if (!pszDnsServer || (!is_ipv4_addr(pszDnsServer) &&
        !is_ipv6_addr(pszDnsServer)))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = get_dns_mode("eth0", &mode);
    bail_on_error(err);
    if (mode == DHCP_DNS)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                        &pszCurrentDnsServers);
    bail_on_error(err);

    pszMatch = strstr(pszCurrentDnsServers, pszDnsServer);
    if (pszMatch == NULL)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    pszNext = pszMatch + strlen(pszDnsServer);
    if (*pszNext == ' ')
    {
        memmove(pszMatch, (pszNext + 1), strlen(pszNext));
    }
    else
    {
        pszMatch = (pszMatch == pszCurrentDnsServers) ? pszMatch : pszMatch - 1;
        *pszMatch = '\0';
    }

    pszNewDnsServersValue = (strlen(pszCurrentDnsServers) > 0) ?
                                pszCurrentDnsServers : NULL;

    err = set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                        pszNewDnsServersValue, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCurrentDnsServers);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
set_dns_servers(
    const char *pszInterfaceName,
    NET_DNS_MODE mode,
    size_t count,
    const char **ppszDnsServers,
    uint32_t flags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char netCfgFileName[MAX_LINE];
    char szSectionName[MAX_LINE];
    char szUseDnsValue[MAX_LINE];
    char *pszCurrentDnsServers = NULL;
    char *pszDnsServersValue = NULL;
    DIR *dirFile = NULL;
    struct dirent *hFile;

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    if (TEST_FLAG(flags, fAPPEND_DNS_SERVERS_LIST))
    {
        err = get_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                            &pszCurrentDnsServers);
        if (err != ENOENT)
        {
            bail_on_error(err);
        }
    }

    err = space_delimited_string_append(count, ppszDnsServers,
                                        pszCurrentDnsServers,
                                        &pszDnsServersValue);
    bail_on_error(err);

    err = EINVAL;
    if (mode == DHCP_DNS)
    {
        sprintf(szUseDnsValue, "true");
        if (count == 0)
        {
            err = set_key_value(pszCfgFileName, szSectionName, KEY_DNS, NULL, 0);
        }
    }
    else if (mode == STATIC_DNS)
    {
        sprintf(szUseDnsValue, "false");
        if (count == 0)
        {
            err = set_key_value(pszCfgFileName, szSectionName, KEY_DNS, NULL, 0);
        }
        else
        {
            err = set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                                pszDnsServersValue, 0);
        }
    }
    bail_on_error(err);

    /* For each .network file - set 'UseDNS=false' */
    if (pszInterfaceName == NULL)
    {
        dirFile = opendir(SYSTEMD_NET_PATH);
        if (dirFile != NULL)
        {
            errno = 0;
            while ((hFile = readdir(dirFile)) != NULL)
            {
                if (!strcmp(hFile->d_name, ".")) continue;
                if (!strcmp(hFile->d_name, "..")) continue;
                if (hFile->d_name[0] == '.') continue;
                if (strstr(hFile->d_name, ".network"))
                {
                    sprintf(netCfgFileName, "%s%s", SYSTEMD_NET_PATH, hFile->d_name);
                    err = set_key_value(netCfgFileName, SECTION_DHCP, KEY_USE_DNS,
                                        szUseDnsValue, 0);
                    bail_on_error(err);
                }
            }
        }
    }

error:
    if (dirFile != NULL)
    {
        closedir(dirFile);
    }
    netmgr_free(pszCurrentDnsServers);
    netmgr_free(pszDnsServersValue);
    netmgr_free(pszCfgFileName);
    return err;
}

int
get_dns_servers(
    const char *pszInterfaceName,
    uint32_t flags,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***pppszDnsServers
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszUseDnsValue = NULL;
    char *pszDnsServersValue = NULL;
    char *pszDnsServersValue2 = NULL;
    char *s1, *s2, **szDnsServersList = NULL;
    size_t i = 0, count = 0;

    if ((pMode == NULL) || (pCount == NULL) || (pppszDnsServers == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = get_dns_mode("eth0", pMode);
    bail_on_error(err);

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    /* Parse pszDnsServersValue */
    err = get_key_value(pszCfgFileName, szSectionName, KEY_DNS, &pszDnsServersValue);
    if (err == ENOENT)
    {
        err = 0;
        goto error;
    }
    bail_on_error(err);
    err = netmgr_alloc_string(pszDnsServersValue, &pszDnsServersValue2);
    bail_on_error(err);

    s2 = pszDnsServersValue;
    do {
        s1 = strsep(&s2, " ");
        if (strlen(s1) > 0)
        {
            count++;
        }
    } while (s2 != NULL);

    if (count > 0)
    {
        err = netmgr_alloc((count * sizeof(char *)), (void *)&szDnsServersList);
        bail_on_error(err);

        s2 = pszDnsServersValue2;
        do {
            s1 = strsep(&s2, " ");
            if (strlen(s1) > 0)
            {
                err = netmgr_alloc_string(s1, &(szDnsServersList[i++]));
                bail_on_error(err);
            }
        } while (s2 != NULL);
    }
    *pCount = count;
    *pppszDnsServers = szDnsServersList;

clean:
    netmgr_free(pszDnsServersValue2);
    netmgr_free(pszDnsServersValue);
    netmgr_free(pszUseDnsValue);
    netmgr_free(pszCfgFileName);
    return err;

error:
    /* Free allocated memory on error */
    if (szDnsServersList != NULL)
    {
        for (i = 0; i < count; i++)
        {
            if (szDnsServersList[i] != NULL)
            {
                netmgr_free(szDnsServersList[i]);
            }
        }
        netmgr_free(szDnsServersList);
    }
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppszDnsServers != NULL)
    {
        *pppszDnsServers = NULL;
    }
    goto clean;
}

int
set_dns_domains(
    const char *pszInterfaceName,
    size_t count,
    const char **ppszDnsDomains,
    uint32_t flags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsDomains = NULL;
    char *pszDnsDomainsValue = NULL;


    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                        &pszCurrentDnsDomains);
    if (err != ENOENT)
    {
        bail_on_error(err);
    }

    err = space_delimited_string_append(count, ppszDnsDomains,
                                        pszCurrentDnsDomains,
                                        &pszDnsDomainsValue);
    bail_on_error(err);
    if (count == 0)
    {
        err = set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS, NULL, 0);
    }
    else
    {
        err = set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                            pszDnsDomainsValue, 0);
    }
    bail_on_error(err);

error:
    netmgr_free(pszCurrentDnsDomains);
    netmgr_free(pszDnsDomainsValue);
    netmgr_free(pszCfgFileName);
    return err;
}

int
add_dns_domain(
    const char *pszInterfaceName,
    size_t count,
    const char **ppszDnsDomains
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsDomains = NULL;
    char *pszDnsDomainsValue = NULL;

    if ((count == 0) || (ppszDnsDomains == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                        &pszCurrentDnsDomains);
    if (err != ENOENT)
    {
        bail_on_error(err);
    }

    err = space_delimited_string_append(count, ppszDnsDomains,
                                        pszCurrentDnsDomains,
                                        &pszDnsDomainsValue);
    bail_on_error(err);

    err = set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                        pszDnsDomainsValue, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCurrentDnsDomains);
    netmgr_free(pszDnsDomainsValue);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
delete_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsDomains = NULL;
    char *pszNewDnsDomainsList = NULL;
    char *pszMatch = NULL;
    char *pszNext = NULL;

    if (pszDnsDomain == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                        &pszCurrentDnsDomains);
    bail_on_error(err);

    pszMatch = strstr(pszCurrentDnsDomains, pszDnsDomain);
    if(pszMatch == NULL)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    pszNext = pszMatch + strlen(pszDnsDomain);
    if(*pszNext == ' ')
    {
        memmove(pszMatch, (pszNext + 1), strlen(pszNext));
    }
    else
    {
        pszMatch = (pszMatch == pszCurrentDnsDomains) ? pszMatch: pszMatch - 1;
        *pszMatch = '\0';
    }

    pszNewDnsDomainsList = (strlen(pszCurrentDnsDomains) > 0) ?
                                pszCurrentDnsDomains : NULL;

    err = set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                        pszNewDnsDomainsList, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszNewDnsDomainsList);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
get_dns_domains(
    const char *pszInterfaceName,
    uint32_t flags,
    size_t *pCount,
    char ***pppszDnsDomains
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszDnsDomainsValue = NULL;
    char *pszDnsDomainValue2 = NULL;
    char *s1, *s2, **ppszDnsDomainsList = NULL;
    size_t i = 0, count = 0;

    if ((pCount == NULL) || (pppszDnsDomains == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                        &pszDnsDomainsValue);
    if (err == ENOENT)
    {
        err = 0;
        goto error;
    }
    bail_on_error(err);

    err = netmgr_alloc_string(pszDnsDomainsValue, &pszDnsDomainValue2);
    bail_on_error(err);

    s2 = pszDnsDomainsValue;
    do {
        s1 = strsep(&s2, " ");
        if (strlen(s1) > 0)
        {
            count++;
        }
    } while (s2 != NULL);

    if (count > 0)
    {
        err = netmgr_alloc((count * sizeof(char *)), (void *)&ppszDnsDomainsList);
        bail_on_error(err);

        s2 = pszDnsDomainValue2;
        do {
            s1 = strsep(&s2, " ");
            if (strlen(s1) > 0)
            {
                err = netmgr_alloc_string(s1, &(ppszDnsDomainsList[i++]));
                bail_on_error(err);
            }
        } while (s2 != NULL);
    }
    *pCount = count;
    *pppszDnsDomains = ppszDnsDomainsList;

clean:
    /* Free allocated memory on error */
    netmgr_free(pszDnsDomainValue2);
    netmgr_free(pszDnsDomainsValue);
    netmgr_free(pszCfgFileName);
    return err;

error:
    netmgr_list_free(count, (void **)ppszDnsDomainsList);
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppszDnsDomains != NULL)
    {
        *pppszDnsDomains = NULL;
    }
    goto clean;
}

/*
 * DHCP options, DUID, IAID configuration APIs
 */

int
set_iaid(
    const char *pszInterfaceName,
    uint32_t iaid
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szValue[MAX_LINE] = "";

    if (!pszInterfaceName)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    sprintf(szValue, "%u", iaid);

    if (iaid > 0)
    {
        err = set_key_value(pszCfgFileName, SECTION_DHCP, KEY_IAID, szValue, 0);
    }
    else
    {
        err = set_key_value(pszCfgFileName, SECTION_DHCP, KEY_IAID, NULL, 0);
    }

error:
    netmgr_free(pszCfgFileName);
    return err;
}

int
get_iaid(
    const char *pszInterfaceName,
    uint32_t *pIaid
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char *pszIaid = NULL;

    if (!pszInterfaceName || !pIaid)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(&pszCfgFileName, pszInterfaceName);
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, SECTION_DHCP, KEY_IAID, &pszIaid);
    bail_on_error(err);

    sscanf(pszIaid, "%u", pIaid);

clean:
    if (pszIaid != NULL)
    {
        netmgr_free(pszIaid);
    }
    netmgr_free(pszCfgFileName);
    return err;

error:
    if (pIaid != NULL)
    {
        *pIaid = 0;
    }
    goto clean;
}

static const char * duid_strtype_from_type(uint16_t type)
{
    if ((type > _DUID_TYPE_MIN) && (type < _DUID_TYPE_MAX))
    {
        return duid_type_table[type];
    }
    return NULL;
}

static uint16_t duid_type_from_strtype(const char *strtype)
{
    DUIDType dt;
    for (dt = _DUID_TYPE_MIN+1; dt < _DUID_TYPE_MAX; dt++)
    {
        if (!strncmp(strtype, duid_type_table[dt], strlen(duid_type_table[dt])))
        {
            return (uint16_t)dt;
        }
    }
    return 0;
}

int
set_duid(
    const char *pszInterfaceName,
    const char *pszDuid
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    const char *duidType;
    uint16_t n1, n2;
    char szDuid[MAX_LINE];

    if (pszInterfaceName != NULL)
    {
        /* TODO: Add support */
        err = ENOTSUP;
    }
    else
    {
        err = get_networkd_conf_filename(&pszCfgFileName);
    }
    bail_on_error(err);

    if ((pszDuid == NULL) || (strlen(pszDuid) == 0))
    {
        err = set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_TYPE, NULL,
                            F_CREATE_CFG_FILE);
        bail_on_error(err);

        err = set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA, NULL,
                            F_CREATE_CFG_FILE);
    }
    else
    {
        if (sscanf(pszDuid, "%hx:%hx:%s", &n1, &n2, szDuid) != 3)
        {
            err = EINVAL;
            bail_on_error(err);
        }

        duidType = duid_strtype_from_type((n1 << 8) | n2);
        if (duidType == NULL)
        {
            err = EINVAL;
            bail_on_error(err);
        }
        /* TODO: Validate DUID length and DUID bytes */

        err = set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_TYPE, duidType,
                            F_CREATE_CFG_FILE);
        bail_on_error(err);

        err = set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA, szDuid,
                            F_CREATE_CFG_FILE);
    }

error:
    netmgr_free(pszCfgFileName);
    return err;
}

int
get_duid(
    const char *pszInterfaceName,
    char **ppszDuid
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    uint16_t duidType;
    char *pszDuidType = NULL;
    char *pszDuid = NULL;

    if (ppszDuid == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        /* TODO: Add support */
        err = ENOTSUP;
    }
    else
    {
        err = get_networkd_conf_filename(&pszCfgFileName);
    }
    bail_on_error(err);

    err = get_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_TYPE, &pszDuidType);
    bail_on_error(err);

    duidType = duid_type_from_strtype(pszDuidType);
    if (duidType == 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA, &pszDuid);
    bail_on_error(err);

    err = netmgr_alloc((strlen(pszDuid) + 8), (void *)ppszDuid);
    bail_on_error(err);
    sprintf(*ppszDuid, "00:%02hu:%s", duidType, pszDuid);

clean:
    if (pszDuid != NULL)
    {
        netmgr_free(pszDuid);
    }
    if (pszDuidType != NULL)
    {
        netmgr_free(pszDuidType);
    }
    netmgr_free(pszCfgFileName);
    return err;

error:
    if (ppszDuid != NULL)
    {
        *ppszDuid = NULL;
    }
    goto clean;
}

