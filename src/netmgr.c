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

int
set_static_ipv4_addr(
    const char *pszInterfaceName,
    const char *pszIPv4Addr,
    uint8_t prefix,
    uint32_t flags
)
{
    return 0;
}

int
delete_static_ipv4_addr(
    const char *pszInterfaceName
)
{
    return 0;
}

int
add_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6Addr,
    uint8_t prefix,
    uint32_t flags
)
{
    return 0;
}

int
delete_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6Addr,
    uint8_t prefix,
    uint32_t flags
)
{
    return 0;
}

int
set_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t dhcpModeFlags
)
{
    return 0;
}

int
get_ip_addr_info(
    const char *pszInterfaceName,
    uint32_t flags,
    size_t *pCount,
    NET_IP_ADDR **ppAddrList
)
{
    return 0;
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

int
set_dns_servers(
    const char *pszInterfaceName,
    NET_DNS_MODE mode,
    size_t count,
    const char **ppDnsServers,
    uint32_t flags
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    char szSectionName[MAX_LINE];
    char szUseDnsValue[MAX_LINE];
    char *szCurrentDnsServers = NULL;
    char *szDnsServersValue = NULL;
    DIR *dirFile = NULL;
    struct dirent *hFile;
    size_t i, bytes = 0;

    if (pszInterfaceName != NULL)
    {
        sprintf(cfgFileName, "%s10-%s.network", SYSTEMD_NET_PATH,
                pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        sprintf(cfgFileName, "%sresolved.conf", SYSTEMD_PATH);
        sprintf(szSectionName, SECTION_RESOLVE);
    }

    if (count > 0)
    {
        if (ppDnsServers == NULL)
        {
            err = EINVAL;
            bail_on_error(err);
        }
        for (i = 0; i < count; i++)
        {
            bytes += strlen(ppDnsServers[i]) + 1;
            /* TODO: Check IP addresses are valid. */
        }

        if (TEST_FLAG(flags, fAPPEND_DNS_SERVERS_LIST))
        {
            err = get_key_value(cfgFileName, szSectionName, KEY_DNS,
                                &szCurrentDnsServers);
           if (err != ENOENT)
           {
               bail_on_error(err);
           }
        }
        if (szCurrentDnsServers != NULL)
        {
            bytes += strlen(szCurrentDnsServers) + 1;
        }
        err = netmgr_alloc(bytes, (void *)&szDnsServersValue);
        bail_on_error(err);

        if (szCurrentDnsServers != NULL)
        {
            strcpy(szDnsServersValue, szCurrentDnsServers);
        }
        for (i = 0; i < count; i++)
        {
            /* TODO: Eliminate duplicates */
            if (strlen(szDnsServersValue) > 0)
            {
                strcat(szDnsServersValue, " ");
            }
            strcat(szDnsServersValue, ppDnsServers[i]);
        }
    }

    err = EINVAL;
    if (mode == DHCP_DNS)
    {
        sprintf(szUseDnsValue, "true");
        if (count == 0)
        {
            err = set_key_value(cfgFileName, szSectionName, KEY_DNS, NULL, 0);
        }
    }
    else if (mode == STATIC_DNS)
    {
        sprintf(szUseDnsValue, "false");
        if (count == 0)
        {
            err = set_key_value(cfgFileName, szSectionName, KEY_DNS, NULL, 0);
        }
        else
        {
            err = set_key_value(cfgFileName, szSectionName, KEY_DNS,
                                szDnsServersValue, 0);
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
                    sprintf(cfgFileName, "%s%s", SYSTEMD_NET_PATH, hFile->d_name);
                    err = set_key_value(cfgFileName, SECTION_DHCP, KEY_USE_DNS,
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
    if (szCurrentDnsServers != NULL)
    {
        netmgr_free(szCurrentDnsServers);
    }
    if (szDnsServersValue != NULL)
    {
        netmgr_free(szDnsServersValue);
    }
    return err;
}

int
get_dns_servers(
    const char *pszInterfaceName,
    uint32_t flags,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***ppDnsServers
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    char szSectionName[MAX_LINE];
    char *pszUseDnsValue = NULL;
    char *pszDnsServersValue = NULL;
    char *pszDnsServersValue2 = NULL;
    char *s1, *s2, **szDnsServersList = NULL;
    size_t i = 0, count = 0;

    if ((pMode == NULL) || (pCount == NULL) || (ppDnsServers == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    sprintf(cfgFileName, "%s10-eth0.network", SYSTEMD_NET_PATH);
    err = get_key_value(cfgFileName, SECTION_DHCP, KEY_USE_DNS, &pszUseDnsValue);
    if ((err == ENOENT) || !strcmp(pszUseDnsValue, "true"))
    {
        *pMode = DHCP_DNS;
        err = 0;
    }
    else if (!strcmp(pszUseDnsValue, "false"))
    {
        *pMode = STATIC_DNS;
    }
    else
    {
        err = EINVAL;
    }
    bail_on_error(err);

    if (pszInterfaceName != NULL)
    {
        sprintf(cfgFileName, "%s10-%s.network", SYSTEMD_NET_PATH, pszInterfaceName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        sprintf(cfgFileName, "%sresolved.conf", SYSTEMD_PATH);
        sprintf(szSectionName, SECTION_RESOLVE);
    }

    /* Parse pszDnsServersValue */
    err = get_key_value(cfgFileName, szSectionName, KEY_DNS, &pszDnsServersValue);
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
    *ppDnsServers = szDnsServersList;

clean:
    if (pszDnsServersValue2 != NULL)
    {
        netmgr_free(pszDnsServersValue2);
    }
    if (pszDnsServersValue != NULL)
    {
        netmgr_free(pszDnsServersValue);
    }
    if (pszUseDnsValue != NULL)
    {
        netmgr_free(pszUseDnsValue);
    }
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
    if (ppDnsServers != NULL)
    {
        *ppDnsServers = NULL;
    }
    goto clean;
}

int
set_dns_domains(
    const char *pszInterfaceName,
    size_t count,
    const char **ppDnsDomains,
    uint32_t flags
)
{
    return 0;
}

int
get_dns_domains(
    const char *pszInterfaceName,
    uint32_t flags,
    size_t *pCount,
    char **ppDnsDomains
)
{
    return 0;
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
    char cfgFileName[MAX_LINE];
    char szValue[MAX_LINE] = "";

    if (!pszInterfaceName)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    sprintf(cfgFileName, "%s10-%s.network", SYSTEMD_NET_PATH, pszInterfaceName);
    sprintf(szValue, "%u", iaid);

    if (iaid > 0)
    {
        err = set_key_value(cfgFileName, SECTION_DHCP, KEY_IAID, szValue, 0);
    }
    else
    {
        err = set_key_value(cfgFileName, SECTION_DHCP, KEY_IAID, NULL, 0);
    }

    bail_on_error(err);

error:
    return err;
}

int
get_iaid(
    const char *pszInterfaceName,
    uint32_t *pIaid
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    char *pszIaid = NULL;

    if (!pszInterfaceName || !pIaid)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    sprintf(cfgFileName, "%s10-%s.network", SYSTEMD_NET_PATH, pszInterfaceName);

    err = get_key_value(cfgFileName, SECTION_DHCP, KEY_IAID, &pszIaid);
    bail_on_error(err);

    sscanf(pszIaid, "%u", pIaid);

clean:
    if (pszIaid != NULL)
    {
        netmgr_free(pszIaid);
    }
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
    char cfgFileName[MAX_LINE];
    const char *duidType;
    uint16_t n1, n2;
    char szDuid[MAX_LINE];

    if (pszInterfaceName != NULL)
    {
        /* TODO: Add support */
        err = ENOTSUP;
        bail_on_error(err);
    }
    else
    {
        sprintf(cfgFileName, "%snetworkd.conf", SYSTEMD_PATH);
    }

    if ((pszDuid == NULL) || (strlen(pszDuid) == 0))
    {
        err = set_key_value(cfgFileName, SECTION_DHCP, KEY_DUID_TYPE, NULL,
                            F_CREATE_CFG_FILE);
        bail_on_error(err);

        err = set_key_value(cfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA, NULL,
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

        err = set_key_value(cfgFileName, SECTION_DHCP, KEY_DUID_TYPE, duidType,
                            F_CREATE_CFG_FILE);
        bail_on_error(err);

        err = set_key_value(cfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA, szDuid,
                            F_CREATE_CFG_FILE);
    }
    bail_on_error(err);

error:
    return err;
}

int
get_duid(
    const char *pszInterfaceName,
    char **ppszDuid
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
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
        bail_on_error(err);
    }
    else
    {
        sprintf(cfgFileName, "%snetworkd.conf", SYSTEMD_PATH);
    }

    err = get_key_value(cfgFileName, SECTION_DHCP, KEY_DUID_TYPE, &pszDuidType);
    bail_on_error(err);

    duidType = duid_type_from_strtype(pszDuidType);
    if (duidType == 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_key_value(cfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA, &pszDuid);
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
    return err;

error:
    if (ppszDuid != NULL)
    {
        *ppszDuid = NULL;
    }
    goto clean;
}

int
set_dns_servers_v0(
    const char *pszInterfaceName,
    const char *pszDnsServers
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    char szSectionName[MAX_LINE];
    char szKey[MAX_LINE] = "DNS";
    char szValue[MAX_LINE];
    DIR *dirFile = NULL;
    struct dirent *hFile;

    if (pszInterfaceName != NULL)
    {
        sprintf(cfgFileName, "%s10-%s.network", SYSTEMD_NET_PATH, pszInterfaceName);
        sprintf(szSectionName, "Network");
    }
    else
    {
        sprintf(cfgFileName, "%sresolved.conf", SYSTEMD_PATH);
        sprintf(szSectionName, "Resolve");
    }

    if ((pszDnsServers == NULL) || (strlen(pszDnsServers) == 0))
    {
        sprintf(szValue, "true");
        err = set_key_value(cfgFileName, szSectionName, szKey, NULL, 0);
    }
    else
    {
        sprintf(szValue, "false");
        err = set_key_value(cfgFileName, szSectionName, szKey, pszDnsServers, 0);
    }
    bail_on_error(err);

    /* For each .network file - set 'UseDNS=false' */
    if (pszInterfaceName == NULL)
    {
        dirFile = opendir(SYSTEMD_NET_PATH);
        if (dirFile != NULL)
        {
            errno = 0;
            sprintf(szSectionName, "DHCP");
            sprintf(szKey, "UseDNS");
            while ((hFile = readdir(dirFile)) != NULL)
            {
                if (!strcmp(hFile->d_name, ".")) continue;
                if (!strcmp(hFile->d_name, "..")) continue;
                if (hFile->d_name[0] == '.') continue;
                if (strstr(hFile->d_name, ".network"))
                {
                    sprintf(cfgFileName, "%s%s", SYSTEMD_NET_PATH, hFile->d_name);
                    err = set_key_value(cfgFileName, szSectionName, szKey, szValue, 0);
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
    return err;
}

