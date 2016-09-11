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
get_network_auto_conf_filename(
    const char *pszIfname,
    char **ppszFilename)
{
    uint32_t err = 0;
    char fname[IFNAMSIZ+strlen("10-.network")+1];

    if ((pszIfname == NULL) || (strlen(pszIfname) > IFNAMSIZ) || !ppszFilename)
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
get_network_manual_conf_filename(
    const char *pszIfname,
    char **ppszFilename)
{
    uint32_t err = 0;
    char fname[IFNAMSIZ+strlen("10-.network.manual")+1];

    if ((pszIfname == NULL) || (strlen(pszIfname) > IFNAMSIZ) || !ppszFilename)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    sprintf(fname, "10-%s.network.manual", pszIfname);
    err = alloc_conf_filename(ppszFilename, SYSTEMD_NET_PATH, fname);
error:
    return err;
}

static uint32_t
get_network_conf_filename(
    const char *pszIfname,
    char **ppszFilename)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL, *pszStr = NULL;

    if (!ppszFilename)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_manual_conf_filename(pszIfname, &pszCfgFileName);
    bail_on_error(err);

    if (access(pszCfgFileName, R_OK|W_OK) == 0)
    {
        *ppszFilename = pszCfgFileName;
        goto cleanup;
    }

    pszStr = strstr(pszCfgFileName, ".manual");
    if (pszStr == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    *pszStr = '\0';

    if (access(pszCfgFileName, R_OK|W_OK) == 0)
    {
        *ppszFilename = pszCfgFileName;
        goto cleanup;
    }
    else
    {
        err = errno;
        bail_on_error(err);
    }

cleanup:
    return err;
error:
    if(ppszFilename)
    {
        *ppszFilename = NULL;
    }
    netmgr_free(pszCfgFileName);
    goto cleanup;
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

static uint32_t
set_interface_state(
    const char *pszInterfaceName,
    NET_LINK_STATE linkState
)
{
    uint32_t err = 0;
    int socket_fd = -1;
    size_t ifNameLen = 0;
    struct ifreq ifr;

    if (IsNullOrEmptyString(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) ||
        (linkState >= LINK_STATE_UNKNOWN))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    ifNameLen = strlen(pszInterfaceName);
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, pszInterfaceName, ifNameLen);
    ifr.ifr_name[ifNameLen] = '\0';

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = ioctl(socket_fd, SIOCGIFFLAGS, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    switch (linkState)
    {
        case LINK_UP:
            if (TEST_FLAG(ifr.ifr_flags, IFF_UP))
            {
                goto cleanup;
            }
            ifr.ifr_flags = ifr.ifr_flags | IFF_UP | IFF_BROADCAST |
                            IFF_RUNNING | IFF_MULTICAST;
            break;
        case LINK_DOWN:
            if (!TEST_FLAG(ifr.ifr_flags, IFF_UP))
            {
                goto cleanup;
            }
            ifr.ifr_flags = ifr.ifr_flags & ~IFF_UP;
            break;
        default:
            err = EINVAL;
    }
    bail_on_error(err);

    err = ioctl(socket_fd, SIOCSIFFLAGS, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

cleanup:
    if (socket_fd > -1)
    {
        close(socket_fd);
    }
    return err;
error:
    goto cleanup;
}

uint32_t
flush_interface_ipaddr(
    const char *pszInterfaceName
)
{
    uint32_t err = 0;
    int socket_fd = -1;
    size_t ifNameLen = 0;
    struct ifreq ifr;
    struct sockaddr_in sin;

    if (IsNullOrEmptyString(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    ifNameLen =  strlen(pszInterfaceName);
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, pszInterfaceName, ifNameLen);
    ifr.ifr_name[ifNameLen] = '\0';

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    memset(&sin, 0, sizeof(struct sockaddr_in));
    inet_aton("0.0.0.0.", &sin.sin_addr);
    sin.sin_family = AF_INET;
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr_in));

    err = ioctl(socket_fd, SIOCSIFADDR, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

cleanup:
    if (socket_fd > -1)
    {
        close(socket_fd);
    }
    return err;
error:
    goto cleanup;
}

uint32_t
get_interface_state(
    const char *pszInterfaceName,
    NET_LINK_STATE *pLinkState
)
{
    uint32_t err = 0;
    int socket_fd = -1;
    size_t ifNameLen = 0;
    struct ifreq ifr;

    if (IsNullOrEmptyString(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) || !pLinkState)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    ifNameLen =  strlen(pszInterfaceName);
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, pszInterfaceName, ifNameLen);
    ifr.ifr_name[ifNameLen] = '\0';

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = ioctl(socket_fd, SIOCGIFFLAGS, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    *pLinkState = TEST_FLAG(ifr.ifr_flags, IFF_UP) ? LINK_UP : LINK_DOWN;

cleanup:
    if (socket_fd > -1)
    {
        close(socket_fd);
    }
    return err;
error:
    if (pLinkState)
    {
        *pLinkState = LINK_STATE_UNKNOWN;
    }
    goto cleanup;

}

uint32_t
get_interface_ipaddr(
    const char *pszInterfaceName,
    NET_ADDR_TYPE addrType,
    size_t *pCount,
    char ***pppszIpAddress
)
{
    uint32_t err = 0;
    size_t count = 0;
    int family = 0, ipType = 0;
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    char **ppszIpAddrList = NULL;
    char host[NI_MAXHOST];

    if (IsNullOrEmptyString(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) || !pCount || !pppszIpAddress)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = getifaddrs(&ifaddr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    //In case addrType has both IPV4 and IPv6 flags set only IPV4 returned
    if (TEST_FLAG(addrType, STATIC_IPV4) || TEST_FLAG(addrType, DHCP_IPV4))
    {
        ipType = AF_INET;
    }
    else if (TEST_FLAG(addrType, STATIC_IPV6) ||
             TEST_FLAG(addrType, DHCP_IPV6) || TEST_FLAG(addrType, AUTO_IPV6))
    {
        ipType = AF_INET6;
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
           continue;
        }

        family = ifa->ifa_addr->sa_family;

        if (strcmp(ifa->ifa_name, pszInterfaceName) && (family == ipType))
        {
            err = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) :
                             sizeof(struct sockaddr_in6),host, NI_MAXHOST,
                             NULL, 0, NI_NUMERICHOST);
            if (err != 0)
            {
                err =  errno;
                bail_on_error(err);
            }
            count++;
            //TODO Getting Global IPv6 Address, getting total count, storing
            //individual address returned(Linked List?), assigning enogh memory to
            //AddrList,and copying the address to the Addrlist. Below code is just
            //for single IPv4
            err = netmgr_alloc((count * sizeof(char *)), (void *)&ppszIpAddrList);
            bail_on_error(err);

            err = netmgr_alloc_string(host, &(ppszIpAddrList[0]));
            bail_on_error(err);
            break;
        }
    }
    *pCount = count;
    *pppszIpAddress = ppszIpAddrList;

cleanup:
    freeifaddrs(ifaddr);
    return err;
error:
    if (pCount)
    {
        *pCount = 0;
    }
    if (pppszIpAddress)
    {
        *pppszIpAddress = NULL;
    }
    netmgr_list_free(count, (void **)ppszIpAddrList);
    goto cleanup;
}

static uint32_t
do_arping(
    const char *pszInterfaceName,
    const char *pszCommandOptions,
    const char *pszDestIpAddr
    )
{
    uint32_t err = 0;
    char *pszArpingCmd = NULL;

    if (IsNullOrEmptyString(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) ||
        IsNullOrEmptyString(pszCommandOptions) ||
        IsNullOrEmptyString(pszDestIpAddr))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(strlen(pszInterfaceName) + strlen(pszDestIpAddr) +
                       strlen(pszCommandOptions) +
                       6 + strlen(pszCommandOptions),
                       (void **)&pszArpingCmd);
    bail_on_error(err);

    sprintf(pszArpingCmd,"%s %s -I %s %s", ARPING_COMMAND,
            pszCommandOptions, pszInterfaceName, pszDestIpAddr);

    err = netmgr_run_command(pszArpingCmd);
    bail_on_error(err);

cleanup:
    netmgr_free(pszArpingCmd);
    return err;
error:
    goto cleanup;

}

uint32_t
ifup(
    const char *pszInterfaceName
)
{
    uint32_t err = 0, err1 = 0, prefix;
    int manual_mode = 0;
    size_t count = 0, ifIpv4Count = 0, ifIpv6Count = 0;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;
    char ipAddr[INET6_ADDRSTRLEN];
    const char arping_dup_addr_check_cmd_options[] = "-D -q -c 2";
    const char arping_update_neighbor_cmd_options[] = "-A -c 3";
    char *pszCfgFileName = NULL;
    char **ppszIpv4Addr = NULL, **ppszIpv6AddrList = NULL;
    char **ppszIpAddrList = NULL;

    if (IsNullOrEmptyString(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_interface_state(pszInterfaceName, &linkState);
    bail_on_error(err);

    err = get_interface_ipaddr(pszInterfaceName, STATIC_IPV4, &ifIpv4Count,
                               &ppszIpv4Addr);
    bail_on_error(err);

    if (ifIpv4Count != 1)
    {
        err = get_interface_ipaddr(pszInterfaceName, STATIC_IPV6, &ifIpv6Count,
                                   &ppszIpv6AddrList);
        bail_on_error(err);
    }

    if ((linkState == LINK_UP) && (ifIpv4Count || ifIpv6Count))
    {
        goto cleanup;
    }

    err = get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &count,
                             &ppszIpAddrList);
    bail_on_error(err);

    err = flush_interface_ipaddr(pszInterfaceName);
    bail_on_error(err);

    err = set_interface_state(pszInterfaceName, LINK_UP);
    bail_on_error(err);

    if (count != 0 && !strcmp(ppszIpAddrList[0], ppszIpv4Addr[0]))
    {
        sscanf(ppszIpAddrList[count-1], "%[^/]/%u", ipAddr, &prefix);

        err = do_arping(pszInterfaceName, arping_dup_addr_check_cmd_options,
                        ipAddr);
        bail_on_error(err);
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    if (strstr(pszCfgFileName,".manual"))
    {
        manual_mode = 1;
        err = set_link_mode(pszInterfaceName, LINK_AUTO);
        bail_on_error(err);
    }

    err = restart_network_service();
    if ((err != 0) && manual_mode)
    {
        //In case this fails, we have two errors.Returning
        //latest error
        err1 = err;
        err = set_link_mode(pszInterfaceName, LINK_MANUAL);
        bail_on_error(err);
        err = err1;
    }
    bail_on_error(err);

    if (manual_mode)
    {
        err = set_link_mode(pszInterfaceName, LINK_MANUAL);
        bail_on_error(err);
    }

    if ((count != 0) && !strcmp(ppszIpAddrList[0], ppszIpv4Addr[0]))
    {
        err = do_arping(pszInterfaceName, arping_update_neighbor_cmd_options,
                        ipAddr);
        bail_on_error(err);
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

cleanup:
    if (ifIpv4Count)
    {
        netmgr_list_free(ifIpv4Count, (void **)ppszIpv4Addr);
    }
    if (ifIpv6Count)
    {
        netmgr_list_free(ifIpv6Count, (void **)ppszIpv6AddrList);
    }
    netmgr_list_free(count, (void **)ppszIpAddrList);
    netmgr_free(pszCfgFileName);
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

    if (IsNullOrEmptyString(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = flush_interface_ipaddr(pszInterfaceName);
    bail_on_error(err);

    err = set_interface_state(pszInterfaceName, LINK_DOWN);
    bail_on_error(err);

cleanup:
    return err;
error:
    goto cleanup;
}

int
set_link_mac_addr(
    const char *pszInterfaceName,
    const char *pszMacAddress
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;

    if (IsNullOrEmptyString(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = set_key_value(pszCfgFileName, SECTION_LINK, KEY_MAC_ADDRESS,
                        pszMacAddress, 0);

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
set_link_mtu(
    const char *pszInterfaceName,
    uint32_t mtu
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szValue[MAX_LINE] = "";

    if (IsNullOrEmptyString(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    if (mtu > 0)
    {
        sprintf(szValue, "%u", mtu);
    }
    else
    {
        sprintf(szValue, "%u", DEFAULT_MTU_VALUE);
    }

    err = set_key_value(pszCfgFileName, SECTION_LINK, KEY_MTU, szValue, 0);

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

int
set_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE mode
)
{
    uint32_t err = 0;
    char *pszAutoCfgFileName = NULL, *pszManualCfgFileName = NULL;
    char *pszCurrentCfgFileName = NULL;

    if (IsNullOrEmptyString(pszInterfaceName) || (mode >= LINK_MODE_UNKNOWN))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_auto_conf_filename(pszInterfaceName, &pszAutoCfgFileName);
    bail_on_error(err);

    err = get_network_manual_conf_filename(pszInterfaceName,
                                           &pszManualCfgFileName);
    bail_on_error(err);

    err = get_network_conf_filename(pszInterfaceName, &pszCurrentCfgFileName);
    bail_on_error(err);

    switch (mode)
    {
        case LINK_MANUAL:
            if (strcmp(pszCurrentCfgFileName, pszManualCfgFileName))
            {
                err = rename(pszAutoCfgFileName, pszManualCfgFileName);
                if (err != 0)
                {
                    err = errno;
                    bail_on_error(err);
                }
            }
            break;
        case LINK_AUTO:
            if (strcmp(pszCurrentCfgFileName, pszAutoCfgFileName))
            {
                err = rename(pszManualCfgFileName, pszAutoCfgFileName);
                if (err != 0)
                {
                    err = errno;
                    bail_on_error(err);
                }
            }
            break;
        default:
            err = EINVAL;
            break;
    }

cleanup:
    netmgr_free(pszCurrentCfgFileName);
    netmgr_free(pszAutoCfgFileName);
    netmgr_free(pszManualCfgFileName);
    return err;
error:
    goto cleanup;
}

int
set_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE state
)
{
    uint32_t err = 0;

    if (IsNullOrEmptyString(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    switch (state)
    {
        case LINK_UP:
            err = ifup(pszInterfaceName);
            break;
        case LINK_DOWN:
            err = ifdown(pszInterfaceName);
            break;
        default:
            err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    return err;
error:
    goto cleanup;
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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
        if (sscanf(pNextKeyValue->pszValue, "%[^/]/%u", ipAddr, &prefix) < 1)
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

static int
add_route_section(
    NET_IP_ROUTE *pRoute
)
{
    uint32_t err = 0, dwNumSections = 0, i;
    char *pszCfgFileName = NULL, buf[MAX_LINE];
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pDestKeyVal = NULL;

    if (!pRoute || IS_NULL_OR_EMPTY(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork) ||
        IS_NULL_OR_EMPTY(pRoute->pszGateway))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(pRoute->pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = ini_cfg_read(pszCfgFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, SECTION_ROUTE, &ppSections,
                                &dwNumSections);
    bail_on_error(err);

    for (i = 0; i < dwNumSections; i++)
    {
        pDestKeyVal = ini_cfg_find_key_value(ppSections[i], KEY_DEST,
                                             pRoute->pszDestNetwork);
        if (pDestKeyVal != NULL)
        {
            err = EEXIST;
            bail_on_error(err);
        }
    }

    err = ini_cfg_add_section(pConfig, SECTION_ROUTE, &pSection);
    bail_on_error(err);

    err = ini_cfg_add_key(pSection, KEY_GATEWAY, pRoute->pszGateway);
    bail_on_error(err);
    err = ini_cfg_add_key(pSection, KEY_DEST, pRoute->pszDestNetwork);
    bail_on_error(err);
    if (pRoute->pszSourceNetwork)
    {
        err = ini_cfg_add_key(pSection, KEY_SRC, pRoute->pszSourceNetwork);
        bail_on_error(err);
    }
    if (pRoute->metric)
    {
        sprintf(buf, "%u", pRoute->metric);
        err = ini_cfg_add_key(pSection, KEY_METRIC, buf);
        bail_on_error(err);
    }
    if (pRoute->scope && (pRoute->scope < NET_ROUTE_SCOPE_MAX))
    {
        switch (pRoute->scope)
        {
            case GLOBAL_ROUTE:
                strcpy(buf, "global");
                break;
            case LINK_ROUTE:
                strcpy(buf, "link");
                break;
            case HOST_ROUTE:
                strcpy(buf, "host");
                break;
            default:
                err = EINVAL;
                bail_on_error(err);
        }
        sprintf(buf, "%u", pRoute->metric);
        err = ini_cfg_add_key(pSection, KEY_SCOPE, buf);
        bail_on_error(err);
    }

    err = ini_cfg_save(pszCfgFileName, pConfig);
    bail_on_error(err);

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
    goto cleanup;
}

static int
delete_route_section(
    NET_IP_ROUTE *pRoute
)
{
    uint32_t err = 0, dwNumSections = 0, i;
    char *pszCfgFileName = NULL;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL;
    PKEYVALUE_INI pDestKeyVal = NULL;

    if (!pRoute || IS_NULL_OR_EMPTY(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(pRoute->pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = ini_cfg_read(pszCfgFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, SECTION_ROUTE, &ppSections,
                                &dwNumSections);
    bail_on_error(err);

    for (i = 0; i < dwNumSections; i++)
    {
        pDestKeyVal = ini_cfg_find_key_value(ppSections[i], KEY_DEST,
                                             pRoute->pszDestNetwork);
        if (pDestKeyVal != NULL)
        {
            break;
        }
    }

    if (pDestKeyVal == NULL)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    err = ini_cfg_delete_section(pConfig, ppSections[i]);
    bail_on_error(err);

    err = ini_cfg_save(pszCfgFileName, pConfig);
    bail_on_error(err);

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
    goto cleanup;
}

static int
get_routes(
    const char *pszInterfaceName,
    size_t *pCount,
    NET_IP_ROUTE ***pppRoutes
)
{
    uint32_t err = 0, dwNumSections = 0, i;
    char *pszCfgFileName = NULL;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL;
    PKEYVALUE_INI pKeyVal = NULL;
    NET_IP_ROUTE **ppRoutes = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pCount || !pppRoutes)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = ini_cfg_read(pszCfgFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, SECTION_ROUTE, &ppSections,
                                &dwNumSections);
    bail_on_error(err);

    err = netmgr_alloc(dwNumSections * sizeof(NET_IP_ROUTE *), (void **)&ppRoutes);
    bail_on_error(err);

    for (i = 0; i < dwNumSections; i++)
    {
        err = netmgr_alloc(sizeof(NET_IP_ROUTE), (void **)&ppRoutes[i]);
        bail_on_error(err);

        pKeyVal = ini_cfg_find_key(ppSections[i], KEY_DEST);
        err = netmgr_alloc_string(pKeyVal->pszValue, &ppRoutes[i]->pszDestNetwork);
        bail_on_error(err);

        pKeyVal = ini_cfg_find_key(ppSections[i], KEY_GATEWAY);
        err = netmgr_alloc_string(pKeyVal->pszValue, &ppRoutes[i]->pszGateway);
        bail_on_error(err);

        pKeyVal = ini_cfg_find_key(ppSections[i], KEY_METRIC);
        if (pKeyVal != NULL)
        {
            ppRoutes[i]->metric = (uint32_t)atoi(pKeyVal->pszValue);
        }
    }

    *pCount = dwNumSections;
    *pppRoutes = ppRoutes;

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
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppRoutes != NULL)
    {
        *pppRoutes = NULL;
    }
    /* TODO: Check MEM LEAK */
    netmgr_list_free(dwNumSections, (void **)ppRoutes);
    goto cleanup;
}

int
add_static_ip_route(
    NET_IP_ROUTE *pRoute,
    uint32_t flags
)
{
    uint32_t err = 0;
    uint8_t prefix = 255;
    char szDestAddr[INET6_ADDRSTRLEN+5];
    NET_IP_ROUTE route;

    if (IS_NULL_OR_EMPTY(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork) ||
        IS_NULL_OR_EMPTY(pRoute->pszGateway) ||
        (sscanf(pRoute->pszDestNetwork, "%[^/]/%hhu", szDestAddr, &prefix) < 1))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (is_ipv4_addr(szDestAddr))
    {
        prefix = (prefix == 255) ? 32 : prefix;
        if ((prefix > 32) || !is_ipv4_addr(pRoute->pszGateway))
        {
            err = EINVAL;
            bail_on_error(err);
        }
    }
    else if (is_ipv6_addr(szDestAddr))
    {
        prefix = (prefix == 255) ? 128 : prefix;
        if ((prefix > 128) || !is_ipv6_addr(pRoute->pszGateway))
        {
            err = EINVAL;
            bail_on_error(err);
        }
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

    memcpy(&route, pRoute, sizeof(route));
    sprintf(szDestAddr, "%s/%hhu", szDestAddr, prefix);
    route.pszDestNetwork = szDestAddr;

    err = add_route_section(&route);
    bail_on_error(err);

cleanup:
    return err;
error:
    goto cleanup;
}

int
delete_static_ip_route(
    NET_IP_ROUTE *pRoute,
    uint32_t flags
)
{
    uint32_t err = 0;
    uint8_t prefix = 255;
    char szDestAddr[INET6_ADDRSTRLEN+5];
    NET_IP_ROUTE route;

    if (IS_NULL_OR_EMPTY(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork) ||
        (sscanf(pRoute->pszDestNetwork, "%[^/]/%hhu", szDestAddr, &prefix) < 1))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (is_ipv4_addr(szDestAddr))
    {
        prefix = (prefix == 255) ? 32 : prefix;
    }
    else if (is_ipv6_addr(szDestAddr))
    {
        prefix = (prefix == 255) ? 128 : prefix;
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

    memcpy(&route, pRoute, sizeof(route));
    sprintf(szDestAddr, "%s/%hhu", szDestAddr, prefix);
    route.pszDestNetwork = szDestAddr;

    err = delete_route_section(&route);
    bail_on_error(err);

cleanup:
    return err;
error:
    goto cleanup;
}

int
get_static_ip_routes(
    const char *pszInterfaceName,
    size_t *pCount,
    NET_IP_ROUTE ***pppRoutesList
)
{
    uint32_t err = 0;

    if (!pszInterfaceName)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* TODO: If pszInterfaceName == NULL, get static route for all if */

    err = get_routes(pszInterfaceName, pCount, pppRoutesList);
    bail_on_error(err);


cleanup:
    return err;
error:
    goto cleanup;
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
            if (strlen(pszNewString) > 0)
            {
                strcat(pszNewString, " ");
            }
            if (strstr(pszNewString, ppszStrings[i]) == NULL)
            {
                strcat(pszNewString, ppszStrings[i]);
            }
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

static uint32_t
space_delimited_string_to_list(
    const char *pszString,
    size_t *pCount,
    char ***pppszStringList
)
{
    uint32_t err = 0;
    size_t i = 0, count = 0;
    char *pszString1 = NULL, *pszString2 = NULL;
    char *s1, *s2, **ppszStringList = NULL;

    if (!pCount || !pppszStringList)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc_string(pszString, &pszString1);
    bail_on_error(err);
    err = netmgr_alloc_string(pszString, &pszString2);
    bail_on_error(err);

    s2 = pszString1;
    do {
        s1 = strsep(&s2, " ");
        if (strlen(s1) > 0)
        {
            count++;
        }
    } while (s2 != NULL);

    if (count > 0)
    {
        err = netmgr_alloc((count * sizeof(char *)), (void *)&ppszStringList);
        bail_on_error(err);

        s2 = pszString2;
        do {
            s1 = strsep(&s2, " ");
            if (strlen(s1) > 0)
            {
                err = netmgr_alloc_string(s1, &(ppszStringList[i++]));
                bail_on_error(err);
            }
        } while (s2 != NULL);
    }

    *pCount = count;
    *pppszStringList = ppszStringList;

cleanup:
    netmgr_free(pszString1);
    netmgr_free(pszString2);
    return err;

error:
    netmgr_list_free(count, (void **)ppszStringList);
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppszStringList != NULL)
    {
        *pppszStringList = NULL;
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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
add_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer,
    uint32_t flags
)
{
    uint32_t err = 0;
    NET_DNS_MODE mode;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsServers = NULL;
    char *pszNewDnsServersValue = NULL;

    if (pszDnsServer == NULL)
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
        err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = space_delimited_string_append(1, &pszDnsServer,
                                        pszCurrentDnsServers,
                                        &pszNewDnsServersValue);
    bail_on_error(err);

    err = set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                        pszNewDnsServersValue, 0);
    bail_on_error(err);

    if (!TEST_FLAG(flags, fNO_RESTART))
    {
        err = restart_network_service();
        bail_on_error(err);
        err = restart_dns_service();
        bail_on_error(err);
    }

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
    const char *pszDnsServer,
    uint32_t flags
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
        err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    if (!TEST_FLAG(flags, fNO_RESTART))
    {
        err = restart_network_service();
        bail_on_error(err);
        err = restart_dns_service();
        bail_on_error(err);
    }

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
    char *pszDnsServersValue = NULL;
    DIR *dirFile = NULL;
    struct dirent *hFile;

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = space_delimited_string_append(count, ppszDnsServers, NULL,
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

    if (!TEST_FLAG(flags, fNO_RESTART))
    {
        err = restart_network_service();
        bail_on_error(err);
        err = restart_dns_service();
        bail_on_error(err);
    }

error:
    if (dirFile != NULL)
    {
        closedir(dirFile);
    }
    netmgr_free(pszDnsServersValue);
    netmgr_free(pszCfgFileName);
    return err;
}

static uint32_t
read_etc_resolv_conf(char **ppszFileBuf)
{
    uint32_t err = 0;
    long len;
    FILE *fp = NULL;
    char *pszFileBuf = NULL;

    if (!ppszFileBuf)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    fp = fopen("/etc/resolv.conf", "r");
    if (fp == NULL)
    {
        err = errno;
        bail_on_error(err);
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        err = errno;
        bail_on_error(err);
    }
    len = ftell(fp);
    if (len == -1)
    {
        err = errno;
        bail_on_error(err);
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = netmgr_alloc((len + 1), (void *)&pszFileBuf);
    bail_on_error(err);

    if (fread(pszFileBuf, len, 1, fp) == 0)
    {
        err = errno;
        bail_on_error(err);
    }

    *ppszFileBuf = pszFileBuf;

cleanup:
    if (fp != NULL)
    {
        fclose(fp);
    }
    return err;

error:
    if (ppszFileBuf != NULL)
    {
        *ppszFileBuf = NULL;
    }
    netmgr_free(pszFileBuf);
    goto cleanup;
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
    char *pszCfgFileName = NULL, *pszFileBuf = NULL;
    char szSectionName[MAX_LINE], szServer[INET6_ADDRSTRLEN];
    char *pszUseDnsValue = NULL, *pszDnsServersValue = NULL;
    char *s1, **ppszDnsServersList = NULL;
    size_t i = 0, count = 0;

    if ((pMode == NULL) || (pCount == NULL) || (pppszDnsServers == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = get_dns_mode("eth0", pMode);
    bail_on_error(err);

    if (pszInterfaceName == NULL)
    {
        err = read_etc_resolv_conf(&pszFileBuf);
        bail_on_error(err);

        s1 = pszFileBuf;
        while ((s1 = strstr(s1, STR_NAMESERVER)) != NULL)
        {
            count++;
            s1++;
        }

        if (count > 0)
        {
            err = netmgr_alloc((count * sizeof(char *)),
                               (void *)&ppszDnsServersList);
            bail_on_error(err);

            s1 = pszFileBuf;
            while ((s1 = strstr(s1, STR_NAMESERVER)) != NULL)
            {
                if (sscanf(s1, "nameserver %s", szServer) != 1)
                {
                    err = errno;
                    bail_on_error(err);
                }
                err = netmgr_alloc_string(szServer, &(ppszDnsServersList[i++]));
                bail_on_error(err);
                s1++;
            } while (s1 != NULL);
        }
    }
    else
    {
        if (!strcmp(pszInterfaceName, "none"))
        {
            err = get_resolved_conf_filename(&pszCfgFileName);
            sprintf(szSectionName, SECTION_RESOLVE);
        }
        else
        {
            err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
            sprintf(szSectionName, SECTION_NETWORK);
        }
        bail_on_error(err);

        err = get_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                            &pszDnsServersValue);
        if (err == ENOENT)
        {
            err = 0;
            goto error;
        }
        bail_on_error(err);

        err = space_delimited_string_to_list(pszDnsServersValue, &count,
                                             &ppszDnsServersList);
        bail_on_error(err);
    }

    *pCount = count;
    *pppszDnsServers = ppszDnsServersList;

clean:
    netmgr_free(pszFileBuf);
    netmgr_free(pszDnsServersValue);
    netmgr_free(pszUseDnsValue);
    netmgr_free(pszCfgFileName);
    return err;

error:
    netmgr_list_free(count, (void **)ppszDnsServersList);
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
add_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain,
    uint32_t flags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsDomains = NULL;
    char *pszDnsDomainsValue = NULL;

    if (pszDnsDomain == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = space_delimited_string_append(1, &pszDnsDomain,
                                        pszCurrentDnsDomains,
                                        &pszDnsDomainsValue);
    bail_on_error(err);

    err = set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                        pszDnsDomainsValue, 0);
    bail_on_error(err);

    if (!TEST_FLAG(flags, fNO_RESTART))
    {
        err = restart_network_service();
        bail_on_error(err);
        err = restart_dns_service();
        bail_on_error(err);
    }

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
    const char *pszDnsDomain,
    uint32_t flags
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
        err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    if (!TEST_FLAG(flags, fNO_RESTART))
    {
        err = restart_network_service();
        bail_on_error(err);
        err = restart_dns_service();
        bail_on_error(err);
    }

cleanup:
    netmgr_free(pszNewDnsDomainsList);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
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
    char *pszDnsDomainsValue = NULL;

    if (pszInterfaceName != NULL)
    {
        err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = space_delimited_string_append(count, ppszDnsDomains, NULL,
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

    if (!TEST_FLAG(flags, fNO_RESTART))
    {
        err = restart_network_service();
        bail_on_error(err);
        err = restart_dns_service();
        bail_on_error(err);
    }

error:
    netmgr_free(pszDnsDomainsValue);
    netmgr_free(pszCfgFileName);
    return err;
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
    size_t count = 0;
    char szSectionName[MAX_LINE];
    char *pszCfgFileName = NULL, *pszFileBuf = NULL;
    char *pszDnsDomainsValue = NULL, **ppszDnsDomainsList = NULL;

    if ((pCount == NULL) || (pppszDnsDomains == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName == NULL)
    {
        err = read_etc_resolv_conf(&pszFileBuf);
        bail_on_error(err);

        pszDnsDomainsValue = strstr(pszFileBuf, STR_SEARCH);
        if (pszDnsDomainsValue == NULL)
        {
            err = ENOENT;
            bail_on_error(err);
        }
        pszDnsDomainsValue = strstr(pszDnsDomainsValue, " ");
        if (pszDnsDomainsValue == NULL)
        {
            err = ENOENT;
            bail_on_error(err);
        }
        pszDnsDomainsValue++;

        err = space_delimited_string_to_list(pszDnsDomainsValue, &count,
                                             &ppszDnsDomainsList);
        pszDnsDomainsValue = NULL;
        bail_on_error(err);
    }
    else
    {
        if (!strcmp(pszInterfaceName, "none"))
        {
            err = get_resolved_conf_filename(&pszCfgFileName);
            sprintf(szSectionName, SECTION_RESOLVE);
        }
        else
        {
            err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
            sprintf(szSectionName, SECTION_NETWORK);
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

        err = space_delimited_string_to_list(pszDnsDomainsValue, &count,
                                             &ppszDnsDomainsList);
        bail_on_error(err);
    }

    *pCount = count;
    *pppszDnsDomains = ppszDnsDomainsList;

clean:
    netmgr_free(pszFileBuf);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

int
stop_network_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl stop systemd-networkd";

    err = netmgr_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

int
restart_network_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl restart systemd-networkd";

    err = netmgr_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

int
stop_dns_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl stop systemd-resolved";

    err = netmgr_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

int
restart_dns_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl restart systemd-resolved";

    err = netmgr_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

