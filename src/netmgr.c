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

static const char *szLinkStateString[] =
{
    "down",
    "up",
    "unknown"
};

static const char *szLinkModeString[] =
{
    "auto",
    "manual",
    "unknown"
};

const char *
nm_link_state_to_string(
    NET_LINK_STATE state
)
{
    if (state > LINK_STATE_UNKNOWN)
    {
        state = LINK_STATE_UNKNOWN;
    }
    return szLinkStateString[state];
}

const char *
nm_link_mode_to_string(
    NET_LINK_MODE mode
)
{
    if (mode > LINK_MODE_UNKNOWN)
    {
        mode = LINK_MODE_UNKNOWN;
    }
    return szLinkModeString[mode];
}

const char *
nm_ip_addr_type_to_string(
    NET_ADDR_TYPE addrType
)
{
    switch (addrType)
    {
        case STATIC_IPV4:
            return "IPv4 static";
        case STATIC_IPV6:
            return "IPv6 static";
        case DHCP_IPV4:
            return "IPv4 dhcp";
        case DHCP_IPV6:
            return "IPv6 dhcp";
        case AUTO_IPV6:
            return "IPv6 autoconf";
        case LINK_LOCAL_IPV6:
            return "IPv6 link-local";
        default:
            break;
    }
    return "Unknown addrtype";
}

static uint32_t
nm_alloc_conf_filename(
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
nm_get_networkd_conf_filename(
    char **ppszFilename)
{
    return nm_alloc_conf_filename(ppszFilename, SYSTEMD_PATH, "networkd.conf");
}

static uint32_t
nm_get_network_auto_conf_filename(
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
    err = nm_alloc_conf_filename(ppszFilename, SYSTEMD_NET_PATH, fname);
error:
    return err;
}

static uint32_t
nm_get_network_manual_conf_filename(
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
    err = nm_alloc_conf_filename(ppszFilename, SYSTEMD_NET_PATH, fname);
error:
    return err;
}

static uint32_t
nm_get_network_conf_filename(
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

    err = nm_get_network_manual_conf_filename(pszIfname, &pszCfgFileName);
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
nm_get_resolved_conf_filename(
    char **ppszFilename)
{
    return nm_alloc_conf_filename(ppszFilename, SYSTEMD_PATH, "resolved.conf");
}


/*
 * Interface configuration APIs
 */

static uint32_t
nm_macaddr_a2n(
    const char *pszMacAddress,
    struct ifreq *pifr)
{
    uint32_t err = 0;
    int i = 0, value = 0;
    char *pszColon = NULL;
    const char *pszMacAddrLocal = NULL;

    if (IS_NULL_OR_EMPTY(pszMacAddress) || !pifr)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    pszMacAddrLocal = pszMacAddress;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        value = 0;
        pszColon = strchr(pszMacAddrLocal, ':');

        if (pszColon)
        {
            pszColon++;
        }
        if (sscanf(pszMacAddrLocal, "%x", &value) != 1) {
            err = EINVAL;
        }
        bail_on_error(err);

        if (value < 0 || value > 255) {
            err = EINVAL;
        }
        bail_on_error(err);

        pifr->ifr_hwaddr.sa_data[i] = value;
        if (!pszColon)
        {
            break;
        }
        pszMacAddrLocal = pszColon;
    }

    if (i != ETHER_ADDR_LEN)
    {
        err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    return err;

error:
    memset(pifr, 0, sizeof(*pifr));
    goto cleanup;
}

uint32_t
nm_set_link_mac_addr(
    const char *pszInterfaceName,
    const char *pszMacAddress
)
{
    uint32_t err = 0;
    int sockFd = -1;
    char *pszCfgFileName = NULL;
    int lockId;
    struct ifreq ifr;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pszInterfaceName, sizeof(ifr.ifr_name));

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    err = nm_macaddr_a2n(pszMacAddress, &ifr);
    bail_on_error(err);

    err = nm_set_key_value(pszCfgFileName, SECTION_LINK, KEY_MAC_ADDRESS,
                           pszMacAddress, 0);
    bail_on_error(err);

    err = nm_ifdown(pszInterfaceName);
    bail_on_error(err);

    err = ioctl(sockFd, SIOCSIFHWADDR, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = nm_ifup(pszInterfaceName);
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    if (sockFd > -1)
    {
        close(sockFd);
    }
    netmgr_free(pszCfgFileName);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_get_link_mac_addr(
    const char *pszInterfaceName,
    char **ppszMacAddress
)
{
    uint32_t err = 0;
    int sockFd = -1;
    char *pszMacAddress = NULL;
    struct ifreq ifr;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) || !ppszMacAddress)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pszInterfaceName, sizeof(ifr.ifr_name));

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = ioctl(sockFd, SIOCGIFHWADDR, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszMacAddress,
                                     "%02x:%02x:%02x:%02x:%02x:%02x",
                                     (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                                     (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                                     (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                                     (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                                     (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                                     (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    bail_on_error(err);

    *ppszMacAddress = pszMacAddress;

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;
error:
    if (ppszMacAddress)
    {
        *ppszMacAddress = NULL;
    }
    netmgr_free(pszMacAddress);
    goto cleanup;
}

uint32_t
nm_set_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE mode
)
{
    uint32_t err = 0;
    char *pszAutoCfgFileName = NULL, *pszManualCfgFileName = NULL;
    char *pszCurrentCfgFileName = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || (mode >= LINK_MODE_UNKNOWN))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_auto_conf_filename(pszInterfaceName,
                                            &pszAutoCfgFileName);
    bail_on_error(err);

    err = nm_get_network_manual_conf_filename(pszInterfaceName,
                                              &pszManualCfgFileName);
    bail_on_error(err);

    err = nm_get_network_conf_filename(pszInterfaceName,
                                       &pszCurrentCfgFileName);
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
    nm_release_write_lock(lockId);
    netmgr_free(pszCurrentCfgFileName);
    netmgr_free(pszAutoCfgFileName);
    netmgr_free(pszManualCfgFileName);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_get_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE *pLinkMode
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) || !pLinkMode)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    if (strstr(pszCfgFileName, ".manual"))
    {
        *pLinkMode = LINK_MANUAL;
    }
    else if (strstr(pszCfgFileName, ".network"))
    {
        *pLinkMode = LINK_AUTO;
    }
    else
    {
        *pLinkMode = LINK_MODE_UNKNOWN;
    }

cleanup:
    netmgr_free(pszCfgFileName);
    return err;

error:
    if (pLinkMode)
    {
        *pLinkMode = LINK_MODE_UNKNOWN;
    }
    goto cleanup;
}

uint32_t
nm_set_link_mtu(
    const char *pszInterfaceName,
    uint32_t mtu
)
{
    uint32_t err = 0;
    int sockFd = -1;
    char *pszCfgFileName = NULL;
    char szValue[MAX_LINE] = "";
    int lockId;
    struct ifreq ifr;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pszInterfaceName, sizeof(ifr.ifr_name));

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    if (mtu > 0)
    {
        ifr.ifr_mtu = mtu;
        sprintf(szValue, "%u", mtu);
    }
    else
    {
        ifr.ifr_mtu = DEFAULT_MTU_VALUE;
        sprintf(szValue, "%u", DEFAULT_MTU_VALUE);
    }

    err = nm_set_key_value(pszCfgFileName, SECTION_LINK, KEY_MTU, szValue, 0);
    bail_on_error(err);

    err = nm_ifdown(pszInterfaceName);
    bail_on_error(err);

    err = ioctl(sockFd, SIOCSIFMTU, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = nm_ifup(pszInterfaceName);
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    if (sockFd > -1)
    {
        close(sockFd);
    }
    netmgr_free(pszCfgFileName);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_get_link_mtu(
    const char *pszInterfaceName,
    uint32_t *pMtu
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct ifreq ifr;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) || !pMtu)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pszInterfaceName, sizeof(ifr.ifr_name));

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = ioctl(sockFd, SIOCGIFMTU, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    *pMtu = ifr.ifr_mtu;

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;
error:
    if (pMtu)
    {
        *pMtu = 0;
    }
    goto cleanup;
}

uint32_t
nm_set_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE linkState
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct ifreq ifr;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) ||
        (linkState >= LINK_STATE_UNKNOWN))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pszInterfaceName, sizeof(ifr.ifr_name));

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = ioctl(sockFd, SIOCGIFFLAGS, &ifr);
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
            SET_FLAG(ifr.ifr_flags, IFF_UP | IFF_BROADCAST |
                     IFF_RUNNING | IFF_MULTICAST);
            break;
        case LINK_DOWN:
            if (!TEST_FLAG(ifr.ifr_flags, IFF_UP))
            {
                goto cleanup;
            }
            CLEAR_FLAG(ifr.ifr_flags, IFF_UP);
            break;
        default:
            err = EINVAL;
    }
    bail_on_error(err);

    err = ioctl(sockFd, SIOCSIFFLAGS, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

cleanup:
    nm_release_write_lock(lockId);
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;
error:
    goto cleanup;
}

uint32_t
nm_get_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE *pLinkState
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct ifreq ifr;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) || !pLinkState)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pszInterfaceName, sizeof(ifr.ifr_name));

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = ioctl(sockFd, SIOCGIFFLAGS, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    *pLinkState = TEST_FLAG(ifr.ifr_flags, IFF_UP) ? LINK_UP : LINK_DOWN;

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;

error:
    if (pLinkState)
    {
        *pLinkState = LINK_STATE_UNKNOWN;
    }
    goto cleanup;
}

static uint32_t
nm_do_arping(
    const char *pszInterfaceName,
    const char *pszCommandOptions,
    const char *pszDestIPv4Addr
)
{
    uint32_t err = 0;
    char *pszArpingCmd = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) ||
        IS_NULL_OR_EMPTY(pszCommandOptions) ||
        IS_NULL_OR_EMPTY(pszDestIPv4Addr))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszArpingCmd, "%s %s -I %s %s",
                                     ARPING_COMMAND, pszCommandOptions,
                                     pszInterfaceName, pszDestIPv4Addr);
    bail_on_error(err);

    err = nm_run_command(pszArpingCmd);
    bail_on_error(err);

cleanup:
    netmgr_free(pszArpingCmd);
    return err;

error:
    goto cleanup;
}

#if 0
static uint32_t
nm_do_ndsend(
    const char *pszInterfaceName,
    const char *pszCommandOptions,
    const char *pszDestIPv6Addr
)
{
    //TODO: Implement
    return 00;
}
#endif

static uint32_t
nm_get_static_ip_addr(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    char ***pppszIpAddrList
);

static uint32_t
nm_get_interface_ipaddr(
    const char *pszInterfaceName,
    NET_ADDR_TYPE addrType,
    size_t *pCount,
    char ***pppszIpAddress
);

uint32_t
nm_ifup(
    const char *pszInterfaceName
)
{
    uint32_t err = 0, err1 = 0;
    uint8_t prefix;
    int retVal = 0;
    size_t staticIp4Count = 0, ip4Count = 0, ip6Count = 0;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    char ipAddr[INET6_ADDRSTRLEN];
    char **ppszIpv4AddrList = NULL, **ppszIpv6AddrList = NULL;
    char **ppszStaticIpv4AddrList = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_link_state(pszInterfaceName, &linkState);
    bail_on_error(err);

    err = nm_get_interface_ipaddr(pszInterfaceName, STATIC_IPV4, &ip4Count,
                                  &ppszIpv4AddrList);
    if (err == ENOENT)
    {
        err = 0;
    }
    bail_on_error(err);

    if (!ip4Count)
    {
        err = nm_get_interface_ipaddr(pszInterfaceName, STATIC_IPV6, &ip6Count,
                                      &ppszIpv6AddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }

    if ((linkState == LINK_UP) && (ip4Count || ip6Count))
    {
        goto cleanup;
    }

    err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &staticIp4Count,
                                &ppszStaticIpv4AddrList);
    if (err == ENOENT)
    {
        err = 0;
    }
    bail_on_error(err);

    err = flush_interface_ipaddr(pszInterfaceName);
    bail_on_error(err);

    err = nm_set_link_state(pszInterfaceName, LINK_UP);
    bail_on_error(err);

    if (staticIp4Count && ip4Count &&
        (strcmp(ppszStaticIpv4AddrList[0], ppszIpv4AddrList[0]) != 0))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (staticIp4Count && !ip4Count)
    {
        retVal = sscanf(ppszStaticIpv4AddrList[0], "%[^/]/%hhu", ipAddr,
                        &prefix);
        if ((retVal != 1) && (retVal != 2))
        {
            err = EINVAL;
            bail_on_error(err);
        }

        err = nm_do_arping(pszInterfaceName, ARPING_DUP_ADDR_CHECK_CMDOPT,
                           ipAddr);
        bail_on_error(err);
    }

    err = nm_get_link_mode(pszInterfaceName, &linkMode);
    bail_on_error(err);

    if (linkMode == LINK_MANUAL)
    {
        err = nm_set_link_mode(pszInterfaceName, LINK_AUTO);
        bail_on_error(err);
    }

    err = nm_restart_network_service();
    if (linkMode == LINK_MANUAL)
    {
        err1 = nm_set_link_mode(pszInterfaceName, LINK_MANUAL);
        bail_on_error(err1);
    }
    bail_on_error(err);

    err = nm_wait_for_ip(pszInterfaceName, DEFAULT_WAIT_FOR_IP_TIMEOUT,
                         NET_ADDR_IPV4 | NET_ADDR_IPV6);
    bail_on_error(err);

    if (staticIp4Count && !ip4Count)
    {
        err = nm_do_arping(pszInterfaceName, ARPING_UPDATE_NEIGHBOR_CMDOPT,
                           ipAddr);
        bail_on_error(err);
    }

cleanup:
    netmgr_list_free(ip4Count, (void **)ppszIpv4AddrList);
    netmgr_list_free(ip6Count, (void **)ppszIpv6AddrList);
    netmgr_list_free(staticIp4Count, (void **)ppszStaticIpv4AddrList);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_ifdown(
    const char *pszInterfaceName
)
{
    uint32_t err = 0;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = flush_interface_ipaddr(pszInterfaceName);
    bail_on_error(err);

    err = nm_set_link_state(pszInterfaceName, LINK_DOWN);
    bail_on_error(err);

cleanup:
    return err;

error:
    goto cleanup;
}

static void
nm_free_interface_list(
    PNET_INTERFACE pInterfaceList
)
{
    while (pInterfaceList)
    {
        PNET_INTERFACE pCurrent = pInterfaceList;
        pInterfaceList = pCurrent->pNext;
        netmgr_free(pCurrent->pszName);
        netmgr_free(pCurrent);
    }
}

static uint32_t
nm_enumerate_systemd_interfaces(
    PNET_INTERFACE *ppInterfaces
)
{
    uint32_t err = 0;
    size_t size1 = 0, size2 = 0;
    char *pszStr1 = NULL, *pszStr2 = NULL;
    DIR *dirFile = NULL;
    struct dirent *hFile;
    PNET_INTERFACE pInterfaceList = NULL;
    PNET_INTERFACE pInterface = NULL;

    if (!ppInterfaces)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    dirFile = opendir(SYSTEMD_NET_PATH);
    if (dirFile == NULL)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    errno = 0;
    while ((hFile = readdir(dirFile)) != NULL)
    {
        if (!strcmp(hFile->d_name, ".")) continue;
        if (!strcmp(hFile->d_name, "..")) continue;
        if (hFile->d_name[0] == '.') continue;
        if (strstr(hFile->d_name, ".network") == NULL) continue;

        pszStr1 = strstr(hFile->d_name, "10-");
        if (pszStr1 == NULL)
        {
            err = ENOENT;
            bail_on_error(err);
        }

        size1 = strlen("10-");
        pszStr2 = strstr(pszStr1 + size1, ".");

        if (pszStr2 == NULL)
        {
            err = ENOENT;
            bail_on_error(err);
        }
        size2 = pszStr2 - (pszStr1 + size1);

        err = netmgr_alloc(sizeof(NET_INTERFACE), (void**)&pInterface);
        bail_on_error(err);

        err = netmgr_alloc_string_len(pszStr1 + size1, size2,
                                      &pInterface->pszName);
        bail_on_error(err);

        pInterface->pNext = pInterfaceList;
        pInterfaceList = pInterface;
        pInterface = NULL;
    }

    *ppInterfaces = pInterfaceList;

cleanup:
    if (dirFile != NULL)
    {
        closedir(dirFile);
    }
    return err;

error:
    if (ppInterfaces)
    {
        *ppInterfaces = NULL;
    }
    if (pInterface)
    {
        nm_free_interface_list(pInterface);
    }
    if (pInterfaceList)
    {
        nm_free_interface_list(pInterfaceList);
    }
    goto cleanup;
}

static uint32_t
nm_get_interface_info(
    const char *pszInterfaceName,
    NET_LINK_INFO **ppLinkInfo
)
{
    uint32_t err = 0, mtu = 0;
    char *pszMacAddress = NULL;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    NET_LINK_INFO *pLinkInfo = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !ppLinkInfo ||
        (strlen(pszInterfaceName) > IFNAMSIZ))
    {
        err =  EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(NET_LINK_INFO), (void **)&pLinkInfo);
    bail_on_error(err);

    err = nm_get_link_mac_addr(pszInterfaceName, &pszMacAddress);
    bail_on_error(err);

    err = nm_get_link_mtu(pszInterfaceName, &mtu);
    bail_on_error(err);

    err = nm_get_link_mode(pszInterfaceName, &linkMode);
    bail_on_error(err);

    err = nm_get_link_state(pszInterfaceName, &linkState);
    bail_on_error(err);

    err = netmgr_alloc_string(pszInterfaceName, &pLinkInfo->pszInterfaceName);
    bail_on_error(err);

    pLinkInfo->pszMacAddress = pszMacAddress;
    pLinkInfo->mtu = mtu;
    pLinkInfo->mode = linkMode;
    pLinkInfo->state = linkState;

    pLinkInfo->pNext = *ppLinkInfo;
    *ppLinkInfo = pLinkInfo;

cleanup:
    return err;

error:
    if (pLinkInfo)
    {
        netmgr_free(pLinkInfo->pszInterfaceName);
        netmgr_free(pLinkInfo->pszMacAddress);
        netmgr_free(pLinkInfo);
    }
    goto cleanup;
}

uint32_t
nm_get_link_info(
    const char *pszInterfaceName,
    NET_LINK_INFO **ppLinkInfo
)
{
    uint32_t err = 0;
    NET_LINK_INFO *pLinkInfo = NULL;
    PNET_INTERFACE pInterfaceList = NULL, pCurInterface = NULL;

    if (!ppLinkInfo)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = nm_enumerate_systemd_interfaces(&pInterfaceList);
        bail_on_error(err);

        pCurInterface = pInterfaceList;
        while (pCurInterface)
        {
            err = nm_get_interface_info(pCurInterface->pszName, &pLinkInfo);
            bail_on_error(err);
            pCurInterface = pCurInterface->pNext;
        }
    }
    else
    {
        err = nm_get_interface_info(pszInterfaceName, &pLinkInfo);
        bail_on_error(err);
    }

    *ppLinkInfo = pLinkInfo;

cleanup:
    return err;

error:
    if (ppLinkInfo)
    {
        *ppLinkInfo = NULL;
    }
    nm_free_link_info(pLinkInfo);
    nm_free_interface_list(pInterfaceList);
    goto cleanup;
}

void
nm_free_link_info(
    NET_LINK_INFO *pNetLinkInfo
)
{
    NET_LINK_INFO *pCurrent = NULL;
    while (pNetLinkInfo)
    {
        pCurrent = pNetLinkInfo;
        pNetLinkInfo = pNetLinkInfo->pNext;
        netmgr_free(pCurrent->pszMacAddress);
        netmgr_free(pCurrent->pszInterfaceName);
        netmgr_free(pCurrent);
    }
}


/*
 * IP Address configuration APIs
 */
static uint32_t
nm_get_static_ip_addr(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    char ***pppszIpAddrList
)
{
    uint32_t err = 0, dwNumSections = 0, nCount = 0, i = 0, prefix;
    char *pszCfgFileName = NULL, ipAddr[INET6_ADDRSTRLEN];
    char **ppszIpAddrList = NULL;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pKeyValue = NULL, pNextKeyValue = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pCount || !pppszIpAddrList)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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
        err = netmgr_alloc((nCount * sizeof(char *)), (void *)&ppszIpAddrList);
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
                                          &(ppszIpAddrList[i++]));
                bail_on_error(err);
            }
            pKeyValue = pNextKeyValue;
        } while (pNextKeyValue != NULL);
    }
    else
    {
        err = ENOENT;
        bail_on_error(err);
    }
    /* TODO: Implement get for DHCPv4, DHCPv6 and AutoV6 */

    *pCount = i;
    *pppszIpAddrList = ppszIpAddrList;

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
    if (ppszIpAddrList != NULL)
    {
        netmgr_list_free(i, (void **)ppszIpAddrList);
    }
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppszIpAddrList != NULL)
    {
        *pppszIpAddrList = NULL;
    }
    goto cleanup;
}

static uint32_t
nm_get_interface_ipaddr(
    const char *pszInterfaceName,
    NET_ADDR_TYPE addrType,
    size_t *pCount,
    char ***pppszIpAddress
)
{
    uint32_t err = 0, ip4Type = 0, ip6Type = 0;
    uint8_t prefix = 0;
    size_t count = 0, i = 0;
    int af = 0;
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    struct sockaddr_in *sockIpv4 = NULL;
    struct sockaddr_in6 *sockIpv6 = NULL;
    char **ppszIpAddrList = NULL;
    char szIpAddr[INET6_ADDRSTRLEN];
    const char *pszIpAddr = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
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

    if (TEST_FLAG(addrType, STATIC_IPV4) || TEST_FLAG(addrType, DHCP_IPV4))
    {
        ip4Type = 1;
    }
    if (TEST_FLAG(addrType, STATIC_IPV6) || TEST_FLAG(addrType, DHCP_IPV6) ||
        TEST_FLAG(addrType, AUTO_IPV6))
    {
        ip6Type = 1;
    }

    if (!ip4Type && !ip6Type)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if ((ifa->ifa_addr == NULL) ||
            (strcmp(ifa->ifa_name, pszInterfaceName) != 0))
        {
           continue;
        }
        af = ifa->ifa_addr->sa_family;

        if (((af == AF_INET) && ip4Type) ||
            ((af == AF_INET6) && ip6Type))
        {
            count++;
        }
    }

    if (count == 0)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    err = netmgr_alloc((count * sizeof(char *)), (void *)&ppszIpAddrList);
    bail_on_error(err);

    for (ifa = ifaddr; count && (ifa != NULL); ifa = ifa->ifa_next)
    {
        if ((ifa->ifa_addr == NULL) ||
            (strcmp(ifa->ifa_name, pszInterfaceName) != 0))
        {
           continue;
        }

        af = ifa->ifa_addr->sa_family;

        if (((af == AF_INET) && ip4Type) ||
            ((af == AF_INET6) && ip6Type))
        {
            switch (af)
            {
                case AF_INET:
                    sockIpv4 = (struct sockaddr_in *)ifa->ifa_addr;
                    pszIpAddr = inet_ntop(af, (void *)&sockIpv4->sin_addr,
                                          szIpAddr, INET_ADDRSTRLEN);
                    break;
                case AF_INET6:
                    sockIpv6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                    pszIpAddr = inet_ntop(af, (void *)&sockIpv6->sin6_addr,
                                          szIpAddr, INET6_ADDRSTRLEN);
                    break;
                 default:
                    err = EINVAL;
                    bail_on_error(err);
                    break;
            }

            if (pszIpAddr == NULL)
            {
                err = errno;
                bail_on_error(err);
            }

            err = get_prefix_from_netmask(ifa->ifa_netmask, &prefix);
            bail_on_error(err);

            err = netmgr_alloc_string_printf(&ppszIpAddrList[i++], "%s/%hhu",
                                             szIpAddr, prefix);
            bail_on_error(err);
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
nm_get_ip_default_gateway(
    const char *pszInterfaceName,
    NET_ADDR_TYPE addrType,
    char **ppszGateway
)
{
    uint32_t err = 0;
    static int msgSeq = 0;
    int sockFd = -1, readLen, msgLen = 0, rtLen, pId;
    struct nlmsghdr *nlHdr, *nlMsg;
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    struct in_addr dst4 = {0}, gw4 = {0};
#define BUFSIZE 8192
    char ifName[IFNAMSIZ], szMsgBuf[BUFSIZE], *pszMsgBuf = szMsgBuf;
    char szGateway[INET6_ADDRSTRLEN], *pszGateway = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !ppszGateway)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if ((sockFd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    memset(pszMsgBuf, 0, BUFSIZE);
    nlMsg = (struct nlmsghdr *)pszMsgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlMsg->nlmsg_type = RTM_GETROUTE;
    SET_FLAG(nlMsg->nlmsg_flags, (NLM_F_DUMP | NLM_F_REQUEST));
    nlMsg->nlmsg_seq = msgSeq++;
    pId = nlMsg->nlmsg_pid = getpid();

    if (send(sockFd, nlMsg, nlMsg->nlmsg_len, 0) < 0)
    {
        err = errno;
        bail_on_error(err);
    }
    do {
        if ((readLen = recv(sockFd, pszMsgBuf, (BUFSIZE - msgLen), 0)) < 0)
        {
            err = errno;
            bail_on_error(err);
        }
        nlHdr = (struct nlmsghdr *)pszMsgBuf;
        if ((NLMSG_OK(nlHdr, readLen) == 0) ||
            (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            err = errno;
            bail_on_error(err);
        }
        if (nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        pszMsgBuf += readLen;
        msgLen += readLen;
        if (!TEST_FLAG(nlHdr->nlmsg_flags, NLM_F_MULTI))
        {
            break;
        }
    } while ((nlHdr->nlmsg_seq != msgSeq) || (nlHdr->nlmsg_pid != pId));

    for (; NLMSG_OK(nlMsg, msgLen); nlMsg = NLMSG_NEXT(nlMsg, msgLen))
    {
        rtMsg = (struct rtmsg *)NLMSG_DATA(((struct nlmsghdr *)nlMsg));
        // TODO: Figure out IPv6
        if ((rtMsg->rtm_table != RT_TABLE_MAIN) ||
            (rtMsg->rtm_family != AF_INET))
        {
            continue;
        }
        rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
        rtLen = RTM_PAYLOAD(nlMsg);
        for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen))
        {
            switch (rtAttr->rta_type)
            {
                case RTA_OIF:
                    if_indextoname(*(int *)RTA_DATA(rtAttr), ifName);
                    break;
                case RTA_GATEWAY:
                    gw4.s_addr = *(uint32_t *)RTA_DATA(rtAttr);
                    break;
                case RTA_DST:
                    dst4.s_addr = *(uint32_t *)RTA_DATA(rtAttr);
                    break;
                default:
                    break;
            }
        }
        if ((dst4.s_addr == 0) && !strcmp(ifName, pszInterfaceName))
        {
            if (inet_ntop(AF_INET, &gw4, szGateway, INET6_ADDRSTRLEN) != NULL)
            {
                err = netmgr_alloc_string(szGateway, &pszGateway);
            }
            else
            {
                err = errno;
            }
            bail_on_error(err);
            break;
        }
    }

    *ppszGateway = pszGateway;

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;

error:
    if (ppszGateway)
    {
        *ppszGateway = NULL;
    }
    netmgr_free(pszGateway);
    goto cleanup;
}

static uint32_t
nm_set_ip_dhcp_mode(
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

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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

    err = nm_set_key_value(pszCfgFileName, SECTION_NETWORK, KEY_DHCP,
                           szDhcpValue, 0);
    bail_on_error(err);

    /* TODO: set IPv6 autoconf setting */

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_get_ip_dhcp_mode(
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

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, SECTION_NETWORK, KEY_DHCP,
                           &pszDhcpValue);
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

    /* TODO: query IPv6 autoconf setting */

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

static uint32_t
nm_set_static_ip_gateway(
    const char *pszInterfaceName,
    const char *pszIpGwAddr
);

static uint32_t
nm_delete_static_ip_gateway(
    const char *pszInterfaceName,
    uint32_t addrTypes
);

static uint32_t
nm_get_static_ip_gateway(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    char ***pppszGwAddrList
);

static uint32_t
nm_set_static_ipv4_addr(
    const char *pszInterfaceName,
    const char *pszIPv4Addr,
    uint8_t prefix
);

static uint32_t
nm_delete_static_ipv4_addr(
    const char *pszInterfaceName
);

static uint32_t
nm_set_static_ip_gateway(
    const char *pszInterfaceName,
    const char *pszIpGwAddr
)
{
    uint32_t err = 0, addrType;
    char *pszCfgFileName = NULL;;

    /* TODO: Handle eth0:0 virtual interfaces */
    if (IS_NULL_OR_EMPTY(pszInterfaceName) || IS_NULL_OR_EMPTY(pszIpGwAddr))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (is_ipv4_addr(pszIpGwAddr))
    {
        addrType = STATIC_IPV4;
    }
    else if (is_ipv6_addr(pszIpGwAddr))
    {
        addrType = STATIC_IPV6;
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_delete_static_ip_gateway(pszInterfaceName, addrType);
    bail_on_error(err);

    err = nm_add_key_value(pszCfgFileName, SECTION_NETWORK, KEY_GATEWAY,
                           pszIpGwAddr, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_delete_static_ip_gateway(
    const char *pszInterfaceName,
    uint32_t addrTypes
)
{
    uint32_t err = 0;
    size_t i, count = 0;
    char *pszCfgFileName = NULL, **ppszGwAddrList = NULL;

    /* TODO: Handle eth0:0 virtual interfaces */
    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_static_ip_gateway(pszInterfaceName, addrTypes, &count,
                                   &ppszGwAddrList);
    bail_on_error(err);

    for (i = 0; i < count; i++)
    {
        err = nm_delete_key_value(pszCfgFileName, SECTION_NETWORK, KEY_GATEWAY,
                                  ppszGwAddrList[i], 0);
        bail_on_error(err);
    }

cleanup:
    netmgr_list_free(count, (void **)ppszGwAddrList);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_get_static_ip_gateway(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    char ***pppszGwAddrList
)
{
    uint32_t err = 0, dwNumSections = 0, nCount = 0, i = 0, prefix;
    char *pszCfgFileName = NULL, ipAddr[INET6_ADDRSTRLEN];
    char **ppszGwAddrList = NULL;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pKeyValue = NULL, pNextKeyValue = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pCount || !pppszGwAddrList)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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
        pNextKeyValue = ini_cfg_find_next_key(pSection, pKeyValue, KEY_GATEWAY);
        if (pNextKeyValue == NULL)
        {
            break;
        }
        if (TEST_FLAG(addrTypes, STATIC_IPV4) &&
            is_ipv4_addr(pNextKeyValue->pszValue))
        {
            nCount++;
        }
        else if (TEST_FLAG(addrTypes, STATIC_IPV6) &&
                 is_ipv6_addr(pNextKeyValue->pszValue))
        {
            nCount++;
        }
        pKeyValue = pNextKeyValue;
    } while (pNextKeyValue != NULL);

    if (nCount > 0)
    {
        err = netmgr_alloc((nCount * sizeof(char *)), (void *)&ppszGwAddrList);
        bail_on_error(err);

        pKeyValue = NULL;
        do
        {
            pNextKeyValue = ini_cfg_find_next_key(pSection, pKeyValue,
                                                  KEY_GATEWAY);
            if (pNextKeyValue == NULL)
            {
                break;
            }
            sscanf(pNextKeyValue->pszValue, "%[^/]/%u", ipAddr, &prefix);
            if ((TEST_FLAG(addrTypes, STATIC_IPV4) &&
                 is_ipv4_addr(pNextKeyValue->pszValue)) ||
                (TEST_FLAG(addrTypes, STATIC_IPV6) &&
                 is_ipv6_addr(pNextKeyValue->pszValue)))
            {
                err = netmgr_alloc_string(pNextKeyValue->pszValue,
                                          &(ppszGwAddrList[i++]));
                bail_on_error(err);
            }
            pKeyValue = pNextKeyValue;
        } while (pNextKeyValue != NULL);
    }

    /* TODO: Implement get for DHCPv4, DHCPv6 and AutoV6 */

    *pCount = i;
    *pppszGwAddrList = ppszGwAddrList;

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
    if (ppszGwAddrList != NULL)
    {
        netmgr_list_free(i, (void **)ppszGwAddrList);
    }
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppszGwAddrList != NULL)
    {
        *pppszGwAddrList = NULL;
    }
    goto cleanup;
}

static uint32_t
nm_set_static_ipv4_addr(
    const char *pszInterfaceName,
    const char *pszIPv4Addr,
    uint8_t prefix
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

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    sprintf(szIpAddr, "%s/%hhu", pszIPv4Addr, prefix);

    err = nm_delete_static_ipv4_addr(pszInterfaceName);
    if (err == ENOENT)
    {
        err = 0;
    }
    bail_on_error(err);

    err = nm_add_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS,
                           szIpAddr, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_delete_static_ipv4_addr(
    const char *pszInterfaceName
)
{
    uint32_t err = 0;
    size_t count = 0;
    char *pszCfgFileName = NULL, **ppszIpAddrList = NULL;

    /* TODO: Handle eth0:0 virtual interfaces */
    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &count,
                                &ppszIpAddrList);
    bail_on_error(err);
    if (count > 1)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (count)
    {
        err = nm_delete_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS,
                                  ppszIpAddrList[0], 0);
        bail_on_error(err);
    }

cleanup:
    netmgr_list_free(count, (void **)ppszIpAddrList);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_set_ipv4_addr_gateway(
    const char *pszInterfaceName,
    NET_IPV4_ADDR_MODE mode,
    const char *pszIPv4AddrPrefix,
    const char *pszIPv4Gateway
)
{
    int n = 0;
    uint32_t err = 0, currModeFlags = 0;
    uint8_t prefix = 0;
    char szIpAddr[INET6_ADDRSTRLEN];
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || (mode >= IPV4_ADDR_MODE_MAX))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if ((mode == IPV4_ADDR_MODE_STATIC) &&
        (IS_NULL_OR_EMPTY(pszIPv4AddrPrefix) ||
        ((n = sscanf(pszIPv4AddrPrefix, "%[^/]/%hhu", szIpAddr, &prefix)) < 1)
        || !is_ipv4_addr(szIpAddr) || (prefix > 32)))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &currModeFlags);
    bail_on_error(err);

    prefix = ((mode == IPV4_ADDR_MODE_STATIC) && (n == 1)) ? 32 : prefix;

    err = nm_delete_static_ipv4_addr(pszInterfaceName);
    if (err == ENOENT)
    {
        err = 0;
    }
    bail_on_error(err);

    err = nm_delete_static_ip_gateway(pszInterfaceName, STATIC_IPV4);
    if (err == ENOENT)
    {
        err = 0;
    }
    bail_on_error(err);

    switch (mode)
    {
        case IPV4_ADDR_MODE_STATIC:
            err = nm_set_static_ipv4_addr(pszInterfaceName, szIpAddr, prefix);
            bail_on_error(err);
            if (!IS_NULL_OR_EMPTY(pszIPv4Gateway))
            {
                err = nm_set_static_ip_gateway(pszInterfaceName,
                                               pszIPv4Gateway);
                bail_on_error(err);
            }
            /* fall-thru */
        case IPV4_ADDR_MODE_NONE:
            CLEAR_FLAG(currModeFlags, fDHCP_IPV4);
            break;

        case IPV4_ADDR_MODE_DHCP:
            SET_FLAG(currModeFlags, fDHCP_IPV4);
            break;

        default:
            break;
    }

    err = nm_set_ip_dhcp_mode(pszInterfaceName, currModeFlags);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_get_ipv4_addr_gateway(
    const char *pszInterfaceName,
    NET_IPV4_ADDR_MODE *pMode,
    char **ppszIPv4AddrPrefix,
    char **ppszIPv4Gateway
)
{
    uint32_t err = 0, modeFlags = 0;
    NET_IPV4_ADDR_MODE ip4Mode = IPV4_ADDR_MODE_NONE;
    char *pszIPv4AddrPrefix = NULL, *pszIPv4Gateway = NULL;
    char **ppszIpAddrList = NULL, **ppszGwAddrList = NULL;
    size_t ipCount, gwCount;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pMode || !ppszIPv4AddrPrefix ||
        !ppszIPv4Gateway)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    if (TEST_FLAG(modeFlags, fDHCP_IPV4))
    {
        ip4Mode = IPV4_ADDR_MODE_DHCP;

        err = nm_get_interface_ipaddr(pszInterfaceName, DHCP_IPV4, &ipCount,
                                      &ppszIpAddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);

        //TODO: Get DHCP IPv4 gateway from routes
        err = nm_get_ip_default_gateway(pszInterfaceName, DHCP_IPV4,
                                        &pszIPv4Gateway);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    else
    {
        //TODO: Get IP addresss from interface via ioctl. If that fails
        // get it as below from file.
        err = nm_get_interface_ipaddr(pszInterfaceName, STATIC_IPV4, &ipCount,
                                      &ppszIpAddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);

        if (ipCount == 0)
        {
            err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4,
                                        &ipCount, &ppszIpAddrList);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);
        }

        if (ppszIpAddrList != NULL)
        {
            ip4Mode = IPV4_ADDR_MODE_STATIC;

            err = nm_get_ip_default_gateway(pszInterfaceName, STATIC_IPV4,
                                            &pszIPv4Gateway);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);
            if (pszIPv4Gateway == NULL)
            {
                err = nm_get_static_ip_gateway(pszInterfaceName, STATIC_IPV4,
                                               &gwCount, &ppszGwAddrList);
                bail_on_error(err);

                if (gwCount)
                {
                    err = netmgr_alloc_string(ppszGwAddrList[0], &pszIPv4Gateway);
                    bail_on_error(err);
                }
            }
        }
        else
        {
            ip4Mode = IPV4_ADDR_MODE_NONE;
        }
    }

    if (ppszIpAddrList != NULL)
    {
        err = netmgr_alloc_string(ppszIpAddrList[0], &pszIPv4AddrPrefix);
        bail_on_error(err);
    }

    *pMode = ip4Mode;
    *ppszIPv4AddrPrefix = pszIPv4AddrPrefix;
    *ppszIPv4Gateway = pszIPv4Gateway;

cleanup:
    netmgr_list_free(ipCount, (void **)ppszIpAddrList);
    netmgr_list_free(gwCount, (void **)ppszGwAddrList);
    return err;

error:
    if (pMode)
    {
        *pMode = IPV4_ADDR_MODE_NONE;
    }
    if (ppszIPv4AddrPrefix)
    {
        *ppszIPv4AddrPrefix = NULL;
    }
    if (ppszIPv4Gateway)
    {
        *ppszIPv4Gateway = NULL;
    }
    netmgr_free(pszIPv4AddrPrefix);
    netmgr_free(pszIPv4Gateway);
    goto cleanup;
}

uint32_t
nm_add_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6AddrPrefix
)
{
    int n = 0;
    uint32_t err = 0;
    uint8_t prefix = 0;
    char *pszCfgFileName = NULL, szIpAddr[INET6_ADDRSTRLEN];
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszIPv6AddrPrefix) ||
        ((n = sscanf(pszIPv6AddrPrefix, "%[^/]/%hhu", szIpAddr, &prefix)) < 1)
        || !is_ipv6_addr(szIpAddr) || (prefix > 128))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_add_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS,
                           pszIPv6AddrPrefix, 0);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_delete_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6AddrPrefix
)
{
    int n;
    uint32_t err = 0;
    uint8_t prefix = 0;
    char *pszCfgFileName = NULL, szIpAddr[INET6_ADDRSTRLEN];
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszIPv6AddrPrefix) ||
        ((n = sscanf(pszIPv6AddrPrefix, "%[^/]/%hhu", szIpAddr, &prefix)) < 1)
        || !is_ipv6_addr(szIpAddr) || (prefix > 128))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_delete_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS,
                              pszIPv6AddrPrefix, 0);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_set_ipv6_addr_mode(
    const char *pszInterfaceName,
    uint32_t enableDhcp,
    uint32_t enableAutoconf
)
{
    uint32_t err = 0, modeFlags;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    if (enableDhcp)
    {
        SET_FLAG(modeFlags, fDHCP_IPV6);
    }
    else
    {
        CLEAR_FLAG(modeFlags, fDHCP_IPV6);
    }

    if (enableAutoconf)
    {
        SET_FLAG(modeFlags, fAUTO_IPV6);
    }
    else
    {
        CLEAR_FLAG(modeFlags, fAUTO_IPV6);
    }

    err = nm_set_ip_dhcp_mode(pszInterfaceName, modeFlags);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    return err;
}

uint32_t
nm_get_ipv6_addr_mode(
    const char *pszInterfaceName,
    uint32_t *pDhcpEnabled,
    uint32_t *pAutoconfEnabled
)
{
    uint32_t err = 0, modeFlags;
    uint32_t dhcpEnabled = 0, autoconfEnabled = 0;

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    if (TEST_FLAG(modeFlags, fDHCP_IPV6))
    {
        dhcpEnabled = 1;
    }
    if (TEST_FLAG(modeFlags, fAUTO_IPV6))
    {
        autoconfEnabled = 1;
    }

    if (pDhcpEnabled)
    {
        *pDhcpEnabled = dhcpEnabled;
    }
    if (pAutoconfEnabled)
    {
        *pAutoconfEnabled = autoconfEnabled;
    }

error:
    return err;
}

static uint32_t
nm_get_ip_addr_type(
    const char *pszInterfaceName,
    const char *pszIpAddr,
    NET_ADDR_TYPE *pAddrType
)
{
    uint32_t err = 0, prefix;
    size_t i = 0, count = 0;
    char ipAddr[INET6_ADDRSTRLEN], *p, **ppszIpAddrList = NULL;
    NET_ADDR_TYPE addrType = 0;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || IS_NULL_OR_EMPTY(pszIpAddr) ||
        !pAddrType || (sscanf(pszIpAddr, "%[^/]/%u", ipAddr, &prefix) < 1))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (is_ipv4_addr(ipAddr))
    {
        err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &count,
                                    &ppszIpAddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);

        if (count && !strcmp(pszIpAddr, ppszIpAddrList[0]))
        {
            addrType = STATIC_IPV4;
        }
        else
        {
            addrType = DHCP_IPV4;
        }
    }

    if (is_ipv6_addr(ipAddr))
    {
        if ((p = strstr(ipAddr, "fe80:")) == ipAddr)
        {
            addrType = LINK_LOCAL_IPV6;
        }
        else
        {
            err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV6, &count,
                                        &ppszIpAddrList);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            for (i = 0; i < count; i++)
            {
                if (!strcmp(pszIpAddr, ppszIpAddrList[i]))
                {
                    addrType = STATIC_IPV6;
                    break;
                }
            }

            if (addrType == 0)
            {
                //TODO: Determine if autoconf
                addrType = DHCP_IPV6;
            }
        }
    }

    if (addrType == 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    *pAddrType = addrType;

cleanup:
    netmgr_list_free(count, (void **)ppszIpAddrList);
    return err;

error:
    if (pAddrType)
    {
        *pAddrType = 0;
    }
    goto cleanup;
}

uint32_t
nm_get_ip_addr(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    NET_IP_ADDR ***pppIpAddrList
)
{
    uint32_t err = 0, modeFlags;
    size_t i = 0, j = 0, ip4Count = 0, ip6Count = 0, nCount = 0;
    char **ppszIp4AddrList = NULL;
    char **ppszIp6AddrList = NULL;
    NET_IP_ADDR **ppIpAddrList = NULL;

    //TODO: If pszInterfaceName is NULL, enumerate all IPs
    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) ||
        !pCount || !pppIpAddrList || !addrTypes)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    if (TEST_FLAG(modeFlags, fDHCP_IPV4) && TEST_FLAG(addrTypes, DHCP_IPV4))
    {
        err = nm_get_interface_ipaddr(pszInterfaceName, DHCP_IPV4, &ip4Count,
                                      &ppszIp4AddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    else if (TEST_FLAG(addrTypes, STATIC_IPV4))
    {
        err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &ip4Count,
                                    &ppszIp4AddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    nCount = ip4Count;

    if (TEST_FLAG(addrTypes, DHCP_IPV6) || TEST_FLAG(addrTypes, AUTO_IPV6))
    {
        err = nm_get_interface_ipaddr(pszInterfaceName,
                                      DHCP_IPV6 | AUTO_IPV6 | STATIC_IPV6,
                                      &ip6Count,
                                      &ppszIp6AddrList);
        if (err == ENOENT)
        {
            err = nm_get_static_ip_addr(pszInterfaceName,
                                        STATIC_IPV6,
                                        &ip6Count,
                                        &ppszIp6AddrList);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);
        }
        bail_on_error(err);
    }
    nCount += ip6Count;

    if (nCount == 0)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    err = netmgr_alloc((nCount * sizeof(PNET_IP_ADDR)), (void *)&ppIpAddrList);
    bail_on_error(err);

    for (i = 0; i < ip4Count; i++)
    {
        err = netmgr_alloc(sizeof(NET_IP_ADDR), (void **)&ppIpAddrList[i]);
        bail_on_error(err);
        err = netmgr_alloc_string(pszInterfaceName,
                                  &ppIpAddrList[i]->pszInterfaceName);
        bail_on_error(err);
        err = netmgr_alloc_string(ppszIp4AddrList[i],
                                  &ppIpAddrList[i]->pszIPAddrPrefix);
        bail_on_error(err);
        ppIpAddrList[i]->type = TEST_FLAG(modeFlags, fDHCP_IPV4) ?
                                          DHCP_IPV4 : STATIC_IPV4;
    }

    for (j = 0; j < ip6Count; j++, i++)
    {
        err = netmgr_alloc(sizeof(NET_IP_ADDR), (void **)&ppIpAddrList[i]);
        bail_on_error(err);
        err = netmgr_alloc_string(pszInterfaceName,
                                  &ppIpAddrList[i]->pszInterfaceName);
        bail_on_error(err);
        err = netmgr_alloc_string(ppszIp6AddrList[j],
                                  &ppIpAddrList[i]->pszIPAddrPrefix);
        bail_on_error(err);
        err = nm_get_ip_addr_type(pszInterfaceName,
                                  ppszIp6AddrList[j],
                                  &(ppIpAddrList[i]->type));
        bail_on_error(err);
    }

    *pCount = nCount;
    *pppIpAddrList = ppIpAddrList;

cleanup:
    netmgr_list_free(ip4Count, (void **)ppszIp4AddrList);
    netmgr_list_free(ip6Count, (void **)ppszIp6AddrList);
    return err;

error:
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppIpAddrList != NULL)
    {
        *pppIpAddrList = NULL;
    }
    if (ppIpAddrList != NULL)
    {
        for (i = 0; i < nCount; i++)
        {
            if (ppIpAddrList[i] == NULL)
            {
                continue;
            }
            netmgr_free(ppIpAddrList[i]->pszInterfaceName);
            netmgr_free(ppIpAddrList[i]->pszIPAddrPrefix);
        }
        netmgr_list_free(nCount, (void **)ppIpAddrList);
    }
    goto cleanup;
}

uint32_t
nm_set_ipv6_gateway(
    const char *pszInterfaceName,
    const char *pszIPv6Gateway
)
{
    uint32_t err = 0;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!pszInterfaceName || (!IS_NULL_OR_EMPTY(pszIPv6Gateway) &&
        !is_ipv6_addr(pszIPv6Gateway)))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszIPv6Gateway)
    {
        err = nm_set_static_ip_gateway(pszInterfaceName, pszIPv6Gateway);
        bail_on_error(err);
    }
    else
    {
        err = nm_delete_static_ip_gateway(pszInterfaceName, STATIC_IPV6);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }

    err = nm_restart_network_service();
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    return err;
}

uint32_t
nm_get_ipv6_gateway(
    const char *pszInterfaceName,
    char **ppszIPv6Gateway
)
{
    uint32_t err = 0;
    char *pszIPv6Gateway = NULL, **ppszGwAddrList = NULL;
    size_t count = 0;

    if (!pszInterfaceName || !ppszIPv6Gateway)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_ip_default_gateway(pszInterfaceName, DHCP_IPV6,
                                    &pszIPv6Gateway);
    if (err == ENOENT)
    {
        err = 0;
    }
    bail_on_error(err);

    if (pszIPv6Gateway == NULL)
    {
        err = nm_get_static_ip_gateway(pszInterfaceName, STATIC_IPV6, &count,
                                       &ppszGwAddrList);
        bail_on_error(err);

        if (count)
        {
            err = netmgr_alloc_string(ppszGwAddrList[0], &pszIPv6Gateway);
            bail_on_error(err);
        }
    }

    *ppszIPv6Gateway = pszIPv6Gateway;

cleanup:
    netmgr_list_free(count, (void **)ppszGwAddrList);
    return err;

error:
    if (ppszIPv6Gateway)
    {
        *ppszIPv6Gateway = NULL;
    }
    netmgr_free(pszIPv6Gateway);
    goto cleanup;
}


/*
 * Route configuration APIs
 */
static uint32_t
nm_add_route_section(
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

    err = nm_get_network_conf_filename(pRoute->pszInterfaceName,
                                       &pszCfgFileName);
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

static uint32_t
nm_delete_route_section(
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

    err = nm_get_network_conf_filename(pRoute->pszInterfaceName,
                                       &pszCfgFileName);
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

static uint32_t
nm_get_routes(
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

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = ini_cfg_read(pszCfgFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, SECTION_ROUTE, &ppSections,
                                &dwNumSections);
    if (dwNumSections == 0)
    {
        err = ENOENT;
    }
    bail_on_error(err);

    err = netmgr_alloc(dwNumSections * sizeof(NET_IP_ROUTE *),
                       (void **)&ppRoutes);
    bail_on_error(err);

    for (i = 0; i < dwNumSections; i++)
    {
        err = netmgr_alloc(sizeof(NET_IP_ROUTE), (void **)&ppRoutes[i]);
        bail_on_error(err);

        err = netmgr_alloc_string(pszInterfaceName, &ppRoutes[i]->pszInterfaceName);
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

uint32_t
nm_add_static_ip_route(
    NET_IP_ROUTE *pRoute
)
{
    uint32_t err = 0;
    uint8_t prefix = 255;
    char szDestAddr[INET6_ADDRSTRLEN+5];
    NET_IP_ROUTE route;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

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

    err = nm_add_route_section(&route);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_delete_static_ip_route(
    NET_IP_ROUTE *pRoute
)
{
    uint32_t err = 0;
    uint8_t prefix = 255;
    char szDestAddr[INET6_ADDRSTRLEN+5];
    NET_IP_ROUTE route;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

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

    err = nm_delete_route_section(&route);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_get_static_ip_routes(
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

    err = nm_get_routes(pszInterfaceName, pCount, pppRoutesList);
    bail_on_error(err);


cleanup:
    return err;
error:
    goto cleanup;
}


/*
 * DNS configuration APIs
 */
static uint32_t
nm_space_delimited_string_append(
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
nm_space_delimited_string_to_list(
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

static uint32_t
nm_get_dns_mode(
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

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, SECTION_DHCP, KEY_USE_DNS,
                           &pszUseDnsValue);
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

uint32_t
nm_add_dns_server(
    const char *pszInterfaceName,
    const char *pszDnsServer
)
{
    uint32_t err = 0;
    NET_DNS_MODE mode;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsServers = NULL;
    char *pszNewDnsServersValue = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszDnsServer) || !(is_ipv4_addr(pszDnsServer) ||
        is_ipv6_addr(pszDnsServer)))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = nm_get_dns_mode("eth0", &mode);
    bail_on_error(err);

    if (mode == DHCP_DNS)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = nm_get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                           &pszCurrentDnsServers);
    if (err != ENOENT)
    {
        bail_on_error(err);
    }

    err = nm_space_delimited_string_append(1, &pszDnsServer,
                                           pszCurrentDnsServers,
                                           &pszNewDnsServersValue);
    bail_on_error(err);

    err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                           pszNewDnsServersValue, 0);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);
    err = nm_restart_dns_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_free(pszCurrentDnsServers);
    netmgr_free(pszNewDnsServersValue);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_delete_dns_server(
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
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszDnsServer) || !(is_ipv4_addr(pszDnsServer) ||
        is_ipv6_addr(pszDnsServer)))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = nm_get_dns_mode("eth0", &mode);
    bail_on_error(err);
    if (mode == DHCP_DNS)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = nm_get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, szSectionName, KEY_DNS,
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

    err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                           pszNewDnsServersValue, 0);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);
    err = nm_restart_dns_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_free(pszCurrentDnsServers);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_set_dns_servers(
    const char *pszInterfaceName,
    NET_DNS_MODE mode,
    size_t count,
    const char **ppszDnsServers
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
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = nm_get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = nm_space_delimited_string_append(count, ppszDnsServers, NULL,
                                           &pszDnsServersValue);
    bail_on_error(err);

    err = EINVAL;
    if (mode == DHCP_DNS)
    {
        sprintf(szUseDnsValue, "true");
        if (count == 0)
        {
            err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                                   NULL, 0);
        }
    }
    else if (mode == STATIC_DNS)
    {
        sprintf(szUseDnsValue, "false");
        if (count == 0)
        {
            err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                                   NULL, 0);
        }
        else
        {
            err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DNS,
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
                    sprintf(netCfgFileName, "%s%s", SYSTEMD_NET_PATH,
                            hFile->d_name);
                    err = nm_set_key_value(netCfgFileName, SECTION_DHCP,
                                           KEY_USE_DNS, szUseDnsValue, 0);
                    bail_on_error(err);
                }
            }
        }
    }

    err = nm_restart_network_service();
    bail_on_error(err);
    err = nm_restart_dns_service();
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    if (dirFile != NULL)
    {
        closedir(dirFile);
    }
    netmgr_free(pszDnsServersValue);
    netmgr_free(pszCfgFileName);
    return err;
}

static uint32_t
nm_read_conf_file(
    const char *pszFilename,
    char **ppszFileBuf)
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

    fp = fopen(pszFilename, "r");
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

uint32_t
nm_get_dns_servers(
    const char *pszInterfaceName,
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
    err = nm_get_dns_mode("eth0", pMode);
    bail_on_error(err);

    if (pszInterfaceName == NULL)
    {
        err = nm_read_conf_file(RESOLV_CONF_FILENAME, &pszFileBuf);
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
            err = nm_get_resolved_conf_filename(&pszCfgFileName);
            sprintf(szSectionName, SECTION_RESOLVE);
        }
        else
        {
            err = nm_get_network_conf_filename(pszInterfaceName,
                                               &pszCfgFileName);
            sprintf(szSectionName, SECTION_NETWORK);
        }
        bail_on_error(err);

        err = nm_get_key_value(pszCfgFileName, szSectionName, KEY_DNS,
                               &pszDnsServersValue);
        if (err == ENOENT)
        {
            err = 0;
            goto error;
        }
        bail_on_error(err);

        err = nm_space_delimited_string_to_list(pszDnsServersValue, &count,
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

uint32_t
nm_add_dns_domain(
    const char *pszInterfaceName,
    const char *pszDnsDomain
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsDomains = NULL;
    char *pszDnsDomainsValue = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (pszDnsDomain == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = nm_get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                           &pszCurrentDnsDomains);
    if (err != ENOENT)
    {
        bail_on_error(err);
    }

    err = nm_space_delimited_string_append(1, &pszDnsDomain,
                                           pszCurrentDnsDomains,
                                           &pszDnsDomainsValue);
    bail_on_error(err);

    err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                           pszDnsDomainsValue, 0);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);
    err = nm_restart_dns_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_free(pszCurrentDnsDomains);
    netmgr_free(pszDnsDomainsValue);
    netmgr_free(pszCfgFileName);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_delete_dns_domain(
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
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (pszDnsDomain == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = nm_get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
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

    err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                           pszNewDnsDomainsList, 0);
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);
    err = nm_restart_dns_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_free(pszNewDnsDomainsList);
    netmgr_free(pszCfgFileName);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_set_dns_domains(
    const char *pszInterfaceName,
    size_t count,
    const char **ppszDnsDomains
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszDnsDomainsValue = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
        sprintf(szSectionName, SECTION_NETWORK);
    }
    else
    {
        err = nm_get_resolved_conf_filename(&pszCfgFileName);
        sprintf(szSectionName, SECTION_RESOLVE);
    }
    bail_on_error(err);

    err = nm_space_delimited_string_append(count, ppszDnsDomains, NULL,
                                           &pszDnsDomainsValue);
    bail_on_error(err);

    if (count == 0)
    {
        err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                               NULL, 0);
    }
    else
    {
        err = nm_set_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                               pszDnsDomainsValue, 0);
    }
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);
    err = nm_restart_dns_service();
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    netmgr_free(pszDnsDomainsValue);
    netmgr_free(pszCfgFileName);
    return err;
}

uint32_t
nm_get_dns_domains(
    const char *pszInterfaceName,
    size_t *pCount,
    char ***pppszDnsDomains
)
{
    uint32_t err = 0;
    size_t count = 0;
    char szSectionName[MAX_LINE];
    char *pszCfgFileName = NULL, *pszFileBuf = NULL;
    char *pszDnsDomainsValue = NULL, **ppszDnsDomainsList = NULL;
    char *pszNewLine = NULL;

    if ((pCount == NULL) || (pppszDnsDomains == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pszInterfaceName == NULL)
    {
        err = nm_read_conf_file(RESOLV_CONF_FILENAME, &pszFileBuf);
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

        pszNewLine = strstr(pszDnsDomainsValue, "\n");
        if (pszNewLine != NULL)
        {
            *pszNewLine = '\0';
        }

        err = nm_space_delimited_string_to_list(pszDnsDomainsValue, &count,
                                                &ppszDnsDomainsList);
        pszDnsDomainsValue = NULL;
        bail_on_error(err);
    }
    else
    {
        if (!strcmp(pszInterfaceName, "none"))
        {
            err = nm_get_resolved_conf_filename(&pszCfgFileName);
            sprintf(szSectionName, SECTION_RESOLVE);
        }
        else
        {
            err = nm_get_network_conf_filename(pszInterfaceName,
                                               &pszCfgFileName);
            sprintf(szSectionName, SECTION_NETWORK);
        }
        bail_on_error(err);

        err = nm_get_key_value(pszCfgFileName, szSectionName, KEY_DOMAINS,
                               &pszDnsDomainsValue);
        if (err == ENOENT)
        {
            err = 0;
            goto error;
        }
        bail_on_error(err);

        err = nm_space_delimited_string_to_list(pszDnsDomainsValue, &count,
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
uint32_t
nm_set_iaid(
    const char *pszInterfaceName,
    uint32_t iaid
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char szValue[MAX_LINE] = "";
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    sprintf(szValue, "%u", iaid);

    if (iaid > 0)
    {
        err = nm_set_key_value(pszCfgFileName, SECTION_DHCP, KEY_IAID,
                               szValue, 0);
    }
    else
    {
        err = nm_set_key_value(pszCfgFileName, SECTION_DHCP, KEY_IAID, NULL, 0);
    }
    bail_on_error(err);

    err = nm_restart_network_service();
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    netmgr_free(pszCfgFileName);
    return err;
}

uint32_t
nm_get_iaid(
    const char *pszInterfaceName,
    uint32_t *pIaid
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char *pszIaid = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pIaid)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, SECTION_DHCP, KEY_IAID, &pszIaid);
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

static const char * nm_duid_strtype_from_type(uint16_t type)
{
    if ((type > _DUID_TYPE_MIN) && (type < _DUID_TYPE_MAX))
    {
        return duid_type_table[type];
    }
    return NULL;
}

static uint16_t nm_duid_type_from_strtype(const char *strtype)
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

uint32_t
nm_set_duid(
    const char *pszInterfaceName,
    const char *pszDuid
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    const char *duidType;
    uint16_t n1, n2;
    char szDuid[MAX_LINE];
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (pszInterfaceName != NULL)
    {
        /* TODO: Add support */
        err = ENOTSUP;
    }
    else
    {
        err = nm_get_networkd_conf_filename(&pszCfgFileName);
    }
    bail_on_error(err);

    if ((pszDuid == NULL) || (strlen(pszDuid) == 0))
    {
        err = nm_set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_TYPE,
                               NULL, F_CREATE_CFG_FILE);
        bail_on_error(err);

        err = nm_set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA,
                               NULL, F_CREATE_CFG_FILE);
        bail_on_error(err);
    }
    else
    {
        if (sscanf(pszDuid, "%hx:%hx:%s", &n1, &n2, szDuid) != 3)
        {
            err = EINVAL;
            bail_on_error(err);
        }

        duidType = nm_duid_strtype_from_type((n1 << 8) | n2);
        if (duidType == NULL)
        {
            err = EINVAL;
            bail_on_error(err);
        }
        /* TODO: Validate DUID length and DUID bytes */

        err = nm_set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_TYPE,
                               duidType, F_CREATE_CFG_FILE);
        bail_on_error(err);

        err = nm_set_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA,
                               szDuid, F_CREATE_CFG_FILE);
        bail_on_error(err);
    }

    err = nm_restart_network_service();
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    netmgr_free(pszCfgFileName);
    return err;
}

uint32_t
nm_get_duid(
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
        err = nm_get_networkd_conf_filename(&pszCfgFileName);
    }
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_TYPE,
                           &pszDuidType);
    bail_on_error(err);

    duidType = nm_duid_type_from_strtype(pszDuidType);
    if (duidType == 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA,
                           &pszDuid);
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


/*
 * NTP configuration APIs
 */
uint32_t
nm_set_ntp_servers(
    size_t count,
    const char **ppszNtpServers
)
{
    uint32_t err = 0;
    char *pszBuf = NULL;
    size_t i;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    // TODO: This is quick code. Fix this to not use sed.
    err = nm_run_command("/usr/bin/cp -f /etc/ntp.conf /tmp/ntpnew.conf");
    bail_on_error(err);

    err = nm_run_command("/usr/bin/sed -i '/^server /d' /tmp/ntpnew.conf");
    bail_on_error(err);

    for (i = 0; i < count; i++)
    {
        err = netmgr_alloc_string_printf(&pszBuf,
                           "/usr/bin/echo server %s >> /tmp/ntpnew.conf",
                           ppszNtpServers[i]);
        bail_on_error(err);
        err = nm_run_command(pszBuf);
        netmgr_free(pszBuf);
        bail_on_error(err);
    }

    err = nm_run_command("/usr/bin/cp -f /tmp/ntpnew.conf /etc/ntp.conf");
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    return err;
}

uint32_t
nm_add_ntp_servers(
    size_t count,
    const char **ppszNtpServers
)
{
    uint32_t err = 0;
    size_t i;
    char *pszBuf = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    // TODO: This is quick code. Fix this to not use run command.
    err = nm_run_command("/usr/bin/cp -f /etc/ntp.conf /tmp/ntpnew.conf");
    bail_on_error(err);

    for (i = 0; i < count; i++)
    {
        err = netmgr_alloc_string_printf(&pszBuf,
                           "/usr/bin/echo server %s >> /tmp/ntpnew.conf",
                           ppszNtpServers[i]);
        bail_on_error(err);
        err = nm_run_command(pszBuf);
        netmgr_free(pszBuf);
        bail_on_error(err);
    }

    err = nm_run_command("/usr/bin/cp -f /tmp/ntpnew.conf /etc/ntp.conf");
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    return err;
}

uint32_t
nm_delete_ntp_servers(
    size_t count,
    const char **ppszNtpServers
)
{
    uint32_t err = 0;
    size_t i;
    char *pszBuf = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    // TODO: This is quick code. Fix this to not use sed.
    err = nm_run_command("/usr/bin/cp -f /etc/ntp.conf /tmp/ntpnew.conf");
    bail_on_error(err);

    for (i = 0; i < count; i++)
    {
        err = netmgr_alloc_string_printf(&pszBuf,
                           "/usr/bin/sed -i '/^server %s/d' /tmp/ntpnew.conf",
                           ppszNtpServers[i]);
        bail_on_error(err);
        err = nm_run_command(pszBuf);
        netmgr_free(pszBuf);
        bail_on_error(err);
    }

    err = nm_run_command("/usr/bin/cp -f /tmp/ntpnew.conf /etc/ntp.conf");
    bail_on_error(err);

error:
    nm_release_write_lock(lockId);
    return err;
}

uint32_t
nm_get_ntp_servers(
    size_t *pCount,
    char ***pppszNtpServers
)
{
    uint32_t err = 0;
    char *pszFileBuf = NULL, szServer[MAX_LINE];
    char *s1, **ppszNtpServersList = NULL;
    size_t i = 0, count = 0;

    if ((pCount == NULL) || (pppszNtpServers == NULL))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_read_conf_file(NTP_CONF_FILENAME, &pszFileBuf);
    bail_on_error(err);

    s1 = pszFileBuf;
    while ((s1 = strstr(s1, STR_SERVER)) != NULL)
    {
        count++;
        s1++;
    }

    if (count > 0)
    {
        err = netmgr_alloc((count * sizeof(char *)),
                           (void *)&ppszNtpServersList);
        bail_on_error(err);

        s1 = pszFileBuf;
        while ((s1 = strstr(s1, STR_SERVER)) != NULL)
        {
            if (sscanf(s1, "server %s", szServer) != 1)
            {
                err = errno;
                bail_on_error(err);
            }
            err = netmgr_alloc_string(szServer, &(ppszNtpServersList[i++]));
            bail_on_error(err);
            s1++;
        } while (s1 != NULL);
    }

    *pCount = count;
    *pppszNtpServers = ppszNtpServersList;

clean:
    netmgr_free(pszFileBuf);
    return err;

error:
    netmgr_list_free(count, (void **)ppszNtpServersList);
    if (pCount != NULL)
    {
        *pCount = 0;
    }
	    if (pppszNtpServers != NULL)
    {
        *pppszNtpServers = NULL;
    }
    goto clean;
}


/*
 * Firewall configuration APIs
 */
uint32_t
nm_add_firewall_rule(
    NET_FW_RULE *pNetFwRule
)
{
    uint32_t err = 0;
    char *pszFileBuf = NULL, *pszFwRule = NULL, *pszNewFileBuf = NULL;

    if ((pNetFwRule == NULL) || (pNetFwRule->type >= FW_RULE_TYPE_MAX))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pNetFwRule->type == FW_RAW)
    {
        err = netmgr_alloc_string_printf(&pszFwRule, "iptables %s",
                                         pNetFwRule->pszRawFwRule);
        bail_on_error(err);
    }
    else
    {
        // TODO:
    }

    err = nm_read_conf_file(FIREWALL_CONF_FILENAME, &pszFileBuf);
    bail_on_error(err);

    if (strstr(pszFileBuf, pszFwRule) != NULL)
    {
        err = EEXIST;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszNewFileBuf, "%s\n%s\n", pszFileBuf,
                                     pszFwRule);
    bail_on_error(err);

    err = nm_atomic_file_update(FIREWALL_CONF_FILENAME, pszNewFileBuf);
    bail_on_error(err);

clean:
    netmgr_free(pszFwRule);
    netmgr_free(pszFileBuf);
    netmgr_free(pszNewFileBuf);
    return err;

error:
    goto clean;
}

uint32_t
nm_delete_firewall_rule(
    NET_FW_RULE *pNetFwRule
)
{
    uint32_t err = 0;
    char *pszFileBuf = NULL, *pszFwRule = NULL, *pszNewFileBuf = NULL;
    char *pszLine = NULL;

    if ((pNetFwRule == NULL) || (pNetFwRule->type >= FW_RULE_TYPE_MAX))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (pNetFwRule->type == FW_RAW)
    {
        err = netmgr_alloc_string_printf(&pszFwRule, "iptables %s",
                                         pNetFwRule->pszRawFwRule);
        bail_on_error(err);
    }
    else
    {
        // TODO:
    }

    err = nm_read_conf_file(FIREWALL_CONF_FILENAME, &pszFileBuf);
    bail_on_error(err);

    if (strstr(pszFileBuf, pszFwRule) == NULL)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    err = netmgr_alloc(strlen(pszFileBuf), (void **)&pszNewFileBuf);
    bail_on_error(err);

    pszLine = strtok(pszFileBuf, "\n");
    while (pszLine != NULL)
    {
        if (strcmp(pszFwRule, pszLine) != 0)
        {
            sprintf(pszNewFileBuf, "%s%s\n", pszNewFileBuf, pszLine);
        }
        pszLine = strtok(NULL, "\n");
    }

    err = nm_atomic_file_update(FIREWALL_CONF_FILENAME, pszNewFileBuf);
    bail_on_error(err);

clean:
    netmgr_free(pszFwRule);
    netmgr_free(pszFileBuf);
    netmgr_free(pszNewFileBuf);
    return err;

error:
    goto clean;
}

uint32_t
nm_get_firewall_rules(
    size_t *pCount,
    NET_FW_RULE ***pppNetFwRules
)
{
    return 0;
}

/*
 * Misc APIs
 */
static uint32_t
nm_get_interface_ipaddr_type(
    const char *pszInterfaceName,
    uint32_t addrTypes,
    size_t *pCount,
    NET_IP_ADDR ***pppIpAddrList
)
{
    uint32_t err = 0, modeFlags;
    size_t i = 0, j = 0, ip4Count = 0, ip6Count = 0, staticIp6Count = 0, nCount = 0;
    char **ppszIp4AddrList = NULL;
    char **ppszIp6AddrList = NULL, **ppszStaticIp6AddrList = NULL;
    NET_IP_ADDR **ppIpAddrList = NULL;

    //TODO: If pszInterfaceName is NULL, enumerate all IPs
    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (strlen(pszInterfaceName) > IFNAMSIZ) ||
        !pCount || !pppIpAddrList || !addrTypes)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    if (TEST_FLAG(modeFlags, fDHCP_IPV4) && TEST_FLAG(addrTypes, DHCP_IPV4))
    {
        err = nm_get_interface_ipaddr(pszInterfaceName, DHCP_IPV4, &ip4Count,
                                      &ppszIp4AddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    else if (TEST_FLAG(addrTypes, STATIC_IPV4))
    {
        err = nm_get_interface_ipaddr(pszInterfaceName, STATIC_IPV4, &ip4Count,
                                      &ppszIp4AddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    nCount = ip4Count;

    if (TEST_FLAG(addrTypes, DHCP_IPV6) ||
        TEST_FLAG(addrTypes, AUTO_IPV6) ||
        TEST_FLAG(addrTypes, STATIC_IPV6))
    {
        err = nm_get_interface_ipaddr(pszInterfaceName,
                                      DHCP_IPV6 | AUTO_IPV6 | STATIC_IPV6,
                                      &ip6Count,
                                      &ppszIp6AddrList);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    nCount += ip6Count;

    if (nCount == 0)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    err = netmgr_alloc((nCount * sizeof(PNET_IP_ADDR)), (void *)&ppIpAddrList);
    bail_on_error(err);

    for (i = 0; i < ip4Count; i++)
    {
        err = netmgr_alloc(sizeof(NET_IP_ADDR), (void **)&ppIpAddrList[i]);
        bail_on_error(err);
        err = netmgr_alloc_string(pszInterfaceName,
                                  &ppIpAddrList[i]->pszInterfaceName);
        bail_on_error(err);
        err = netmgr_alloc_string(ppszIp4AddrList[i],
                                  &ppIpAddrList[i]->pszIPAddrPrefix);
        bail_on_error(err);
        ppIpAddrList[i]->type = TEST_FLAG(modeFlags, fDHCP_IPV4) ?
                                          DHCP_IPV4 : STATIC_IPV4;
    }

    for (j = 0; j < ip6Count; j++, i++)
    {
        err = netmgr_alloc(sizeof(NET_IP_ADDR), (void **)&ppIpAddrList[i]);
        bail_on_error(err);
        err = netmgr_alloc_string(pszInterfaceName,
                                  &ppIpAddrList[i]->pszInterfaceName);
        bail_on_error(err);
        err = netmgr_alloc_string(ppszIp6AddrList[j],
                                  &ppIpAddrList[i]->pszIPAddrPrefix);
        bail_on_error(err);
        err = nm_get_ip_addr_type(pszInterfaceName,
                                  ppszIp6AddrList[j],
                                  &(ppIpAddrList[i]->type));
        bail_on_error(err);
    }

    *pCount = nCount;
    *pppIpAddrList = ppIpAddrList;

cleanup:
    netmgr_list_free(ip4Count, (void **)ppszIp4AddrList);
    netmgr_list_free(ip6Count, (void **)ppszIp6AddrList);
    netmgr_list_free(staticIp6Count, (void **)ppszStaticIp6AddrList);
    return err;

error:
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppIpAddrList != NULL)
    {
        *pppIpAddrList = NULL;
    }
    if (ppIpAddrList != NULL)
    {
        for (i = 0; i < nCount; i++)
        {
            if (ppIpAddrList[i] == NULL)
            {
                continue;
            }
            netmgr_free(ppIpAddrList[i]->pszInterfaceName);
            netmgr_free(ppIpAddrList[i]->pszIPAddrPrefix);
        }
        netmgr_list_free(nCount, (void **)ppIpAddrList);
    }
    goto cleanup;
}


static uint32_t
nm_open_netlink(
    uint32_t addrType,
    int *pSockFd
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct sockaddr_nl addr;

    if (!pSockFd)
    {
        err = EINVAL;
    }
    bail_on_error(err);

    sockFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockFd < 0)
    {
        err = EINVAL;
    }
    bail_on_error(err);
    memset((void *)&addr, 0, sizeof(addr));

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid ();
    if (addrType == 0)
    {
        addr.nl_groups = RTMGRP_LINK;
    }

    if (TEST_FLAG(addrType, STATIC_IPV4) || TEST_FLAG(addrType, DHCP_IPV4))
    {
        addr.nl_groups = addr.nl_groups | RTMGRP_IPV4_IFADDR;
    }

    if (TEST_FLAG(addrType, STATIC_IPV6)
        || TEST_FLAG(addrType, DHCP_IPV6)
        || TEST_FLAG(addrType, AUTO_IPV6)
        || TEST_FLAG(addrType, LINK_LOCAL_IPV6))
    {
        addr.nl_groups = addr.nl_groups | RTMGRP_IPV6_IFADDR;
    }

    if (bind(sockFd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        err = errno;
    }
    bail_on_error(err);
    *pSockFd = sockFd;

cleanup:
    return err;
error:
    if (pSockFd)
    {
        *pSockFd = -1;
    }
    goto cleanup;
}

static uint32_t
nm_handle_nic_newaddr(
    struct ifaddrmsg *pIfAddrMsg,
    int ifAddrMsgLen,
    const char *pszInterfaceName,
    uint32_t addrType,
    int *done)
{
    uint32_t err = 0, addrTypeGet = 0;
    int matched = 0;
    size_t i = 0, ip4Count = 0, ip6Count = 0;
    char szIpAddr[INET6_ADDRSTRLEN];
    char **ppIp4AddrList = NULL, **ppIp6AddrList = NULL;
    char *pszIpAddrPrefix = NULL;
    struct rtattr *pRouteAttr = NULL;

    if (!pIfAddrMsg ||
        !ifAddrMsgLen ||
        IS_NULL_OR_EMPTY(pszInterfaceName) ||
        !addrType ||
        !done)
    {
        err = EINVAL;
    }
    bail_on_error(err);

    pRouteAttr = IFA_RTA(pIfAddrMsg);
    for (;RTA_OK(pRouteAttr, ifAddrMsgLen);
         pRouteAttr = RTA_NEXT(pRouteAttr, ifAddrMsgLen))
    {
        if (pRouteAttr->rta_type != IFA_LOCAL)
        {
            continue;
        }
        addrTypeGet = 0;

        if (inet_ntop(pIfAddrMsg->ifa_family,
            RTA_DATA(pRouteAttr),
            szIpAddr,
            sizeof(szIpAddr)) == NULL)
        {
            err = errno;
        }
        bail_on_error(err);

        err = netmgr_alloc_string_printf(&pszIpAddrPrefix, "%s/%u",
                                         szIpAddr, pIfAddrMsg->ifa_prefixlen);
        bail_on_error(err);

        err = nm_get_ip_addr_type(pszInterfaceName,
                                  szIpAddr,
                                  &addrTypeGet);
        bail_on_error(err);

        if (TEST_FLAG(addrType, addrTypeGet) &&
            TEST_FLAG(addrTypeGet, STATIC_IPV4))
        {
            err = nm_get_static_ip_addr(pszInterfaceName,
                                        STATIC_IPV4,
                                        &ip4Count,
                                        &ppIp4AddrList);
            bail_on_error(err);

            if (strcmp(ppIp4AddrList[0], pszIpAddrPrefix) != 0)
            {
                err = EINVAL;
            }
            bail_on_error(err);
            *done = 1;
            break;
        }

        if (TEST_FLAG(addrType, addrTypeGet) &&
            TEST_FLAG(addrTypeGet, STATIC_IPV6))
        {
            err = nm_get_static_ip_addr(pszInterfaceName,
                                        STATIC_IPV6,
                                        &ip6Count,
                                        &ppIp6AddrList);
            bail_on_error(err);

            for (i = 0; i < ip6Count; i++)
            {
                if (strcmp(ppIp6AddrList[i], pszIpAddrPrefix) == 0)
                {
                    matched = 1;
                    break;
                }
            }
            if (!matched)
            {
                err = EINVAL;
            }
            bail_on_error(err);
            *done = 1;
            break;
        }

        if (TEST_FLAG(addrType, addrTypeGet))
        {
            *done = 1;
            break;
        }

        netmgr_list_free(ip4Count, (void **)ppIp4AddrList);
        netmgr_list_free(ip6Count, (void **)ppIp6AddrList);
        netmgr_free(pszIpAddrPrefix);
    }

cleanup:
    netmgr_list_free(ip4Count, (void **)ppIp4AddrList);
    netmgr_list_free(ip6Count, (void **)ppIp6AddrList);
    netmgr_free(pszIpAddrPrefix);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_handle_nic_event(
    const char *pszInterfaceName,
    int sockFd,
    uint32_t addrType,
    int *done)
{
    uint32_t err = 0, ip4Type = 0, ip6Type = 0;
    int readLen = 0, ifAddrMsgLen = 0;
#define BUFSIZE 8192
    char buf[BUFSIZE];
    char ifName[IFNAMSIZ];
    struct iovec iov = { buf, sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    struct nlmsghdr *nlHdr;
    struct ifinfomsg *pIfInfo = NULL;
    struct ifaddrmsg *pIfAddr = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) ||
        (sockFd == -1) ||
        !done)
    {
        err = EINVAL;
    }
    bail_on_error(err);

    if (TEST_FLAG(addrType, STATIC_IPV4) ||
        TEST_FLAG(addrType, DHCP_IPV4))
    {
        ip4Type = 1;
    }

    if (TEST_FLAG(addrType, STATIC_IPV6) ||
        TEST_FLAG(addrType, DHCP_IPV6) ||
        TEST_FLAG(addrType, AUTO_IPV6) ||
        TEST_FLAG(addrType, LINK_LOCAL_IPV6))
    {
        ip6Type = 1;
    }

    while (1)
    {
        readLen = 0;
        readLen = recvmsg(sockFd, &msg, 0);
        if (readLen < 0)
        {
            err = errno;
        }
        bail_on_error(err);

        nlHdr = (struct nlmsghdr *)buf;

        if ((NLMSG_OK(nlHdr, readLen) == 0) ||
            (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            err = errno;
            bail_on_error(err);
        }
        if (nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }

        for (; NLMSG_OK(nlHdr, readLen);
             nlHdr = NLMSG_NEXT(nlHdr, readLen))
        {
            memset(ifName, 0 ,sizeof(ifName));
            switch (nlHdr->nlmsg_type)
            {
                case RTM_NEWADDR:
                    pIfAddr = NLMSG_DATA(nlHdr);
                    if_indextoname(pIfAddr->ifa_index, ifName);
                    if ((strcmp(pszInterfaceName, ifName) != 0) ||
                        !addrType)
                    {
                        break;
                    }

                    if (!((ip4Type && (pIfAddr->ifa_family == AF_INET)) ||
                        (ip6Type && (pIfAddr->ifa_family == AF_INET6))))
                    {
                        break;
                    }
                    ifAddrMsgLen = IFA_PAYLOAD(nlHdr);
                    err = nm_handle_nic_newaddr(pIfAddr,
                                                ifAddrMsgLen,
                                                pszInterfaceName,
                                                addrType,
                                                done);
                    bail_on_error(err);
                    break;
                case RTM_NEWLINK:
                    pIfInfo = NLMSG_DATA(nlHdr);
                    if_indextoname(pIfInfo->ifi_index, ifName);
                    if (!strcmp(pszInterfaceName, ifName) &&
                        !addrType &&
                        TEST_FLAG(pIfInfo->ifi_flags, IFF_UP))
                    {
                        *done = 1;
                    }
                    break;
                case NLMSG_ERROR:
                    err = EINVAL;
                    bail_on_error(err);
                default:
                    break;
            }
            if (*done)
            {
                goto cleanup;
            }
        }
    }

cleanup:
    return err;
error:
    goto cleanup;
}

uint32_t
nm_wait_for_link_up(
    const char *pszInterfaceName,
    uint32_t timeout
)
{
    uint32_t err = 0;
    int sockFd = -1, retval = -1, done = 0;
    fd_set readFd;
    struct timeval tval;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;

    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_link_state(pszInterfaceName, &linkState);
    bail_on_error(err);

    if (linkState == LINK_UP)
    {
        goto cleanup;
    }

    err = nm_open_netlink(0, &sockFd);
    bail_on_error(err);

    tval.tv_sec = timeout;
    tval.tv_usec = 0;

    while (1)
    {
        FD_ZERO(&readFd);
        FD_CLR(sockFd, &readFd);
        FD_SET(sockFd, &readFd);

        retval = select(sockFd+1, &readFd, NULL, NULL, &tval);
        if (retval == -1)
        {
            err = errno;
        }
        else if (retval)
        {
            err = nm_handle_nic_event(pszInterfaceName, sockFd, 0, &done);
        }
        else
        {
            err = ETIME;
        }
        bail_on_error(err);

        if (done)
        {
            break;
        }
    }

cleanup:
    return err;
error:
    goto cleanup;
}

uint32_t
nm_wait_for_ip(
    const char *pszInterfaceName,
    uint32_t timeout,
    NET_ADDR_TYPE addrTypes
)
{
    uint32_t err = 0, modeFlags;
    int sockFd = -1, retval = -1, done = 0, matched = 0, foundIp = 0;
    fd_set readFd;
    struct timeval tval;
    size_t i = 0, j = 0, addrCount = 0, ip4Count = 0, ip6Count = 0;
    char **ppIp4AddrList = NULL, **ppIp6AddrList = NULL;
    NET_IP_ADDR **ppIpAddrList = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName))
    {
        err = EINVAL;
    }
    bail_on_error(err);

    //If addrtype is 0, irrespective of the dhcp mode send success
    if (!addrTypes)
    {
        goto cleanup;
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    err = nm_get_interface_ipaddr_type(pszInterfaceName,
                                       addrTypes,
                                       &addrCount,
                                       &ppIpAddrList);
    if (err == ENOENT)
    {
        err = 0;
    }
    bail_on_error(err);

    for (i = 0; i < addrCount; i++)
    {
        if (TEST_FLAG(addrTypes, STATIC_IPV4) &&
            TEST_FLAG(ppIpAddrList[i]->type, STATIC_IPV4))
        {
            err = nm_get_static_ip_addr(pszInterfaceName,
                                        STATIC_IPV4,
                                        &ip4Count,
                                        &ppIp4AddrList);
            bail_on_error(err);

            if (strcmp(ppIp4AddrList[0],
                ppIpAddrList[i]->pszIPAddrPrefix) != 0)
            {
                err = EINVAL;
            }
            bail_on_error(err);
            foundIp = 1;
            break;
        }
        if (TEST_FLAG(addrTypes, STATIC_IPV6) &&
            TEST_FLAG(ppIpAddrList[i]->type, STATIC_IPV6))
        {
            err = nm_get_static_ip_addr(pszInterfaceName,
                                        STATIC_IPV6,
                                        &ip6Count,
                                        &ppIp6AddrList);
            bail_on_error(err);
            for (j = 0; j < ip6Count; j++)
            {
                if (strcmp(ppIp6AddrList[j],
                    ppIpAddrList[i]->pszIPAddrPrefix) == 0)
                {
                    matched = 1;
                    break;
                }
            }
            if (!matched)
            {
                err = EINVAL;
            }
            bail_on_error(err);
            foundIp = 1;
            break;
        }
        if (TEST_FLAG(addrTypes, ppIpAddrList[i]->type))
        {
            foundIp = 1;
            break;
        }
    }

    if (foundIp)
    {
        goto cleanup;
    }

    err = nm_open_netlink(addrTypes, &sockFd);
    bail_on_error(err);

    tval.tv_sec = timeout;
    tval.tv_usec = 0;

    while (1)
    {
        FD_ZERO(&readFd);
        FD_CLR(sockFd, &readFd);
        FD_SET(sockFd, &readFd);

        retval = select(sockFd+1, &readFd, NULL, NULL, &tval);
        if (retval == -1)
        {
            err = errno;
        }
        else if (retval)
        {
            err = nm_handle_nic_event(pszInterfaceName, sockFd, addrTypes, &done);
        }
        else
        {
            err = ETIME;
        }
        bail_on_error(err);

        if (done)
        {
            break;
        }
    }

cleanup:
    netmgr_list_free(ip4Count, (void **)ppIp4AddrList);
    netmgr_list_free(ip6Count, (void **)ppIp6AddrList);
    if (ppIpAddrList != NULL)
    {
        for (i = 0; i < addrCount; i++)
        {
            if (ppIpAddrList[i] == NULL)
            {
                continue;
            }
            netmgr_free(ppIpAddrList[i]->pszInterfaceName);
            netmgr_free(ppIpAddrList[i]->pszIPAddrPrefix);
        }
        netmgr_list_free(addrCount, (void **)ppIpAddrList);
    }

    return err;
error:
    goto cleanup;
}

uint32_t
nm_set_network_param(
    const char *pszInterfaceName,
    const char *pszParamName,
    const char *pszParamValue
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char *pszParam = NULL, *pszParamPtr = NULL;
    char *pszSectionName = NULL, *pszKeyName = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || IS_NULL_OR_EMPTY(pszParamName))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = netmgr_alloc_string(pszParamName, &pszParam);
    bail_on_error(err);
    pszParamPtr = pszParam;
    pszSectionName = strsep(&pszParam, SECTION_KEY_DELIM);
    if (pszSectionName == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    pszKeyName = pszParam;

    err = nm_set_key_value(pszCfgFileName, pszSectionName, pszKeyName,
                           pszParamValue, 0);
    bail_on_error(err);

cleanup:
    netmgr_free(pszParamPtr);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_get_network_param(
    const char *pszInterfaceName,
    const char *pszParamName,
    char **ppszParamValue
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char *pszParam = NULL, *pszParamPtr = NULL;
    char *pszSectionName = NULL, *pszKeyName = NULL, *pszParamValue = NULL;

    if (IS_NULL_OR_EMPTY(pszInterfaceName) || IS_NULL_OR_EMPTY(pszParamName) ||
        !ppszParamValue)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = netmgr_alloc_string(pszParamName, &pszParam);
    bail_on_error(err);
    pszParamPtr = pszParam;
    pszSectionName = strsep(&pszParam, SECTION_KEY_DELIM);
    if (pszSectionName == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    pszKeyName = pszParam;

    err = nm_get_key_value(pszCfgFileName, pszSectionName, pszKeyName,
                           &pszParamValue);
    bail_on_error(err);

    *ppszParamValue = pszParamValue;

cleanup:
    netmgr_free(pszParamPtr);
    netmgr_free(pszCfgFileName);
    return err;
error:
    if (ppszParamValue)
    {
        *ppszParamValue = NULL;
    }
    goto cleanup;
}


/*
 * Service management APIs
 */
uint32_t
nm_stop_network_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl stop systemd-networkd";

    err = nm_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

uint32_t
nm_restart_network_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl restart systemd-networkd";

    err = nm_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

uint32_t
nm_stop_dns_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl stop systemd-resolved";

    err = nm_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

uint32_t
nm_restart_dns_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl restart systemd-resolved";

    err = nm_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

uint32_t
nm_stop_ntp_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl stop ntpd";

    err = nm_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

uint32_t
nm_restart_ntp_service()
{
    uint32_t err = 0;
    const char command[] = "systemctl restart ntpd";

    err = nm_run_command(command);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}

