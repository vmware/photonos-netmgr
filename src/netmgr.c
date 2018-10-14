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

const char *
nm_get_error_info(
    uint32_t nmErrCode
)
{
    switch (nmErrCode)
    {
        case NM_ERR_INVALID_PARAMETER:
            return "invalid parameter";
        case NM_ERR_NOT_SUPPORTED:
            return "not supported";
        case NM_ERR_OUT_OF_MEMORY:
            return "out of memory";
        case NM_ERR_VALUE_NOT_FOUND:
            return "value not found";
        case NM_ERR_VALUE_EXISTS:
            return "value exists";
        case NM_ERR_INVALID_INTERFACE:
            return "invalid interface";
        case NM_ERR_INVALID_ADDRESS:
            return "invalid address";
        case NM_ERR_INVALID_MODE:
            return "invalid mode";
        case NM_ERR_BAD_CONFIG_FILE:
            return "error in config file";
        case NM_ERR_WRITE_FAILED:
            return "write failed";
        case NM_ERR_TIME_OUT:
            return "timed out";
        case NM_ERR_DHCP_TIME_OUT:
            return "dhcp timed out";
        default:
            return strerror(nmErrCode);
    }
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
        err = NM_ERR_INVALID_PARAMETER;
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
nm_get_resolved_conf_filename(
    char **ppszFilename)
{
    return nm_alloc_conf_filename(ppszFilename, SYSTEMD_PATH, "resolved.conf");
}

static uint32_t
nm_get_networkd_conf_filename(
    char **ppszFilename)
{
    return nm_alloc_conf_filename(ppszFilename, SYSTEMD_PATH, "networkd.conf");
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

    if (IS_NULL_OR_EMPTY(pszFilename) || !ppszFileBuf)
    {
        err = NM_ERR_INVALID_PARAMETER;
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

    err = netmgr_alloc((len + 1), (void **)&pszFileBuf);
    bail_on_error(err);

    if (fread(pszFileBuf, len, 1, fp) != 1)
    {
        if (!feof(fp))
        {
            err = ferror(fp);
            bail_on_error(err);
        }
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

static uint32_t
nm_regex_match_ifname(
    const char *pszIfName,
    const char *pszMatchName)
{
    uint32_t err = 0;
    regex_t rx;
    regmatch_t rm;
    size_t patternLen, ifNameLen, n;
    char *q, *pszPattern = NULL;
    const char *p;

    if (!IS_VALID_INTERFACE_NAME(pszIfName) ||
        !IS_VALID_INTERFACE_NAME(pszMatchName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    ifNameLen = strlen(pszIfName);
    patternLen = strlen(pszMatchName);
    for (p = strchr(pszMatchName, '*'), n = 0; p; p = strchr(++p, '*'), n++);

    err = netmgr_alloc(patternLen + n + 1, (void **)&pszPattern);
    bail_on_error(err);

    for (p = pszMatchName, q = pszPattern; *p; p++, q++)
    {
        if (*p == '*')
        {
            *q++ = '.';
        }
        *q = *p;
    }

    err = regcomp(&rx, pszPattern, 0);
    bail_on_error(err);

    err = regexec(&rx, pszIfName, 1, &rm, 0);
    bail_on_error(err);
    if ((rm.rm_eo - rm.rm_so) < ifNameLen)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

cleanup:
    netmgr_free(pszPattern);
    regfree(&rx);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_get_network_conf_filename_match(
    const char *pszIfName,
    char **ppszFilename,
    size_t *pMatchLen)
{
    uint32_t err = 0;
    size_t matchLen = 0;
    struct dirent *hFile;
    DIR *dirFile = NULL;
    char *p, *pszFileName = NULL, *pszMatchName = NULL, *pszCfgFileName = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszIfName) || !ppszFilename)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    dirFile = opendir(SYSTEMD_NET_PATH);
    if (dirFile == NULL)
    {
        err = errno;
        bail_on_error(err);
    }

    // TODO: Looks fine but closely vet this logic with systemd
    errno = 0;
    while ((hFile = readdir(dirFile)) != NULL)
    {
        if (!strcmp(hFile->d_name, ".")) continue;
        if (!strcmp(hFile->d_name, "..")) continue;
        if (hFile->d_name[0] == '.') continue;
        if ((((p = strstr(hFile->d_name, ".network")) != NULL) &&
             (strlen(p) == strlen(".network"))) ||
            (((p = strstr(hFile->d_name, ".network.manual")) != NULL) &&
             (strlen(p) == strlen(".network.manual"))))
        {
            err = nm_alloc_conf_filename(&pszFileName,
                                         SYSTEMD_NET_PATH,
                                         hFile->d_name);
            bail_on_error(err);
            err = nm_get_key_value(pszFileName,
                                   SECTION_MATCH,
                                   KEY_NAME,
                                   &pszMatchName);
            if ((err == NM_ERR_VALUE_NOT_FOUND) ||
                (err == NM_ERR_BAD_CONFIG_FILE))
            {
                /* Ignore cfg file with invalid/missing Match section */
                err = 0;
            }
            bail_on_error(err);

            if (pszMatchName && !nm_regex_match_ifname(pszIfName, pszMatchName))
            {
                if (pszCfgFileName == NULL)
                {
                    pszCfgFileName = pszFileName;
                    matchLen = strlen(pszMatchName);
                    pszFileName = NULL;
                    continue;
                }
                if (strcmp(pszCfgFileName, pszFileName) > 0)
                {
                    netmgr_free(pszCfgFileName);
                    pszCfgFileName = pszFileName;
                    matchLen = strlen(pszMatchName);
                    pszFileName = NULL;
                }
            }

            netmgr_free(pszMatchName);
            pszMatchName = NULL;
            netmgr_free(pszFileName);
            pszFileName = NULL;
        }
    }

    if (!pszCfgFileName)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

    *ppszFilename = pszCfgFileName;
    if (pMatchLen)
    {
        *pMatchLen = matchLen;
    }

cleanup:
    if (dirFile != NULL)
    {
        closedir(dirFile);
    }
    netmgr_free(pszMatchName);
    netmgr_free(pszFileName);
    return err;

error:
    if (ppszFilename)
    {
        *ppszFilename = NULL;
    }
    if (pMatchLen)
    {
        *pMatchLen = 0;
    }
    netmgr_free(pszCfgFileName);
    goto cleanup;
}

static uint32_t
nm_get_network_conf_filename(
    const char *pszIfName,
    char **ppszFilename)
{
    return nm_get_network_conf_filename_match(pszIfName, ppszFilename, NULL);
}

static uint32_t
nm_get_network_conf_filename_for_update(
    const char *pszIfName,
    char **ppszFilename)
{
    uint32_t err = 0;
    size_t ifNameLen, matchLen = 0;
    char fName[IFNAMSIZ+strlen(SYSTEMD_NET_PATH)+strlen("00-.network")+1];
    char *pszFilename = NULL, *pszNewFilename = NULL, *pszCmd = NULL;

    // TODO: IS VALID_INTERFACE_NAME needs to check if device actually exists
    if (!IS_VALID_INTERFACE_NAME(pszIfName) || !ppszFilename)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_match(pszIfName, &pszFilename, &matchLen);
    if (err == NM_ERR_VALUE_NOT_FOUND)
    {
        err = 0;
    }
    bail_on_error(err);

    ifNameLen = strlen(pszIfName);
    if ((pszFilename == NULL) || (matchLen < ifNameLen))
    {
        sprintf(fName, "%s00-%s.network", SYSTEMD_NET_PATH, pszIfName);
        if (access(fName, F_OK) == 0)
        {
            /* Designated conf file for this interface exists with bad match */
            err = NM_ERR_BAD_CONFIG_FILE;
            bail_on_error(err);
        }

        err = netmgr_alloc_string(fName, &pszNewFilename);
        bail_on_error(err);

        /* Create dedicated conf for interface based on best match conf file */
        if (pszFilename != NULL)
        {
            err = netmgr_alloc_string_printf(&pszCmd,
                                             "/usr/bin/cp -f -p %s %s",
                                             pszFilename,
                                             pszNewFilename);
            bail_on_error(err);

            err = nm_run_command(pszCmd);
            bail_on_error(err);
        }

        err = nm_set_key_value(pszNewFilename,
                               SECTION_MATCH,
                               KEY_NAME,
                               pszIfName,
                               F_CREATE_CFG_FILE);
        bail_on_error(err);
    }
    else
    {
        err = netmgr_alloc_string(pszFilename, &pszNewFilename);
        bail_on_error(err);
    }

    *ppszFilename = pszNewFilename;

cleanup:
    netmgr_free(pszFilename);
    netmgr_free(pszCmd);
    return err;

error:
    if (ppszFilename)
    {
        *ppszFilename = NULL;
    }
    netmgr_free(pszNewFilename);
    goto cleanup;
}

static uint32_t
nm_get_network_auto_conf_filename(
    const char *pszIfName,
    char **ppszFilename)
{
    uint32_t err = 0;
    char *pszConfFilename = NULL, *pManual = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszIfName) || !ppszFilename)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszIfName, &pszConfFilename);
    bail_on_error(err);

    if ((pManual = strstr(pszConfFilename, ".manual")) != NULL)
    {
        *pManual = '\0';
    }

    *ppszFilename = pszConfFilename;

cleanup:
    return err;
error:
    if (ppszFilename)
    {
        *ppszFilename = NULL;
    }
    netmgr_free(pszConfFilename);
    goto cleanup;
}

static uint32_t
nm_get_network_manual_conf_filename(
    const char *pszIfName,
    char **ppszFilename)
{
    uint32_t err = 0;
    char *pszConfFilename = NULL, *pManual = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszIfName) || !ppszFilename)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszIfName, &pszConfFilename);
    bail_on_error(err);

    if ((pManual = strstr(pszConfFilename, ".manual")) == NULL)
    {
        err = nm_alloc_conf_filename(ppszFilename, pszConfFilename, ".manual");
        bail_on_error(err);
        netmgr_free(pszConfFilename);
    }
    else
    {
        *ppszFilename = pszConfFilename;
    }

cleanup:
    return err;
error:
    if (ppszFilename)
    {
        *ppszFilename = NULL;
    }
    netmgr_free(pszConfFilename);
    goto cleanup;
}

static uint32_t
nm_string_to_line_array(
    const char *pszStrBuf,
    size_t *pLineCount,
    char ***pppszLineBuf)
{
    uint32_t err = 0, len;
    size_t i = 0, lineCount = 0;
    char *p1, *p2, *pEnd, **ppszLineBuf = NULL;

    if (!pszStrBuf || !*pszStrBuf || !pLineCount || !pppszLineBuf)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    p1 = (char *)pszStrBuf;
    pEnd = strchr(pszStrBuf, '\0');
    do
    {
        p1 = strchr(p1, '\n');
        if (p1 == NULL)
        {
            break;
        }
        lineCount++;
        p1++;
    } while (p1 < pEnd);

    if (lineCount == 0)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

    err = netmgr_alloc(lineCount * sizeof(char **), (void **)&ppszLineBuf);
    bail_on_error(err);

    p1 = (char *)pszStrBuf;
    do
    {
        p2 = strchr(p1, '\n');
        if (p2 == NULL)
        {
            break;
        }
        len = p2 - p1 + 1;
        err = netmgr_alloc(len + 1, (void **)&ppszLineBuf[i]);
        bail_on_error(err);
        memcpy(ppszLineBuf[i], p1, len);
        i++;
        p1 = p2 + 1;
    } while (p1 < pEnd);

    *pLineCount = lineCount;
    *pppszLineBuf = ppszLineBuf;

cleanup:
    return err;

error:
    if (pLineCount)
    {
        *pLineCount = 0;
    }
    if (pppszLineBuf)
    {
        *pppszLineBuf = NULL;
    }
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
    goto cleanup;
}

uint32_t
nm_touch_network_conf_file(
    const char *pszInterfaceName,
    char **ppszFilename)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    if (ppszFilename != NULL)
    {
        *ppszFilename = pszCfgFileName;
    }
    else
    {
        netmgr_free(pszCfgFileName);
    }

cleanup:
    nm_release_write_lock(lockId);
    return err;
error:
    if (ppszFilename != NULL)
    {
        *ppszFilename = NULL;
    }
    netmgr_free(pszCfgFileName);
    goto cleanup;
}

/*
 * Interface configuration APIs
 */
static uint32_t
nm_update_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE linkState
);

static uint32_t
nm_update_mac_address(
    const char *pszInterfaceName,
    const char *pszMacAddress
)
{
    uint32_t err = 0;
    int sockFd = -1;
    int addrLen = 0;
    struct ifreq ifr = {};

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    strncpy(ifr.ifr_name, pszInterfaceName, IFNAMSIZ - 1);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    addrLen = sscanf(pszMacAddress, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                                    &ifr.ifr_hwaddr.sa_data[0],
                                    &ifr.ifr_hwaddr.sa_data[1],
                                    &ifr.ifr_hwaddr.sa_data[2],
                                    &ifr.ifr_hwaddr.sa_data[3],
                                    &ifr.ifr_hwaddr.sa_data[4],
                                    &ifr.ifr_hwaddr.sa_data[5]);
    if (addrLen != ETHER_ADDR_LEN)
    {
        err = NM_ERR_INVALID_ADDRESS;
        bail_on_error(err);
    }

    err = nm_update_link_state(pszInterfaceName, LINK_DOWN);
    bail_on_error(err);

    err = ioctl(sockFd, SIOCSIFHWADDR, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = nm_update_link_state(pszInterfaceName, LINK_UP);
    bail_on_error(err);

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;

error:
    goto cleanup;
}

uint32_t
nm_set_link_mac_addr(
    const char *pszInterfaceName,
    const char *pszMacAddress
)
{
    uint32_t err = 0, err1 = 0;
    char *pszCfgFileName = NULL, *pszOldMacAddress = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_link_mac_addr(pszInterfaceName, &pszOldMacAddress);
    bail_on_error(err);

    if (strlen(pszMacAddress) > 0)
    {
        err = nm_update_mac_address(pszInterfaceName, pszMacAddress);
        bail_on_error(err);
    }

    err = nm_set_key_value(pszCfgFileName, SECTION_LINK, KEY_MAC_ADDRESS,
                           strlen(pszMacAddress) ? pszMacAddress : NULL, 0);
    if (err)
    {
        err1 = nm_update_mac_address(pszInterfaceName, pszOldMacAddress);
        bail_on_error(err1);
    }
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_free(pszOldMacAddress);
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
    struct ifreq ifr = {};

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !ppszMacAddress)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    strncpy(ifr.ifr_name, pszInterfaceName, IFNAMSIZ - 1);

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

static uint32_t
nm_update_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE linkMode
)
{
    uint32_t err = 0, sdVersion = 0;;
    char *pszAutoCfgFileName = NULL, *pszManualCfgFileName = NULL;
    char *pszCurrentCfgFileName = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        (linkMode >= LINK_MODE_UNKNOWN))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_systemd_version(&sdVersion);
    bail_on_error(err);

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCurrentCfgFileName);
    bail_on_error(err);

    if (sdVersion >= 233)
    {
        switch (linkMode)
        {
            case LINK_MANUAL:
                err = nm_set_key_value(pszCurrentCfgFileName,
                                       SECTION_LINK,
                                       KEY_UNMANAGED,
                                       "yes",
                                       0);
                break;
            case LINK_AUTO:
                err = nm_set_key_value(pszCurrentCfgFileName,
                                       SECTION_LINK,
                                       KEY_UNMANAGED,
                                       "no",
                                       0);
                break;
            default:
                err = NM_ERR_INVALID_PARAMETER;
                break;
        }
        bail_on_error(err);
    }
    else
    {
        err = nm_get_network_auto_conf_filename(pszInterfaceName,
                                                &pszAutoCfgFileName);
        bail_on_error(err);

        err = nm_get_network_manual_conf_filename(pszInterfaceName,
                                                  &pszManualCfgFileName);
        bail_on_error(err);

        switch (linkMode)
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
                err = NM_ERR_INVALID_PARAMETER;
                break;
        }
    }

cleanup:
    netmgr_free(pszCurrentCfgFileName);
    netmgr_free(pszAutoCfgFileName);
    netmgr_free(pszManualCfgFileName);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_set_link_mode(
    const char *pszInterfaceName,
    NET_LINK_MODE linkMode
)
{
    uint32_t err = 0;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    err = nm_update_link_mode(pszInterfaceName, linkMode);
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
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
    uint32_t err = 0, sdVersion = 0;
    char *pszCfgFileName = NULL, *pszUnmanaged = NULL;;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pLinkMode)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_systemd_version(&sdVersion);
    bail_on_error(err);

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    if (sdVersion >= 233)
    {
        err = nm_get_key_value(pszCfgFileName,
                               SECTION_LINK,
                               KEY_UNMANAGED,
                               &pszUnmanaged);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
            *pLinkMode = LINK_AUTO;
        }
        else if (err == 0)
        {
            if (!strcasecmp(pszUnmanaged, "yes"))
            {
                *pLinkMode = LINK_MANUAL;
            }
            else if (!strcasecmp(pszUnmanaged, "no"))
            {
                *pLinkMode = LINK_AUTO;
            }
            else
            {
                *pLinkMode = LINK_MODE_UNKNOWN;
            }
        }
        bail_on_error(err);
    }
    else
    {
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
    }

cleanup:
    netmgr_free(pszUnmanaged);
    netmgr_free(pszCfgFileName);
    return err;

error:
    if (pLinkMode)
    {
        *pLinkMode = LINK_MODE_UNKNOWN;
    }
    goto cleanup;
}


static uint32_t
nm_update_link_mtu(
    const char *pszInterfaceName,
    uint32_t mtu
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct ifreq ifr = {};

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    strncpy(ifr.ifr_name, pszInterfaceName, IFNAMSIZ - 1);

    if (mtu > 0)
    {
        ifr.ifr_mtu = mtu;
    }
    else
    {
        ifr.ifr_mtu = DEFAULT_MTU_VALUE;
    }

    err = nm_update_link_state(pszInterfaceName, LINK_DOWN);
    bail_on_error(err);

    err = ioctl(sockFd, SIOCSIFMTU, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = nm_update_link_state(pszInterfaceName, LINK_UP);
    bail_on_error(err);

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;

error:
    goto cleanup;

}

uint32_t
nm_set_link_mtu(
    const char *pszInterfaceName,
    uint32_t mtu
)
{
    uint32_t err = 0, err1 = 0, oldMtu = 0;
    char *pszCfgFileName = NULL;
    char szValue[MAX_LINE] = {};
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_link_mtu(pszInterfaceName, &oldMtu);
    bail_on_error(err);

    if (mtu == 0)
    {
        mtu = DEFAULT_MTU_VALUE;
    }

    err = nm_update_link_mtu(pszInterfaceName, mtu);
    bail_on_error(err);

    sprintf(szValue, "%u", mtu);

    err = nm_set_key_value(pszCfgFileName, SECTION_LINK, KEY_MTU, szValue, 0);
    if (err)
    {
        err1 = nm_update_link_mtu(pszInterfaceName, oldMtu);
        bail_on_error(err1);
    }
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
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
    struct ifreq ifr = {};

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pMtu)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    strncpy(ifr.ifr_name, pszInterfaceName, IFNAMSIZ - 1);

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

static uint32_t
nm_update_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE linkState
)
{
    uint32_t err = 0;
    int sockFd = -1;
    struct ifreq ifr = {};

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        (linkState >= LINK_STATE_UNKNOWN))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    strncpy(ifr.ifr_name, pszInterfaceName, IFNAMSIZ - 1);

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
            err = NM_ERR_INVALID_PARAMETER;
    }
    bail_on_error(err);

    err = ioctl(sockFd, SIOCSIFFLAGS, &ifr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    return err;
error:
    goto cleanup;
}

uint32_t
nm_set_link_state(
    const char *pszInterfaceName,
    NET_LINK_STATE linkState
)
{
    uint32_t err = 0;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    err = nm_update_link_state(pszInterfaceName, linkState);
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
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
    struct ifreq ifr = {};

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pLinkState)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    strncpy(ifr.ifr_name, pszInterfaceName, IFNAMSIZ - 1);

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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszCommandOptions) ||
        IS_NULL_OR_EMPTY(pszDestIPv4Addr))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszArpingCmd,
                                     "%s %s -I %s %s",
                                     ARPING_COMMAND,
                                     pszCommandOptions,
                                     pszInterfaceName,
                                     pszDestIPv4Addr);
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
nm_get_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t *pDhcpModeFlags
);

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
    uint32_t err = 0, err1 = 0, dhcpModeFlags;
    uint8_t prefix;
    int retVal = 0;
    size_t staticIp4Count = 0, staticIp6Count = 0, ip4Count = 0, ip6Count = 0;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    char ipAddr[INET6_ADDRSTRLEN];
    char **ppszIpv4AddrList = NULL, **ppszIpv6AddrList = NULL;
    char **ppszStaticIpv4AddrList = NULL, **ppszStaticIpv6AddrList = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_link_state(pszInterfaceName, &linkState);
    bail_on_error(err);

    err = nm_get_interface_ipaddr(pszInterfaceName, STATIC_IPV4, &ip4Count,
                                  &ppszIpv4AddrList);
    if (err == NM_ERR_VALUE_NOT_FOUND)
    {
        err = 0;
    }
    bail_on_error(err);

    if (!ip4Count)
    {
        err = nm_get_interface_ipaddr(pszInterfaceName, STATIC_IPV6, &ip6Count,
                                      &ppszIpv6AddrList);
        if (err == NM_ERR_VALUE_NOT_FOUND)
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
    if (err == NM_ERR_VALUE_NOT_FOUND)
    {
        err = 0;
    }
    bail_on_error(err);

    err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV6, &staticIp6Count,
                                &ppszStaticIpv6AddrList);
    if (err == NM_ERR_VALUE_NOT_FOUND)
    {
        err = 0;
    }
    bail_on_error(err);

    err = flush_interface_ipaddr(pszInterfaceName);
    bail_on_error(err);

    err = nm_update_link_state(pszInterfaceName, LINK_UP);
    bail_on_error(err);

    if (staticIp4Count && ip4Count &&
        (strcmp(ppszStaticIpv4AddrList[0], ppszIpv4AddrList[0]) != 0))
    {
        err = NM_ERR_BAD_CONFIG_FILE;
        bail_on_error(err);
    }

    if (staticIp4Count && !ip4Count)
    {
        retVal = sscanf(ppszStaticIpv4AddrList[0], "%[^/]/%hhu", ipAddr,
                        &prefix);
        if ((retVal != 1) && (retVal != 2))
        {
            err = NM_ERR_BAD_CONFIG_FILE;
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
        err = nm_update_link_mode(pszInterfaceName, LINK_AUTO);
        bail_on_error(err);
    }

    err = nm_restart_network_service();
    if (linkMode == LINK_MANUAL)
    {
        err1 = nm_update_link_mode(pszInterfaceName, LINK_MANUAL);
        bail_on_error(err1);
    }
    bail_on_error(err);

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &dhcpModeFlags);
    bail_on_error(err);

    if (staticIp4Count || staticIp6Count ||
        TEST_FLAG(dhcpModeFlags, fDHCP_IPV4) ||
        TEST_FLAG(dhcpModeFlags, fDHCP_IPV6))
    {
        err = nm_wait_for_ip(pszInterfaceName, DEFAULT_WAIT_FOR_IP_TIMEOUT,
                             NET_ADDR_IPV4 | NET_ADDR_IPV6);
        bail_on_error(err);
    }

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
    netmgr_list_free(staticIp6Count, (void **)ppszStaticIpv6AddrList);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
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
    char *pszFile = NULL;
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    PNET_INTERFACE pInterfaceList = NULL;
    PNET_INTERFACE pInterface = NULL;

    if (!ppInterfaces)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = getifaddrs(&ifaddr);
    if (err != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr->sa_family != AF_PACKET)
        {
            continue;
        }
        if (nm_get_network_conf_filename(ifa->ifa_name, &pszFile) == 0)
        {
            err = netmgr_alloc(sizeof(NET_INTERFACE), (void**)&pInterface);
            bail_on_error(err);

            err = netmgr_alloc_string(ifa->ifa_name, &pInterface->pszName);
            bail_on_error(err);

            pInterface->pNext = pInterfaceList;
            pInterfaceList = pInterface;
            pInterface = NULL;
        }
        netmgr_free(pszFile);
        pszFile = NULL;
    }

    *ppInterfaces = pInterfaceList;

cleanup:
    freeifaddrs(ifaddr);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !ppLinkInfo)
    {
        err = NM_ERR_INVALID_PARAMETER;
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
    netmgr_free(pszMacAddress);
    if (pLinkInfo)
    {
        netmgr_free(pLinkInfo->pszInterfaceName);
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
        err = NM_ERR_INVALID_PARAMETER;
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
    nm_free_interface_list(pInterfaceList);
    return err;

error:
    if (ppLinkInfo)
    {
        *ppLinkInfo = NULL;
    }
    nm_free_link_info(pLinkInfo);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pCount ||
        !pppszIpAddrList)
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        err = NM_ERR_BAD_CONFIG_FILE;
        bail_on_error(err);
    }
    else if (dwNumSections == 0)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
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
            err = NM_ERR_BAD_CONFIG_FILE;
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
        err = netmgr_alloc((nCount * sizeof(char *)), (void **)&ppszIpAddrList);
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
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pCount ||
        !pppszIpAddress)
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        err = NM_ERR_VALUE_NOT_FOUND;
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
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

    err = netmgr_alloc((count * sizeof(char *)), (void **)&ppszIpAddrList);
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
    char *pszMsgBuf, szIfName[IFNAMSIZ] = {0}, szMsgBuf[BUFSIZE] = {0};
    char *pszGateway = NULL, szGateway[INET6_ADDRSTRLEN] = {0};

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !ppszGateway)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if ((sockFd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        err = errno;
        bail_on_error(err);
    }

    pszMsgBuf = szMsgBuf;
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

    do
    {
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
        if (rtMsg->rtm_table != RT_TABLE_MAIN)
        {
            continue;
        }
        if (((addrType == STATIC_IPV4) || (addrType == DHCP_IPV4)) &&
            (rtMsg->rtm_family != AF_INET))
        {
            continue;
        }
        if (((addrType == STATIC_IPV6) || (addrType == DHCP_IPV6) ||
             (addrType == AUTO_IPV6)) && (rtMsg->rtm_family != AF_INET6))
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
                    if_indextoname(*(int *)RTA_DATA(rtAttr), szIfName);
                    break;
                case RTA_GATEWAY:
                    if (rtMsg->rtm_family == AF_INET)
                    {
                        gw4.s_addr = *(uint32_t *)RTA_DATA(rtAttr);
                    }
                    break;
                case RTA_DST:
                    if (rtMsg->rtm_family == AF_INET)
                    {
                        dst4.s_addr = *(uint32_t *)RTA_DATA(rtAttr);
                    }
                    break;
                default:
                    break;
            }
        }
        if ((addrType == STATIC_IPV4) || (addrType == DHCP_IPV4))
        {
            if ((dst4.s_addr == 0) && !strcmp(szIfName, pszInterfaceName))
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
nm_set_sysctl_persistent_value(
    const char *pszSysctlKey,
    const char *pszValue
)
{
    uint32_t err = 0, found = 0;
    size_t len, i, lineCount = 0;
    char *pszFileBuf = NULL, *pszNewFileBuf = NULL;
    char *pszKeyValue = NULL, **ppszLineBuf = NULL;
    FILE *fp;

    if (IS_NULL_OR_EMPTY(pszSysctlKey) || IS_NULL_OR_EMPTY(pszValue))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_read_conf_file(SYSCTL_CONF_FILENAME, &pszFileBuf);
    if (err == ENOENT)
    {
        err = 0;
        if ((fp = fopen(SYSCTL_CONF_FILENAME, "a+")) != NULL)
        {
            fclose(fp);
        }
        else
        {
            err = errno;
            bail_on_error(err);
        }
    }
    bail_on_error(err);

    if (!IS_NULL_OR_EMPTY(pszFileBuf))
    {
        err = nm_string_to_line_array(pszFileBuf, &lineCount, &ppszLineBuf);
        bail_on_error(err);
    }

    len = strlen(pszSysctlKey) + strlen(pszValue) + 4;

    err = netmgr_alloc_string_printf(&pszKeyValue, "%s=%s\n", pszSysctlKey,
                                     pszValue);
    bail_on_error(err);

    if (pszFileBuf != NULL)
    {
        len += strlen(pszFileBuf);
    }

    err = netmgr_alloc(len, (void **)&pszNewFileBuf);
    bail_on_error(err);

    for (i = 0; i < lineCount; i++)
    {
        if (!strncmp(ppszLineBuf[i], pszSysctlKey, strlen(pszSysctlKey)))
        {
            netmgr_free(ppszLineBuf[i]);
            ppszLineBuf[i] = pszKeyValue;
            pszKeyValue = NULL;
            found = 1;
        }
        strcat(pszNewFileBuf, ppszLineBuf[i]);
    }

    if (!found)
    {
        if (pszNewFileBuf[strlen(pszNewFileBuf)-1] != '\n')
        {
            strcat(pszNewFileBuf, "\n");
        }
        strcat(pszNewFileBuf, pszKeyValue);
    }

    err = nm_atomic_file_update(SYSCTL_CONF_FILENAME, pszNewFileBuf);
    bail_on_error(err);

cleanup:
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
    netmgr_free(pszNewFileBuf);
    netmgr_free(pszFileBuf);
    netmgr_free(pszKeyValue);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_set_sysctl_procfs_value(
    const char *pszProcfsPath,
    const char *pszValue
)
{
    uint32_t err = 0;
    FILE *pFile = NULL;

    if (IS_NULL_OR_EMPTY(pszProcfsPath) || IS_NULL_OR_EMPTY(pszValue))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    pFile = fopen(pszProcfsPath, "w");
    if (pFile == NULL)
    {
        err = errno;
        bail_on_error(err);
    }

    if (fputs(pszValue, pFile) == EOF)
    {
        err = ferror(pFile);
        bail_on_error(err);
    }

cleanup:
    if (pFile != NULL)
    {
        fclose(pFile);
    }
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_get_sysctl_procfs_value(
    const char *pszProcfsPath,
    char **ppszValue
)
{
    uint32_t err = 0;
    FILE *pFile = NULL;
    size_t len = 0;
    ssize_t lLen = 0;
    char *p, *pszLine = NULL, *pszValue = NULL;

    if (IS_NULL_OR_EMPTY(pszProcfsPath) || !ppszValue)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    pFile = fopen(pszProcfsPath, "r");
    if (pFile == NULL)
    {
        err = errno;
        bail_on_error(err);
    }

    lLen = getline(&pszLine, &len, pFile);
    if (lLen < 0)
    {
        err = errno;
        bail_on_error(err);
    }
    err = netmgr_alloc_string(pszLine, &pszValue);
    bail_on_error(err);
    p = strrchr(pszValue, '\n');
    if (p != NULL)
    {
        *p = '\0';
    }
    *ppszValue = pszValue;

cleanup:
    if (pFile != NULL)
    {
        fclose(pFile);
    }
    return err;
error:
    netmgr_free(pszValue);
    if (ppszValue)
    {
        *ppszValue = NULL;
    }
    goto cleanup;
}

static uint32_t
nm_get_ipv6_enable(
    const char *pszInterfaceName,
    uint32_t *pEnabled);

static uint32_t
nm_set_ip_dhcp_mode(
    const char *pszInterfaceName,
    uint32_t dhcpModeFlags
)
{
    uint32_t err = 0;
    char *pszCfgFileName = NULL;
    char *pszProcfsAutov6Path = NULL;
    char *pszSysctlAutov6Key = NULL;
    char szAutov6Value[] = "0";
    char szDhcpValue[MAX_LINE] = "no";

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    if (TEST_FLAG(dhcpModeFlags, fAUTO_IPV6))
    {
        sprintf(szAutov6Value, "1");
    }

    err = netmgr_alloc_string_printf(&pszProcfsAutov6Path,
                                     "/proc/sys/net/ipv6/conf/%s/autoconf",
                                     pszInterfaceName);
    bail_on_error(err);

    err = netmgr_alloc_string_printf(&pszSysctlAutov6Key,
                                     "net.ipv6.conf.%s.autoconf",
                                     pszInterfaceName);
    bail_on_error(err);

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    if (TEST_FLAG(dhcpModeFlags, fDHCP_IPV4) &&
        TEST_FLAG(dhcpModeFlags, fDHCP_IPV6))
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

    err = nm_set_key_value(pszCfgFileName, SECTION_NETWORK, KEY_DHCP,
                           szDhcpValue, 0);
    bail_on_error(err);

    err = nm_set_sysctl_procfs_value(pszProcfsAutov6Path, szAutov6Value);
    bail_on_error(err);

    err = nm_set_sysctl_persistent_value(pszSysctlAutov6Key, szAutov6Value);
    bail_on_error(err);

cleanup:
    netmgr_free(pszProcfsAutov6Path);
    netmgr_free(pszSysctlAutov6Key);
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
    uint32_t err = 0, mode = 0, v6enabled = 0;
    char *pszCfgFileName = NULL;
    char *pszDhcpValue = NULL;
    char *pszProcfsAutov6Path = NULL;
    char *pszAutov6Value = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pDhcpModeFlags)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, SECTION_NETWORK, KEY_DHCP,
                           &pszDhcpValue);
    if ((err == NM_ERR_VALUE_NOT_FOUND) || !strcmp(pszDhcpValue, "no"))
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
        err = NM_ERR_INVALID_PARAMETER;
    }
    bail_on_error(err);

    err = nm_get_ipv6_enable(pszInterfaceName, &v6enabled);
    if ((err == ENOENT) || (err == NM_ERR_VALUE_NOT_FOUND))
    {
        err = 0;
        v6enabled = 0;
    }
    bail_on_error(err);

    if (!v6enabled)
    {
        CLEAR_FLAG(mode, fDHCP_IPV6);
        goto done;
    }

    err = netmgr_alloc_string_printf(&pszProcfsAutov6Path,
                                     "/proc/sys/net/ipv6/conf/%s/autoconf",
                                     pszInterfaceName);
    bail_on_error(err);

    err = nm_get_sysctl_procfs_value(pszProcfsAutov6Path, &pszAutov6Value);
    if ((err == ENOENT) || (err == NM_ERR_VALUE_NOT_FOUND))
    {
        err = 0;
    }
    bail_on_error(err);

    if ((pszAutov6Value != NULL) && !strcmp(pszAutov6Value, "1"))
    {
        mode |= fAUTO_IPV6;
    }

done:
    *pDhcpModeFlags = mode;

cleanup:
    netmgr_free(pszDhcpValue);
    netmgr_free(pszAutov6Value);
    netmgr_free(pszProcfsAutov6Path);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszIpGwAddr))
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        err = NM_ERR_INVALID_ADDRESS;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pCount ||
        !pppszGwAddrList)
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        err = NM_ERR_BAD_CONFIG_FILE;
        bail_on_error(err);
    }
    else if (dwNumSections == 0)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
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
        err = netmgr_alloc((nCount * sizeof(char *)), (void **)&ppszGwAddrList);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszIPv4Addr))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (!is_ipv4_addr(pszIPv4Addr) || (prefix > 32))
    {
        err = NM_ERR_INVALID_ADDRESS;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    sprintf(szIpAddr, "%s/%hhu", pszIPv4Addr, prefix);

    err = nm_delete_static_ipv4_addr(pszInterfaceName);
    if (err == NM_ERR_VALUE_NOT_FOUND)
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &count,
                                &ppszIpAddrList);
    bail_on_error(err);
    if (count > 1)
    {
        err = NM_ERR_BAD_CONFIG_FILE;
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        (mode >= IPV4_ADDR_MODE_MAX))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if ((mode == IPV4_ADDR_MODE_STATIC) &&
        (IS_NULL_OR_EMPTY(pszIPv4AddrPrefix) ||
        ((n = sscanf(pszIPv4AddrPrefix, "%[^/]/%hhu", szIpAddr, &prefix)) < 1)
        || !is_ipv4_addr(szIpAddr) || (prefix > 32)))
    {
        err = NM_ERR_INVALID_ADDRESS;
        bail_on_error(err);
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &currModeFlags);
    bail_on_error(err);

    prefix = ((mode == IPV4_ADDR_MODE_STATIC) && (n == 1)) ? 32 : prefix;

    err = nm_delete_static_ipv4_addr(pszInterfaceName);
    if (err == NM_ERR_VALUE_NOT_FOUND)
    {
        err = 0;
    }
    bail_on_error(err);

    err = nm_delete_static_ip_gateway(pszInterfaceName, STATIC_IPV4);
    if (err == NM_ERR_VALUE_NOT_FOUND)
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        !(pMode || ppszIPv4AddrPrefix || ppszIPv4Gateway))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    if (TEST_FLAG(modeFlags, fDHCP_IPV4))
    {
        ip4Mode = IPV4_ADDR_MODE_DHCP;

        err = nm_get_interface_ipaddr(pszInterfaceName, DHCP_IPV4, &ipCount,
                                      &ppszIpAddrList);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);

        //TODO: Get DHCP IPv4 gateway from routes
        err = nm_get_ip_default_gateway(pszInterfaceName, DHCP_IPV4,
                                        &pszIPv4Gateway);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    else
    {
        /* Get IP addresss from interface via API. If that fails, read file */
        err = nm_get_interface_ipaddr(pszInterfaceName, STATIC_IPV4, &ipCount,
                                      &ppszIpAddrList);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);

        if (ipCount == 0)
        {
            err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4,
                                        &ipCount, &ppszIpAddrList);
            if (err == NM_ERR_VALUE_NOT_FOUND)
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
            if (err == NM_ERR_VALUE_NOT_FOUND)
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

    if (pMode)
    {
        *pMode = ip4Mode;
    }
    if (ppszIPv4AddrPrefix)
    {
        *ppszIPv4AddrPrefix = pszIPv4AddrPrefix;
    }
    else
    {
        netmgr_free(pszIPv4AddrPrefix);
    }
    if (ppszIPv4Gateway)
    {
        *ppszIPv4Gateway = pszIPv4Gateway;
    }
    else
    {
        netmgr_free(pszIPv4Gateway);
    }

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

static uint32_t
nm_set_ipv6_enable(
    const char *pszInterfaceName,
    uint32_t enabled)
{
    uint32_t err = 0;
    char *pszSysctlDisablev6Key = NULL;
    char *pszProcfsDisablev6Path = NULL;
    char szDisablev6Value[] = "0";

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    if (!enabled)
    {
        sprintf(szDisablev6Value, "1");
    }

    err = netmgr_alloc_string_printf(&pszProcfsDisablev6Path,
                                     "/proc/sys/net/ipv6/conf/%s/disable_ipv6",
                                     pszInterfaceName);
    bail_on_error(err);

    err = netmgr_alloc_string_printf(&pszSysctlDisablev6Key,
                                     "net.ipv6.conf.%s.disable_ipv6",
                                     pszInterfaceName);
    bail_on_error(err);

    err = nm_set_sysctl_procfs_value(pszProcfsDisablev6Path, szDisablev6Value);
    bail_on_error(err);

    err = nm_set_sysctl_persistent_value(pszSysctlDisablev6Key,
                                         szDisablev6Value);
    bail_on_error(err);

cleanup:
    netmgr_free(pszProcfsDisablev6Path);
    netmgr_free(pszSysctlDisablev6Key);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_get_ipv6_enable(
    const char *pszInterfaceName,
    uint32_t *pEnabled)
{
    uint32_t err = 0, enabled = 0;
    char *pszDisableIpv6 = NULL;
    char *pszProcfsDisablev6Path = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pEnabled)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszProcfsDisablev6Path,
                                     "/proc/sys/net/ipv6/conf/%s/disable_ipv6",
                                     pszInterfaceName);
    bail_on_error(err);

    err = nm_get_sysctl_procfs_value(pszProcfsDisablev6Path, &pszDisableIpv6);
    bail_on_error(err);

    if (!strcmp(pszDisableIpv6, "0"))
    {
        enabled = 1;
    }

    *pEnabled = enabled;

cleanup:
    netmgr_free(pszProcfsDisablev6Path);
    netmgr_free(pszDisableIpv6);
    return err;
error:
    if (pEnabled)
    {
        *pEnabled = 0;
    }
    goto cleanup;
}

uint32_t
nm_add_static_ipv6_addr(
    const char *pszInterfaceName,
    const char *pszIPv6AddrPrefix
)
{
    int n = 0;
    uint32_t err = 0, v6enabled = 0;
    uint8_t prefix = 0;
    char *pszCfgFileName = NULL, szIpAddr[INET6_ADDRSTRLEN];
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszIPv6AddrPrefix) ||
        ((n = sscanf(pszIPv6AddrPrefix, "%[^/]/%hhu", szIpAddr, &prefix)) < 1)
        || !is_ipv6_addr(szIpAddr) || (prefix > 128))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    err = nm_add_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS,
                           pszIPv6AddrPrefix, 0);
    bail_on_error(err);

    err = nm_get_ipv6_enable(pszInterfaceName, &v6enabled);
    bail_on_error(err);

    if (!v6enabled)
    {
        err = nm_set_ipv6_enable(pszInterfaceName, 1);
        bail_on_error(err);
    }

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
    uint32_t err = 0, autov6, dhcpv6, v6enabled;
    uint8_t prefix = 0;
    char *pszCfgFileName = NULL, szIpAddr[INET6_ADDRSTRLEN], **ppszIp = NULL;
    int n, lockId;
    size_t c = 0;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszIPv6AddrPrefix) ||
        ((n = sscanf(pszIPv6AddrPrefix, "%[^/]/%hhu", szIpAddr, &prefix)) < 1)
        || !is_ipv6_addr(szIpAddr) || (prefix > 128))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
    bail_on_error(err);

    err = nm_delete_key_value(pszCfgFileName, SECTION_NETWORK, KEY_ADDRESS,
                              pszIPv6AddrPrefix, 0);
    bail_on_error(err);

    /* Disable IPv6 if no autov6, no dhcpv6, and no staticv6 configured */
    err = nm_get_ipv6_addr_mode(pszInterfaceName, &autov6, &dhcpv6);
    bail_on_error(err);

    if (!autov6 && !dhcpv6)
    {
        err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV6, &c, &ppszIp);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);
        if (c == 0)
        {
            err = nm_get_ipv6_enable(pszInterfaceName, &v6enabled);
            bail_on_error(err);

            if (v6enabled)
            {
                err = nm_set_ipv6_enable(pszInterfaceName, 0);
                bail_on_error(err);
            }
        }
    }

    err = nm_restart_network_service();
    bail_on_error(err);

cleanup:
    nm_release_write_lock(lockId);
    netmgr_list_free(c, (void **)ppszIp);
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
    uint32_t err = 0, modeFlags, v6enabled;
    char **ppszIp = NULL;
    size_t c = 0;
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

    /* Disable IPv6 if no autov6, no dhcpv6, and no staticv6 configured */
    err = nm_get_ipv6_enable(pszInterfaceName, &v6enabled);
    bail_on_error(err);

    if (!enableDhcp && !enableAutoconf)
    {
        err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV6, &c, &ppszIp);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);
        if (c == 0)
        {
            if (v6enabled)
            {
                err = nm_set_ipv6_enable(pszInterfaceName, 0);
                bail_on_error(err);
            }
        }
    }
    else
    {
        if (!v6enabled)
        {
            err = nm_set_ipv6_enable(pszInterfaceName, 1);
            bail_on_error(err);
        }
    }

    err = nm_restart_network_service();
    bail_on_error(err);

error:
    netmgr_list_free(c, (void **)ppszIp);
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
    size_t i, count = 0;
    char ipAddr[INET6_ADDRSTRLEN], **ppszIpAddrList = NULL, *pszMacAddr = NULL;
    NET_ADDR_TYPE addrType = 0;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pszIpAddr) || !pAddrType ||
        (sscanf(pszIpAddr, "%[^/]/%u", ipAddr, &prefix) < 1))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (is_ipv4_addr(ipAddr))
    {
        err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &count,
                                    &ppszIpAddrList);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);

        for (i = 0; i < count; i++)
        {
            if (count && !strcmp(pszIpAddr, ppszIpAddrList[i]))
            {
                addrType = STATIC_IPV4;
                break;
            }
        }
        if (addrType == 0)
        {
            addrType = DHCP_IPV4;
        }
    }

    if (is_ipv6_addr(ipAddr))
    {
        if (is_ipv6_link_local_addr(ipAddr))
        {
            addrType = LINK_LOCAL_IPV6;
        }
        else
        {
            err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV6, &count,
                                        &ppszIpAddrList);
            if (err == NM_ERR_VALUE_NOT_FOUND)
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
                /* Determine if it is SLAAC / autoconf address */
                err = nm_get_link_mac_addr(pszInterfaceName, &pszMacAddr);
                bail_on_error(err);

                if (is_ipv6_autoconf_addr(ipAddr, pszMacAddr))
                {
                    addrType = AUTO_IPV6;
                }
                else
                {
                    addrType = DHCP_IPV6;
                }
            }
        }
    }

    if (addrType == 0)
    {
        err = NM_ERR_INVALID_ADDRESS;
        bail_on_error(err);
    }

    *pAddrType = addrType;

cleanup:
    netmgr_list_free(count, (void **)ppszIpAddrList);
    netmgr_free(pszMacAddr);
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
    uint32_t err = 0, modeFlags, addrType;
    size_t i = 0, j = 0, ip4Count = 0, ip6Count = 0, nCount = 0;
    char **ppszIp4AddrList = NULL;
    char **ppszIp6AddrList = NULL;
    NET_IP_ADDR **ppIpAddrList = NULL;

    //TODO: If pszInterfaceName is NULL, enumerate all IPs
    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        !pCount || !pppIpAddrList || !addrTypes)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_ip_dhcp_mode(pszInterfaceName, &modeFlags);
    bail_on_error(err);

    if (TEST_FLAG(modeFlags, fDHCP_IPV4) && TEST_FLAG(addrTypes, DHCP_IPV4))
    {
        err = nm_get_interface_ipaddr(pszInterfaceName, DHCP_IPV4, &ip4Count,
                                      &ppszIp4AddrList);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    else if (TEST_FLAG(addrTypes, STATIC_IPV4))
    {
        err = nm_get_static_ip_addr(pszInterfaceName, STATIC_IPV4, &ip4Count,
                                    &ppszIp4AddrList);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = 0;
        }
        bail_on_error(err);
    }
    nCount = ip4Count;

    if (TEST_FLAG(addrTypes, DHCP_IPV6) ||
        TEST_FLAG(addrTypes, AUTO_IPV6) ||
        TEST_FLAG(addrTypes, STATIC_IPV6) ||
        TEST_FLAG(addrTypes, LINK_LOCAL_IPV6))
    {
        err = nm_get_interface_ipaddr(pszInterfaceName,
                                      NET_ADDR_IPV6 | LINK_LOCAL_IPV6,
                                      &ip6Count,
                                      &ppszIp6AddrList);
        if (err == NM_ERR_VALUE_NOT_FOUND)
        {
            err = nm_get_static_ip_addr(pszInterfaceName,
                                        STATIC_IPV6,
                                        &ip6Count,
                                        &ppszIp6AddrList);
            if (err == NM_ERR_VALUE_NOT_FOUND)
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
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

    err = netmgr_alloc((nCount * sizeof(PNET_IP_ADDR)), (void **)&ppIpAddrList);
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

    for (j = 0; j < ip6Count; j++)
    {
        err = nm_get_ip_addr_type(pszInterfaceName,
                                  ppszIp6AddrList[j],
                                  &addrType);
        bail_on_error(err);
        if (!TEST_FLAG(addrTypes, addrType))
        {
            continue;
        }
        err = netmgr_alloc(sizeof(NET_IP_ADDR), (void **)&ppIpAddrList[i]);
        bail_on_error(err);
        err = netmgr_alloc_string(pszInterfaceName,
                                  &ppIpAddrList[i]->pszInterfaceName);
        bail_on_error(err);
        err = netmgr_alloc_string(ppszIp6AddrList[j],
                                  &ppIpAddrList[i]->pszIPAddrPrefix);
        bail_on_error(err);
        ppIpAddrList[i]->type = addrType;
        i++;
    }

    *pCount = i;
    if (i == 0)
    {
        netmgr_list_free(nCount, (void **)ppIpAddrList);
        ppIpAddrList = NULL;
    }
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) ||
        (!IS_NULL_OR_EMPTY(pszIPv6Gateway) &&
        !is_ipv6_addr(pszIPv6Gateway)))
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        if (err == NM_ERR_VALUE_NOT_FOUND)
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !ppszIPv6Gateway)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_ip_default_gateway(pszInterfaceName, DHCP_IPV6,
                                    &pszIPv6Gateway);
    if (err == NM_ERR_VALUE_NOT_FOUND)
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
    char *pszCfgFileName = NULL, buf[MAX_LINE] = {0};
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pDestKeyVal = NULL;

    if (!pRoute || !IS_VALID_INTERFACE_NAME(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork) ||
        IS_NULL_OR_EMPTY(pRoute->pszGateway))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pRoute->pszInterfaceName,
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
            err = NM_ERR_VALUE_EXISTS;
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
            err = NM_ERR_INVALID_PARAMETER;
            bail_on_error(err);
    }
    err = ini_cfg_add_key(pSection, KEY_SCOPE, buf);
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
nm_delete_route_section(
    NET_IP_ROUTE *pRoute
)
{
    uint32_t err = 0, dwNumSections = 0, i;
    char *pszCfgFileName = NULL;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL;
    PKEYVALUE_INI pDestKeyVal = NULL;

    if (!pRoute || !IS_VALID_INTERFACE_NAME(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pRoute->pszInterfaceName,
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
        err = NM_ERR_VALUE_NOT_FOUND;
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pCount || !pppRoutes)
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        err = NM_ERR_VALUE_NOT_FOUND;
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
    char szBufDestAddr[INET6_ADDRSTRLEN+128];
    NET_IP_ROUTE route = {0};
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!IS_VALID_INTERFACE_NAME(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork) ||
        IS_NULL_OR_EMPTY(pRoute->pszGateway) ||
        (sscanf(pRoute->pszDestNetwork, "%[^/]/%hhu", szDestAddr, &prefix) < 1))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (is_ipv4_addr(szDestAddr))
    {
        prefix = (prefix == 255) ? 32 : prefix;
        if ((prefix > 32) || !is_ipv4_addr(pRoute->pszGateway))
        {
            err = NM_ERR_INVALID_ADDRESS;
            bail_on_error(err);
        }
    }
    else if (is_ipv6_addr(szDestAddr))
    {
        prefix = (prefix == 255) ? 128 : prefix;
        if ((prefix > 128) || !is_ipv6_addr(pRoute->pszGateway))
        {
            err = NM_ERR_INVALID_ADDRESS;
            bail_on_error(err);
        }
    }
    else
    {
        err = NM_ERR_INVALID_ADDRESS;
        bail_on_error(err);
    }

    memcpy(&route, pRoute, sizeof(route));
    sprintf(szBufDestAddr, "%s/%hhu", szDestAddr, prefix);
    route.pszDestNetwork = szBufDestAddr;

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
    char szbufDestAddr[INET6_ADDRSTRLEN+128];
    NET_IP_ROUTE route;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (!IS_VALID_INTERFACE_NAME(pRoute->pszInterfaceName) ||
        IS_NULL_OR_EMPTY(pRoute->pszDestNetwork) ||
        (sscanf(pRoute->pszDestNetwork, "%[^/]/%hhu", szDestAddr, &prefix) < 1))
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        err = NM_ERR_INVALID_ADDRESS;
        bail_on_error(err);
    }

    memcpy(&route, pRoute, sizeof(route));
    sprintf(szbufDestAddr, "%s/%hhu", szDestAddr, prefix);
    route.pszDestNetwork = szbufDestAddr;

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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (count > 0)
    {
        if (ppszStrings == NULL)
        {
            err = NM_ERR_INVALID_PARAMETER;
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
        err = netmgr_alloc(bytes, (void **)&pszNewString);
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
    if (ppszNewString != NULL)
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
        err = NM_ERR_INVALID_PARAMETER;
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
        err = netmgr_alloc((count * sizeof(char *)), (void **)&ppszStringList);
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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
    bail_on_error(err);

    err = nm_get_key_value(pszCfgFileName, SECTION_DHCP, KEY_USE_DNS,
                           &pszUseDnsValue);
    if ((err == NM_ERR_VALUE_NOT_FOUND) || !strcmp(pszUseDnsValue, "true"))
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
        err = NM_ERR_BAD_CONFIG_FILE;
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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = nm_get_dns_mode(PHOTON_ETH0_NAME, &mode);
    bail_on_error(err);

    if (mode == DHCP_DNS)
    {
        err = NM_ERR_INVALID_MODE;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                      &pszCfgFileName);
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
    if (err != NM_ERR_VALUE_NOT_FOUND)
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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = nm_get_dns_mode(PHOTON_ETH0_NAME, &mode);
    bail_on_error(err);
    if (mode == DHCP_DNS)
    {
        err = NM_ERR_INVALID_MODE;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                      &pszCfgFileName);
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
        err = NM_ERR_VALUE_NOT_FOUND;
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
        err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                      &pszCfgFileName);
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

    err = NM_ERR_INVALID_MODE;
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
        if (dirFile == NULL)
        {
            err = errno;
            bail_on_error(err);
        }

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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    /* Determine DNS mode from UseDNS value in 10-eth0.network */
    err = nm_get_dns_mode(PHOTON_ETH0_NAME, pMode);
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
                               (void **)&ppszDnsServersList);
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
            }
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
        if (err == NM_ERR_VALUE_NOT_FOUND)
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
    uint32_t err = 0, sdVersion = 0;
    char *pszCfgFileName = NULL;
    char szSectionName[MAX_LINE];
    char *pszCurrentDnsDomains = NULL;
    char *pszDnsDomainsValue = NULL;
    int lockId;

    err = nm_acquire_write_lock(0, &lockId);
    bail_on_error(err);

    if (pszDnsDomain == NULL)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_get_systemd_version(&sdVersion);
    bail_on_error(err);

    if (sdVersion <= 228)
    {
        if (pszInterfaceName == NULL)
        {
            pszInterfaceName = PHOTON_ETH0_NAME;
        }
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                      &pszCfgFileName);
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
    if (err != NM_ERR_VALUE_NOT_FOUND)
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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (!system("/usr/lib/systemd/systemd --v | grep systemd | \
                 cut -d' ' -f2 | grep 2[0-2][0-8] > /dev/null"))
    {
        /* systemd version <= 228 */
        if (pszInterfaceName == NULL)
        {
            pszInterfaceName = PHOTON_ETH0_NAME;
        }
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                      &pszCfgFileName);
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
    if (pszMatch == NULL)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

    pszNext = pszMatch + strlen(pszDnsDomain);
    if (*pszNext == ' ')
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
    netmgr_free(pszCurrentDnsDomains);
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

    if (!system("/usr/lib/systemd/systemd --v | grep systemd | \
                 cut -d' ' -f2 | grep 2[0-2][0-8] > /dev/null"))
    {
        /* systemd version <= 228 */
        if (pszInterfaceName == NULL)
        {
            pszInterfaceName = PHOTON_ETH0_NAME;
        }
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                      &pszCfgFileName);
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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (pszInterfaceName == NULL)
    {
        err = nm_read_conf_file(RESOLV_CONF_FILENAME, &pszFileBuf);
        bail_on_error(err);

        pszDnsDomainsValue = strstr(pszFileBuf, STR_SEARCH);
        if (pszDnsDomainsValue == NULL)
        {
            err = NM_ERR_VALUE_NOT_FOUND;
            bail_on_error(err);
        }
        pszDnsDomainsValue = strstr(pszDnsDomainsValue, " ");
        if (pszDnsDomainsValue == NULL)
        {
            err = NM_ERR_VALUE_NOT_FOUND;
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
        if (err == NM_ERR_VALUE_NOT_FOUND)
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                  &pszCfgFileName);
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

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pIaid)
    {
        err = NM_ERR_INVALID_PARAMETER;
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
        err = nm_get_network_conf_filename_for_update(pszInterfaceName,
                                                      &pszCfgFileName);
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
            err = NM_ERR_INVALID_PARAMETER;
            bail_on_error(err);
        }

        duidType = nm_duid_strtype_from_type((n1 << 8) | n2);
        if (duidType == NULL)
        {
            err = NM_ERR_INVALID_PARAMETER;
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
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (pszInterfaceName != NULL)
    {
        err = nm_get_network_conf_filename(pszInterfaceName, &pszCfgFileName);
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
        err = NM_ERR_BAD_CONFIG_FILE;
        bail_on_error(err);
    }

    err = nm_get_key_value(pszCfgFileName, SECTION_DHCP, KEY_DUID_RAWDATA,
                           &pszDuid);
    bail_on_error(err);

    err = netmgr_alloc((strlen(pszDuid) + 8), (void **)ppszDuid);
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
        err = NM_ERR_INVALID_PARAMETER;
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
                           (void **)&ppszNtpServersList);
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
        }
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
    size_t i, lineCount = 0;
    char *pszFileBuf = NULL, *pszFwRule = NULL, **ppszLineBuf = NULL;
    char *pszNewFileBuf = NULL;

    if ((pNetFwRule == NULL) || (pNetFwRule->type >= FW_RULE_TYPE_MAX))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (pNetFwRule->type != FW_RAW)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszFwRule, "iptables %s",
                                     pNetFwRule->pszRawFwRule);
    bail_on_error(err);

    err = nm_read_conf_file(FIREWALL_CONF_FILENAME, &pszFileBuf);
    bail_on_error(err);

    if (strstr(pszFileBuf, pszFwRule) != NULL)
    {
        err = NM_ERR_VALUE_EXISTS;
        bail_on_error(err);
    }

    err = nm_string_to_line_array(pszFileBuf, &lineCount, &ppszLineBuf);
    bail_on_error(err);

    err = netmgr_alloc(strlen(pszFileBuf) + strlen(pszFwRule) + 4,
                       (void **)&pszNewFileBuf);
    bail_on_error(err);

    /* Append rule to end of file before the 'End' comment */
    for (i = 0; i < (lineCount - 1); i++)
    {
        strcat(pszNewFileBuf, ppszLineBuf[i]);
    }

    strcat(pszNewFileBuf, pszFwRule);
    strcat(pszNewFileBuf, "\n\n");
    strcat(pszNewFileBuf, ppszLineBuf[lineCount-1]);

    err = nm_atomic_file_update(FIREWALL_CONF_FILENAME, pszNewFileBuf);
    bail_on_error(err);

    err = nm_reload_firewall_config();
    bail_on_error(err);

clean:
    netmgr_free(pszFwRule);
    netmgr_free(pszFileBuf);
    netmgr_free(pszNewFileBuf);
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
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
    size_t i, lineCount = 0;
    char *pszFileBuf = NULL, *pszFwRule = NULL, **ppszLineBuf = NULL;
    char *p, *pszNewFileBuf = NULL;

    if ((pNetFwRule == NULL) || (pNetFwRule->type >= FW_RULE_TYPE_MAX))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (pNetFwRule->type != FW_RAW)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszFwRule, "iptables %s",
                                     pNetFwRule->pszRawFwRule);
    bail_on_error(err);

    err = nm_read_conf_file(FIREWALL_CONF_FILENAME, &pszFileBuf);
    bail_on_error(err);

    if (strcmp(pszFwRule, "iptables *") &&
        (strstr(pszFileBuf, pszFwRule) == NULL))
    {
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

    err = netmgr_alloc(strlen(pszFileBuf), (void **)&pszNewFileBuf);
    bail_on_error(err);

    err = nm_string_to_line_array(pszFileBuf, &lineCount, &ppszLineBuf);
    bail_on_error(err);

    /* Remove the matching rule from the file and the next empty line.
       If rule is '*' delete all rules.  */
    for (i = 0; i < lineCount; i++)
    {
        if ((!strcmp(pszFwRule, "iptables *") &&
            ((p = strstr(ppszLineBuf[i], "iptables")) == ppszLineBuf[i])) ||
            (strstr(ppszLineBuf[i], pszFwRule) != NULL))
        {
            netmgr_free(ppszLineBuf[i]);
            ppszLineBuf[i] = NULL;
            if (((i+1) < (lineCount-1)) && !strcmp(ppszLineBuf[i+1], "\n"))
            {
                i++;
                netmgr_free(ppszLineBuf[i]);
                ppszLineBuf[i] = NULL;
            }
            if (!strcmp(pszFwRule, "iptables *"))
            {
                continue;
            }
            break;
        }
    }

    for (i = 0; i < lineCount; i++)
    {
        if (ppszLineBuf[i] != NULL)
        {
            strcat(pszNewFileBuf, ppszLineBuf[i]);
        }
    }

    err = nm_atomic_file_update(FIREWALL_CONF_FILENAME, pszNewFileBuf);
    bail_on_error(err);

    err = nm_reload_firewall_config();
    bail_on_error(err);

clean:
    netmgr_free(pszFwRule);
    netmgr_free(pszFileBuf);
    netmgr_free(pszNewFileBuf);
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
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
    uint32_t err = 0;
    size_t i, j = 0, lineCount = 0, ruleCount = 0;
    char *p, *pszFileBuf = NULL, **ppszLineBuf = NULL;
    NET_FW_RULE **ppNetFwRules = NULL;

    if (!pCount || !pppNetFwRules)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_read_conf_file(FIREWALL_CONF_FILENAME, &pszFileBuf);
    bail_on_error(err);

    err = nm_string_to_line_array(pszFileBuf, &lineCount, &ppszLineBuf);
    bail_on_error(err);

    for (i = 0; i < lineCount; i++)
    {
        /* If line begins with iptables, add the rule */
        p = strstr(ppszLineBuf[i], "iptables");
        if ((p != NULL) && (p == ppszLineBuf[i]))
        {
            ruleCount++;
        }
    }

    err = netmgr_alloc(ruleCount * sizeof(NET_FW_RULE *),
                       (void **)&ppNetFwRules);
    bail_on_error(err);

    for (i = 0; i < lineCount; i++)
    {
        p = strstr(ppszLineBuf[i], "iptables");
        if ((p != NULL) && (p == ppszLineBuf[i]))
        {
            err = netmgr_alloc(sizeof(NET_FW_RULE),
                               (void **)&ppNetFwRules[j]);
            bail_on_error(err);
            ppNetFwRules[j]->type = FW_RAW;
            err = netmgr_alloc_string_len(ppszLineBuf[i],
                                          strlen(ppszLineBuf[i])-1,
                                          &ppNetFwRules[j]->pszRawFwRule);
            bail_on_error(err);
            j++;
        }
    }

    *pCount = ruleCount;
    *pppNetFwRules = ppNetFwRules;

clean:
    netmgr_free(pszFileBuf);
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
    return err;

error:
    if (pCount)
    {
        *pCount = 0;
    }
    if (pppNetFwRules)
    {
        *pppNetFwRules = NULL;
    }
    for (i = 0; i < ruleCount; i++)
    {
        if (ppNetFwRules[i] != NULL)
        {
            netmgr_free(ppNetFwRules[i]->pszRawFwRule);
            netmgr_free(ppNetFwRules[i]);
        }
    }
    netmgr_free(ppNetFwRules);
    goto clean;
}


/*
 * Misc APIs
 */
uint32_t
nm_set_hostname(
    const char *pszHostname
)
{
    uint32_t err = 0;
    char *pszCmd = NULL;

    if (IS_NULL_OR_EMPTY(pszHostname))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszCmd,
                                     "hostnamectl set-hostname %s",
                                     pszHostname);
    bail_on_error(err);

    err = nm_run_command(pszCmd);
    bail_on_error(err);

clean:
    netmgr_free(pszCmd);
    return err;
error:
    goto clean;
}

uint32_t
nm_get_hostname(
    char **ppszHostname
)
{
    uint32_t err = 0;
    char *pszHostname = NULL, *pszNewline = NULL;

    if (!ppszHostname)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = nm_read_conf_file(HOSTNAME_CONF_FILENAME, &pszHostname);
    bail_on_error(err);

    pszNewline = strchr(pszHostname, '\n');
    if (pszNewline != NULL)
    {
        *pszNewline = '\0';
    }

    *ppszHostname = pszHostname;

clean:
    return err;
error:
    if (ppszHostname)
    {
        ppszHostname = NULL;
    }
    netmgr_free(pszHostname);
    goto clean;
}

uint32_t
nm_wait_for_link_up(
    const char *pszInterfaceName,
    uint32_t timeout
)
{
    uint32_t err = 0;
    int sockFd = -1, retval = -1, linkUp = 0;
    fd_set readFd;
    char ifName[IFNAMSIZ];
    struct timeval tval, *pTval = NULL;
    struct ifinfomsg *pIfInfo = NULL;
    PNET_NETLINK_MESSAGE pNetLinkMsgList = NULL;
    PNET_NETLINK_MESSAGE pCurNetLinkMsgList = NULL;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    err = nm_get_link_state(pszInterfaceName, &linkState);
    bail_on_error(err);

    if (linkState == LINK_UP)
    {
        goto cleanup;
    }

    err = open_netlink_socket(RTMGRP_LINK, &sockFd);
    bail_on_error(err);

    if (timeout > 0)
    {
        tval.tv_sec = timeout;
        tval.tv_usec = 0;
        pTval = &tval;
    }

    while (1)
    {
        FD_ZERO(&readFd);
        FD_CLR(sockFd, &readFd);
        FD_SET(sockFd, &readFd);

        retval = select(sockFd+1, &readFd, NULL, NULL, pTval);
        if (retval == -1)
        {
            err = errno;
        }
        else if (retval)
        {
            err = handle_netlink_event(sockFd, &pNetLinkMsgList);
        }
        else
        {
            err = NM_ERR_TIME_OUT;
        }
        bail_on_error(err);

        pCurNetLinkMsgList = pNetLinkMsgList;
        while (pCurNetLinkMsgList)
        {
            if (pCurNetLinkMsgList->msgType != RTM_NEWLINK)
            {
                pCurNetLinkMsgList = pCurNetLinkMsgList->pNext;
            }
            memset(ifName, 0, sizeof(ifName));
            pIfInfo = pCurNetLinkMsgList->pMsg;
            if_indextoname(pIfInfo->ifi_index, ifName);
            if (!strcmp(pszInterfaceName, ifName) &&
                TEST_FLAG(pIfInfo->ifi_flags, IFF_UP))
            {
                linkUp = 1;
                break;
            }

            pCurNetLinkMsgList = pCurNetLinkMsgList->pNext;
        }

        if (linkUp)
        {
            break;
        }
        free_netlink_message_list(pNetLinkMsgList);
        pNetLinkMsgList = NULL;
    }

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    free_netlink_message_list(pNetLinkMsgList);
    return err;
error:
    goto cleanup;
}

static uint32_t
nm_validate_netlink_ipaddr(
    const char *pszInterfaceName,
    struct ifaddrmsg *pIfAddrMsg,
    int ifAddrMsgLen,
    uint32_t addrType)
{
    uint32_t err = 0, nlAddrType = 0;
    int ipAddrValid = 0;
    char szIpAddr[INET6_ADDRSTRLEN];
    char *pszIpAddrPrefix = NULL;
    struct rtattr *pRouteAttr = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName) || !pIfAddrMsg ||
        !ifAddrMsgLen || !addrType)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    pRouteAttr = IFA_RTA(pIfAddrMsg);
    for (;RTA_OK(pRouteAttr, ifAddrMsgLen);
         pRouteAttr = RTA_NEXT(pRouteAttr, ifAddrMsgLen))
    {
        if (pRouteAttr->rta_type != IFA_LOCAL &&
            pRouteAttr->rta_type != IFA_ADDRESS)
        {
            continue;
        }
        nlAddrType = 0;

        if (inet_ntop(pIfAddrMsg->ifa_family, RTA_DATA(pRouteAttr), szIpAddr,
                      sizeof(szIpAddr)) == NULL)
        {
            err = errno;
            bail_on_error(err);
        }

        err = netmgr_alloc_string_printf(&pszIpAddrPrefix, "%s/%u",
                                         szIpAddr, pIfAddrMsg->ifa_prefixlen);
        bail_on_error(err);

        err = nm_get_ip_addr_type(pszInterfaceName,
                                  pszIpAddrPrefix,
                                  &nlAddrType);
        bail_on_error(err);

        if (TEST_FLAG(addrType, nlAddrType))
        {
            ipAddrValid = 1;
            break;
        }

        netmgr_free(pszIpAddrPrefix);
        pszIpAddrPrefix = NULL;
    }

    if (!ipAddrValid)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
    }

cleanup:
    netmgr_free(pszIpAddrPrefix);
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
    uint32_t err = 0, netLinkGroups = 0, ip4Type = 0, ip6Type = 0;
    int sockFd = -1, retval = -1, ipAddrValid = 0;
    int ifAddrMsgLen = 0;
    size_t i = 0, ipCount = 0;
    fd_set readFd;
    struct timeval tval, *pTval = NULL;
    struct ifaddrmsg *pIfAddr = NULL;
    char ifName[IFNAMSIZ];
    char **ppszIpAddrList = NULL;
    NET_ADDR_TYPE ipAddrType = 0;
    PNET_NETLINK_MESSAGE pNetLinkMsgList = NULL;
    PNET_NETLINK_MESSAGE pCurNetLinkMsgList = NULL;

    if (!IS_VALID_INTERFACE_NAME(pszInterfaceName))
    {
        err = NM_ERR_INVALID_INTERFACE;
        bail_on_error(err);
    }

    /* addrTypes = 0 implies no action is needed */
    if (!addrTypes)
    {
        goto cleanup;
    }

    err = nm_get_interface_ipaddr(pszInterfaceName,
                                  addrTypes,
                                  &ipCount,
                                  &ppszIpAddrList);
    if (err == NM_ERR_VALUE_NOT_FOUND)
    {
        err = 0;
    }
    bail_on_error(err);

    for (i = 0; i < ipCount; i++)
    {
        err = nm_get_ip_addr_type(pszInterfaceName,
                                  ppszIpAddrList[i],
                                  &ipAddrType);
        if (TEST_FLAG(addrTypes, ipAddrType))
        {
            goto cleanup;
        }
    }

    if (TEST_FLAG(addrTypes, STATIC_IPV4) || TEST_FLAG(addrTypes, DHCP_IPV4))
    {
        ip4Type = 1;
        netLinkGroups = RTMGRP_IPV4_IFADDR;
    }

    if (TEST_FLAG(addrTypes, STATIC_IPV6) || TEST_FLAG(addrTypes, DHCP_IPV6) ||
        TEST_FLAG(addrTypes, AUTO_IPV6) || TEST_FLAG(addrTypes, LINK_LOCAL_IPV6))
    {
        ip6Type = 1;
        netLinkGroups |= RTMGRP_IPV6_IFADDR;
    }

    err = open_netlink_socket(netLinkGroups, &sockFd);
    bail_on_error(err);

    if (timeout > 0)
    {
        tval.tv_sec = timeout;
        tval.tv_usec = 0;
        pTval = &tval;
    }

    while (1)
    {
        FD_ZERO(&readFd);
        FD_CLR(sockFd, &readFd);
        FD_SET(sockFd, &readFd);

        retval = select(sockFd+1, &readFd, NULL, NULL, pTval);
        if (retval == -1)
        {
            err = errno;
        }
        else if (retval)
        {
            err = handle_netlink_event(sockFd, &pNetLinkMsgList);
        }
        else
        {
            if (TEST_FLAG(addrTypes, DHCP_IPV4) || TEST_FLAG(addrTypes, DHCP_IPV6))
            {
                err = NM_ERR_DHCP_TIME_OUT;
            }
            else
            {
                err = NM_ERR_TIME_OUT;
            }
        }
        bail_on_error(err);

        pCurNetLinkMsgList = pNetLinkMsgList;
        while (pCurNetLinkMsgList)
        {
            if (pCurNetLinkMsgList->msgType != RTM_NEWADDR)
            {
                pCurNetLinkMsgList = pCurNetLinkMsgList->pNext;
                continue;
            }
            memset(ifName, 0, sizeof(ifName));
            pIfAddr = pCurNetLinkMsgList->pMsg;
            ifAddrMsgLen = pCurNetLinkMsgList->msgLen;
            if_indextoname(pIfAddr->ifa_index, ifName);

            if ((strcmp(pszInterfaceName, ifName) != 0) ||
                !((ip4Type && (pIfAddr->ifa_family == AF_INET)) ||
                (ip6Type && (pIfAddr->ifa_family == AF_INET6))))
            {
                pCurNetLinkMsgList = pCurNetLinkMsgList->pNext;
                continue;
            }

            err = nm_validate_netlink_ipaddr(pszInterfaceName,
                                             pIfAddr,
                                             ifAddrMsgLen,
                                             addrTypes);
            if (err == 0)
            {
                ipAddrValid = 1;
                break;
            }
            if (err == NM_ERR_VALUE_NOT_FOUND)
            {
                err = 0;
            }
            bail_on_error(err);

            pCurNetLinkMsgList = pCurNetLinkMsgList->pNext;
        }
        if (ipAddrValid)
        {
            break;
        }
        free_netlink_message_list(pNetLinkMsgList);
        pNetLinkMsgList = NULL;
    }

cleanup:
    if (sockFd > -1)
    {
        close(sockFd);
    }
    free_netlink_message_list(pNetLinkMsgList);
    netmgr_list_free(ipCount, (void **)ppszIpAddrList);
    return err;

error:
    goto cleanup;
}

uint32_t
nm_set_network_param(
    const char *pszObjectName,
    const char *pszParamName,
    const char *pszParamValue
)
{
    uint32_t err = 0;
    struct stat fs = {0};
    char *pszCfgFileName = NULL;
    char *pszParam = NULL, *pszParamPtr = NULL;
    char *pszSectionName = NULL, *pszKeyName = NULL;
    char op = 's';

    if (IS_NULL_OR_EMPTY(pszObjectName) || IS_NULL_OR_EMPTY(pszParamName))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (stat(pszObjectName, &fs) != 0)
    {
        /* Assume pszObjectName is interface name */
        err = nm_get_network_conf_filename(pszObjectName, &pszCfgFileName);
        bail_on_error(err);
    }
    else
    {
        /* Check if pszObjectName is a regular file */
        if (TEST_FLAG(fs.st_mode, S_IFREG))
        {
            err = netmgr_alloc_string(pszObjectName, &pszCfgFileName);
        }
        else
        {
            err = NM_ERR_INVALID_PARAMETER;
        }
        bail_on_error(err);
    }

    if ((pszParamName[0] == '+') || (pszParamName[0] == '-'))
    {
        op = pszParamName[0];
        pszParamName++;
    }

    err = netmgr_alloc_string(pszParamName, &pszParam);
    bail_on_error(err);

    pszParamPtr = pszParam;
    pszSectionName = strsep(&pszParam, SECTION_KEY_DELIM);
    if (pszSectionName == NULL)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }
    pszKeyName = pszParam;

    switch (op)
    {
        case '+':
            err = nm_add_key_value(pszCfgFileName,
                                   pszSectionName,
                                   pszKeyName,
                                   pszParamValue,
                                   0);
            bail_on_error(err);
            break;
        case '-':
            err = nm_delete_key_value(pszCfgFileName,
                                      pszSectionName,
                                      pszKeyName,
                                      pszParamValue,
                                      0);
            bail_on_error(err);
            break;
        default:
            err = nm_set_key_value(pszCfgFileName,
                                   pszSectionName,
                                   pszKeyName,
                                   pszParamValue,
                                   0);
            bail_on_error(err);
    }

cleanup:
    netmgr_free(pszParamPtr);
    netmgr_free(pszCfgFileName);
    return err;
error:
    goto cleanup;
}

uint32_t
nm_get_network_param(
    const char *pszObjectName,
    const char *pszParamName,
    char **ppszParamValue
)
{
    uint32_t err = 0;
    struct stat fs = {0};
    char *pszCfgFileName = NULL;
    char *pszParam = NULL, *pszParamPtr = NULL;
    char *pszSectionName = NULL, *pszKeyName = NULL, *pszParamValue = NULL;

    if (IS_NULL_OR_EMPTY(pszObjectName) ||
        IS_NULL_OR_EMPTY(pszParamName) ||
        !ppszParamValue)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    if (stat(pszObjectName, &fs) != 0)
    {
        /* Assume pszObjectName is interface name */
        err = nm_get_network_conf_filename(pszObjectName, &pszCfgFileName);
        bail_on_error(err);
    }
    else
    {
        /* Check if pszObjectName is a regular file */
        if (TEST_FLAG(fs.st_mode, S_IFREG))
        {
            err = netmgr_alloc_string(pszObjectName, &pszCfgFileName);
        }
        else
        {
            err = NM_ERR_INVALID_PARAMETER;
        }
        bail_on_error(err);
    }

    err = netmgr_alloc_string(pszParamName, &pszParam);
    bail_on_error(err);

    pszParamPtr = pszParam;
    pszSectionName = strsep(&pszParam, SECTION_KEY_DELIM);
    if (pszSectionName == NULL)
    {
        err = NM_ERR_INVALID_PARAMETER;
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

uint32_t
nm_reload_firewall_config()
{
    uint32_t err = 0;

    err = nm_run_command(FIREWALL_CONF_FILENAME);
    bail_on_error(err);

clean:
    return err;
error:
    goto clean;
}
