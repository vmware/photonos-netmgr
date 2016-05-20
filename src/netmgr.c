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
set_iaid(
    const char *pszInterfaceName,
    const uint32_t iaid
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    const char szSectionName[] = "Link";
    const char szKey[] = "IAID";
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
        err = set_key_value(cfgFileName, szSectionName, szKey, szValue, 0);
    }
    else
    {
        err = set_key_value(cfgFileName, szSectionName, szKey, NULL, 0);
    }

    bail_on_error(err);

error:
    return err;
}

int
get_iaid(
    const char *pszInterfaceName,
    uint32_t *iaid
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    const char szSectionName[] = "Link";
    const char szKey[] = "IAID";
    char szIaid[MAX_LINE];

    if (!pszInterfaceName)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    sprintf(cfgFileName, "%s10-%s.network", SYSTEMD_NET_PATH, pszInterfaceName);

    err = get_key_value(cfgFileName, szSectionName, szKey, szIaid);
    bail_on_error(err);

    sscanf(szIaid, "%u", iaid);

error:
    return err;
}

int
set_duid(
    const char *pszInterfaceName,
    const char *pszDuid
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    const char szSectionName[] = "DUID";
    const char szKey[] = "RawData";

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

    if (strlen(pszDuid) == 0)
    {
        err = set_key_value(cfgFileName, szSectionName, szKey, NULL, 0);
    }
    else
    {
        err = set_key_value(cfgFileName, szSectionName, szKey, pszDuid, 0);
    }
    bail_on_error(err);

error:
    return err;
}

int
get_duid(
    const char *pszInterfaceName,
    char *pszDuid
)
{

    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    const char szSectionName[] = "DUID";
    const char szKey[] = "RawData";

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

    err = get_key_value(cfgFileName, szSectionName, szKey, pszDuid);
    bail_on_error(err);

error:
    return err;
}

int
set_dns_servers(
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

    if (strlen(pszDnsServers) == 0)
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

int
get_dns_servers(
    const char *pszInterfaceName,
    char *pszDnsServers
)
{
    uint32_t err = 0;
    char cfgFileName[MAX_LINE];
    char szSectionName[MAX_LINE];
    char szKey[MAX_LINE] = "DNS";

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

    err = get_key_value(cfgFileName, szSectionName, szKey, pszDnsServers);
    bail_on_error(err);

error:
    return err;
}
