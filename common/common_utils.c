/*
 * Copyright © 2016 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the ?~@~\License?~@~]); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ?~@~\AS IS?~@~] BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "includes.h"

uint32_t
is_ipv4_addr(const char *pszIpAddr)
{
    struct sockaddr_in sa;
    return (inet_pton(AF_INET, pszIpAddr, &(sa.sin_addr)) != 0);
}

uint32_t
is_ipv6_addr(const char *pszIpAddr)
{
    struct sockaddr_in6 sa;
    return (inet_pton(AF_INET6, pszIpAddr, &(sa.sin6_addr)) != 0);
}

uint32_t
get_prefix_from_netmask(
    struct sockaddr *pSockAddr,
    uint8_t *pPrefix
)
{
    uint32_t err = 0;
    size_t i = 0;
    unsigned char byte;
    uint8_t numBitsSet = 0;

    if (!pSockAddr || ((pSockAddr->sa_family != AF_INET) &&
        (pSockAddr->sa_family != AF_INET6)) ||
        !pPrefix)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    for (i = 0; i < 14; i++)
    {
        byte = pSockAddr->sa_data[i];
        while (byte)
        {
            if ((byte & 0x01))
            {
                numBitsSet++;
            }
            byte = byte >> 1 ;
        }
    }

    *pPrefix = numBitsSet;

cleanup:
    return err;

error:
    goto cleanup;
}

