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
get_ipaddr_prefix(
    struct sockaddr *sin,
    uint8_t *prefix
)
{
    uint32_t err = 0;
    int i = 0;
    unsigned char l;
    uint8_t numBitsSet = 0;

    if (!sin || ((sin->sa_family != AF_INET) && (sin->sa_family != AF_INET6)) ||
        !prefix)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    for(i = 0; i < 14; i++)
    {
        l = sin->sa_data[i];
        while (l)
        {
            numBitsSet++;
            l = l >> 1 ;
        }
    }

    *prefix = numBitsSet;

cleanup:
    return err;

error:
    goto cleanup;
}

