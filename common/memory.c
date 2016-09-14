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
netmgr_alloc(
    size_t size,
    void** ppMemory
    )
{
    uint32_t err = 0;
    void* pMemory = NULL;

    if (!ppMemory || size <= 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    pMemory = calloc(1, size);
    if (!pMemory)
    {
        err = ENOMEM;
        bail_on_error(err);
    }

    *ppMemory = pMemory;

cleanup:

    return err;

error:

    if (ppMemory)
    {
        *ppMemory = NULL;
    }

    goto cleanup;
}

uint32_t
netmgr_alloc_string(
    const char* pszSrc,
    char**      ppszDst
    )
{
    uint32_t err = 0;
    char* pszDst = NULL;
    size_t len = 0;

    if (!pszSrc || !ppszDst)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    len = strlen(pszSrc);

    err = netmgr_alloc(len+1, (void*)&pszDst);
    bail_on_error(err);

    if (len)
    {
        memcpy(pszDst, pszSrc, len);
    }

    *ppszDst = pszDst;

cleanup:

    return err;

error:

    if (ppszDst)
    {
        *ppszDst = NULL;
    }
    if (pszDst)
    {
        netmgr_free(pszDst);
    }
    goto cleanup;
}

uint32_t
netmgr_alloc_string_len(
    const char* pszSrc,
    size_t      len,
    char**      ppszDst
    )
{
    uint32_t err = 0;
    char* pszDst = NULL;

    if (!pszSrc || !ppszDst)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(len+1, (void*)&pszDst);
    bail_on_error(err);

    if (len)
    {
        memcpy(pszDst, pszSrc, len);
    }

    *ppszDst = pszDst;

cleanup:

    return err;

error:

    if (ppszDst)
    {
        *ppszDst = NULL;
    }
    if (pszDst)
    {
        netmgr_free(pszDst);
    }

    goto cleanup;
}

uint32_t
netmgr_alloc_string_printf(
    char** ppszDst,
    const char* pszFmt,
    ...
    )
{
    uint32_t err = 0;
    size_t nSize = 0;
    char* pszDst = NULL;
    char chDstTest = '\0';
    va_list argList;

    if(!ppszDst || !pszFmt)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    //Find size
    va_start(argList, pszFmt);
    nSize = vsnprintf(&chDstTest, 1, pszFmt, argList);
    va_end(argList);

    if(nSize <= 0)
    {
        err = errno;
        bail_on_error(err);
    }
    nSize = nSize + 1;

    err = netmgr_alloc(nSize, (void**)&pszDst);
    bail_on_error(err);

    va_start(argList, pszFmt);
    nSize = vsnprintf(pszDst, nSize, pszFmt, argList);
    va_end(argList);

    if(nSize <= 0)
    {
        err = errno;
        bail_on_error(err);
    }
    *ppszDst = pszDst;

cleanup:
    return err;

error:
    if(ppszDst)
    {
        *ppszDst = NULL;
    }
    netmgr_free(pszDst);
    goto cleanup;
}

void
netmgr_free(
    void* pMemory
    )
{
    if (pMemory)
    {
        free(pMemory);
    }
}

void
netmgr_list_free(
    size_t count,
    void **ppMemory
    )
{
    size_t i;

    if (ppMemory != NULL)
    {
        for (i = 0; i < count; i++)
        {
            if (ppMemory[i] != NULL)
            {
                netmgr_free(ppMemory[i]);
            }
        }
        netmgr_free(ppMemory);
    }
}

