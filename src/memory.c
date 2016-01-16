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
ini_cfg_alloc(
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
ini_cfg_alloc_string(
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

    err = ini_cfg_alloc(len+1, (void*)&pszDst);
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
        ini_cfg_free(pszDst);
    }
    goto cleanup;
}

uint32_t
ini_cfg_alloc_string_len(
    const char* pszSrc,
    size_t      len,
    char**      ppszDst
    )
{
    uint32_t err = 0;
    char* pszDst = NULL;

    if (!pszSrc || !ppszDst || len < 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = ini_cfg_alloc(len+1, (void*)&pszDst);
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
        ini_cfg_free(pszDst);
    }

    goto cleanup;
}

void
ini_cfg_free(
    void* pMemory
    )
{
    if (pMemory)
    {
        free(pMemory);
    }
}

