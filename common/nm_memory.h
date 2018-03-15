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

// memory.c

#define IS_NULL_OR_EMPTY(_pstr)  (!(_pstr) || !(*(_pstr)))

uint32_t
netmgr_alloc(
    size_t size,
    void** pMemory
    );

uint32_t
netmgr_alloc_string(
    const char* pszSrc,
    char**      ppszDst
    );

uint32_t
netmgr_alloc_string_len(
    const char* pszSrc,
    size_t      len,
    char**      ppszDst
    );

uint32_t
netmgr_alloc_string_printf(
    char** ppszDst,
    const char* pszFmt,
    ...
    );

void
netmgr_free(
    void* pMemory
    );

void
netmgr_list_free(
    size_t count,
    void **ppMemory
    );
