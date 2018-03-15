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

#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#define MAX_DUID_SIZE                  128
#define DEFAULT_MTU_VALUE              1500
#define DEFAULT_WAIT_FOR_IP_TIMEOUT    30

typedef enum DUIDType {
    _DUID_TYPE_MIN      = 0,
    DUID_TYPE_LLT       = 1,
    DUID_TYPE_EN        = 2,
    DUID_TYPE_LL        = 3,
    DUID_TYPE_UUID      = 4,
    _DUID_TYPE_MAX,
} DUIDType;

static const char* const duid_type_table[_DUID_TYPE_MAX] = {
    [DUID_TYPE_LLT]  = "link-layer-time",
    [DUID_TYPE_EN]   = "vendor",
    [DUID_TYPE_LL]   = "link-layer",
    [DUID_TYPE_UUID] = "uuid",
};

#endif /* __CONSTANTS_H__ */


