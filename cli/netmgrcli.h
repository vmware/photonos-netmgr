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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _CMD_OP
{
    OP_INVALID = 0,
    OP_GET,
    OP_SET,
    OP_ADD,
    OP_DEL,
    OP_MAX
} CMD_OP;

/* command option key-value pair */
typedef struct _OPTIONKV
{
    struct _OPTIONKV *pNext;
    char *pszKey;
    char *pszValue;
} OPTIONKV, *POPTIONKV;

typedef struct _NETMGR_CMD
{
    struct _NETMGR_CMD *pNext;
    char *pszCmd;
    CMD_OP op;
    POPTIONKV pCmdOpt;
} NETMGR_CMD, *PNETMGR_CMD;


uint32_t
netmgrcli_parse_cmdline(
    int argc,
    char** argv,
    PNETMGR_CMD *ppCmd
);

void
netmgrcli_free_cmd(
    PNETMGR_CMD pCmd
);

uint32_t
netmgrcli_find_cmdopt(
    PNETMGR_CMD pCmd,
    char *optName,
    char **optValue
);

#ifdef __cplusplus
}
#endif
