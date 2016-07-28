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

typedef struct _NETMGR_CMD_ARGS
{
    //options
    int nIPv4;
    int nIPv6;
    int nVersion;
    int nHelp;
    int nVerbose;
    //command args
    char** ppszCmds;
    int nCmdCount;
    int argc;
    char **argv;
}NETMGR_CMD_ARGS, *PNETMGR_CMD_ARGS;

//Map command name to client function
typedef struct _NETMGR_CLI_CMD_MAP
{
    char* pszCmdName;
    uint32_t (*pFnCmd)(PNETMGR_CMD_ARGS);
    char* pszParams;
    char* pszHelpMessage;
}NETMGR_CLI_CMD_MAP, *PNETMGR_CLI_CMD_MAP;

#ifdef __cplusplus
}
#endif
