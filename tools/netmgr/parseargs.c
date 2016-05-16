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

static NETMGR_CMD_ARGS _opt = {0};

//options - incomplete
static struct option pstOptions[] =
{
    {"help",          no_argument, 0, 'h'},                //-h --help
    {"version",       no_argument, &_opt.nVersion, 1},     //--version
    {"verbose",       no_argument, 0, 'v'},                //-v --verbose
    {"4",             no_argument, 0, '4'},                //-4 IPv4 only
    {"6",             no_argument, 0, '6'},                //-6 IPv6 only
    {0, 0, 0, 0}

};

uint32_t
parse_args(
    int argc,
    char** argv,
    PNETMGR_CMD_ARGS* ppCmdArgs
    )
{
    uint32_t err = 0;
    int nOptionIndex = 0;
    int nOption = 0;
    int nIndex = 0;

    PNETMGR_CMD_ARGS pCmdArgs = NULL;

    if(argc == 0 || !argv || !ppCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(NETMGR_CMD_ARGS), (void*)&pCmdArgs);
    bail_on_error(err);

    opterr = 0;//tell getopt to not print errors
    while (1)
    {

        nOption = getopt_long (
                       argc,
                       argv,
                       "46hv",
                       pstOptions,
                       &nOptionIndex);
        if (nOption == -1)
            break;

        switch(nOption)
        {
            case '4':
                _opt.nIPv4 = 1;
            break;
            case '6':
                _opt.nIPv6 = 1;
            break;
            case 'h':
                _opt.nHelp = 1;
            break;
            case 'v':
                _opt.nVerbose= 1;
            break;
            case '?':
                fprintf(stderr, "no such command or option\n");
                err = 1;
                bail_on_error(err);
        }
    }
    err = copy_cmd_args(&_opt, pCmdArgs);
    bail_on_error(err);

    //Collect extra args
    if (optind < argc)
    {
        pCmdArgs->nCmdCount = argc-optind;
        err = netmgr_alloc(
                  sizeof(char*) * pCmdArgs->nCmdCount,
                  (void**)&pCmdArgs->ppszCmds);
        bail_on_error(err);

        while (optind < argc)
        {
            err = netmgr_alloc_string(
                      argv[optind++],
                      &pCmdArgs->ppszCmds[nIndex++]);
            bail_on_error(err);
        }
    }

    *ppCmdArgs = pCmdArgs;

cleanup:
    return err;
error:
    if(ppCmdArgs)
    {
        *ppCmdArgs = NULL;
    }
    if(pCmdArgs)
    {
        free_cmd_args(pCmdArgs);
    }
    
    goto cleanup;
}

uint32_t
copy_cmd_args(
    PNETMGR_CMD_ARGS pOptions,
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;
    if(!pOptions || !pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    pCmdArgs->nIPv4 = pOptions->nIPv4;
    pCmdArgs->nIPv6 = pOptions->nIPv6;
    pCmdArgs->nVerbose = pOptions->nVerbose;
    pCmdArgs->nVersion = pOptions->nVersion;
    pCmdArgs->nHelp = pOptions->nHelp;

cleanup:
    return err;
error:
    goto cleanup;
}

void
free_cmd_args(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    if(pCmdArgs)
    {
        int i = 0;
        for(i = 0; i < pCmdArgs->nCmdCount; ++i)
        {
            if(pCmdArgs->ppszCmds[i])
            {
                netmgr_free(pCmdArgs->ppszCmds[i]);
            }
        }
        if(pCmdArgs->ppszCmds)
        {
            netmgr_free(pCmdArgs->ppszCmds);
        }
        netmgr_free(pCmdArgs);
    }
}
