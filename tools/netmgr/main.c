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

int main(int argc, char* argv[])
{
    uint32_t err = 0;
    PNETMGR_CMD_ARGS pCmdArgs = NULL;
    NETMGR_CLI_CMD_MAP arCmdMap[] =
    {
        {"help",    cmd_help},
        {"ifup",    cmd_ifup},
        {"ifdown",  cmd_ifdown},
        {"list",    cmd_list},
    };

    int nCommandCount = sizeof(arCmdMap)/sizeof(NETMGR_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;

    err = parse_args(argc, argv, &pCmdArgs);
    bail_on_error(err);

    //If --version, show version and exit
    if(pCmdArgs->nVersion)
    {
        show_version();
    }
    else if(pCmdArgs->nHelp)
    {
        cmd_help(pCmdArgs);
    }
    else if(pCmdArgs->nCmdCount > 0)
    {
        pszCmd = pCmdArgs->ppszCmds[0];
        while(nCommandCount--)
        {
            if(!strcmp(pszCmd, arCmdMap[nCommandCount].pszCmdName))
            {
                err = arCmdMap[nCommandCount].pFnCmd(pCmdArgs);
                bail_on_error(err);
                nFound = 0;
                break;
            }
        }
        if(!nFound)
        {
            err = 1;
            bail_on_error(err);
        }
    }
    else
    {
        cmd_help(pCmdArgs);
    }

cleanup:
    return err;
error:
    goto cleanup;
}

void
show_version(
    )
{
    fprintf(stdout, "%s: %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

uint32_t
cmd_help(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    fprintf(stdout, "Usage: netmgr [options] command\n");
    fprintf(stdout, "\n");

    fprintf(stdout, "List of commands\n");
    fprintf(stdout, "\n");

    fprintf(stdout, "help\tshows this message\n");
    fprintf(stdout, "ifup <interfacename>\tbring up the specified interface if it is currently down.\n");
    fprintf(stdout, "ifdown <interfacename>\tbring down the specified interface if it is currently up.\n");
    fprintf(stdout, "list\tshows list of available interfaces. use -6 to show ipv6 only\n");

    return 0;
}

uint32_t
cmd_ifdown(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        err = EDOM;
        bail_on_error(err);
    }

    err = ifdown(pCmdArgs->ppszCmds[1]);
    bail_on_error(err);

cleanup:
    return err;
error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "ifdown requires interface name or names as argument\n");
    }
    goto cleanup;
}

uint32_t
cmd_ifup(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        err = EDOM;
        bail_on_error(err);
    }

    err = ifup(pCmdArgs->ppszCmds[1]);
    bail_on_error(err);

cleanup:
    return err;
error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "ifup requires interface name or names as argument\n");
    }
    goto cleanup;
}

uint32_t
cmd_list(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;
    int nFamily = PF_INET;

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    if(pCmdArgs->nIPv6)
    {
        nFamily = PF_INET6;
    }

    err = enum_interfaces(nFamily);
    bail_on_error(err);

cleanup:
    return err;
error:
    goto cleanup;
}
