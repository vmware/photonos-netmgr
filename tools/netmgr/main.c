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

//name of command,
//pointer to command invoke
//parameters if any
//help message
NETMGR_CLI_CMD_MAP arCmdMap[] =
{
    {"help",
     cmd_help,
     "",
     "show this message"
    },
    {"ifup",
     cmd_ifup,
     "<interfacename>",
     "bring up the specified interface if it is currently down."
    },
    {"ifdown",
     cmd_ifdown,
     "<interfacename>",
     "bring down the specified interface if it is currently up."
    },
    {"list",
     cmd_list,
     "-4 or -6",
     "shows list of available interfaces. -4 is the default"
    },
    {"set_iaid",
     cmd_set_iaid,
     "<interfacename> <IAID>",
     "set IAID"
    },
    {"get_iaid",
     cmd_get_iaid,
     "<interfacename>",
     "get IAID"
    },
    {"set_duid",
     cmd_set_duid,
     "<interfacename> <DUID>",
     "set DUID"
    },
    {"get_duid",
     cmd_get_duid,
     "<interfacename>",
     "get DUID"
    },
    {"set_dns_servers_v0",
     cmd_set_dns_servers_v0,
     "<dns servers list>",
     "set dns servers"
    },
    {"set_dns_servers",
     cmd_set_dns_servers,
     "<DNS mode> <dns servers list>",
     "set dns mode and servers list"
    },
    {"get_dns_servers",
     cmd_get_dns_servers,
     "",
     "get dns mode and servers list"
    },
};

int main(int argc, char* argv[])
{
    uint32_t err = 0;
    PNETMGR_CMD_ARGS pCmdArgs = NULL;

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
                nFound = 1;
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
    if(pCmdArgs)
    {
        free_cmd_args(pCmdArgs);
    }
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
    int i = 0;
    int nCommandCount = sizeof(arCmdMap)/sizeof(NETMGR_CLI_CMD_MAP);
    fprintf(stdout, "Usage: netmgr [options] command\n");
    fprintf(stdout, "\n");

    fprintf(stdout, "List of commands\n");
    fprintf(stdout, "\n");

    for(i = 0; i < nCommandCount; ++i)
    {
        fprintf(stdout,
                "%s %s\t%s\n",
                arCmdMap[i].pszCmdName,
                arCmdMap[i].pszParams,
                arCmdMap[i].pszHelpMessage);
    }

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
    PNETMGR_INTERFACE pInterface = NULL;
    PNETMGR_INTERFACE pCurrent = NULL;

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }
    if(pCmdArgs->nIPv6)
    {
        nFamily = PF_INET6;
    }

    err = enum_interfaces(nFamily, &pInterface);
    bail_on_error(err);

    pCurrent = pInterface;
    while(pCurrent)
    {
        fprintf(stdout, "%s\n", pCurrent->pszName);
        pCurrent = pCurrent->pNext;
    }

cleanup:
    if(pInterface)
    {
        free_interface(pInterface);
    }
    return err;
error:
    goto cleanup;
}

uint32_t
cmd_set_iaid(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if(pCmdArgs->nCmdCount < 3)
    {
        err = EDOM;
        bail_on_error(err);
    }

    err = set_iaid(pCmdArgs->ppszCmds[1], (uint32_t)atoi(pCmdArgs->ppszCmds[2]));
    bail_on_error(err);

cleanup:
    return err;

error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "Usage: set_iaid <ifname> <iaid>\n");
    }
    goto cleanup;
}

uint32_t
cmd_get_iaid(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0, iaid;

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

    err = get_iaid(pCmdArgs->ppszCmds[1], &iaid);
    bail_on_error(err);

    fprintf(stdout, "IAID=%u\n", iaid);

cleanup:
    return err;

error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "Usage: get_iaid <ifname>\n");
    }
    goto cleanup;
}

uint32_t
cmd_set_duid(
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

    err = set_duid(NULL, pCmdArgs->ppszCmds[1]);
    bail_on_error(err);

cleanup:
    return err;

error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "Usage: set_duid <duid>\n");
    }
    goto cleanup;
}

uint32_t
cmd_get_duid(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;
    char *duid = NULL;

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if(pCmdArgs->nCmdCount < 1)
    {
        err = EDOM;
        bail_on_error(err);
    }

    err = get_duid(NULL, &duid);
    bail_on_error(err);

    fprintf(stdout, "DUID=%s\n", duid);

cleanup:
    if (duid != NULL)
    {
        netmgr_free(duid);
    }
    return err;

error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "Usage: get_duid\n");
    }
    goto cleanup;
}

uint32_t
cmd_set_dns_servers_v0(
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

    err = set_dns_servers_v0(NULL, pCmdArgs->ppszCmds[1]);
    bail_on_error(err);

cleanup:
    return err;

error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "Usage: set_dns_servers_v0 <dns server list>\n");
    }
    goto cleanup;
}

uint32_t
cmd_set_dns_servers(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;
    size_t i = 0, count = 0;
    NET_DNS_MODE mode;
    char *s1, *s2, **szDnsServersList = NULL;
    char szDnsServers[1024];

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if(pCmdArgs->nCmdCount < 3)
    {
        err = EDOM;
        bail_on_error(err);
    }

    if (!strcmp(pCmdArgs->ppszCmds[1], "dhcp"))
    {
        mode = DHCP_DNS;
    }
    else if (!strcmp(pCmdArgs->ppszCmds[1], "static"))
    {
        mode = STATIC_DNS;
    }
    else
    {
        err = EINVAL;
        bail_on_error(err);
    }

    strcpy(szDnsServers, pCmdArgs->ppszCmds[2]);
    if (strlen(szDnsServers) > 0)
    {
        s2 = pCmdArgs->ppszCmds[2];
        do {
            s1 = strsep(&s2, " ");
            if (strlen(s1) > 0)
            {
                count++;
            }
        } while (s2 != NULL);
    }

    if (count > 0)
    {
        err = netmgr_alloc((count * sizeof(char *)), (void *)&szDnsServersList);
        bail_on_error(err);

        s2 = szDnsServers;
        do {
            s1 = strsep(&s2, " ");
            if (strlen(s1) > 0)
            {
                err = netmgr_alloc_string(s1, &(szDnsServersList[i++]));
                bail_on_error(err);
            }
        } while (s2 != NULL);
    }

    err = set_dns_servers(NULL, mode, count, (const char **)szDnsServersList, 0);
    bail_on_error(err);

cleanup:
    /* Free allocated memory */
    if (szDnsServersList != NULL)
    {
        for (i = 0; i < count; i++)
        {
            if (szDnsServersList[i] != NULL)
            {
                netmgr_free(szDnsServersList[i]);
            }
        }
        netmgr_free(szDnsServersList);
    }
    return err;

error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "Usage: set_dns_servers <dns mode> <dns server list>\n");
    }
    goto cleanup;
}

uint32_t
cmd_get_dns_servers(
    PNETMGR_CMD_ARGS pCmdArgs
    )
{
    uint32_t err = 0;
    NET_DNS_MODE mode;
    size_t i, count;
    char **dnsServers;

    if(!pCmdArgs)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if(pCmdArgs->nCmdCount < 1)
    {
        err = EDOM;
        bail_on_error(err);
    }

    err = get_dns_servers(NULL, 0, &mode, &count, &dnsServers);
    bail_on_error(err);

    if (mode == STATIC_DNS)
    {
        fprintf(stdout, "DNSMode=static\n");
    }
    else
    {
        fprintf(stdout, "DNSMode=dhcp\n");
    }

    fprintf(stdout, "DNSServers=");
    for (i = 0; i < count; i++)
    {
        fprintf(stdout, "%s ", dnsServers[i]);
        netmgr_free(dnsServers[i]);
    }
    netmgr_free(dnsServers);
    fprintf(stdout, "\n");

cleanup:
    return err;

error:
    if(err == EDOM)
    {
        fprintf(
               stderr,
               "Usage: get_dns_servers\n");
    }
    goto cleanup;
}

