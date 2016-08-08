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

static uint32_t
cmd_dhcp_duid(PNETMGR_CMD pCmd)
{
    uint32_t err = 0;
    char *pszIfname = NULL, *pszDuid = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    if (pCmd->op == OP_SET)
    {
        err = netmgrcli_find_cmdopt(pCmd, "duid", &pszDuid);
        bail_on_error(err);

        err = set_duid(pszIfname, pszDuid);
        pszDuid = NULL;
        bail_on_error(err);
    }

    if (pCmd->op == OP_GET)
    {
        err = get_duid(pszIfname, &pszDuid);
        bail_on_error(err);

        fprintf(stdout, "DUID=%s\n", pszDuid);
    }

cleanup:
    /* Free allocated memory */
    netmgr_free(pszDuid);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_if_iaid(PNETMGR_CMD pCmd)
{
    uint32_t err = 0, iaid = 0;
    char *pszIfname = NULL, *pszIaid = NULL;

    err = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
    bail_on_error(err);

    if (pCmd->op == OP_SET)
    {
        err = netmgrcli_find_cmdopt(pCmd, "iaid", &pszIaid);
        bail_on_error(err);

        err = set_iaid(pszIfname, (uint32_t)atoi(pszIaid));
        bail_on_error(err);
    }

    if (pCmd->op == OP_GET)
    {
        err = get_iaid(pszIfname, &iaid);
        bail_on_error(err);

        fprintf(stdout, "IAID=%u\n", iaid);
    }

cleanup:
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_dns_servers(PNETMGR_CMD pCmd)
{
    uint32_t err = 0;
    size_t i = 0, count = 0;
    int add_servers = 0;
    NET_DNS_MODE mode = DNS_MODE_INVALID;
    char *pszMode, *s1, *s2, *pszServers = NULL, **szDnsServersList = NULL;
    char szServers[2048], *pszIfname = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    if (pCmd->op == OP_SET)
    {
        err = netmgrcli_find_cmdopt(pCmd, "mode", &pszMode);
        bail_on_error(err);

        if (!strcmp(pszMode, "dhcp"))
        {
            mode = DHCP_DNS;
        }
        else if (!strcmp(pszMode, "static"))
        {
            mode = STATIC_DNS;
        }

        err = netmgrcli_find_cmdopt(pCmd, "servers", &pszServers);
        if (err == ENOENT)
        {
            err = 0;
        }
        bail_on_error(err);

        if (pszServers != NULL)
        {
            strcpy(szServers, pszServers);
            if (strlen(szServers) > 0)
            {
                s2 = szServers;
                do {
                    s1 = strsep(&s2, ",");
                    if (strlen(s1) > 0)
                    {
                        count++;
                    }
                } while (s2 != NULL);
            }
        }
        if (count > 0)
        {
            err = netmgr_alloc((count * sizeof(char*)),
                               (void *)&szDnsServersList);
            bail_on_error(err);
            strcpy(szServers, pszServers);
            s2 = szServers;
            do {
                s1 = strsep(&s2, ",");
                if (strlen(s1) > 0)
                {
                    if ((i == 0) && !strcmp(s1,"+"))
                    {
                        add_servers = 1;
                        count -= 1;
                        continue;
                    }
                    err = netmgr_alloc_string(s1, &(szDnsServersList[i++]));
                    bail_on_error(err);
                }
            } while (s2 != NULL);
        }

        if (add_servers == 0)
        {
            err = set_dns_servers(pszIfname, mode, count,
                                  (const char **)szDnsServersList, 0);
        }
        else
        {
            err = add_dns_servers(pszIfname, count,
                                  (const char **)szDnsServersList);
        }
        bail_on_error(err);
    }

    if (pCmd->op == OP_GET)
    {
        char **szDnsServers = NULL;
        err = get_dns_servers(pszIfname, 0, &mode, &count, &szDnsServers);
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
            fprintf(stdout, "%s ", szDnsServers[i]);
            netmgr_free(szDnsServers[i]);
        }
        netmgr_free(szDnsServers);
        fprintf(stdout, "\n");
    }

cleanup:
    /* Free allocated memory */
    if (szDnsServersList != NULL)
    {
        for (i = 0; i < count; i++)
        {
            netmgr_free(szDnsServersList[i]);
        }
        netmgr_free(szDnsServersList);
    }
    return err;

error:
    goto cleanup;
}

typedef struct _NETMGR_CLI_HANDLER
{
    char* pszCmdName;
    uint32_t (*pFnCmd)(PNETMGR_CMD);
} NETMGR_CLI_HANDLER, *PNETMGR_CLI_HANDLER;

NETMGR_CLI_HANDLER cmdHandler[] =
{
    { "dns_servers",           cmd_dns_servers },
    { "dhcp_duid",             cmd_dhcp_duid },
    { "if_iaid",               cmd_if_iaid },
};

void
show_version()
{
    fprintf(stdout, "%s: %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

int main(int argc, char* argv[])
{
    uint32_t err = 0;
    PNETMGR_CMD pCmd = NULL;
    size_t i, cmdCount = sizeof(cmdHandler)/sizeof(NETMGR_CLI_HANDLER);

    err = netmgrcli_parse_cmdline(argc, argv, &pCmd);
    bail_on_error(err);

    for (i = 0; i < cmdCount; i++)
    {
        if (!strcmp(pCmd->pszCmd, cmdHandler[i].pszCmdName))
        {
            err = cmdHandler[i].pFnCmd(pCmd);
            break;
        }
    }

cleanup:
    netmgrcli_free_cmd(pCmd);
    return err;
error:
    goto cleanup;
}

