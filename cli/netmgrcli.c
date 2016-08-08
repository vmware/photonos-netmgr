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
netmgrcli_alloc_cmd(
    char *cmdName,
    PNETMGR_CMD *ppCmd
    )
{
    uint32_t err = 0;
    PNETMGR_CMD pCmd = NULL;

    err = netmgr_alloc(sizeof(NETMGR_CMD), (void **)&pCmd);
    bail_on_error(err);

    pCmd->id = CMD_INVALID;
    *ppCmd = pCmd;

cleanup:
    return err;

error:
    if(ppCmd)
    {
        *ppCmd = NULL;
    }
    if(pCmd)
    {
        netmgrcli_free_cmd(pCmd);
    }
    goto cleanup;
}

static void
netmgrcli_free_keyvalue(POPTIONKV pKeyValue)
{
    if (pKeyValue)
    {
        netmgr_free(pKeyValue->pszKey);
        netmgr_free(pKeyValue->pszValue);
        netmgr_free(pKeyValue);
    }
}

static uint32_t
netmgrcli_alloc_keyvalue(
    char *key,
    char *value,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0;
    POPTIONKV pKeyVal = NULL;

    err = netmgr_alloc(sizeof(OPTIONKV), (void **)&pKeyVal);
    bail_on_error(err);

    err = netmgr_alloc_string(key, &pKeyVal->pszKey);
    bail_on_error(err);

    err = netmgr_alloc_string(value, &pKeyVal->pszValue);
    bail_on_error(err);

    pKeyVal->pNext = pCmd->pCmdOpt;
    pCmd->pCmdOpt = pKeyVal;

cleanup:
    return err;

error:
    netmgrcli_free_keyvalue(pKeyVal);
    goto cleanup;
}

static struct option dhcpDuidOptions[] =
{
    {"set",          no_argument,          0,    's'},
    {"get",          no_argument,          0,    'g'},
    {"duid",         required_argument,    0,    'd'},
    {"interface",    required_argument,    0,    'i'},
    {0, 0, 0, 0}
};

uint32_t
cli_dhcp_duid(
    int argc,
    char **argv,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0, validDuid = 0;
    int nOptionIndex = 0, nOption = 0;
    CMD_OP op = OP_INVALID;

    opterr = 0;
    optind = 1;
    while (1)
    {
        nOption = getopt_long(argc,
                              argv,
                              "sgd:i:",
                              dhcpDuidOptions,
                              &nOptionIndex);
        if (nOption == -1)
            break;

        switch(nOption)
        {
            case 's':
                op = OP_SET;
                break;
            case 'g':
                op = OP_GET;
                break;
            case 'd':
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("duid", optarg, pCmd);
                }
                else
                {
                    err = netmgrcli_alloc_keyvalue("duid", "", pCmd);
                }
                validDuid = 1;
                break;
            case 'i':
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("interface", optarg, pCmd);
                }
                else
                {
                    fprintf(stderr, "Invalid interface name.\n");
                    err = EDOM;
                }
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
        bail_on_error(err);
    }

    if ((op == OP_INVALID) || ((op == OP_SET) && !validDuid))
    {
        err = EDOM;
        bail_on_error(err);
    }

    pCmd->id = CMD_DHCP_DUID;
    pCmd->op = op;

cleanup:
    return err;

error:
    pCmd->op = OP_INVALID;
    /* TODO: Free allocated memory */
    if(err == EDOM)
    {
        fprintf(stderr,
                "Usage:\ndhcp_duid --get\n"
                "dhcp_duid --set --duid '00:01:00:00:11:22:33:44:55:66:77:88'\n");
    }
    goto cleanup;
}

static struct option ifIaidOptions[] =
{
    {"set",          no_argument,          0,    's'},
    {"get",          no_argument,          0,    'g'},
    {"iaid",         required_argument,    0,     0 },
    {"interface",    required_argument,    0,    'i'},
    {0, 0, 0, 0}
};

uint32_t
cli_if_iaid(
    int argc,
    char **argv,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0, ifNameValid = 0, iaidValid = 0;
    int nOptionIndex = 0, nOption = 0;
    CMD_OP op = OP_INVALID;

    opterr = 0;
    optind = 1;
    while (1)
    {
        nOption = getopt_long(argc,
                              argv,
                              "sgd:i:",
                              ifIaidOptions,
                              &nOptionIndex);
        if (nOption == -1)
            break;

        switch(nOption)
        {
            case 's':
                op = OP_SET;
                break;
            case 'g':
                op = OP_GET;
                break;
            case 'i':
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("interface", optarg, pCmd);
                    ifNameValid = 1;
                }
                else
                {
                    fprintf(stderr, "Invalid interface name.\n");
                    err = EDOM;
                }
                break;
            case 0:
                /* --iaid option */
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("iaid", optarg, pCmd);
                }
                else
                {
                    err = netmgrcli_alloc_keyvalue("iaid", "", pCmd);
                }
                iaidValid = 1;
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
        bail_on_error(err);
    }

    if ((op == OP_INVALID) || !ifNameValid || ((op == OP_SET) && !iaidValid))
    {
        err = EDOM;
        bail_on_error(err);
    }

    pCmd->id = CMD_IF_IAID;
    pCmd->op = op;

cleanup:
    return err;

error:
    pCmd->op = OP_INVALID;
    /* TODO: Free allocated memory */
    if(err == EDOM)
    {
        fprintf(stderr,
                "Usage:\nif_iaid --get --interface <IfName>\n"
                "if_iaid --set --interface <IfName> --iaid '12345'\n");
    }
    goto cleanup;
}

static struct option dnsServerOptions[] =
{
    {"set",          no_argument,          0,    's'},
    {"get",          no_argument,          0,    'g'},
    {"mode",         required_argument,    0,    'm'},
    {"servers",      required_argument,    0,     0 },
    {"interface",    required_argument,    0,    'i'},
    {0, 0, 0, 0}
};

uint32_t
cli_dns_servers(
    int argc,
    char **argv,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0, invalidMode = 1;
    int nOptionIndex = 0, nOption = 0;
    CMD_OP op = OP_INVALID;

    opterr = 0;
    optind = 1;
    while (1)
    {
        nOption = getopt_long(argc,
                              argv,
                              "sgm:i:",
                              dnsServerOptions,
                              &nOptionIndex);
        if (nOption == -1)
            break;

        switch(nOption)
        {
            case 's':
                op = OP_SET;
                break;
            case 'g':
                op = OP_GET;
                break;
            case 'm':
                if (!strcmp(optarg, "dhcp") || !strcmp(optarg, "static"))
                {
                    err = netmgrcli_alloc_keyvalue("mode", optarg, pCmd);
                    invalidMode = 0;
                }
                break;
            case 'i':
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("interface", optarg, pCmd);
                }
                else
                {
                    fprintf(stderr, "Invalid interface name.\n");
                    err = EDOM;
                }
                break;
            case 0:
                /* --servers option */
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("servers", optarg, pCmd);
                }
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
        bail_on_error(err);
    }

    if ((op == OP_INVALID) || ((op == OP_SET) && invalidMode))
    {
        err = EDOM;
        bail_on_error(err);
    }

    pCmd->id = CMD_DNS_SERVERS;
    pCmd->op = op;

cleanup:
    return err;

error:
    pCmd->op = OP_INVALID;
    /* TODO: Free allocated memory */
    if(err == EDOM)
    {
        fprintf(stderr,
                "Usage:\ndns_servers --get\ndns_servers --set --mode "
                 "dhcp|static --servers <server1,server2,...>\n");
    }
    goto cleanup;
}


/* Map command name to command parser function */
typedef struct _NETMGRCLI_CMD_MAP
{
    char *pszCmdName;
    uint32_t (*pFnCmd)(int, char**, PNETMGR_CMD);
    char *pszParams;
    char *pszHelpMessage;
} NETMGRCLI_CMD_MAP, *PNETMGRCLI_CMD_MAP;

NETMGRCLI_CMD_MAP cmdMap[] =
{
    {"dns_servers",
     cli_dns_servers,
     "--set --mode [dhcp|static] --servers <DNS servers list>",
     "get or set DNS mode, DNS servers list"
    },
    {"dhcp_duid",
     cli_dhcp_duid,
     "--set --duid <DUID string> --interface <interface name>",
     "get or set DHCP DUID, optionally per interface"
    },
    {"if_iaid",
     cli_if_iaid,
     "--set --iaid <IAID value>> --interface <interface name>",
     "get or set interface IAID"
    },
};

static uint32_t
show_help()
{
    int i = 0;
    int nCmdCount = sizeof(cmdMap)/sizeof(NETMGRCLI_CMD_MAP);
    fprintf(stdout, "Usage: netmgr command <command options ...>\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "For help: netmgr -h or netmgr --version\n");
    fprintf(stdout, "For version: netmgr -v or netmgr --version\n");
    fprintf(stdout, "\n");

    fprintf(stdout, "List of commands\n");
    fprintf(stdout, "\n");

    for(i = 0; i < nCmdCount; ++i)
    {
        fprintf(stdout, "%s %s\t%s\n",
                cmdMap[i].pszCmdName,
                cmdMap[i].pszParams,
                cmdMap[i].pszHelpMessage);
    }
    return 0;
}

extern void show_version();

uint32_t
netmgrcli_parse_cmdline(
    int argc,
    char** argv,
    PNETMGR_CMD *ppCmd
    )
{
    uint32_t err = 0;
    PNETMGR_CMD pCmd = NULL;
    size_t i, cmdCount = sizeof(cmdMap)/sizeof(NETMGRCLI_CMD_MAP);;

    if(argc == 0 || !argv || !ppCmd)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    /* Process version (-v) and help (-h) */
    if ((argc < 2) || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
    {
        /* print usage and exit */
        show_help();
        exit(0);
    }
    if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version"))
    {
        /* print version and exit */
        show_version();
        exit(0);
    }

    for (i = 0; i < cmdCount; i++)
    {
        if (!strcmp(argv[1], cmdMap[i].pszCmdName))
        {
            err = netmgrcli_alloc_cmd(argv[1], &pCmd);
            bail_on_error(err);
            err = cmdMap[i].pFnCmd(argc, argv, pCmd);
            break;
        }
    }

    if (!pCmd)
    {
        fprintf(stdout, "Unknown command %s\n", argv[1]);
        show_help();
        err = EDOM;
        bail_on_error(err);
    }

    *ppCmd = pCmd;

cleanup:
    return err;

error:
    if(ppCmd)
    {
        *ppCmd = NULL;
    }
    if(pCmd)
    {
        netmgrcli_free_cmd(pCmd);
    }
    goto cleanup;
}

uint32_t
netmgrcli_find_cmdopt(
    PNETMGR_CMD pCmd,
    char *pszOptName,
    char **ppszOptValue
)
{
    uint32_t err = ENOENT;
    char *pszOptValue = NULL;
    POPTIONKV pKeyVal;

    if (!pCmd || !pszOptName || !*pszOptName)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    for (pKeyVal = pCmd->pCmdOpt; pKeyVal; pKeyVal = pKeyVal->pNext)
    {
        if (!strcmp(pszOptName, pKeyVal->pszKey))
        {
            err = 0;
            pszOptValue = pKeyVal->pszValue;
            break;
        }
    }

    *ppszOptValue = pszOptValue;

cleanup:
    return err;

error:
    if (ppszOptValue)
    {
        *ppszOptValue = NULL;
    }
    goto cleanup;
}

void
netmgrcli_free_cmd(
    PNETMGR_CMD pCmd
    )
{
    POPTIONKV kv, kvnext;
    if(pCmd)
    {
        for (kv = pCmd->pCmdOpt; kv;)
        {
            kvnext = kv->pNext;
            netmgrcli_free_keyvalue(kv);
            kv = kvnext;
        }
        netmgr_free(pCmd);
    }
}

