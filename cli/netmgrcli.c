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
netmgrcli_alloc_string(
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

    pszDst = calloc(1, (len + 1));
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
        free(pszDst);
    }
    goto cleanup;
}

static uint32_t
netmgrcli_alloc_cmd(
    char *cmdName,
    PNETMGR_CMD *ppCmd
    )
{
    uint32_t err = 0;
    PNETMGR_CMD pCmd = NULL;

    pCmd = calloc(1, sizeof(NETMGR_CMD));
    if (!pCmd)
    {
        err = ENOMEM;
        bail_on_error(err);
    }

    err = netmgrcli_alloc_string(cmdName, &pCmd->pszCmd);
    bail_on_error(err);

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

static uint32_t
netmgrcli_alloc_keyvalue(
    char *key,
    char *value,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0;
    POPTIONKV pKeyVal = NULL;

    pKeyVal = calloc(1, sizeof(OPTIONKV));
    if (!pKeyVal)
    {
        err = ENOMEM;
        bail_on_error(err);
    }

    err = netmgrcli_alloc_string(key, &pKeyVal->pszKey);
    bail_on_error(err);

    err = netmgrcli_alloc_string(value, &pKeyVal->pszValue);
    bail_on_error(err);

    pKeyVal->pNext = pCmd->pCmdOpt;
    pCmd->pCmdOpt = pKeyVal;

cleanup:
    return err;

error:
    if (pKeyVal)
    {
        if (pKeyVal->pszKey)
        {
            free(pKeyVal->pszKey);
        }
        if (pKeyVal->pszValue)
        {
            free(pKeyVal->pszValue);
        }
        free(pKeyVal);
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
    uint32_t err = 0;
    int nOptionIndex = 0;
    int nOption = 0;
    CMD_OP op = OP_INVALID;
    int invalid_mode = 0;
    char szServers[2048];

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
                    netmgrcli_alloc_keyvalue("mode", optarg, pCmd);
                }
                else
                {
                    invalid_mode = 1;
                }
                break;
            case 0:
                /* --servers option */
                strcpy(szServers, optarg);
                if (strlen(optarg) > 0)
                {
                    netmgrcli_alloc_keyvalue("servers", optarg, pCmd);
                }
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
    }

    if (op == OP_INVALID)
    {
        err = EDOM;
        bail_on_error(err);
    }

    if (op == OP_SET)
    {
        if (invalid_mode)
        {
            err = EDOM;
            bail_on_error(err);
        }
    }

    pCmd->op = op;

cleanup:
    /* Free allocated memory */
    return err;

error:
    pCmd->op = OP_INVALID;
    if(err == EDOM)
    {
        fprintf(stderr,
                "Usage:\ndns_servers --get\ndns_servers --set --mode "
                 "dhcp|static --servers <server1,server2,...>\n");
    }
    goto cleanup;
}

/*  name of command,
 *  pointer to command invoke
 *  parameters if any
 *  help message
 */
NETMGRCLI_CMD_MAP cmdMap[] =
{
    {"dns_servers",
     cli_dns_servers,
     "--set --mode [dhcp|static] --servers <DNS servers list>",
     "get or set DNS mode, DNS servers list"
    },
};


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
    if ((argc < 2) || (!strcmp(argv[1], "-h")))
    {
        /* print usage and exit */
        printf("netmgr <command> <command options ...>\n");
        exit(0);
    }

    if (!strcmp(argv[1], "-h"))
    {
        /* print version and exit */
        printf("netmgr version <placeholder>\n");
        exit(0);
    }

    for (i = 0; i < cmdCount; i++)
    {
        if (!strcmp(argv[1], cmdMap[i].pszCmdName))
        {
            err = netmgrcli_alloc_cmd(argv[1], &pCmd);
            bail_on_error(err);
            cmdMap[i].pFnCmd(argc, argv, pCmd);
            break;
        }
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
        free(pCmd->pszCmd);
        for (kv = pCmd->pCmdOpt; kv;)
        {
            kvnext = kv->pNext;
            if (kv->pszKey)
            {
                free(kv->pszKey);
            }
            if (kv->pszValue)
            {
                free(kv->pszValue);
            }
            free(kv);
            kv = kvnext;
        }
        free(pCmd);
    }
}

