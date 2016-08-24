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
    if (ppCmd)
    {
        *ppCmd = NULL;
    }
    if (pCmd)
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

static struct option ip4AddrOptions[] =
{
    {"set",          no_argument,          0,    's'},
    {"get",          no_argument,          0,    'g'},
    {"interface",    required_argument,    0,    'i'},
    {"mode",         required_argument,    0,    'm'},
    {"addr",         required_argument,    0,    'a'},
    {"prefix",       required_argument,    0,    'p'},
    {"gateway",      required_argument,    0,     0 },
    {0, 0, 0, 0}
};

uint32_t
cli_ip4_address(
    int argc,
    char **argv,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0, validIfName = 0, validMode = 0;
    int nOptionIndex = 0, nOption = 0;
    CMD_OP op = OP_INVALID;

    opterr = 0;
    optind = 1;
    while (1)
    {
        nOption = getopt_long(argc,
                              argv,
                              "sgi:m:a:p:",
                              ip4AddrOptions,
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
                    validIfName = 1;
                }
                else
                {
                    fprintf(stderr, "Invalid interface name.\n");
                    err = EDOM;
                }
                break;
            case 'm':
                if (!strcmp(optarg, "dhcp") || !strcmp(optarg, "static") ||
                    !strcmp(optarg, "none"))
                {
                    err = netmgrcli_alloc_keyvalue("mode", optarg, pCmd);
                    validMode = 1;
                }
                break;
            case 'a':
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("address", optarg, pCmd);
                }
                else
                {
                    fprintf(stderr, "Invalid IPv4 address.\n");
                    err = EDOM;
                }
                break;
            case 'p':
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("prefix", optarg, pCmd);
                }
                else
                {
                    fprintf(stderr, "Invalid IPv4 address prefix.\n");
                    err = EDOM;
                }
                break;
            case 0:
                /* --gateway option */
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("gateway", optarg, pCmd);
                }
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
        bail_on_error(err);
    }

    if ((op == OP_INVALID) || !validIfName || ((op == OP_SET) && !validMode))
    {
        err = EDOM;
        bail_on_error(err);
    }

    pCmd->id = CMD_IP4_ADDRESS;
    pCmd->op = op;

cleanup:
    return err;

error:
    pCmd->op = OP_INVALID;
    if (err == EDOM)
    {
        fprintf(stderr,
                "Usage:\nip4_address --get --interface <ifame>\n"
                "ip4_address --set --interface <ifname> --mode dhcp|static|none"
                " --addr <IPv4 address> --prefix <IPv4 prefix>\n");
    }
    goto cleanup;
}

static struct option ip6AddrOptions[] =
{
    {"add",          no_argument,          0,    'p'},
    {"del",          no_argument,          0,    'm'},
    {"set",          no_argument,          0,    's'},
    {"get",          no_argument,          0,    'g'},
    {"interface",    required_argument,    0,    'i'},
    {"dhcp",         required_argument,    0,    'd'},
    {"autoconf",     required_argument,    0,    'a'},
    {"addrlist",     required_argument,    0,    '1'},
    {"gateway",      required_argument,    0,    '2' },
    {0, 0, 0, 0}
};

uint32_t
cli_ip6_address(
    int argc,
    char **argv,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0, validIfName = 0, validAddr = 0;
    int nOptionIndex = 0, nOption = 0;
    CMD_OP op = OP_INVALID;

    opterr = 0;
    optind = 1;
    while (1)
    {
        nOption = getopt_long(argc,
                              argv,
                              "pmsgi:d:a:12",
                              ip6AddrOptions,
                              &nOptionIndex);
        if (nOption == -1)
            break;

        switch(nOption)
        {
            case 'p':
                op = OP_ADD;
                break;
            case 'm':
                op = OP_DEL;
                break;
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
                    validIfName = 1;
                }
                else
                {
                    fprintf(stderr, "Invalid interface name.\n");
                    err = EDOM;
                }
                break;
            case 'd':
                if (!strcmp(optarg, "1") || !strcmp(optarg, "true"))
                {
                    err = netmgrcli_alloc_keyvalue("dhcp", "1", pCmd);
                }
                else
                {
                    err = netmgrcli_alloc_keyvalue("dhcp", "0", pCmd);
                }
                break;
            case 'a':
                if (!strcmp(optarg, "1") || !strcmp(optarg, "true"))
                {
                    err = netmgrcli_alloc_keyvalue("autoconf", "1", pCmd);
                }
                else
                {
                    err = netmgrcli_alloc_keyvalue("autoconf", "0", pCmd);
                }
                break;
            case '1':
                /* --addrlist option */
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("addrlist", optarg, pCmd);
                    validAddr = 1;
                }
                break;
            case '2':
                /* --gateway option */
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("gateway", optarg, pCmd);
                }
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
        bail_on_error(err);
    }

    if ((op == OP_INVALID) || !validIfName ||
        (((op == OP_ADD) || (op == OP_DEL)) && !validAddr))
    {
        err = EDOM;
        bail_on_error(err);
    }

    pCmd->id = CMD_IP6_ADDRESS;
    pCmd->op = op;

cleanup:
    return err;

error:
    pCmd->op = OP_INVALID;
    if (err == EDOM)
    {
        fprintf(stderr,
                "Usage:\nip6_address --get --interface <ifame>\n"
                "ip6_address --add|--del --interface <ifame> "
                "--addrlist <IPv6Addr1/prefix,IPv6Addr2/prefix,...>\n"
                "ip6_address --set --interface <ifname> --dhcp <1|0> "
                "--autoconf <1|0>\n");
    }
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
    if (err == EDOM)
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
    if (err == EDOM)
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
    {"add",          no_argument,          0,    'a'},
    {"del",          no_argument,          0,    'd'},
    {"mode",         required_argument,    0,    'm'},
    {"servers",      required_argument,    0,     0 },
    {"interface",    required_argument,    0,    'i'},
    {"norestart",    no_argument,          0,    'n'},
    {0, 0, 0, 0}
};

uint32_t
cli_dns_servers(
    int argc,
    char **argv,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0, invalidMode = 1, emptyServerList = 1;
    int nOptionIndex = 0, nOption = 0;
    CMD_OP op = OP_INVALID;

    opterr = 0;
    optind = 1;
    while (1)
    {
        nOption = getopt_long(argc,
                              argv,
                              "sngadm:i:",
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
            case 'a':
                op = OP_ADD;
                break;
            case 'd':
                op = OP_DEL;
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
            case 'n':
                err = netmgrcli_alloc_keyvalue("norestart","true",pCmd);
                break;
            case 0:
                /* --servers option */
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("servers", optarg, pCmd);
                    emptyServerList = 0;
                }
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
        bail_on_error(err);
    }

    if ((op == OP_INVALID) || ((op == OP_SET) && invalidMode) ||
        (((op == OP_ADD) || (op == OP_DEL)) && emptyServerList))
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
    if (err == EDOM)
    {
        fprintf(stderr,
                "Usage:\ndns_servers --get\ndns_servers --set --mode "
                 "dhcp|static --servers <server1,server2,...>\n"
                 "dns_servers --add|--del --servers <server>\n");
    }
    goto cleanup;
}

static struct option dnsDomainsOptions[] =
{
    {"set",          no_argument,          0,    's'},
    {"get",          no_argument,          0,    'g'},
    {"domains",      required_argument,    0,     0 },
    {"interface",    required_argument,    0,    'i'},
    {"del",          no_argument,          0,    'd'},
    {"add",          no_argument,          0,    'a'},
    {"norestart",    no_argument,          0,    'n'},
    {0, 0, 0, 0}
};


uint32_t
cli_dns_domains(
    int argc,
    char **argv,
    PNETMGR_CMD pCmd
    )
{
    uint32_t err = 0, domains_option_present = 0;
    int nOptionIndex = 0, nOption = 0;
    CMD_OP op = OP_INVALID;

    opterr = 0;
    optind = 1;
    while (1)
    {
        nOption = getopt_long(argc,
                              argv,
                              "sngdai:",
                              dnsDomainsOptions,
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
                }
                else
                {
                    fprintf(stderr, "Invalid interface name.\n");
                    err = EDOM;
                }
                break;
            case 'd':
                op = OP_DEL;
                break;
            case 'a':
                op = OP_ADD;
                break;
            case 'n':
                err = netmgrcli_alloc_keyvalue("norestart","true",pCmd);
                break;
            case 0:
                /* --domains option */
                if (strlen(optarg) > 0)
                {
                    err = netmgrcli_alloc_keyvalue("domains", optarg, pCmd);
                    domains_option_present = 1;
                }
                break;
            case '?':
                /* Option not handled here. Ignore. */
                break;
        }
        bail_on_error(err);
    }

    if ((op == OP_INVALID) ||
        (((op == OP_DEL) ||(op == OP_ADD)) &&
        (domains_option_present == 0)))
    {
        err = EDOM;
        bail_on_error(err);
    }

    pCmd->id = CMD_DNS_DOMAINS;
    pCmd->op = op;

cleanup:
    return err;

error:
    pCmd->op = OP_INVALID;
    /* TODO: Free allocated memory */
    if(err == EDOM)
    {
        fprintf(stderr,
                "Usage:\ndns_domains --get\ndns_domains --set --norestart "
                 "--domains <domain1,domain2,...>\n"
                 "dns_domains --add --norestart --domains <domain1,domain2,..>\n"
                 "dns_domains --del --norestart --domains <domain1>\n");
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
    {"ip4_address",
     cli_ip4_address,
     "--set --interface <interface name> --mode <dhcp|static> --addr <IPv4 Address>"
     " --prefix <prefix> --gateway <default gateway>",
     "get or set IPv4 address and default gateway for interface"
    },
    {"ip6_address",
     cli_ip6_address,
     "--set --interface <interface name> --dhcp <1|0> --autoconf <1|0> "
     "--addrlist <IPv6 Address/Prefix list> --gateway <Default IPv6 gateway>",
     "add or delete IPv6 addresses and default gateway for interface"
    },
    {"dns_servers",
     cli_dns_servers,
     "--set --mode <dhcp|static> --servers <DNS servers list>",
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
    {"dns_domains",
     cli_dns_domains,
     "--set --del --add --domains <Domains list>",
     "get or set DNS domains list"
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

void
netmgrcli_show_version()
{
    fprintf(stdout, "%s: %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

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

    if (argc == 0 || !argv || !ppCmd)
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
        netmgrcli_show_version();
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
    if (ppCmd)
    {
        *ppCmd = NULL;
    }
    if (pCmd)
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

    if (!pCmd || IS_NULL_OR_EMPTY(pszOptName))
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
    if (pCmd)
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

