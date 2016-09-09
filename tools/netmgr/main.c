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
cmd_ip4_address(PNETMGR_CMD pCmd)
{
    uint32_t err = 0, mode = 0;
    char *pszIfName = NULL, *pszMode = NULL;
    char *pszAddr = NULL, *pszPrefix = NULL, *pszGateway = NULL;
    char **ppszAddrList = NULL;
    size_t count;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfName);

    if (pCmd->op == OP_SET)
    {
        err = netmgrcli_find_cmdopt(pCmd, "mode", &pszMode);
        bail_on_error(err);

        err = get_ip_dhcp_mode(pszIfName, &mode);
        bail_on_error(err);

        if (!strcmp(pszMode, "static"))
        {
            err = netmgrcli_find_cmdopt(pCmd, "address", &pszAddr);
            bail_on_error(err);

            err = netmgrcli_find_cmdopt(pCmd, "prefix", &pszPrefix);
            bail_on_error(err);

            netmgrcli_find_cmdopt(pCmd, "gateway", &pszGateway);

            CLEAR_FLAG(mode, fDHCP_IPV4);
            err = set_ip_dhcp_mode(pszIfName, mode);
            bail_on_error(err);

            err = set_static_ipv4_addr(pszIfName, pszAddr, atoi(pszPrefix), 0);

            if (pszGateway)
            {
                // TODO: set default route
            }
        }
        else
        {
            err = delete_static_ipv4_addr(pszIfName);
            if (err != ENOENT)
            {
                bail_on_error(err);
            }

            if (!strcmp(pszMode, "dhcp"))
            {
                SET_FLAG(mode, fDHCP_IPV4);
            }
            else
            {
                CLEAR_FLAG(mode, fDHCP_IPV4);
            }

            err = set_ip_dhcp_mode(pszIfName, mode);
        }
        bail_on_error(err);
    }

    if (pCmd->op == OP_GET)
    {
        err = get_ip_dhcp_mode(pszIfName, &mode);
        bail_on_error(err);

        err = get_static_ip_addr(pszIfName, STATIC_IPV4, &count, &ppszAddrList);
        bail_on_error(err);

        if (TEST_FLAG(mode, fDHCP_IPV4))
        {
            fprintf(stdout, "IPv4 Address Mode: dhcp\n");
        }
        else if (ppszAddrList != NULL)
        {
            fprintf(stdout, "IPv4 Address Mode: static\n");
        }
        else
        {
            fprintf(stdout, "IPv4 Address Mode: none\n");
        }
        fprintf(stdout, "IPv4 Address=%s\n", ppszAddrList[0]);

        // TODO: get default route
    }

cleanup:
    netmgr_list_free(count, (void **)ppszAddrList);
    netmgr_free(pszGateway);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_ip6_address(PNETMGR_CMD pCmd)
{
    uint32_t err = 0, mode = 0;
    char *pszIfName = NULL, *pszDhcp = NULL, *pszAutoconf = NULL;
    char *pszAddrList = NULL, *pszGateway = NULL;
    char *a1, *a2, szAddr[INET6_ADDRSTRLEN], **ppszAddrList = NULL;
    uint8_t prefix;
    size_t i, count;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfName);

    switch (pCmd->op)
    {
        case OP_ADD:
        case OP_DEL:
            err = netmgrcli_find_cmdopt(pCmd, "addrlist", &pszAddrList);
            if (err != ENOENT)
            {
                bail_on_error(err);
            }
            if (pszAddrList != NULL)
            {
                a2 = pszAddrList;
                do {
                    a1 = strsep(&a2, ",");
                    if (strlen(a1) == 0)
                    {
                        continue;
                    }
                    sscanf(a1, "%[^/]/%hhu", szAddr, &prefix);
                    if (pCmd->op == OP_ADD)
                    {
                        err = add_static_ipv6_addr(pszIfName, szAddr, prefix, 0);
                    }
                    else
                    {
                        err = delete_static_ipv6_addr(pszIfName, szAddr, prefix, 0);
                    }
                    bail_on_error(err);
                } while (a2 != NULL);
            }

        case OP_SET:
            err = get_ip_dhcp_mode(pszIfName, &mode);
            bail_on_error(err);

            err = netmgrcli_find_cmdopt(pCmd, "dhcp", &pszDhcp);
            if (err != ENOENT)
            {
                bail_on_error(err);
            }
            err = netmgrcli_find_cmdopt(pCmd, "autoconf", &pszAutoconf);
            if (err != ENOENT)
            {
                bail_on_error(err);
            }
            err = netmgrcli_find_cmdopt(pCmd, "gateway", &pszGateway);
            if (err != ENOENT)
            {
                bail_on_error(err);
            }

            if (pszDhcp != NULL)
            {
                if (!strcmp(pszDhcp, "1"))
                {
                    SET_FLAG(mode, fDHCP_IPV6);
                }
                else
                {
                    CLEAR_FLAG(mode, fDHCP_IPV6);
                }
            }
            if (pszAutoconf != NULL)
            {
                if (!strcmp(pszAutoconf, "1"))
                {
                    SET_FLAG(mode, fAUTO_IPV6);
                }
                else
                {
                    CLEAR_FLAG(mode, fAUTO_IPV6);
                }
            }

            err = set_ip_dhcp_mode(pszIfName, mode);
            bail_on_error(err);

            if (pszGateway)
            {
                // TODO: set default route
            }
            break;

        case OP_GET:
            err = get_ip_dhcp_mode(pszIfName, &mode);
            bail_on_error(err);

            err = get_static_ip_addr(pszIfName, STATIC_IPV6, &count, &ppszAddrList);
            bail_on_error(err);

            if (TEST_FLAG(mode, fDHCP_IPV6))
            {
                fprintf(stdout, "IPv6 Address Mode: dhcp\n");
            }
            else if (ppszAddrList != NULL)
            {
                fprintf(stdout, "IPv6 Address Mode: static\n");
            }
            else
            {
                fprintf(stdout, "IPv6 Address Mode: none\n");
            }
            for (i = 0; i < count; i++)
            {
                fprintf(stdout, "IPv6 Address=%s\n", ppszAddrList[i]);
            }
            // TODO: get default route
            break;

        default:
            err = EINVAL;
    }

cleanup:
    netmgr_list_free(count, (void **)ppszAddrList);
    netmgr_free(pszGateway);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_ip_route(PNETMGR_CMD pCmd)
{
    uint32_t err = 0;
    size_t i, count = 0;
    char *pszMetric = NULL, *pszScope = NULL;
    NET_IP_ROUTE ipRoute = {0}, **ppRoutesList = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &ipRoute.pszInterfaceName);

    switch (pCmd->op)
    {
        case OP_ADD:
            netmgrcli_find_cmdopt(pCmd, "gateway", &ipRoute.pszGateway);

            err = netmgrcli_find_cmdopt(pCmd, "metric", &pszMetric);
            if (err == ENOENT)
            {
                err = 0;
                ipRoute.metric = 1024;
            }
            else
            {
                sscanf(pszMetric, "%u", &ipRoute.metric);
            }
            bail_on_error(err);

            err = netmgrcli_find_cmdopt(pCmd, "scope", &pszScope);
            if (err == ENOENT)
            {
                err = 0;
                // TODO: scope = default
            }
            bail_on_error(err);

        case OP_DEL:
            netmgrcli_find_cmdopt(pCmd, "destination", &ipRoute.pszDestNetwork);

            if (pCmd->op == OP_ADD)
            {
                err = add_static_ip_route(&ipRoute, 0);
            }
            else
            {
                err = delete_static_ip_route(&ipRoute, 0);
            }
            bail_on_error(err);
            break;

        case OP_GET:
            err = get_static_ip_routes(ipRoute.pszInterfaceName, &count, &ppRoutesList);
            fprintf(stdout, "Static IP Routes:\n");
            for (i = 0; i < count; i++)
            {
                fprintf(stdout, "Route #%zu\n", i+1);
                fprintf(stdout, "  Dest=%s\n", ppRoutesList[i]->pszDestNetwork);
                fprintf(stdout, "  Gateway=%s\n", ppRoutesList[i]->pszGateway);
                fprintf(stdout, "  Scope=%u\n", ppRoutesList[i]->scope);
                fprintf(stdout, "  Metric=%u\n", ppRoutesList[i]->metric);
            }
            fprintf(stdout, "\n");
            break;

        default:
            err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    /* TODO: MEM LEAK CHECK */
    netmgr_list_free(count, (void **)ppRoutesList);
    return err;

error:
    goto cleanup;
}

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
    uint32_t err = 0, flags = 0;
    size_t i = 0, count = 0;
    NET_DNS_MODE mode = DNS_MODE_INVALID;
    char *pszIfname = NULL, *pszMode = NULL;
    char *pszDnsServers = NULL, *pszNoRestart = NULL;
    char *s1, *s2, *pszServers = NULL, **ppszDnsServersList = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    switch (pCmd->op)
    {
        case OP_SET:
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
        case OP_ADD:
        case OP_DEL:
            err = netmgrcli_find_cmdopt(pCmd, "servers", &pszDnsServers);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszDnsServers != NULL)
            {
                err = netmgr_alloc_string(pszDnsServers, &pszServers);
                bail_on_error(err);
                if (strlen(pszServers) > 0)
                {
                    s2 = pszServers;
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
                                   (void *)&ppszDnsServersList);
                bail_on_error(err);
                strcpy(pszServers, pszDnsServers);
                s2 = pszServers;
                do {
                    s1 = strsep(&s2, ",");
                    if (strlen(s1) > 0)
                    {
                        err = netmgr_alloc_string(s1, &(ppszDnsServersList[i++]));
                        bail_on_error(err);
                    }
                } while (s2 != NULL);
            }
            err = netmgrcli_find_cmdopt(pCmd, "norestart", &pszNoRestart);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);
            if ((pszNoRestart != NULL) && !strcmp(pszNoRestart, "true"))
            {
                flags = fNO_RESTART;
            }
            if (pCmd->op == OP_SET)
            {
                err = set_dns_servers(pszIfname, mode, count,
                                      (const char **)ppszDnsServersList, flags);
            }
            else if (pCmd->op == OP_ADD)
            {
                err = add_dns_server(pszIfname, ppszDnsServersList[0], flags);
            }
            else if (pCmd->op == OP_DEL)
            {
                err = delete_dns_server(pszIfname, ppszDnsServersList[0], flags);
            }
            break;

        case OP_GET:
            err = get_dns_servers(pszIfname, 0, &mode, &count,
                                  &ppszDnsServersList);
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
                fprintf(stdout, "%s ", ppszDnsServersList[i]);
            }
            fprintf(stdout, "\n");
            break;

        default:
            err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    netmgr_list_free(count, (void **)ppszDnsServersList);
    netmgr_free(pszServers);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_dns_domains(PNETMGR_CMD pCmd)
{
    uint32_t err = 0, flags = 0;
    size_t i = 0, count = 0;
    char *s1, *s2, *pszDnsDomains= NULL, **ppszDnsDomainsList = NULL;
    char *pszDomains = NULL, *pszIfname = NULL, *pszNoRestart = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    switch(pCmd->op)
    {
        case OP_SET:
        case OP_ADD:
        case OP_DEL:
            err = netmgrcli_find_cmdopt(pCmd, "domains", &pszDnsDomains);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszDnsDomains != NULL)
            {
                err = netmgr_alloc_string(pszDnsDomains, &pszDomains);
                bail_on_error(err);
                if (strlen(pszDomains) > 0)
                {
                    s2 = pszDomains;
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
                                   (void *)&ppszDnsDomainsList);
                bail_on_error(err);
                strcpy(pszDomains, pszDnsDomains);
                s2 = pszDomains;
                do {
                    s1 = strsep(&s2, ",");
                    if (strlen(s1) > 0)
                    {
                        err = netmgr_alloc_string(s1, &(ppszDnsDomainsList[i++]));
                        bail_on_error(err);
                    }
                } while (s2 != NULL);
            }
            err = netmgrcli_find_cmdopt(pCmd, "norestart", &pszNoRestart);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);
            if ((pszNoRestart != NULL) && !strcmp(pszNoRestart, "true"))
            {
                flags = fNO_RESTART;
            }
            if (pCmd->op == OP_SET)
            {
                err = set_dns_domains(pszIfname, count,
                                      (const char **)ppszDnsDomainsList, flags);
            }
            else if (pCmd->op == OP_ADD)
            {
                err = add_dns_domain(pszIfname, ppszDnsDomainsList[0], flags);
            }
            else if (pCmd->op == OP_DEL)
            {
                err = delete_dns_domain(pszIfname, ppszDnsDomainsList[0], flags);
                bail_on_error(err);
            }
            bail_on_error(err);
            break;

        case OP_GET:
            err = get_dns_domains(pszIfname, 0, &count, &ppszDnsDomainsList);
            bail_on_error(err);

            fprintf(stdout, "Domains=");
            for (i = 0; i < count; i++)
            {
                fprintf(stdout, "%s ", ppszDnsDomainsList[i]);
            }
            fprintf(stdout, "\n");
            break;

        default:
            err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    netmgr_list_free(count, (void **)ppszDnsDomainsList);
    netmgr_free(pszDomains);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_link_info(PNETMGR_CMD pCmd)
{
    uint32_t err = 0, mtu = 0;
    char *pszIfname = NULL, *pszLinkMode = NULL, *pszLinkState = NULL;
    char *pszMacAddr = NULL, *pszMtu = NULL, *pszEnd = NULL;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;

    switch (pCmd->op)
    {
        case OP_SET:
            err = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
            bail_on_error(err);

            err = netmgrcli_find_cmdopt(pCmd, "mode", &pszLinkMode);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszLinkMode != NULL)
            {
                if (!strcmp(pszLinkMode, "manual"))
                {
                    linkMode = LINK_MANUAL;
                }
                else if (!strcmp(pszLinkMode, "auto"))
                {
                    linkMode = LINK_AUTO;
                }
                if (linkMode == LINK_MODE_UNKNOWN)
                {
                    err = EDOM;
                }
                bail_on_error(err);

                err = set_link_mode(pszIfname, linkMode);
                bail_on_error(err);
            }

            err = netmgrcli_find_cmdopt(pCmd, "state", &pszLinkState);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszLinkState != NULL)
            {
                if (!strcmp(pszLinkState, "up"))
                {
                    linkState = LINK_UP;
                }
                else if (!strcmp(pszLinkState, "down"))
                {
                    linkState = LINK_DOWN;
                }
                if (linkState == LINK_STATE_UNKNOWN)
                {
                    err = EDOM;
                }
                bail_on_error(err);

                err = set_link_state(pszIfname, linkState);
                bail_on_error(err);
            }

            err = netmgrcli_find_cmdopt(pCmd, "macaddr", &pszMacAddr);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszMacAddr != NULL)
            {
                err = set_link_mac_addr(pszIfname, pszMacAddr);
                bail_on_error(err);
            }

            err = netmgrcli_find_cmdopt(pCmd, "mtu", &pszMtu);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszMtu != NULL)
            {
                mtu = (uint32_t)strtoul(pszMtu, &pszEnd, 10);
                err = set_link_mtu(pszIfname, mtu);
                bail_on_error(err);
            }
            break;
        case OP_GET:
            err = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
            break;
        default:
            err =  EINVAL;
    }
    bail_on_error(err);

cleanup:
    netmgr_free(pszMacAddr);
    netmgr_free(pszLinkMode);
    netmgr_free(pszMtu);
    netmgr_free(pszLinkState);
    return err;
error:
    goto cleanup;
}

typedef struct _NETMGR_CLI_HANDLER
{
    CMD_ID id;
    uint32_t (*pFnCmd)(PNETMGR_CMD);
} NETMGR_CLI_HANDLER, *PNETMGR_CLI_HANDLER;

NETMGR_CLI_HANDLER cmdHandler[] =
{
    { CMD_LINK_INFO,           cmd_link_info       },
    { CMD_IP4_ADDRESS,         cmd_ip4_address     },
    { CMD_IP6_ADDRESS,         cmd_ip6_address     },
    { CMD_IP_ROUTE,            cmd_ip_route        },
    { CMD_DHCP_DUID,           cmd_dhcp_duid       },
    { CMD_IF_IAID,             cmd_if_iaid         },
    { CMD_DNS_SERVERS,         cmd_dns_servers     },
    { CMD_DNS_DOMAINS,         cmd_dns_domains     },
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
        if (pCmd->id == cmdHandler[i].id)
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

