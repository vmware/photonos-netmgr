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
cmd_link_info(PNETMGR_CMD pCmd)
{
    uint32_t err = 0, mtu = 0;
    char *pszIfname = NULL, *pszLinkMode = NULL, *pszLinkState = NULL;
    char *pszMacAddr = NULL, *pszMtu = NULL, *pszEnd = NULL;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    NET_LINK_INFO *pNetLinkInfo = NULL;

    switch (pCmd->op)
    {
        case OP_SET:
            err = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
            bail_on_error(err);

            err = netmgrcli_find_cmdopt(pCmd, "macaddr", &pszMacAddr);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);
            if (pszMacAddr != NULL)
            {
                err = nm_set_link_mac_addr(pszIfname, pszMacAddr);
                bail_on_error(err);
            }

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
                    bail_on_error(err);
                }
                err = nm_set_link_mode(pszIfname, linkMode);
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
                err = nm_set_link_mtu(pszIfname, mtu);
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
                    err = nm_ifup(pszIfname);
                }
                else if (!strcmp(pszLinkState, "down"))
                {
                    err = nm_ifdown(pszIfname);
                }
                else
                {
                    err = EDOM;
                }
                bail_on_error(err);
            }
            break;

        case OP_GET:
            err = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            err = nm_get_link_info(pszIfname, &pNetLinkInfo);
            bail_on_error(err);

            fprintf(stdout, "%-10s\t%-17s\t%-10s\t%-10s\t%-10s\n", "Name",
                    "MacAddress", "Mode", "MTU", "State");
            while (pNetLinkInfo)
            {
                fprintf(stdout, "%-10s\t", pNetLinkInfo->pszInterfaceName);
                fprintf(stdout, "%-17s\t", pNetLinkInfo->pszMacAddress);
                fprintf(stdout, "%-10s\t",
                        nm_link_mode_to_string(pNetLinkInfo->mode));
                fprintf(stdout, "%-10u\t", pNetLinkInfo->mtu);
                fprintf(stdout, "%-25s\n",
                        nm_link_state_to_string(pNetLinkInfo->state));
                pNetLinkInfo = pNetLinkInfo->pNext;
            }
            break;

        default:
            err =  EINVAL;
    }
    bail_on_error(err);

cleanup:
    nm_free_link_info(pNetLinkInfo);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_ip4_address(PNETMGR_CMD pCmd)
{
    uint32_t err = 0;
    NET_IPV4_ADDR_MODE ip4Mode;
    char *pszIfName = NULL, *pszMode = NULL;
    char *pszIpAddr = NULL, *pszGateway = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfName);

    switch (pCmd->op)
    {
        case OP_SET:
            err = netmgrcli_find_cmdopt(pCmd, "mode", &pszMode);
            bail_on_error(err);

            if (!strcmp(pszMode, "dhcp"))
            {
                ip4Mode = IPV4_ADDR_MODE_DHCP;
            }
            else if (!strcmp(pszMode, "static"))
            {
                ip4Mode = IPV4_ADDR_MODE_STATIC;
            }
            else if (!strcmp(pszMode, "none"))
            {
                ip4Mode = IPV4_ADDR_MODE_NONE;
            }
            else
            {
                err = EINVAL;
                bail_on_error(err);
            }

            netmgrcli_find_cmdopt(pCmd, "address", &pszIpAddr);

            netmgrcli_find_cmdopt(pCmd, "gateway", &pszGateway);

            err = nm_set_ipv4_addr_gateway(pszIfName, ip4Mode, pszIpAddr,
                                           pszGateway);
            pszIpAddr = NULL;
            pszGateway = NULL;
            bail_on_error(err);
            break;

        case OP_GET:
            err = nm_get_ipv4_addr_gateway(pszIfName, &ip4Mode, &pszIpAddr,
                                           &pszGateway);
            bail_on_error(err);

            if (ip4Mode == IPV4_ADDR_MODE_NONE)
            {
                fprintf(stdout, "IPv4 Address Mode: none\n");
            }
            else if (ip4Mode == IPV4_ADDR_MODE_DHCP)
            {
                fprintf(stdout, "IPv4 Address Mode: dhcp\n");
            }
            else
            {
                fprintf(stdout, "IPv4 Address Mode: static\n");
            }
            if (pszIpAddr != NULL)
            {
                fprintf(stdout, "IPv4 Address=%s\n", pszIpAddr);
            }
            if (pszGateway != NULL)
            {
                fprintf(stdout, "IPv4 Gateway=%s\n", pszGateway);
            }
            // TODO: Display DHCP IPv4 address as well as static IPv4 address
            // TODO: Display address configured on interface (higher preference)
            // TODO: Display default gateway from interface (higher preference over file info)
            break;

        default:
            break;
    }

cleanup:
    netmgr_free(pszIpAddr);
    netmgr_free(pszGateway);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_ip6_address(PNETMGR_CMD pCmd)
{
    uint32_t err = 0, dhcpEnabled, autoconfEnabled;;
    char *pszIfName = NULL, *pszDhcp = NULL, *pszAutoconf = NULL;
    char *pszAddrList = NULL, *pszGateway = NULL, *pszNewGateway = NULL;
    char *a1, *a2;
    NET_IP_ADDR **ppIpAddrList = NULL;
    size_t i, count;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfName);

    err = nm_get_ipv6_addr_mode(pszIfName, &dhcpEnabled, &autoconfEnabled);
    bail_on_error(err);

    switch (pCmd->op)
    {
        case OP_ADD:
        case OP_DEL:
            err = netmgrcli_find_cmdopt(pCmd, "addrlist", &pszAddrList);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszAddrList != NULL)
            {
                a2 = pszAddrList;
                do {
                    a1 = strsep(&a2, ",");
                    if (strlen(a1) == 0)
                    {
                        continue;
                    }
                    if (pCmd->op == OP_ADD)
                    {
                        err = nm_add_static_ipv6_addr(pszIfName, a1);
                    }
                    else
                    {
                        err = nm_delete_static_ipv6_addr(pszIfName, a1);
                    }
                    bail_on_error(err);
                } while (a2 != NULL);
            }

            err = netmgrcli_find_cmdopt(pCmd, "gateway", &pszNewGateway);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszNewGateway != NULL)
            {
                err = nm_get_ipv6_gateway(pszIfName, &pszGateway);
                if (err == ENOENT)
                {
                    err = 0;
                }
                bail_on_error(err);

                if (pCmd->op == OP_ADD)
                {
                    if (pszGateway != NULL)
                    {
                        err = EEXIST;
                    }
                    else
                    {
                        err = nm_set_ipv6_gateway(pszIfName, pszNewGateway);
                    }
                }
                else
                {
                    if (!pszGateway || (strcmp(pszGateway, pszNewGateway) != 0))
                    {
                        err = ENOENT;
                    }
                    else
                    {
                        err = nm_set_ipv6_gateway(pszIfName, NULL);
                    }
                }
                bail_on_error(err);
                pszGateway = NULL;
            }

        case OP_SET:
            err = netmgrcli_find_cmdopt(pCmd, "dhcp", &pszDhcp);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);
            err = netmgrcli_find_cmdopt(pCmd, "autoconf", &pszAutoconf);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (!pszDhcp && !pszAutoconf)
            {
                break;
            }

            if (pszDhcp != NULL)
            {
                dhcpEnabled  = (!strcmp(pszDhcp, "1")) ? 1 : 0;
            }
            if (pszAutoconf != NULL)
            {
                autoconfEnabled  = (!strcmp(pszAutoconf, "1")) ? 1 : 0;
            }

            // TODO: Implement configuration of autoconf IPv6 enable / disable
            err = nm_set_ipv6_addr_mode(pszIfName, dhcpEnabled,
                                        autoconfEnabled);
            bail_on_error(err);
            break;

        case OP_GET:

            // TODO: Implement function to get IPv6 addr from ioctls,
            // and query static IP addr if that fails.
            err = nm_get_ip_addr(pszIfName, DHCP_IPV6 | AUTO_IPV6 | STATIC_IPV6,
                                 &count, &ppIpAddrList);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            err = nm_get_ipv6_gateway(pszIfName, &pszGateway);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (dhcpEnabled)
            {
                fprintf(stdout, "DHCP IPv6 enabled\n");
            }
            if (autoconfEnabled)
            {
            // TODO: Implement configuration of autoconf IPv6 enable / disable
                fprintf(stdout, "Autoconf IPv6 enabled\n");
            }
            for (i = 0; i < count; i++)
            {
                fprintf(stdout, "%s Address=%s\n",
                        nm_ip_addr_type_to_string(ppIpAddrList[i]->type),
                        ppIpAddrList[i]->pszIPAddrPrefix);
            }
            if (pszGateway != NULL)
            {
                fprintf(stdout, "IPv6 Gateway=%s\n", pszGateway);
            }
            // TODO: Display DHCP IPv4 address as well as static IPv4 address
            // TODO: Display address configured on interface (higher preference)
            // TODO: Display default gateway from interface (higher preference over file info)
            break;

        default:
            err = EINVAL;
    }

cleanup:
    if (ppIpAddrList != NULL)
    {
        for (i = 0; i < count; i++)
        {
            if (ppIpAddrList[i] == NULL)
            {
                continue;
            }
            netmgr_free(ppIpAddrList[i]->pszInterfaceName);
            netmgr_free(ppIpAddrList[i]->pszIPAddrPrefix);
        }
        netmgr_list_free(count, (void **)ppIpAddrList);
    }
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
                err = nm_add_static_ip_route(&ipRoute);
            }
            else
            {
                err = nm_delete_static_ip_route(&ipRoute);
            }
            bail_on_error(err);
            break;

        case OP_GET:
            err = nm_get_static_ip_routes(ipRoute.pszInterfaceName, &count,
                                          &ppRoutesList);
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

        err = nm_set_duid(pszIfname, pszDuid);
        pszDuid = NULL;
        bail_on_error(err);
    }

    if (pCmd->op == OP_GET)
    {
        err = nm_get_duid(pszIfname, &pszDuid);
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

        err = nm_set_iaid(pszIfname, (uint32_t)atoi(pszIaid));
        bail_on_error(err);
    }

    if (pCmd->op == OP_GET)
    {
        err = nm_get_iaid(pszIfname, &iaid);
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
    NET_DNS_MODE dnsMode = DNS_MODE_INVALID;
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
                dnsMode = DHCP_DNS;
            }
            else if (!strcmp(pszMode, "static"))
            {
                dnsMode = STATIC_DNS;
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
                        err = netmgr_alloc_string(s1,
                                                  &(ppszDnsServersList[i++]));
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
                //TODO: Handle norestart
            }
            if (pCmd->op == OP_SET)
            {
                err = nm_set_dns_servers(pszIfname, dnsMode, count,
                                         (const char **)ppszDnsServersList);
            }
            else if (pCmd->op == OP_ADD)
            {
                err = nm_add_dns_server(pszIfname, ppszDnsServersList[0]);
            }
            else if (pCmd->op == OP_DEL)
            {
                err = nm_delete_dns_server(pszIfname, ppszDnsServersList[0]);
            }
            break;

        case OP_GET:
            err = nm_get_dns_servers(pszIfname, &dnsMode, &count,
                                     &ppszDnsServersList);
            bail_on_error(err);

            if (dnsMode == STATIC_DNS)
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
    uint32_t err = 0;
    size_t i = 0, count = 0;
    char *s1, *s2, *pszDnsDomains= NULL, **ppszDnsDomainsList = NULL;
    char *pszDomains = NULL, *pszIfname = NULL, *pszNoRestart = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    switch (pCmd->op)
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
                        err = netmgr_alloc_string(s1,
                                                  &(ppszDnsDomainsList[i++]));
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
                //TODO: Handle
            }
            if (pCmd->op == OP_SET)
            {
                err = nm_set_dns_domains(pszIfname, count,
                                         (const char **)ppszDnsDomainsList);
            }
            else if (pCmd->op == OP_ADD)
            {
                err = nm_add_dns_domain(pszIfname, ppszDnsDomainsList[0]);
            }
            else if (pCmd->op == OP_DEL)
            {
                err = nm_delete_dns_domain(pszIfname, ppszDnsDomainsList[0]);
                bail_on_error(err);
            }
            bail_on_error(err);
            break;

        case OP_GET:
            err = nm_get_dns_domains(pszIfname, &count, &ppszDnsDomainsList);
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
cmd_ntp_servers(PNETMGR_CMD pCmd)
{
    uint32_t err = 0;
    size_t i = 0, count = 0;
    char *pszNtpServers = NULL;
    char *s1, *s2, *pszServers = NULL, **ppszNtpServersList = NULL;

    switch (pCmd->op)
    {
        case OP_SET:
        case OP_ADD:
        case OP_DEL:
            err = netmgrcli_find_cmdopt(pCmd, "servers", &pszNtpServers);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszNtpServers != NULL)
            {
                err = netmgr_alloc_string(pszNtpServers, &pszServers);
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
                                   (void *)&ppszNtpServersList);
                bail_on_error(err);
                strcpy(pszServers, pszNtpServers);
                s2 = pszServers;
                do {
                    s1 = strsep(&s2, ",");
                    if (strlen(s1) > 0)
                    {
                        err = netmgr_alloc_string(s1,
                                                  &(ppszNtpServersList[i++]));
                        bail_on_error(err);
                    }
                } while (s2 != NULL);
            }
            if (pCmd->op == OP_SET)
            {
                err = nm_set_ntp_servers(count,
                                         (const char **)ppszNtpServersList);
            }
            else if (pCmd->op == OP_ADD)
            {
                err = nm_add_ntp_servers(count,
                                         (const char **)ppszNtpServersList);
            }
            else if (pCmd->op == OP_DEL)
            {
                err = nm_delete_ntp_servers(count,
                                            (const char **)ppszNtpServersList);
            }
            break;

        case OP_GET:
            err = nm_get_ntp_servers(&count, &ppszNtpServersList);
            bail_on_error(err);

            fprintf(stdout, "NTPServers= ");
            for (i = 0; i < count; i++)
            {
                fprintf(stdout, "%s ", ppszNtpServersList[i]);
            }
            fprintf(stdout, "\n");
            break;

        default:
            err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    netmgr_list_free(count, (void **)ppszNtpServersList);
    netmgr_free(pszServers);
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_fw_rule(PNETMGR_CMD pCmd)
{
    uint32_t err = 0;
    char *pszFwRule = NULL;
    NET_FW_RULE netFwRule = {0};

    switch (pCmd->op)
    {
        case OP_ADD:
        case OP_DEL:
            err = netmgrcli_find_cmdopt(pCmd, "rule", &pszFwRule);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            netFwRule.ipVersion = IPV4;
            netFwRule.type = FW_RAW;
            netFwRule.pszRawFwRule = pszFwRule;
            pszFwRule = NULL;

            if (pCmd->op == OP_ADD)
            {
                err = nm_add_firewall_rule(&netFwRule);
            }
            else if (pCmd->op == OP_DEL)
            {
                err = nm_delete_firewall_rule(&netFwRule);
            }
            break;

        case OP_GET:
#if 0
            err = nm_get_ntp_servers(&count, &ppszNtpServersList);
            bail_on_error(err);

            fprintf(stdout, "NTPServers= ");
            for (i = 0; i < count; i++)
            {
                fprintf(stdout, "%s ", ppszNtpServersList[i]);
            }
            fprintf(stdout, "\n");
            break;
#endif
        default:
            err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    return err;

error:
    goto cleanup;
}

static uint32_t
cmd_net_info(PNETMGR_CMD pCmd)
{
    uint32_t err = 0;
    char *pszIfname = NULL, *pszParamName = NULL, *pszParamValue = NULL;

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    switch (pCmd->op)
    {
        case OP_SET:
            err = netmgrcli_find_cmdopt(pCmd, "paramname", &pszParamName);
            bail_on_error(err);

            err = netmgrcli_find_cmdopt(pCmd, "paramvalue", &pszParamValue);
            if (err == ENOENT)
            {
                err = 0;
            }
            bail_on_error(err);

            if (pszParamName != NULL)
            {
                err = nm_set_network_param(pszIfname, pszParamName,
                                           pszParamValue);
                pszParamValue = NULL;
                bail_on_error(err);
            }
            break;

        case OP_GET:
            err = netmgrcli_find_cmdopt(pCmd, "paramname", &pszParamName);
            bail_on_error(err);

            err = nm_get_network_param(pszIfname, pszParamName, &pszParamValue);
            bail_on_error(err);

            fprintf(stdout, "ParamName: %s, ParamValue: %s\n", pszParamName,
                    pszParamValue);
            break;

        default:
            err = EINVAL;
    }
    bail_on_error(err);

cleanup:
    netmgr_free(pszParamValue);
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
    { CMD_NTP_SERVERS,         cmd_ntp_servers     },
    { CMD_FW_RULE    ,         cmd_fw_rule         },
    { CMD_NET_INFO ,           cmd_net_info        },
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

