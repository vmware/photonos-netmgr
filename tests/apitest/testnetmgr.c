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

START_TEST(test_dhcp_duid)
{
    uint32_t err = 0;
    char *duid = NULL;
    char *pszTestDuid = "00:01:00:00:11:22:33:44:55:66:77:89";
    printf("Running DHCP DUID tests..\n");

    err = nm_set_duid(NULL, pszTestDuid);
    printf("set_duid_err = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_set_duid returned error: %s\n",
                   nm_get_error_info(err));

    err = nm_get_duid(NULL, &duid);
    printf("get_duid_err = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_get_duid returned error: %s\n",
                   nm_get_error_info(err));

    ck_assert_msg(!strcmp(duid, pszTestDuid),
                  "Was expecting %s got %s instead",
                  pszTestDuid, duid);
    netmgr_free(duid);
}
END_TEST

START_TEST(test_iaid)
{
    uint32_t err = 0, iaid = 0, testIaid = 2000;
    char *pszIfName = "eth0";
    char *pszFileName = NULL;
    char szValue[MAX_LINE] = "";

    printf("Running IAID test..\n");

    err = nm_set_iaid(pszIfName, testIaid);
    printf("nm_set_iaid = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_set_iaid returned error: %s\n",
                   nm_get_error_info(err));

    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    sprintf(szValue, "%u", testIaid);

    err = test_file_value(pszFileName, SECTION_DHCP, KEY_IAID, szValue);

    ck_assert_msg(err == 0,
                  "File Read for Iaid returned %s",
                  nm_get_error_info(err));

    err = nm_get_iaid(pszIfName, &iaid);
    printf("nm_get_iaid = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_set_iaid returned error: %s\n",
                   nm_get_error_info(err));

    ck_assert_msg(iaid == testIaid,
                  "Was expecting Iaid %lu but got %lu instead",
                  testIaid,
                  iaid);

    netmgr_free(pszFileName);
}
END_TEST

START_TEST(test_link_mode)
{
    uint32_t err = 0;
    char *pszIfName = "eth0";
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN, testLinkMode = LINK_AUTO;

    printf("Running link mode test..\n");

    err = nm_set_link_mode(pszIfName, testLinkMode);
    printf("nm_set_link_mode = %u\n", err);

    ck_assert_msg(err == 0,
                  "set_link_mode returned err %s\n",
                  nm_get_error_info(err));

    err = nm_get_link_mode(pszIfName, &linkMode);
    printf("nm_get_link_mode = %u\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_link_mode returned err %s\n",
                   nm_get_error_info(err));

    ck_assert_msg(testLinkMode == linkMode,
                  "Was expecting linkMode %s but found linkMode %s",
                  nm_link_mode_to_string(testLinkMode),
                  nm_link_mode_to_string(linkMode));
}
END_TEST

char *pszLinkState[]= {"DOWN", "UP"};
NET_LINK_STATE testLinkState[] = {LINK_DOWN, LINK_UP};

START_TEST(test_link_state)
{
    uint32_t err = 0;
    char *pszIfName = "eth0";
    char *pszFindLinkStateCmd = NULL;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;

    printf("Running link state test..\n");

    err = nm_set_link_state(pszIfName, testLinkState[_i]);
    printf("nm_set_link_state = %u\n", err);

    ck_assert_msg(err == 0,
                  "set_link_state returned %s\n",
                  nm_get_error_info(err));

    err = netmgr_alloc_string_printf(&pszFindLinkStateCmd,
                                     "ip link show dev %s | grep \"state %s\" > /dev/null",
                                     pszIfName, pszLinkState[_i]);
    ck_assert_msg(err == 0,
                  "Netmgr Alloc String returned err: %s\n",
                  nm_get_error_info(err));

    err = system_command(pszFindLinkStateCmd);
    ck_assert_msg(err == 0,
                  "Link State was not set. Error returned: %s\n",
                  nm_get_error_info(err));

    err = nm_get_link_state(pszIfName, &linkState);
    ck_assert_msg(err == 0,
                  "nm_get_link_state returned err %s",
                  nm_get_error_info(err));

    ck_assert_msg(testLinkState[_i] == linkState,
                  "Was expecting linkState %s but found linkState %s",
                  nm_link_state_to_string(testLinkState[_i]),
                  nm_link_state_to_string(linkState));
   netmgr_free(pszFindLinkStateCmd);
}
END_TEST

START_TEST(test_link_mac_addr)
{
    uint32_t err = 0;
    char *pszIfName = "eth0";
    char *pszMacAddress = NULL, *pszTestMacAddress = "00:0c:29:24:91:5c";
    char *pszFindLinkMacAddrCmd = NULL, *pszFileName = NULL;
    printf("Running link Mac Address test..\n");

    err = nm_set_link_mac_addr(pszIfName, pszTestMacAddress);
    ck_assert_msg(err == 0,
                  "set_link_mac_addr returned err %s",
                  nm_get_error_info(err));

    err = netmgr_alloc_string_printf(&pszFindLinkMacAddrCmd,
                                     "ip link show dev %s | grep \"link/ether %s\" > /dev/null",
                                     pszIfName, pszTestMacAddress);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = system_command(pszFindLinkMacAddrCmd);
    ck_assert_msg(err == 0, "Link Mac Addr was was not found err = %lu \n", err);

    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = test_file_value(pszFileName,
                          SECTION_LINK,
                          KEY_MAC_ADDRESS,
                          pszTestMacAddress);
    ck_assert_msg(err == 0,
                  "File Read for Mac Address returned: %s",
                  nm_get_error_info(err));

    err = nm_get_link_mac_addr(pszIfName, &pszMacAddress);
    printf("get_link_mac_addr = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg(!strcmp(pszTestMacAddress, pszMacAddress),
                  "Was expecting interface %s MacAdress %s but found %s",
                  pszIfName,
                  pszTestMacAddress,
                  pszMacAddress);

    netmgr_free(pszFileName);
    netmgr_free(pszMacAddress);
    netmgr_free(pszFindLinkMacAddrCmd);
}
END_TEST

START_TEST(test_link_mtu)
{
    uint32_t err = 0, mtu = 0, testMtu = 1500;
    char *pszIfName = "eth0";
    char *pszFindMtuCmd = NULL;
    char *pszFileName = NULL;
    char szMtu[MAX_LINE] = "";

    printf("Running link mtu test..\n");

    err = nm_set_link_mtu(pszIfName, testMtu);
    printf("set_link_mtu = %u\n", err);
    ck_assert_msg(err == 0, "set_link_mtu returned %lu", err);

    sprintf(szMtu, "%u", testMtu);
    err = netmgr_alloc_string_printf(&pszFindMtuCmd,
                                     "ip link show dev %s | grep \"mtu %s\" > /dev/null",
                                     pszIfName, szMtu);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = system_command(pszFindMtuCmd);

    ck_assert_msg(err == 0,
                  "Command %s err = %lu \n",
                  pszFindMtuCmd,
                  err);

    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = test_file_value(pszFileName, SECTION_LINK, KEY_MTU, szMtu);
    ck_assert_msg(err == 0,
                  "File Read for MTU returned %s",
                  nm_get_error_info(err));

    err = nm_get_link_mtu(pszIfName, &mtu);
    printf("get_link_mtu = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg(testMtu == mtu,
                  "Was expecting interface %s mtu %lu but found %lu",
                  pszIfName,
                  testMtu,
                  mtu);

    netmgr_free(pszFindMtuCmd);
    netmgr_free(pszFileName);
}
END_TEST

START_TEST(test_dns_servers)
{
    uint32_t err = 0;
    size_t i = 0, serverCount = 0, testServerCount = 0;
    NET_DNS_MODE mode = DNS_MODE_INVALID, testDnsMode = STATIC_DNS;
    char *pszIfName = "eth0", *pszFileName = NULL;
    char **ppszDnsServers = NULL;
    char *pszSearchResolveFile = NULL;
    char *pszSearchNWFile = NULL;
    char *pszTestDnsServers[] = {"10.10.10.10", "20.20.20.20", "30.30.30.30"};
    char *pszTestDelDnsServers[] = {"20.20.20.20"};
    char *pszTestPostDelDnsServers[] = {"10.10.10.10", "30.30.30.30"};
    char *pszTestAddDnsServers[] = {"40.40.40.40"};
    char *pszTestPostAddDnsServers[] = {"10.10.10.10", "30.30.30.30", "40.40.40.40"};

    printf("Running DHCP DNS Servers test..\n");

    testServerCount = sizeof(pszTestDnsServers) / sizeof(char *);

    //Test mode DHCP_DNS and send values. API should return EINVAL
    err = nm_set_dns_servers(pszIfName,
                             DHCP_DNS,
                             testServerCount,
                             (const char **)pszTestDnsServers);
    ck_assert_msg(err == NM_ERR_INVALID_MODE,
                  "nm_set_dns_servers returned error: %s\n",
                  nm_get_error_info(err));

    //Test mode DHCP_DNS with empty Server list
    err = nm_set_dns_servers(pszIfName,
                             DHCP_DNS,
                             0,
                             NULL);
    ck_assert_msg(err == 0, "nm_set_dns_servers returned %lu\n", err);

    err = nm_get_dns_servers(pszIfName,
                             &mode,
                             &serverCount,
                             &ppszDnsServers);
    printf("nm_get_dns_servers = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg((0 == serverCount),
                  "Was expecting 0 dnsServer but found %lu dnsServer",
                  serverCount);

    err = nm_set_dns_servers(pszIfName,
                             testDnsMode,
                             testServerCount,
                             (const char **)pszTestDnsServers);
    printf("nm_set_dns_servers = %u\n", err);
    ck_assert_msg(err == 0, "nm_set_dns_servers returned %lu\n", err);

    //Search for the servers in resolve.conf file
    for (i = 0; i < testServerCount; i++)
    {
        err = netmgr_alloc_string_printf(&pszSearchResolveFile,
                                         "grep \"nameserver %s\" %s > /dev/null",
                                         pszTestDnsServers[i],
                                         RESOLV_CONF_FILENAME);
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

        err = system_command(pszSearchResolveFile);
        ck_assert_msg(err == 0,
                      "DNS Server %s was not Set in file %s err = %lu \n",
                      pszTestDnsServers[i],
                      RESOLV_CONF_FILENAME,
                      err);
        netmgr_free(pszSearchResolveFile);
    }

    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = test_file_value_list(pszFileName,
                               SECTION_NETWORK,
                               KEY_DNS,
                               (const char **)pszTestDnsServers,
                               testServerCount);
    ck_assert_msg(err == 0,
                  "File Read for DNS Servers returned error: %s",
                  nm_get_error_info(err));

    err = nm_get_dns_servers(pszIfName,
                             &mode,
                             &serverCount,
                             &ppszDnsServers);
    printf("nm_get_dns_servers = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg((testServerCount == serverCount),
                  "Was expecting %lu dnsServer but found %lu dnsServer",
                  testServerCount, serverCount);

    for (i = 0; i < serverCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsServers[i], pszTestDnsServers[i]),
                      "Was expecting Dns Domain %s but found %s",
                      ppszDnsServers[i],
                      pszTestDnsServers[i]);
    }

    netmgr_list_free(serverCount, (void **)ppszDnsServers);
    serverCount = 0;
    ppszDnsServers = NULL;

    // Test deletion of servers
    testServerCount = sizeof(pszTestDelDnsServers) / sizeof(char *);

    for (i = 0; i < testServerCount; i++)
    {
        err = nm_delete_dns_server(pszIfName,
                                   (const char *)pszTestDelDnsServers[i]);
        printf("nm_delete_dns_servers = %u\n", err);
        ck_assert_msg(err == 0,
                      "nm_delete_dns_servers returned error: %s\n",
                      nm_get_error_info(err));

        err = netmgr_alloc_string_printf(&pszSearchResolveFile,
                                         "grep \"nameserver %s\" %s > /dev/null",
                                         pszTestDelDnsServers[i],
                                         RESOLV_CONF_FILENAME);
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

        err = system_command(pszSearchResolveFile);
        ck_assert_msg(err != 0,
                      "DNS Server %s was Set in file %s err = %lu \n",
                      pszTestDelDnsServers[i],
                      RESOLV_CONF_FILENAME,
                      err);
        netmgr_free(pszSearchResolveFile);
    }

    testServerCount = sizeof(pszTestPostDelDnsServers) / sizeof(char *);
    err = test_file_value_list(pszFileName,
                               SECTION_NETWORK,
                               KEY_DNS,
                               (const char **)pszTestPostDelDnsServers,
                               testServerCount);
    ck_assert_msg(err == 0,
                  "File Read for DNS Servers returned error: %s",
                  nm_get_error_info(err));

    err = nm_get_dns_servers(pszIfName,
                             &mode,
                             &serverCount,
                             &ppszDnsServers);
    printf("nm_get_dns_servers = %u\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_dns_servers returned error: %s\n",
                  nm_get_error_info(err));

    ck_assert_msg((testServerCount == serverCount),
                  "Was expecting %lu dnsServer but found %lu dnsServer",
                  testServerCount, serverCount);

    for (i = 0; i < serverCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsServers[i], pszTestPostDelDnsServers[i]),
                      "Was expecting Dns Domain %s but found %s",
                      ppszDnsServers[i],
                      pszTestDnsServers[i]);
    }

    netmgr_list_free(serverCount, (void **)ppszDnsServers);

    serverCount = 0;
    ppszDnsServers = NULL;

    // Test Addition of servers
    testServerCount = sizeof(pszTestAddDnsServers) / sizeof(char *);

    for (i = 0; i < testServerCount; i++)
    {
        err = nm_add_dns_server(pszIfName,
                                (const char *)pszTestAddDnsServers[i]);
        printf("nm_add_dns_servers = %u\n", err);
        ck_assert_msg(err == 0,
                      "nm_add_dns_servers returned error: %s\n",
                      nm_get_error_info(err));

        err = netmgr_alloc_string_printf(&pszSearchResolveFile,
                                         "grep \"nameserver %s\" %s > /dev/null",
                                         pszTestAddDnsServers[i],
                                         RESOLV_CONF_FILENAME);
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

        err = system_command(pszSearchResolveFile);
        ck_assert_msg(err == 0,
                      "DNS Server %s was Set in file %s err = %lu \n",
                      pszTestDelDnsServers[i],
                      RESOLV_CONF_FILENAME,
                      err);
        netmgr_free(pszSearchResolveFile);
    }

    testServerCount = sizeof(pszTestPostAddDnsServers) / sizeof(char *);
    err = test_file_value_list(pszFileName,
                               SECTION_NETWORK,
                               KEY_DNS,
                               (const char **)pszTestPostAddDnsServers,
                               testServerCount);
    ck_assert_msg(err == 0,
                  "File Read for DNS Servers returned error: %s",
                  nm_get_error_info(err));

    err = nm_get_dns_servers(pszIfName,
                             &mode,
                             &serverCount,
                             &ppszDnsServers);
    printf("nm_get_dns_servers = %u\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_dns_servers returned error: %s\n",
                  nm_get_error_info(err));

    ck_assert_msg((testServerCount == serverCount),
                  "Was expecting %lu dnsServer but found %lu dnsServer",
                  testServerCount, serverCount);

    for (i = 0; i < serverCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsServers[i], pszTestPostAddDnsServers[i]),
                      "Was expecting Dns Domain %s but found %s",
                      ppszDnsServers[i],
                      pszTestDnsServers[i]);
    }

    netmgr_free(pszFileName);
    netmgr_list_free(serverCount, (void **)ppszDnsServers);
}
END_TEST

START_TEST(test_dns_domains)
{
    uint32_t err = 0;
    size_t i = 0, domainCount = 0, testDomainCount = 0;
    char *pszIfName = "eth0", *pszSearchResolveFile;
    char *pszFileName = NULL;
    char **ppszDnsDomains = NULL;
    char *pszTestDnsDomains[] = {"bar.com", "abcd.com", "foo.com"};
    char *pszTestDelDnsDomains[] = {"foo.com"};
    char *pszTestPostDelDnsDomains[] = {"bar.com", "abcd.com"};
    char *pszTestAddDnsDomains[] = {"xyz.com"};
    char *pszTestPostAddDnsDomains[] = {"bar.com", "abcd.com", "xyz.com"};

    printf("Running DNS Domains test..\n");

    testDomainCount = sizeof(pszTestDnsDomains) / sizeof(char *);

    err = nm_set_dns_domains(pszIfName,
                             testDomainCount,
                             (const char **)pszTestDnsDomains);
    ck_assert_msg(err == 0, "nm_set_dns_domains returned %lu \n", err);

    for (i = 0; i < testDomainCount; i++)
    {
        err = netmgr_alloc_string_printf(&pszSearchResolveFile,
                                         "grep %s %s > /dev/null",
                                         pszTestDnsDomains[i],
                                         RESOLV_CONF_FILENAME);
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

        err = system_command(pszSearchResolveFile);
        ck_assert_msg(err == 0,
                      "DNS Domain %s was not Set in file %s err = %lu \n",
                      pszTestDnsDomains[i],
                      RESOLV_CONF_FILENAME,
                      err);
        netmgr_free(pszSearchResolveFile);
    }


    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = test_file_value_list(pszFileName,
                               SECTION_NETWORK,
                               KEY_DOMAINS,
                               (const char **)pszTestDnsDomains,
                               testDomainCount);
    ck_assert_msg(err == 0,
                  "File Read for DNS Domains returned error: %s",
                   nm_get_error_info(err));

    err = nm_get_dns_domains(pszIfName,
                             &domainCount,
                             &ppszDnsDomains);
    printf("nm_get_dns_domains = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg((testDomainCount == domainCount),
                  "Was expecting %lu dnsDomain but found %lu dnsDomain",
                  testDomainCount, domainCount);
    for (i = 0; i < domainCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsDomains[i],
                              pszTestDnsDomains[i]),
                      "Was expecting Dns Domain %s but found %s",
                      ppszDnsDomains[i],
                      pszTestDnsDomains[i]);
    }

    netmgr_list_free(domainCount, (void **)ppszDnsDomains);
    domainCount = 0;
    ppszDnsDomains = NULL;

    //Test deletion of Dns Domain
    testDomainCount = sizeof(pszTestDelDnsDomains) / sizeof(char *);

    for (i = 0; i < testDomainCount; i++)
    {
        err = nm_delete_dns_domain(pszIfName,
                                   (const char *)pszTestDelDnsDomains[i]);
        printf("nm_delete_dns_domains = %u\n", err);
        ck_assert_msg(err == 0,
                      "nm_delete_dns_domains returned error: %s\n",
                      nm_get_error_info(err));

        err = netmgr_alloc_string_printf(&pszSearchResolveFile,
                                         "grep %s %s > /dev/null",
                                         pszTestDelDnsDomains[i],
                                         RESOLV_CONF_FILENAME);
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

        err = system_command(pszSearchResolveFile);
        ck_assert_msg(err != 0,
                      "DNS Domain %s was Set in file %s err = %lu \n",
                      pszTestDelDnsDomains[i],
                      RESOLV_CONF_FILENAME,
                      err);
        netmgr_free(pszSearchResolveFile);
    }

    testDomainCount = sizeof(pszTestPostDelDnsDomains) / sizeof(char *);
    err = test_file_value_list(pszFileName,
                               SECTION_NETWORK,
                               KEY_DOMAINS,
                               (const char **)pszTestPostDelDnsDomains,
                               testDomainCount);
    ck_assert_msg(err == 0,
                  "File Read for DNS Domains returned error: %s",
                  nm_get_error_info(err));

    err = nm_get_dns_domains(pszIfName,
                             &domainCount,
                             &ppszDnsDomains);
    printf("nm_get_dns_domains = %u\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_dns_domains returned error: %s\n",
                  nm_get_error_info(err));

    ck_assert_msg((testDomainCount == domainCount),
                  "Was expecting %lu dns Domain but found %lu dns Domain",
                  testDomainCount, domainCount);

    for (i = 0; i < domainCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsDomains[i], pszTestPostDelDnsDomains[i]),
                      "Was expecting Dns Domain %s but found %s",
                      pszTestPostDelDnsDomains[i],
                      ppszDnsDomains[i]);
    }

    netmgr_list_free(domainCount, (void **)ppszDnsDomains);
    domainCount = 0;
    ppszDnsDomains = NULL;

    //Test Addition of Dns Domains
    testDomainCount = sizeof(pszTestAddDnsDomains) / sizeof(char *);

    for (i = 0; i < testDomainCount; i++)
    {
        err = nm_add_dns_domain(pszIfName,
                                (const char *)pszTestAddDnsDomains[i]);
        printf("nm_add_dns_domain = %u\n", err);
        ck_assert_msg(err == 0,
                      "nm_add_dns_domain returned error: %s\n",
                      nm_get_error_info(err));

        err = netmgr_alloc_string_printf(&pszSearchResolveFile,
                                         "grep %s %s > /dev/null",
                                         pszTestAddDnsDomains[i],
                                         RESOLV_CONF_FILENAME);
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

        err = system_command(pszSearchResolveFile);
        ck_assert_msg(err == 0,
                      "DNS Domain %s was not Set in file %s err = %lu \n",
                      pszTestAddDnsDomains[i],
                      RESOLV_CONF_FILENAME,
                      err);
        netmgr_free(pszSearchResolveFile);
    }

    testDomainCount = sizeof(pszTestPostAddDnsDomains) / sizeof(char *);
    err = test_file_value_list(pszFileName,
                               SECTION_NETWORK,
                               KEY_DOMAINS,
                               (const char **)pszTestPostAddDnsDomains,
                               testDomainCount);
    ck_assert_msg(err == 0,
                  "File Read for DNS Domains returned error: %s",
                  nm_get_error_info(err));

    err = nm_get_dns_domains(pszIfName,
                             &domainCount,
                             &ppszDnsDomains);
    printf("nm_get_dns_domains = %u\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_dns_domains returned error: %s\n",
                  nm_get_error_info(err));

    ck_assert_msg((testDomainCount == domainCount),
                  "Was expecting %lu dns Domain but found %lu dns Domain",
                  testDomainCount, domainCount);

    for (i = 0; i < domainCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsDomains[i], pszTestPostAddDnsDomains[i]),
                      "Was expecting Dns Domain %s but found %s",
                      pszTestPostAddDnsDomains[i],
                      ppszDnsDomains[i]);
    }

    netmgr_free(pszFileName);
    netmgr_list_free(domainCount, (void **)ppszDnsDomains);
}
END_TEST

START_TEST(test_hostname)
{
    uint32_t err = 0;
    size_t lineLen = 0;
    FILE *pFile = NULL;
    char *pszHostName = NULL;
    char *pszHostNameCmd = NULL;
    char *pszTestHostName = "netmgr_ut";

    printf("Running Hostname test..\n");

    err = nm_set_hostname(pszTestHostName);
    printf("nm_set_hostname = %u\n", err);
    ck_assert_msg(err == 0,
                  "nm_set_hostname returned err %s\n",
                  nm_get_error_info(err));

    err = netmgr_alloc_string_printf(&pszHostNameCmd,
                                     "hostname | grep %s > /dev/null",
                                     pszTestHostName);
    ck_assert_msg(err == 0,
                  "Netmgr Alloc String failed with error %s\n",
                  nm_get_error_info(err));

    err = system_command(pszHostNameCmd);
    ck_assert_msg(err == 0, "Hostname not set\n");

    err = nm_get_hostname(&pszHostName);
    printf("nm_get_hostname = %u\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_hostname returned %s\n",
                  nm_get_error_info(err));

    ck_assert_msg(!strcmp(pszTestHostName, pszHostName),
                  "Was expecting %s but get host name returned %s\n",
                  pszTestHostName,
                  pszHostName);

    netmgr_free(pszHostNameCmd);
    netmgr_free(pszHostName);
}
END_TEST

START_TEST(test_firewall_rules)
{
    uint32_t err = 0;
    size_t i = 0, ruleCount = 0;
    NET_FW_RULE testFwRule = {0};
    NET_FW_RULE **ppNetFwRule = NULL;

    printf("Running Firewall Rules test..\n");

    testFwRule.ipVersion = IPV4;
    testFwRule.type = FW_RAW;
    testFwRule.pszRawFwRule = "-A INPUT -i eth1 -j ACCEPT ";

    err = nm_add_firewall_rule(&testFwRule);
    printf("nm_add_firewall_rule = %u\n", err);

    err = nm_get_firewall_rules(&ruleCount, &ppNetFwRule);
    printf("nm_get_firewall_rules = %u\n", err);

    //TODO Write the comparision test
    for (i = 0; i < ruleCount; i++)
    {
        netmgr_free(ppNetFwRule[i]->pszRawFwRule);
        netmgr_free(ppNetFwRule[i]);
    }
    netmgr_free(ppNetFwRule);
}
END_TEST

START_TEST(test_if_up_down)
{
    uint32_t err = 0;
    char *pszIfName = "eth0", *pszLinkState = NULL;
    char *pszSetInterfaceStateCmd = NULL;
    char *pszFindLinkStateCmd = NULL;

    printf("Running Interface Up/Down test..\n");
    err = netmgr_alloc_string_printf(&pszSetInterfaceStateCmd,
                                     "ip link set dev %s down",
                                     pszIfName);
    ck_assert_msg(err == 0,
                  "Netmgr Alloc String failed with error %s\n",
                  nm_get_error_info(err));

    err = system_command(pszSetInterfaceStateCmd);
    ck_assert_msg(err == 0, "%s command failed\n", pszSetInterfaceStateCmd);
    netmgr_free(pszSetInterfaceStateCmd);

    err = nm_ifup(pszIfName);
    ck_assert_msg(err == 0,
                  "nm_ifup returned error %s\n",
                  nm_get_error_info(err));

    pszLinkState = "UP";
    err = netmgr_alloc_string_printf(&pszFindLinkStateCmd,
                                     "ip link show dev %s | grep \"state %s\" "
                                     "> /dev/null",
                                     pszIfName, pszLinkState);
    ck_assert_msg(err == 0,
                  "Netmgr Alloc String returned err %s\n",
                  nm_get_error_info(err));

    err = system_command(pszFindLinkStateCmd);
    ck_assert_msg(err == 0, "Link State was not set UP\n");
    netmgr_free(pszFindLinkStateCmd);

    err = nm_ifdown(pszIfName);
    ck_assert_msg(err == 0,
                  "nm_ifdown returned error %s\n",
                  nm_get_error_info(err));

    pszLinkState = "DOWN";
    err = netmgr_alloc_string_printf(&pszFindLinkStateCmd,
                                     "ip link show dev %s | grep \"state %s\" "
                                     "> /dev/null",
                                     pszIfName, pszLinkState);
    ck_assert_msg(err == 0,
                  "Netmgr Alloc String returned err %s\n",
                  nm_get_error_info(err));

    err = system_command(pszFindLinkStateCmd);
    ck_assert_msg(err == 0, "Link State was not set DOWN\n");
    netmgr_free(pszFindLinkStateCmd);

    err = netmgr_alloc_string_printf(&pszSetInterfaceStateCmd,
                                     "ip link set dev %s up",
                                     pszIfName);
    ck_assert_msg(err == 0,
                  "Netmgr Alloc String failed with error %s\n",
                  nm_get_error_info(err));

    err = system_command(pszSetInterfaceStateCmd);
    ck_assert_msg(err == 0, "%s command failed\n", pszSetInterfaceStateCmd);
    netmgr_free(pszSetInterfaceStateCmd);
}
END_TEST

START_TEST(test_ntp_servers)
{
    uint32_t err = 0;
    size_t i = 0, ntpServerCount = 0, testNtpServerCount = 0;
    char *pszSearchNtpConfFile = NULL;
    char **ppszNtpServers = NULL;
    char *pszTestNtpServers[] = {"0.us.pool.ntp.org", "1.us.pool.ntp.org"};
    char *pszTestDelNtpServers[] = {"0.us.pool.ntp.org"};
    char *pszTestPostDeleteNtpServers[] = {"1.us.pool.ntp.org"};
    char *pszTestAddNtpServers[] = {"2.us.pool.ntp.org"};
    char *pszTestPostAddNtpServers[] = {"1.us.pool.ntp.org", "2.us.pool.ntp.org"};

    printf("Running NTP Servers test..\n");

    testNtpServerCount = sizeof(pszTestNtpServers) / sizeof(char *);

    err = nm_set_ntp_servers(testNtpServerCount,
                             (const char **)pszTestNtpServers);
    ck_assert_msg(err == 0,
                  "nm_set_ntp_servers returned error: %s\n",
                  nm_get_error_info(err));


    for (i = 0; i < testNtpServerCount; i++)
    {
        err = netmgr_alloc_string_printf(&pszSearchNtpConfFile,
                                         "grep \"server %s\" %s > /dev/null",
                                         pszTestNtpServers[i],
                                         "/etc/ntp.conf");
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

        err = system_command(pszSearchNtpConfFile);
        ck_assert_msg(err == 0,
                      "NTP Server %s was not Set in file /etc/ntp.conf.%s command returned err = %lu\n",
                      pszTestNtpServers[i],
                      pszSearchNtpConfFile,
                      err);
        netmgr_free(pszSearchNtpConfFile);
    }

    err = nm_get_ntp_servers(&ntpServerCount,
                             &ppszNtpServers);
    printf("nm_get_ntp_servers returned = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_get_ntp_servers returned error:%s\n",
                  nm_get_error_info(err));

    ck_assert_msg((testNtpServerCount == ntpServerCount),
                  "Was expecting %lu ntp servers but found %lu ntp servers\n",
                  testNtpServerCount, ntpServerCount);

    for (i = 0; i < ntpServerCount; i++)
    {
        ck_assert_msg(!strcmp(ppszNtpServers[i], pszTestNtpServers[i]),
                      "Was expecting NTP server %s but found %s\n",
                      pszTestNtpServers[i],
                      ppszNtpServers[i]);
    }

    netmgr_list_free(ntpServerCount, (void **)ppszNtpServers);
    ppszNtpServers = NULL;
    ntpServerCount = 0;

    testNtpServerCount = sizeof(pszTestDelNtpServers) / sizeof(char *);

    err = nm_delete_ntp_servers(testNtpServerCount,
                                (const char **)pszTestDelNtpServers);
    ck_assert_msg(err == 0,
                  "nm_delete_ntp_servers returned error: %s\n",
                  nm_get_error_info(err));

    for (i = 0; i < testNtpServerCount; i++)
    {
        err = netmgr_alloc_string_printf(&pszSearchNtpConfFile,
                                         "grep \"server %s\" %s > /dev/null",
                                         pszTestDelNtpServers[i],
                                         "/etc/ntp.conf");
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

        err = system_command("grep \"server 0.us.pool.ntp.org\" /etc/ntp.conf");
        ck_assert_msg(err != 0,
                      "NTP Server %s was Set in file /etc/ntp.conf."
                      "\"%s\" command returned err = %lu\n",
                      pszTestDelNtpServers[i],
                      pszSearchNtpConfFile,
                      err);
        netmgr_free(pszSearchNtpConfFile);
    }
    err = nm_get_ntp_servers(&ntpServerCount,
                             &ppszNtpServers);
    printf("nm_get_ntp_servers returned = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_get_ntp_servers returned error:%s\n",
                  nm_get_error_info(err));

    testNtpServerCount = sizeof(pszTestPostDeleteNtpServers) / sizeof(char *);

    ck_assert_msg((testNtpServerCount == ntpServerCount),
                  "Was expecting %lu ntp servers but found %lu ntp servers\n",
                  testNtpServerCount, ntpServerCount);

    for (i = 0; i < ntpServerCount; i++)
    {
        ck_assert_msg(!strcmp(ppszNtpServers[i],
                              pszTestPostDeleteNtpServers[i]),
                      "Was expecting NTP server %s but found %s\n",
                      pszTestPostDeleteNtpServers[i],
                      ppszNtpServers[i]);
    }


    netmgr_list_free(ntpServerCount, (void **)ppszNtpServers);
    ppszNtpServers = NULL;
    ntpServerCount = 0;

    testNtpServerCount = sizeof(pszTestAddNtpServers) / sizeof(char *);

    err = nm_add_ntp_servers(testNtpServerCount,
                             (const char **)pszTestAddNtpServers);
    ck_assert_msg(err == 0,
                  "nm_add_ntp_servers returned error: %s\n",
                  nm_get_error_info(err));


    testNtpServerCount = sizeof(pszTestPostAddNtpServers) / sizeof(char *);
    for (i = 0; i < testNtpServerCount; i++)
    {
        err = netmgr_alloc_string_printf(&pszSearchNtpConfFile,
                                         "grep \"server %s\" %s > /dev/null",
                                         pszTestPostAddNtpServers[i],
                                         "/etc/ntp.conf");
        ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

        err = system_command(pszSearchNtpConfFile);
        ck_assert_msg(err == 0,
                      "NTP Server %s was not Set in file /etc/ntp.conf.%s command returned err = %lu\n",
                      pszTestPostAddNtpServers[i],
                      pszSearchNtpConfFile,
                      err);
        netmgr_free(pszSearchNtpConfFile);
    }

    err = nm_get_ntp_servers(&ntpServerCount,
                             &ppszNtpServers);
    printf("nm_get_ntp_servers returned = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_get_ntp_servers returned error:%s\n",
                  nm_get_error_info(err));

    ck_assert_msg((testNtpServerCount == ntpServerCount),
                  "Was expecting %lu ntp servers but found %lu ntp servers\n",
                  testNtpServerCount, ntpServerCount);

    for (i = 0; i < ntpServerCount; i++)
    {
        ck_assert_msg(!strcmp(ppszNtpServers[i],
                              pszTestPostAddNtpServers[i]),
                      "Was expecting NTP server %s but found %s\n",
                      pszTestPostAddNtpServers[i],
                      ppszNtpServers[i]);
    }

    netmgr_list_free(ntpServerCount, (void **)ppszNtpServers);
}
END_TEST


START_TEST(test_routes)
{
    uint32_t err = 0, routeMetric = 1024;
    size_t i = 0, routeCount = 0;
    char *pszIfName = "eth0";
    char *pszTestDestNetwork = "192.168.76.0/24";
    char *pszTestGateway = "192.168.77.2";
    NET_ROUTE_SCOPE testRouteScope = GLOBAL_ROUTE;
    NET_IP_ROUTE testIpRoute = { 
                                  pszIfName,
                                  pszTestDestNetwork,
                                  "",
                                  pszTestGateway,
                                  testRouteScope,
                                  routeMetric,
                                  0
                                };
    char *pszFileName = NULL;
    char szMetric[MAX_LINE] = "";
    NET_IP_ROUTE **ppRouteList = NULL;

    printf("Running IP Route test..\n");

    err = nm_add_static_ip_route(&testIpRoute);
    printf("nm_add_static_ip_route = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_add_static_ip_route returned error:%s\n",
                  nm_get_error_info(err));

    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = test_file_routes(pszFileName,
                           SECTION_ROUTE,
                           KEY_DEST,
                           (const char *)testIpRoute.pszDestNetwork);
    ck_assert_msg(err == 0,
                  "File Read for Route Destination Network returned error: %s",
                  nm_get_error_info(err));

    err = test_file_routes(pszFileName,
                           SECTION_ROUTE,
                           KEY_GATEWAY,
                           (const char *)testIpRoute.pszGateway);
    ck_assert_msg(err == 0,
                  "File Read for Route Gateway returned error: %s",
                  nm_get_error_info(err));

    sprintf(szMetric, "%u", testIpRoute.metric);

    err = test_file_routes(pszFileName,
                           SECTION_ROUTE,
                           KEY_METRIC,
                           (const char *)szMetric);
    ck_assert_msg(err == 0,
                  "File Read for Route Metric returned error: %s",
                  nm_get_error_info(err));

    err = nm_get_static_ip_routes(pszIfName, &routeCount, &ppRouteList);
    printf("nm_get_static_ip_route = %u\n", err);

    ck_assert_msg(err == 0,
                  "nm_get_static_ip_route returned error:%s\n",
                  nm_get_error_info(err));

    ck_assert_msg(routeCount == 1,
                  "nm_get_static_ip_route returned %lu routes but expected "
                  "1 route\n",
                  routeCount);

    for (i = 0; i < routeCount; i++)
    {
        ck_assert_msg(!strcmp(testIpRoute.pszDestNetwork,
                              ppRouteList[i]->pszDestNetwork),
                      "Was expecting Destination Network %s but found %s\n",
                      testIpRoute.pszDestNetwork,
                      ppRouteList[i]->pszDestNetwork);

        ck_assert_msg(!strcmp(testIpRoute.pszGateway,
                              ppRouteList[i]->pszGateway),
                      "Was expecting Gateway %s but found %s\n",
                      testIpRoute.pszGateway,
                      ppRouteList[i]->pszGateway);

        ck_assert_msg(testIpRoute.metric == ppRouteList[i]->metric,
                      "Was expecting Metric %lu but found %lu\n",
                      testIpRoute.metric,
                      ppRouteList[i]->metric);

    }

    netmgr_free(pszFileName);
    for (i = 0; i < routeCount; i++)
    {
        netmgr_free(ppRouteList[i]->pszInterfaceName);
        netmgr_free(ppRouteList[i]->pszDestNetwork);
        netmgr_free(ppRouteList[i]->pszSourceNetwork);
        netmgr_free(ppRouteList[i]->pszGateway);
        netmgr_free(ppRouteList[i]);
    }
    netmgr_free(ppRouteList);
}
END_TEST

START_TEST(test_ip4)
{
    uint32_t err = 0;
    char *pszIfName = "eth0";
    char *pszFileName = NULL;
    char *pszTestIpv4AddrPrefix = "10.10.10.1/24";
    char *pszTestIpv4Gateway = "192.168.77.2";
    char *pszIpv4AddrPrefix = NULL;
    char *pszIpv4Gateway = NULL;
    char *pszGrepIpCmd = NULL;
    NET_IPV4_ADDR_MODE ip4Mode = IPV4_ADDR_MODE_MAX;

    printf("Running IPv4 tests...\n");

    err = nm_set_ipv4_addr_gateway(pszIfName,
                                   IPV4_ADDR_MODE_STATIC,
                                   pszTestIpv4AddrPrefix,
                                   pszTestIpv4Gateway);
    printf("nm_set_ipv4_addr_gateway returned %lu\n", err);
    ck_assert_msg(err == 0,
                  "nm_set_ipv4_addr_gateway returned error: %s\n",
                   nm_get_error_info(err));

    err = nm_get_ipv4_addr_gateway(pszIfName,
                                   &ip4Mode,
                                   &pszIpv4AddrPrefix,
                                   &pszIpv4Gateway);
    printf("nm_get_ipv4_addr_gateway returned %lu\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_ipv4_addr_gateway returned error: %s\n",
                   nm_get_error_info(err));

    ck_assert_msg(TEST_FLAG(ip4Mode, IPV4_ADDR_MODE_STATIC),
                  "IPV4_ADDR_MODE_STATIC was not set\n");

    ck_assert_msg((pszIpv4AddrPrefix != NULL),
                  "Ipv4 Address returned is NULL instead of %s\n",
                   pszTestIpv4AddrPrefix);

    ck_assert_msg((pszIpv4Gateway != NULL),
                  "Gateway value returned is NULL instead of %s\n",
                   pszTestIpv4Gateway);

    ck_assert_msg(!strcmp(pszTestIpv4AddrPrefix, pszIpv4AddrPrefix),
                  "nm_get_ipv4_addr_gateway returned Ipv4 Address %s instead of %s\n",
                   pszIpv4AddrPrefix,
                   pszTestIpv4AddrPrefix);

    ck_assert_msg(!strcmp(pszTestIpv4Gateway, pszIpv4Gateway),
                  "nm_get_ipv4_addr_gateway returned Gateway %s instead of %s\n",
                   pszIpv4Gateway,
                   pszTestIpv4Gateway);

    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = test_file_value(pszFileName, SECTION_NETWORK, KEY_ADDRESS, pszTestIpv4AddrPrefix);
    ck_assert_msg(err == 0,
                  "File Read for Static IPv4 address returned %s",
                  nm_get_error_info(err));

    err = test_file_value(pszFileName, SECTION_NETWORK, KEY_GATEWAY, pszTestIpv4Gateway);
    ck_assert_msg(err == 0,
                  "File Read for Static IPv4 Gateway returned %s",
                  nm_get_error_info(err));

    err = netmgr_alloc_string_printf(&pszGrepIpCmd,
                                     "ip addr show dev %s | grep \"inet %s\" > /dev/null",
                                     pszIfName,
                                     pszTestIpv4AddrPrefix);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

    err = system_command(pszGrepIpCmd);
    ck_assert_msg(err == 0,
                  "Command %s failed after setting the IPv6 address\n",
                  pszGrepIpCmd);
    netmgr_free(pszFileName);
    netmgr_free(pszGrepIpCmd);
    netmgr_free(pszIpv4AddrPrefix);
    netmgr_free(pszIpv4Gateway);

}
END_TEST

START_TEST(test_ip6)
{
    uint32_t err = 0, testEnableDhcp = 0, testEnableAutoConf = 1;
    uint32_t enableDhcp = 0, enableAutoConf = 1;
    char *pszIfName = "eth0";
    char *pszTestIpv6AddrPrefix = "fc00:10:118:101:20c:29ff:fe41:2fba/64";
    char *pszTestIpv6Gateway = "192.168.77.2";
    char *pszIpv6AddrPrefix = NULL;
    char *pszIpv6Gateway = NULL;
    char *pszDisableIpv6Stat = NULL;
    char *pszEnableAutoConfStat = NULL;
    char *pszSysCtlValCmd = NULL;
    char *pszGrepIpCmd = NULL;
    char *pszFileName = NULL;

    printf("Running IPv6 tests..\n");

    //Disable dhcp and enable auto conf
    err = nm_set_ipv6_addr_mode(pszIfName,
                                testEnableDhcp,
                                testEnableAutoConf);
    printf("nm_set_ipv6_addr_mode returned %lu\n", err);
    ck_assert_msg(err == 0,
                  "nm_set_ipv6_addr_mode returned error: %s\n",
                  nm_get_error_info(err));

    err = nm_get_ipv6_addr_mode(pszIfName,
                                &enableDhcp,
                                &enableAutoConf);
    printf("nm_get_ipv6_addr_mode returned %lu\n", err);
    ck_assert_msg(err == 0,
                  "nm_get_ipv6_addr_mode returned error: %s\n",
                  nm_get_error_info(err));

    ck_assert_msg(enableDhcp == testEnableDhcp,
                  "nm_get_ipv6_addr_mode returned enableDhcp %lu instead of %lu\n",
                   enableDhcp,
                   testEnableDhcp);

    ck_assert_msg(enableAutoConf == testEnableAutoConf,
                  "nm_get_ipv6_addr_mode returned enableAutoConf %lu instead of %lu\n",
                   enableAutoConf,
                   testEnableAutoConf);

    err = netmgr_alloc_string_printf(&pszFileName,
                                     "/etc/systemd/network/10-%s.network",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu", err);

    err = test_file_value(pszFileName, SECTION_NETWORK, KEY_DHCP, "no");
    ck_assert_msg(err == 0,
                  "File Read for Static IPv4 address returned %s",
                  nm_get_error_info(err));

    err = netmgr_alloc_string_printf(&pszEnableAutoConfStat,
                                     "grep 1 /proc/sys/net/ipv6/conf/%s/autoconf > /dev/null",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

    err = system_command(pszEnableAutoConfStat);
    ck_assert_msg(err == 0,
                  "AutoConf is disabled in file "
                  "/proc/sys/net/ipv6/conf/%s/disable_ipv6 after "
                  "setting AutoConf\n",
                  pszIfName);
    netmgr_free(pszEnableAutoConfStat);

    err = netmgr_alloc_string_printf(&pszSysCtlValCmd,
                                     "grep net.ipv6.conf.%s.autoconf=1 %s > /dev/null",
                                     pszIfName,
                                     SYSCTL_CONF_FILENAME);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

    err = system_command(pszSysCtlValCmd);
    ck_assert_msg(err == 0,
                  "AutoConf Key: net.ipv6.conf.%s.autoconf=1 not found in file "
                  "%s\n",
                  pszIfName,
                  SYSCTL_CONF_FILENAME);
    netmgr_free(pszSysCtlValCmd);

    //Test static ipv6 address
    err = nm_add_static_ipv6_addr(pszIfName,
                                  pszTestIpv6AddrPrefix);
    printf("nm_add_static_ipv6_addr returned %lu\n", err);
    ck_assert_msg(err == 0,
                  "nm_add_static_ipv6_addr returned error: %s\n",
                  nm_get_error_info(err));

    //Test contents of /proc/sys/net/ipv6/conf/%s/disable_ipv6 file
    err = netmgr_alloc_string_printf(&pszDisableIpv6Stat,
                                     "grep 0 /proc/sys/net/ipv6/conf/%s/disable_ipv6 > /dev/null",
                                     pszIfName);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

    err = system_command(pszDisableIpv6Stat);
    ck_assert_msg(err == 0,
                  "IPv6 is disabled in file "
                  "/proc/sys/net/ipv6/conf/%s/disable_ipv6 even after adding "
                  "static IPv6 addr\n",
                  pszIfName);
    netmgr_free(pszDisableIpv6Stat);

    //Test static ip address is set using ip command
    err = netmgr_alloc_string_printf(&pszGrepIpCmd,
                                     "ip addr show dev %s | grep \"inet6 %s\" > /dev/null",
                                     pszIfName,
                                     pszTestIpv6AddrPrefix);
    ck_assert_msg(err == 0, "Netmgr Alloc String failed %lu\n", err);

    err = system_command(pszGrepIpCmd);
    ck_assert_msg(err == 0,
                  "Command %s failed after setting the IPv6 address\n",
                  pszGrepIpCmd);

    //Test File for ipv6 address
    err = test_file_value(pszFileName, SECTION_NETWORK, KEY_ADDRESS, pszTestIpv6AddrPrefix);
    ck_assert_msg(err == 0,
                  "File Read for Static IPv6 address returned %s",
                  nm_get_error_info(err));

    err = nm_delete_static_ipv6_addr(pszIfName,
                                  pszTestIpv6AddrPrefix);
    printf("nm_del_static_ipv6_addr returned %lu\n", err);
    ck_assert_msg(err == 0,
                  "nm_del_static_ipv6_addr returned error: %s\n",
                  nm_get_error_info(err));

    //Test static ip using ip command
    err = system_command(pszGrepIpCmd);
    ck_assert_msg(err != 0,
                  "Command %s failed after deleting the IPv6 address\n",
                  pszGrepIpCmd);

    netmgr_free(pszGrepIpCmd);
    netmgr_free(pszFileName);
}
END_TEST
Suite *test_netmgr_suite(void)
{
    Suite *s;
    TCase *tcCore;

    s = suite_create("NetMgrTestSuite");
    tcCore = tcase_create("NetMgrTestCore");
    tcase_add_test(tcCore, test_dhcp_duid);
    tcase_add_test(tcCore, test_link_mac_addr);
    tcase_add_test(tcCore, test_link_mode);
    tcase_add_loop_test(tcCore, test_link_state, 0, 2);
    tcase_add_test(tcCore, test_link_mtu);
    tcase_add_test(tcCore, test_dns_servers);
    tcase_add_test(tcCore, test_iaid);
    tcase_add_test(tcCore, test_hostname);
    tcase_add_test(tcCore, test_dns_domains);
    tcase_add_test(tcCore, test_firewall_rules);
    tcase_add_test(tcCore, test_ntp_servers);
    tcase_add_test(tcCore, test_if_up_down);
    tcase_add_test(tcCore, test_ip4);
    tcase_add_test(tcCore, test_ip6);
    tcase_add_test(tcCore, test_routes);
    suite_add_tcase(s, tcCore);
    return s;
}

int main(void)
{
    int numFailed;
    Suite *s;
    SRunner *sr;
    printf("Running utils API Tests..\n");

    s = test_netmgr_suite();
    sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    numFailed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (numFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

