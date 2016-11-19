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

typedef struct _TEST_SYSTEM_NW_VALUES
{
    char *pDuid;
    size_t domainCount;
    char **ppszDnsDomains;
    size_t dnsServerCount;
    char **ppszDnsServers;
}TEST_SYSTEM_NW_VALUES, *PTEST_SYSTEM_NW_VALUES;

typedef struct _INTERFACE_VALUES
{
    char *pszIfName;
    char *pDuid;
    char *pszMacAddress;
    uint32_t mtu;
    uint32_t iaid;
    NET_LINK_MODE linkMode;
    NET_LINK_STATE linkState;
    size_t domainCount;
    char **ppszDnsDomains;
    size_t dnsServerCount;
    char **ppszDnsServers;
}TEST_INTERFACE_VALUES, *PTEST_INTERFACE_VALUES;

TEST_SYSTEM_NW_VALUES testSystemValues =
{
    "00:01:00:00:11:22:33:44:55:66:77:88",
    2,
    (char *[]){"bar.com", "abcd.com"},
    2,
    (char *[]){"10.10.10.10", "20.20.20.20"}
};

TEST_INTERFACE_VALUES testIfaceValues =
{  
    "eth1",
    "00:01:00:00:11:22:33:44:55:66:77:88",
    "00:0c:29:24:91:5c",
    1500,
    2000,
    LINK_AUTO,
    LINK_UP,
    2,
    (char *[]){"bar.com", "abcd.com"},
    2,
    (char *[]){"10.10.10.10", "20.20.20.20"}
};

START_TEST(test_dhcpduid)
{
    uint32_t err = 0;
    char *duid = NULL;

    printf("Running DHCP DUID tests..\n");

    err = nm_get_duid(NULL, &duid);
    printf("get_duid_err = %u\n", err);

    ck_assert_msg(!strcmp(duid, testSystemValues.pDuid),
                  "Was expecting %s got %s instead",
                  testSystemValues.pDuid, duid);
    netmgr_free(duid);
}
END_TEST

START_TEST(test_get_link_mode)
{
    uint32_t err = 0;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;

    printf("Running get_link_mode..\n");

    err = nm_get_link_mode(testIfaceValues.pszIfName, &linkMode);
    printf("get_link_mode = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg(testIfaceValues.linkMode == linkMode,
                  "Was expecting linkMode %s but found linkMode %s",
                  nm_link_mode_to_string(testIfaceValues.linkMode),
                  nm_link_mode_to_string(linkMode));
}
END_TEST

START_TEST(test_get_link_state)
{
    uint32_t err = 0;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;

    printf("Running get_link_state..\n");

    err = nm_get_link_state(testIfaceValues.pszIfName, &linkState);
    printf("get_link_state = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg(testIfaceValues.linkState == linkState,
                  "Was expecting linkState %s but found linkState %s",
                  nm_link_state_to_string(testIfaceValues.linkState),
                  nm_link_state_to_string(linkState));
}
END_TEST

START_TEST(test_get_link_mac_addr)
{
    uint32_t err = 0;
    char *pszMacAddress = NULL;

    printf("Running get_link_mac_addr..\n");

    err = nm_get_link_mac_addr(testIfaceValues.pszIfName, &pszMacAddress);
    printf("get_link_mac_addr = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg(!strcmp(testIfaceValues.pszMacAddress, pszMacAddress),
                  "Was expecting interface %s MacAdress %s but found %s",
                  testIfaceValues.pszIfName,
                  testIfaceValues.pszMacAddress,
                  pszMacAddress);
    netmgr_free(pszMacAddress);
}
END_TEST

START_TEST(test_get_link_mtu)
{
    uint32_t err = 0, mtu = 0;

    printf("Running get_link_mtu..\n");

    err = nm_get_link_mtu(testIfaceValues.pszIfName, &mtu);
    printf("get_link_mtu = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg(testIfaceValues.mtu == mtu,
                  "Was expecting interface %s mtu %lu but found %lu",
                  testIfaceValues.pszIfName,
                  testIfaceValues.mtu,
                  mtu);
}
END_TEST

START_TEST(test_get_dns_servers)
{
    uint32_t err = 0;
    size_t i = 0, serverCount = 0;
    NET_DNS_MODE mode = DNS_MODE_INVALID;
    char **ppszDnsServers = NULL;

    printf("Running get_dns_servers..\n");

    err = nm_get_dns_servers(testIfaceValues.pszIfName,
                             &mode,
                             &serverCount,
                             &ppszDnsServers);
    printf("nm_get_dns_servers = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);
    ck_assert_msg((testIfaceValues.dnsServerCount == serverCount),
                  "Was expecting %lu dnsServer but found %lu dnsServer",
                  testIfaceValues.dnsServerCount, serverCount);
    for (i = 0; i < serverCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsServers[i],
                              testIfaceValues.ppszDnsServers[i]),
                      "Was expecting Dns Domain %s but found %s",
                      ppszDnsServers[i],
                      testIfaceValues.ppszDnsServers[i]);
    }

    netmgr_list_free(serverCount, (void **)ppszDnsServers);
}
END_TEST

START_TEST(test_get_dns_domains)
{
    uint32_t err = 0;
    size_t i = 0, domainCount = 0;
    char **ppszDnsDomains = NULL;
    printf("Running get_dns_domains..\n");

    err = nm_get_dns_domains(testIfaceValues.pszIfName,
                             &domainCount,
                             &ppszDnsDomains);
    printf("nm_get_dns_domains = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg((testIfaceValues.domainCount == domainCount),
                  "Was expecting %lu dnsDomain but found %lu dnsDomain",
                  testIfaceValues.domainCount, domainCount);
    for (i = 0; i < domainCount; i++)
    {
        ck_assert_msg(!strcmp(ppszDnsDomains[i],
                              testIfaceValues.ppszDnsDomains[i]),
                      "Was expecting Dns Domain %s but found %s",
                      ppszDnsDomains[i],
                      testIfaceValues.ppszDnsDomains[i]);
    }
    netmgr_list_free(domainCount, (void **)ppszDnsDomains);
}
END_TEST

START_TEST(test_get_iaid)
{
    uint32_t err = 0, iaid = 0;

    printf("Running get_iaid..\n");

    err = nm_get_iaid(testIfaceValues.pszIfName, &iaid);
    printf("nm_get_iaid = %u\n", err);

    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);
    ck_assert_msg(iaid == testIfaceValues.iaid, "Was expecting 'eth1'");
}
END_TEST

START_TEST(test_hostname)
{
    uint32_t err = 0;
    size_t lineLen = 0;
    FILE *pFile = NULL;
    char *pszHostName = NULL;
    char *pszLine = NULL;
    printf("Running get_hostname..\n");

    err = nm_get_hostname(&pszHostName);
    printf("nm_get_hostname = %u\n", err);
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);
    
    pFile = popen("/usr/bin/hostname", "r");
    if (pFile == NULL)
    {
        err = errno;
    }
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);
    
    if (getline(&pszLine, &lineLen, pFile) < 0)
    {
        err = errno;
    }
    ck_assert_msg(err == 0, "Was expecting err 0 got %lu instead", err);

    ck_assert_msg(!strcmp(pszLine, pszHostName), "Was expecting 'eth1'");
    if (pFile != NULL)
    {
        pclose(pFile);
    }
    netmgr_free(pszLine);
    netmgr_free(pszHostName);
}
END_TEST

START_TEST(test_get_firewall_rules)
{
    uint32_t err = 0;
    size_t i = 0, ruleCount = 0;
    NET_FW_RULE **ppNetFwRule = NULL;

    printf("Running get_firewall_rules..\n");

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

Suite *test_netmgr_suite(void)
{
    Suite *s;
    TCase *tcCore;

    s = suite_create("NetMgrTestSuite");
    tcCore = tcase_create("NetMgrTestCore");
    tcase_add_test(tcCore, test_dhcpduid);
    tcase_add_test(tcCore, test_get_link_mode);
    tcase_add_test(tcCore, test_get_link_state);
    tcase_add_test(tcCore, test_get_link_mac_addr);
    tcase_add_test(tcCore, test_get_link_mtu);
    tcase_add_test(tcCore, test_get_dns_servers);
    tcase_add_test(tcCore, test_get_dns_domains);
    tcase_add_test(tcCore, test_get_iaid);
    tcase_add_test(tcCore, test_hostname);
    tcase_add_test(tcCore, test_get_firewall_rules);
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
    srunner_run_all(sr, CK_NORMAL);
    numFailed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (numFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

