/*
 * Copyright © 2016-2018 VMware, Inc.  All Rights Reserved.
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

START_TEST(test_getkeyvalue)
{
    uint32_t err = 0;
    char *pszValue = NULL;

    printf("nm_get_key_value test:\n");
    err = nm_get_key_value("/etc/systemd/network/10-eth0.network",
                           "Match",
                           "Name",
                           &pszValue);
    ck_assert_msg(strcmp(pszValue, "eth0") == 0, "Was expecting 'eth0'");
    netmgr_free(pszValue);
}
END_TEST

Suite *test_utils_suite(void)
{
    Suite *s;
    TCase *tcCore;

    s = suite_create("UtilsTestSuite");
    tcCore = tcase_create("UtilsTestCore");
    tcase_add_test(tcCore, test_getkeyvalue);
    suite_add_tcase(s, tcCore);
    return s;
}

int main(void)
{
    int numFailed;
    Suite *s;
    SRunner *sr;

    printf("Running utils API Tests..\n");

    s = test_utils_suite();
    sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    numFailed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (numFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
