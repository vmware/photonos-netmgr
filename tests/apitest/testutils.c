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

START_TEST(test_getkeyvalue)
{
    uint32_t err = 0;
    char *pszValue = NULL;

    printf("nm_get_key_value test:\n");
    err = nm_get_key_value("eth0", "Match", "Name", &pszValue);
    ck_assert(strcmp(pszValue, "eth0") == 0);
    netmgr_free(pszValue);
}
END_TEST

int main()
{
    printf("Running utils API Tests..\n");
    return 0;
}
