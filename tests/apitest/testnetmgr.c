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

uint32_t test_dhcpduid()
{
    uint32_t err = 0;
    char *duid = NULL;

    printf("Running DHCP DUID tests..\n");

    err = nm_get_duid(NULL, &duid);
    printf("get_duid_err=%u\n", err);
    if (err == ENOENT)
    {
        /* We expected ENOENT */
        err = 0;
    }
    netmgr_free(duid);

    return err;
}

uint32_t test_ifiaid()
{
    uint32_t err = 0, iaid = 0;

    printf("Running Interface IAID tests..\n");

    err = nm_get_iaid("eth0", &iaid);
    printf("get_iaid_err=%u\n", err);
    if (err == ENOENT)
    {
        /* We expected ENOENT */
        err = 0;
    }

    return err;
}

int main()
{
    uint32_t err = 0;
    printf("Running netmgr API Tests..\n");

    err = test_dhcpduid();
    bail_on_error(err);

    err = test_ifiaid();
    bail_on_error(err);

error:
    return err;
}
