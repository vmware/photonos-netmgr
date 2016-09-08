/*
 * Copyright © 2016 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the ?~@~\License?~@~]); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ?~@~\AS IS?~@~] BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#define F_CREATE_CFG_FILE              0x00000001

int
set_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
);

int
add_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
);

int
delete_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
);

int
get_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    char **ppszValue
);

int
netmgr_run_command(
    const char *pszCommand
);

int
add_interface_ini(
    const char *pszInterfaceName,
    PINTERFACE_INI pInterfaceDummyIni
);

void
delete_interface_ini(
    PINTERFACE_INI pInterfaceDummyIni
);

#endif /* __UTILS_H__ */
