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

#ifndef __UTILS_H__
#define __UTILS_H__

#define F_CREATE_CFG_FILE              0x00000001

uint32_t
nm_set_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
);

uint32_t
nm_add_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
);

uint32_t
nm_delete_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
);

uint32_t
nm_get_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    char **ppszValue
);

uint32_t
nm_get_systemd_version(
    uint32_t *psdVersion
);

uint32_t
nm_atomic_file_update(
    const char *pszFileName,
    const char *pszFileBuf
);

uint32_t
nm_run_command(
    const char *pszCommand
);

uint32_t
nm_acquire_write_lock(
    uint32_t timeOut,
    int *pLockId
);

uint32_t
nm_release_write_lock(
    int lockId
);

uint32_t
nm_read_one_line(
    const char *pszPath,
    char **ppszLine
);

uint32_t
nm_write_one_line(
    const char *pszPath,
    const char *pszValue
);

#endif /* __UTILS_H__ */
