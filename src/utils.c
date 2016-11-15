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

#include "includes.h"

uint32_t
nm_set_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
)
{
    uint32_t err = 0, dwNumSections = 0;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pKeyValue = NULL;
    FILE *fp;

    if (IS_NULL_OR_EMPTY(pszConfigFileName) || IS_NULL_OR_EMPTY(pszSection) ||
        IS_NULL_OR_EMPTY(pszKey))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (TEST_FLAG(flags, F_CREATE_CFG_FILE))
    {
        /* 'touch' the file if it does't exist */
        if ((fp = fopen(pszConfigFileName, "a+")) != NULL)
        {
            fclose(fp);
        }
        else
        {
            err = errno;
            bail_on_error(err);
        }
    }

    err = ini_cfg_read(pszConfigFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, pszSection, &ppSections, &dwNumSections);
    bail_on_error(err);

    if (dwNumSections > 1)
    {
        /* TODO: Better error reporting */
        err = EINVAL;
        bail_on_error(err);
    }
    else if ((dwNumSections == 0) && (pszValue != NULL))
    {
        err = ini_cfg_add_section(pConfig, pszSection, &pSection);
        bail_on_error(err);
    }
    else
    {
        pSection = ppSections[0];
    }

    pKeyValue = ini_cfg_find_key(pSection, pszKey);
    if (pKeyValue == NULL)
    {
        if (pszValue != NULL)
        {
            err = ini_cfg_add_key(pSection, pszKey, pszValue);
        }
    }
    else
    {
        if (pszValue != NULL)
        {
            err = ini_cfg_set_value(pSection, pszKey, pszValue);
        }
        else
        {
            err = ini_cfg_delete_key(pSection, pszKey);
        }
    }
    bail_on_error(err);

    err = ini_cfg_save(pszConfigFileName, pConfig);
    bail_on_error(err);

error:
    if (ppSections != NULL)
    {
        ini_cfg_free_sections(ppSections, dwNumSections);
    }
    if (pConfig != NULL)
    {
        ini_cfg_free_config(pConfig);
    }
    return err;
}

uint32_t
nm_add_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
)
{
    uint32_t err = 0, dwNumSections = 0;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pKeyValue = NULL;

    if (IS_NULL_OR_EMPTY(pszConfigFileName) || IS_NULL_OR_EMPTY(pszSection) ||
        IS_NULL_OR_EMPTY(pszKey) || IS_NULL_OR_EMPTY(pszValue))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = ini_cfg_read(pszConfigFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, pszSection, &ppSections, &dwNumSections);
    bail_on_error(err);

    if (dwNumSections > 1)
    {
        /* TODO: Better error reporting */
        err = EINVAL;
        bail_on_error(err);
    }
    else if (dwNumSections == 0)
    {
        err = ini_cfg_add_section(pConfig, pszSection, &pSection);
        bail_on_error(err);
    }
    else
    {
        pSection = ppSections[0];
    }

    pKeyValue = ini_cfg_find_key_value(pSection, pszKey, pszValue);
    if (pKeyValue != NULL)
    {
        err = EEXIST;
    }
    else
    {
        err = ini_cfg_add_key(pSection, pszKey, pszValue);
    }
    bail_on_error(err);

    err = ini_cfg_save(pszConfigFileName, pConfig);
    bail_on_error(err);

error:
    if (ppSections != NULL)
    {
        ini_cfg_free_sections(ppSections, dwNumSections);
    }
    if (pConfig != NULL)
    {
        ini_cfg_free_config(pConfig);
    }
    return err;
}

uint32_t
nm_delete_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue,
    uint32_t flags
)
{
    uint32_t err = 0, dwNumSections = 0;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pKeyValue = NULL;

    if (IS_NULL_OR_EMPTY(pszConfigFileName) || IS_NULL_OR_EMPTY(pszSection) ||
        IS_NULL_OR_EMPTY(pszKey) || IS_NULL_OR_EMPTY(pszValue))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = ini_cfg_read(pszConfigFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, pszSection, &ppSections, &dwNumSections);
    bail_on_error(err);

    if (dwNumSections > 1)
    {
        /* TODO: Better error reporting */
        err = EINVAL;
        bail_on_error(err);
    }
    else if (dwNumSections == 0)
    {
        err = ENOENT;
        bail_on_error(err);
    }
    else
    {
        pSection = ppSections[0];
    }

    pKeyValue = ini_cfg_find_key_value(pSection, pszKey, pszValue);
    if (pKeyValue == NULL)
    {
        err = ENOENT;
    }
    else
    {
        err = ini_cfg_delete_key_value(pSection, pKeyValue);
    }
    bail_on_error(err);

    err = ini_cfg_save(pszConfigFileName, pConfig);
    bail_on_error(err);

error:
    if (ppSections != NULL)
    {
        ini_cfg_free_sections(ppSections, dwNumSections);
    }
    if (pConfig != NULL)
    {
        ini_cfg_free_config(pConfig);
    }
    return err;
}

uint32_t
nm_get_key_value(
    const char *pszConfigFileName,
    const char *pszSection,
    const char *pszKey,
    char **ppszValue
)
{
    uint32_t err = 0, dwNumSections = 0;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI *ppSections = NULL, pSection = NULL;
    PKEYVALUE_INI pKeyValue = NULL;
    *ppszValue = NULL;

    if (IS_NULL_OR_EMPTY(pszConfigFileName) || IS_NULL_OR_EMPTY(pszSection) ||
        IS_NULL_OR_EMPTY(pszKey))
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = ini_cfg_read(pszConfigFileName, &pConfig);
    bail_on_error(err);

    err = ini_cfg_find_sections(pConfig, pszSection, &ppSections, &dwNumSections);
    bail_on_error(err);

    if (dwNumSections > 1)
    {
        /* TODO: Log error */
        err = EINVAL;
        bail_on_error(err);
    }
    else if (dwNumSections == 0)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    pSection = ppSections[0];

    pKeyValue = ini_cfg_find_key(pSection, pszKey);
    if (pKeyValue == NULL)
    {
        err = ENOENT;
        bail_on_error(err);
    }
    /* malloc return memory - caller to free */
    err = netmgr_alloc_string(pKeyValue->pszValue, ppszValue);

error:
    if (ppSections != NULL)
    {
        ini_cfg_free_sections(ppSections, dwNumSections);
    }
    if (pConfig != NULL)
    {
        ini_cfg_free_config(pConfig);
    }
    return err;
}

uint32_t
nm_atomic_file_update(
    const char *pszFileName,
    const char *pszFileBuf
)
{
    uint32_t err = 0;
    char *pszTmpFileName = NULL;
    FILE *pFile = NULL;

    if (!pszFileName || !*pszFileName || !pszFileBuf)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_printf(&pszTmpFileName, "%s.new", pszFileName);
    bail_on_error(err);

    pFile = fopen(pszTmpFileName, "w+");
    if (!pFile)
    {
        err = errno;
        bail_on_error(err);
    }

    /* coverity[var_deref_model] */
    if (fprintf(pFile, "%s", pszFileBuf) < 0)
    {
        err = EBADF;
        bail_on_error(err);
    }
    fclose(pFile);
    pFile = NULL;

    if (chmod(pszTmpFileName, S_IRUSR|S_IWUSR|S_IXUSR|
                              S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    if (rename(pszTmpFileName, pszFileName) < 0)
    {
        err = errno;
        bail_on_error(err);
    }

clean:
    netmgr_free(pszTmpFileName);
    if (pFile)
    {
        fclose(pFile);
    }
    return err;
error:
    goto clean;
}

uint32_t
nm_run_command(
    const char *pszCommand
)
{
    uint32_t err = 0;
    FILE *pipe_fp = NULL;

    if (pszCommand == NULL)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    pipe_fp = popen(pszCommand, "r");
    if (pipe_fp == NULL)
    {
        err = errno;
        bail_on_error(err);
    }

clean:
    if (pipe_fp != NULL)
    {
        if (pclose(pipe_fp) == -1)
        {
            err = errno;
        }
    }
    return err;
error:
    goto clean;
}

uint32_t
nm_acquire_write_lock(
    uint32_t timeOut,
    int *pLockId
)
{
    uint32_t err = 0;
    int lockFd = -1;
    struct flock fLock = { F_WRLCK, SEEK_SET, 0, 0, getpid() };

    if (!pLockId)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    lockFd = open(NM_LOCK_FILENAME, O_CREAT | O_WRONLY, S_IRWXU);
    if (lockFd == -1)
    {
        err = errno;
        bail_on_error(err);
    }

    if (fcntl(lockFd, F_SETLKW, &fLock) == -1)
    {
        err = errno;
        bail_on_error(err);
    }

    *pLockId = lockFd;

cleanup:
    return err;
error:
    if (lockFd > -1)
    {
        close(lockFd);
    }
    if (pLockId)
    {
        *pLockId = -1;
    }
    goto cleanup;
}

uint32_t
nm_release_write_lock(
    int lockId
)
{
    uint32_t err = 0;
    struct flock fLock = { F_UNLCK, SEEK_SET, 0, 0, getpid() };

    if (lockId < 0)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    if (fcntl(lockId, F_SETLKW, &fLock) == -1)
    {
        err = errno;
        bail_on_error(err);
    }
    close(lockId);

error:
    return err;
}
