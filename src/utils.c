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

int
set_key_value(
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

    if ((flags & F_CREATE_CFG_FILE) && access(pszConfigFileName, R_OK|W_OK) < 0)
    {
        /* 'touch' the file */
        if ((fp = fopen(pszConfigFileName, "w")) != NULL)
        {
            fclose(fp);
        }
        else
        {
            /* TODO: Better error reporting */
            err = EINVAL;
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

int
add_key_value(
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

int
delete_key_value(
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

int
get_key_value(
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

int
add_interface_ini(
    const char *pszInterfaceName,
    PINTERFACE_INI pInterfaceDummyIni
)
{
    uint32_t err = 0;
    PINTERFACE_INI pInterfaceIni = NULL;
    if (IS_NULL_OR_EMPTY(pszInterfaceName) || !pInterfaceDummyIni)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(INTERFACE_INI), (void *)&pInterfaceIni);
    bail_on_error(err);

    err = netmgr_alloc_string(pszInterfaceName, &pInterfaceIni->pszName);
    bail_on_error(err);

    pInterfaceIni->pNext = pInterfaceDummyIni->pNext;
    pInterfaceDummyIni->pNext = pInterfaceIni;

cleanup:
    return err;
error:
    netmgr_free(pInterfaceIni->pszName);
    netmgr_free(pInterfaceIni);
    goto cleanup;
}

void
delete_interface_ini(
    PINTERFACE_INI pInterfaceDummyIni
)
{
    PINTERFACE_INI pCur = NULL, pNext = NULL;

    if (pInterfaceDummyIni)
    {
        pCur = pInterfaceDummyIni->pNext;
        while (pCur)
        {
            pNext = pCur->pNext;
            if (pCur->pszName)
            {
                netmgr_free(pCur->pszName);
            }
            netmgr_free(pCur);
            pCur = pNext;
        }

    }
}

int
netmgr_run_command(
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
        if ((err = pclose(pipe_fp)) == -1)
        {
            err = errno;
        }
    }
    return err;
error:
    goto clean;
}

