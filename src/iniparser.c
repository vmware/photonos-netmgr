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

static
uint32_t
ini_cfg_parse_section_name(
    const char* pszBuffer,
    char**      ppszName
    );

static
uint32_t
ini_cfg_parse_key_value(
    const char* pszBuffer,
    char**      ppszKey,
    char**      ppszValue
    );

static
void
ini_cfg_free_section(
    PSECTION_INI pSection
    );

static
void
ini_cfg_free_keyvalue(
    PKEYVALUE_INI pKeyValue
    );

uint32_t
ini_cfg_read(
    const char*  pszPath,
    PCONFIG_INI* ppConfig
    )
{
    uint32_t err = 0;
    FILE* fp = NULL;
    PCONFIG_INI pConfig = NULL;
    PSECTION_INI pSection = NULL;
    char* pszName = NULL;
    char* pszKey = NULL;
    char* pszValue = NULL;

    if (!pszPath || !*pszPath || !ppConfig)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    fp = fopen(pszPath, "r");
    if (!fp)
    {
        err = errno;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(CONFIG_INI), (void*)&pConfig);
    bail_on_error(err);

    err = netmgr_alloc_string(pszPath, &pConfig->pszPath);
    bail_on_error(err);

    while(!feof(fp))
    {
        char buffer[1024];
        const char* pszCursor = NULL;

        if (!fgets(buffer, sizeof(buffer), fp))
        {
            if (feof(fp))
            {
                break;
            }
            err = errno;
            bail_on_error(err);
        }

        pszCursor = &buffer[0];

        // skip leading whitespace
        while (pszCursor && *pszCursor && isspace((int)*pszCursor))
        {
            pszCursor++;
        }
        // skip empty lines and comments
        if (!pszCursor || !*pszCursor || *pszCursor == '#')
        {
            continue;
        }
        else if (*pszCursor == '[') // section
        {
            if (pszName)
            {
                netmgr_free(pszName);
                pszName = NULL;
            }

            err = ini_cfg_parse_section_name(pszCursor, &pszName);
            bail_on_error(err);

            err = ini_cfg_add_section(pConfig, pszName, &pSection);
            bail_on_error(err);
        }
        else // key value pair
        {
            if (!pSection)
            {
                err = EBADMSG;
                bail_on_error(err);
            }

            if (pszKey)
            {
                netmgr_free(pszKey);
                pszKey = NULL;
            }
            if (pszValue)
            {
                netmgr_free(pszValue);
                pszValue = NULL;
            }

            err = ini_cfg_parse_key_value(pszCursor, &pszKey, &pszValue);
            bail_on_error(err);

            err = ini_cfg_add_key(pSection, pszKey, pszValue);
            bail_on_error(err);
        }
    }

    *ppConfig = pConfig;

cleanup:

    if (fp)
    {
        fclose(fp);
    }
    if (pszName)
    {
        netmgr_free(pszName);
    }
    if (pszKey)
    {
        netmgr_free(pszKey);
    }
    if (pszValue)
    {
        netmgr_free(pszValue);
    }

    return err;

error:

    if (ppConfig)
    {
        *ppConfig = NULL;
    }
    if (pConfig)
    {
        ini_cfg_free_config(pConfig);
    }

    goto cleanup;
}

uint32_t
ini_cfg_create_config(
    PCONFIG_INI* ppConfig
    )
{
    uint32_t err = 0;
    PCONFIG_INI pConfig = NULL;

    if (!ppConfig)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(CONFIG_INI), (void*)&pConfig);
    bail_on_error(err);

    *ppConfig = pConfig;

cleanup:

    return err;

error:

    if (ppConfig)
    {
        *ppConfig = NULL;
    }
    if (pConfig)
    {
        ini_cfg_free_config(pConfig);
    }

    goto cleanup;
}

uint32_t
ini_cfg_add_section(
    PCONFIG_INI pConfig,
    const char* pszName,
    PSECTION_INI* ppSection
    )
{
    uint32_t err = 0;
    PSECTION_INI pSection = NULL;
    PSECTION_INI pCursor = NULL;

    if (!pConfig || !pszName || !*pszName || !ppSection)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(SECTION_INI), (void*)&pSection);
    bail_on_error(err);

    err = netmgr_alloc_string(pszName, &pSection->pszName);
    bail_on_error(err);

    pCursor = pConfig->pSection;
    while (pCursor && pCursor->pNext != NULL)
    {
        pCursor = pCursor->pNext;
    }

    if (!pCursor)
    {
        pConfig->pSection = pSection;
    }
    else
    {
        pCursor->pNext = pSection;
    }

    *ppSection = pSection;

cleanup:

    return err;

error:

    if (ppSection)
    {
        *ppSection = NULL;
    }
    if (pSection)
    {
        ini_cfg_free_section(pSection);
    }

    goto cleanup;
}

uint32_t
ini_cfg_find_sections(
    PCONFIG_INI    pConfig,
    const char*    pszName,
    PSECTION_INI** pppSections,
    uint32_t*      pdwNumSections
    )
{
    uint32_t err = 0;
    uint32_t nSections = 0;
    PSECTION_INI* ppSections = NULL;
    PSECTION_INI  pCursor = NULL;
    size_t iSection = 0;

    if (!pConfig || !pszName || !*pszName || !pppSections || !pdwNumSections)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    *pdwNumSections = 0;
    *pppSections = NULL;

    for (pCursor = pConfig->pSection; pCursor; pCursor = pCursor->pNext)
    {
        if (!strcmp(pCursor->pszName, pszName))
        {
            nSections++;
        }
    }

    if (!nSections)
    {
        goto cleanup;
    }

    err = netmgr_alloc(sizeof(PSECTION_INI) * nSections, (void*)&ppSections);
    bail_on_error(err);

    for (pCursor = pConfig->pSection; pCursor; pCursor = pCursor->pNext)
    {
        if (!strcmp(pCursor->pszName, pszName))
        {
            ppSections[iSection++] = pCursor;
        }
    }

    *pppSections = ppSections;
    *pdwNumSections = nSections;

cleanup:

    return err;

error:

    if (pppSections)
    {
        *pppSections = NULL;
    }
    if (pdwNumSections)
    {
        *pdwNumSections = 0;
    }
    if (ppSections)
    {
        netmgr_free(ppSections);
    }

    goto cleanup;
}

void
ini_cfg_free_sections(
    PSECTION_INI* ppSections,
    uint32_t      dwNumSections
    )
{
    if (ppSections)
    {
        netmgr_free(ppSections);
    }
}

uint32_t
ini_cfg_delete_sections(
    PCONFIG_INI   pConfig,
    const char*   pszName
    )
{
    uint32_t err = 0;
    PSECTION_INI *ppCursor = NULL;
    PSECTION_INI pCandidate = NULL;

    if (!pConfig || !pszName || !*pszName)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    ppCursor = &pConfig->pSection;
    while (*ppCursor)
    {
        if (!strcmp((*ppCursor)->pszName, pszName))
        {
            pCandidate = *ppCursor;
            *ppCursor = pCandidate->pNext;
            break;
        }

        ppCursor = &(*ppCursor)->pNext;
    }
    if (pCandidate)
    {
        pCandidate->pNext = NULL;

        ini_cfg_free_section(pCandidate);
    }

error:

    return err;
}

uint32_t
ini_cfg_delete_section(
    PCONFIG_INI   pConfig,
    PSECTION_INI  pSection
    )
{
    uint32_t err = 0;
    PSECTION_INI *pCursor = NULL;
    PSECTION_INI pCandidate = NULL;

    if (!pConfig || !pSection)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    for (pCursor = &pConfig->pSection; *pCursor; pCursor = &(*pCursor)->pNext)
    {
        if (*pCursor == pSection)
        {
            pCandidate = *pCursor;
            *pCursor = pCandidate->pNext;
            break;
        }
    }

    if (!pCandidate)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    pCandidate->pNext = NULL;
    ini_cfg_free_section(pCandidate);

error:
    return err;
}

PKEYVALUE_INI
ini_cfg_find_key(
    PSECTION_INI  pSection,
    const char*   pszKey
    )
{
    PKEYVALUE_INI pKeyValue = NULL;
    PKEYVALUE_INI pCursor = pSection->pKeyValue;

    if (!pszKey || !*pszKey)
    {
        goto cleanup;
    }

    for (; !pKeyValue && pCursor; pCursor = pCursor->pNext)
    {
        if (!strcmp(pCursor->pszKey, pszKey) && (pCursor->pszValue != NULL))
        {
            pKeyValue = pCursor;
        }
    }

cleanup:
    return pKeyValue;
}

PKEYVALUE_INI
ini_cfg_find_next_key(
    PSECTION_INI  pSection,
    PKEYVALUE_INI pKeyValue,
    const char*   pszKey
    )
{
    PKEYVALUE_INI pNextKeyVal = NULL;
    PKEYVALUE_INI pCursor;

    if (!pszKey || !*pszKey)
    {
        goto cleanup;
    }

    pCursor = (pKeyValue == NULL) ? pSection->pKeyValue : pKeyValue->pNext;

    for (; !pNextKeyVal && pCursor; pCursor = pCursor->pNext)
    {
        if (!strcmp(pCursor->pszKey, pszKey) && (pCursor->pszValue != NULL))
        {
            pNextKeyVal = pCursor;
            break;
        }
    }

cleanup:
    return pNextKeyVal;
}

PKEYVALUE_INI
ini_cfg_find_key_value(
    PSECTION_INI  pSection,
    const char*   pszKey,
    const char*   pszValue
    )
{
    PKEYVALUE_INI pKeyValue = NULL;
    PKEYVALUE_INI pCursor = pSection->pKeyValue;

    if (!pszKey || !*pszKey || !pszValue || !*pszValue)
    {
        goto cleanup;
    }

    for (; !pKeyValue && pCursor; pCursor = pCursor->pNext)
    {
        if (!strcmp(pCursor->pszKey, pszKey) && (pCursor->pszValue != NULL)
            && !strcmp(pCursor->pszValue, pszValue))
        {
            pKeyValue = pCursor;
        }
    }

cleanup:
    return pKeyValue;
}

uint32_t
ini_cfg_add_key(
    PSECTION_INI  pSection,
    const char*   pszKey,
    const char*   pszValue
    )
{
    uint32_t err = 0;
    PKEYVALUE_INI pKeyValue = NULL;
    PKEYVALUE_INI pCursor = NULL;

    if (!pSection || !pszKey || !*pszKey)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(sizeof(KEYVALUE_INI), (void*)&pKeyValue);
    bail_on_error(err);

    err = netmgr_alloc_string(pszKey, &pKeyValue->pszKey);
    bail_on_error(err);

    if ((pszValue != NULL) && (strlen(pszValue) > 0))
    {
        err = netmgr_alloc_string(pszValue, &pKeyValue->pszValue);
        bail_on_error(err);
    }

    pCursor = pSection->pKeyValue;
    while (pCursor && pCursor->pNext != NULL)
    {
        pCursor = pCursor->pNext;
    }

    if (!pCursor)
    {
        pSection->pKeyValue = pKeyValue;
    }
    else
    {
        pCursor->pNext = pKeyValue;
    }

cleanup:

    return err;

error:

    if (pKeyValue)
    {
        ini_cfg_free_keyvalue(pKeyValue);
    }

    goto cleanup;
}

uint32_t
ini_cfg_set_value(
    PSECTION_INI  pSection,
    const char*   pszKey,
    const char*   pszValue
    )
{
    uint32_t err = 0;
    char* pszNewValue = NULL;
    PKEYVALUE_INI pCandidate = NULL;

    if (!pSection || !pszKey || !*pszKey || !pszValue || !*pszValue)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    pCandidate = ini_cfg_find_key(pSection, pszKey);
    if (!pCandidate)
    {
        err = ENOENT;
        bail_on_error(err);
    }

    err = netmgr_alloc_string(pszValue, &pszNewValue);
    bail_on_error(err);

    if (pCandidate->pszValue)
    {
        netmgr_free(pCandidate->pszValue);
    }

    pCandidate->pszValue = pszNewValue;

error:

    return err;
}

uint32_t
ini_cfg_delete_key(
    PSECTION_INI  pSection,
    const char*   pszKey
    )
{
    uint32_t err = 0;
    PKEYVALUE_INI *pCursor = NULL;
    PKEYVALUE_INI pCandidate = NULL;

    if (!pSection || !pszKey || !*pszKey)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    pCursor = &pSection->pKeyValue;
    while (*pCursor)
    {
        if (!strcmp((*pCursor)->pszKey, pszKey))
        {
            pCandidate = *pCursor;
            *pCursor = pCandidate->pNext;
            break;
        }
        pCursor = &(*pCursor)->pNext;
    }

    if (pCandidate)
    {
        pCandidate->pNext = NULL;
        ini_cfg_free_keyvalue(pCandidate);
    }

error:

    return err;
}

uint32_t
ini_cfg_delete_key_value(
    PSECTION_INI  pSection,
    PKEYVALUE_INI pKeyValue
    )
{
    uint32_t err = 0;
    PKEYVALUE_INI *pCursor = NULL;
    PKEYVALUE_INI pCandidate = NULL;

    if (!pSection || !pKeyValue)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    pCursor = &pSection->pKeyValue;
    while (*pCursor)
    {
        if (*pCursor == pKeyValue)
        {
            pCandidate = *pCursor;
            *pCursor = pCandidate->pNext;
            break;
        }
        pCursor = &(*pCursor)->pNext;
    }

    if (pCandidate)
    {
        pCandidate->pNext = NULL;
        ini_cfg_free_keyvalue(pCandidate);
    }

error:
    return err;
}

uint32_t
ini_cfg_save(
    const char*   pszPath,
    PCONFIG_INI   pConfig
    )
{
    uint32_t err = 0;
    char* pszTmpPath = NULL, *pszValue;
    const char* pszSuffix = ".new";
    FILE* fp = NULL;
    PSECTION_INI pSection = NULL;

    if (!pszPath || !*pszPath || !pConfig)
    {
        err = EINVAL;
        bail_on_error(err);
    }

    err = netmgr_alloc(
            strlen(pszPath)+strlen(pszSuffix)+1,
            (void*)&pszTmpPath);
    bail_on_error(err);

    sprintf(pszTmpPath, "%s%s", pszPath, pszSuffix);

    fp = fopen(pszTmpPath, "w+");
    if (!fp)
    {
        err = errno;
        bail_on_error(err);
    }

    for (pSection = pConfig->pSection; pSection; pSection = pSection->pNext)
    {
        PKEYVALUE_INI pKeyValue = pSection->pKeyValue;

        if (fprintf(fp, "\n[%s]\n", pSection->pszName) < 0)
        {
            err = EBADF;
            bail_on_error(err);
        }

        for (; pKeyValue; pKeyValue = pKeyValue->pNext)
        {
            pszValue = (pKeyValue->pszValue != NULL) ? pKeyValue->pszValue : "";
            if(fprintf(fp, "%s=%s\n", pKeyValue->pszKey, pszValue) < 0)
            {
                err = EBADF;
                bail_on_error(err);
            }
        }
    }

    fclose(fp);
    fp = NULL;

    if (chmod(pszTmpPath, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) != 0)
    {
        bail_on_error(errno);
    }

    if (rename(pszTmpPath, pszPath) < 0)
    {
        err = errno;
        bail_on_error(err);
    }

cleanup:

    if (pszTmpPath)
    {
        netmgr_free(pszTmpPath);
    }
    if (fp)
    {
        fclose(fp);
    }

    return err;

error:

    goto cleanup;
}

void
ini_cfg_free_config(
    PCONFIG_INI pConfig
    )
{
    if (pConfig)
    {
        if (pConfig->pszPath)
        {
            netmgr_free(pConfig->pszPath);
        }
        while (pConfig->pSection)
        {
            PSECTION_INI pSection = pConfig->pSection;

            pConfig->pSection = pSection->pNext;

            ini_cfg_free_section(pSection);
        }
        netmgr_free(pConfig);
    }
}

static
uint32_t
ini_cfg_parse_section_name(
    const char* pszBuffer,
    char**      ppszName
    )
{
    uint32_t err = 0;
    const char* pszCursor = pszBuffer;
    const char* pszNameMarker = NULL;
    size_t len = 0;
    char* pszName = NULL;

    // skip leading whitespace
    while (pszCursor && *pszCursor && isspace((int)*pszCursor))
    {
        pszCursor++;
    }
    // check prefix
    if (!pszCursor || !*pszCursor || *pszCursor != '[')
    {
        err = EBADMSG;
        bail_on_error(err);
    }
    // skip prefix
    pszCursor++;
    // skip whitespace
    while (pszCursor && *pszCursor && isspace((int)*pszCursor))
    {
        pszCursor++;
    }
    pszNameMarker = pszCursor;
    if (!pszNameMarker || !*pszNameMarker)
    {
        err = EBADMSG;
        bail_on_error(err);
    }
    // allow only (('a'-'z') || ('A'-'Z'))+
    while (pszCursor && *pszCursor && isalpha((int)*pszCursor))
    {
        pszCursor++;
        len++;
    }
    // skip whitespace
    while (pszCursor && *pszCursor && isspace((int)*pszCursor))
    {
        pszCursor++;
    }
    // check suffix
    if (!pszCursor || !*pszCursor || *pszCursor != ']')
    {
        err = EBADMSG;
        bail_on_error(err);
    }
    // skip suffix
    pszCursor++;
    // skip whitespace
    while (pszCursor && *pszCursor && isspace((int)*pszCursor))
    {
        pszCursor++;
    }
    // Expect end of line and a non-empty name
    if ((pszCursor && *pszCursor) || !len)
    {
        err = EBADMSG;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_len(pszNameMarker, len, &pszName);
    bail_on_error(err);

    *ppszName = pszName;

cleanup:

    return err;

error:

    if (ppszName)
    {
        *ppszName = NULL;
    }
    if (pszName)
    {
        netmgr_free(pszName);
    }

    goto cleanup;
}

static
uint32_t
ini_cfg_parse_key_value(
    const char* pszBuffer,
    char**      ppszKey,
    char**      ppszValue
    )
{
    uint32_t err = 0;
    const char* pszCursor = pszBuffer;
    const char* pszKeyMarker = NULL;
    const char* pszValueMarker = NULL;
    size_t len_key = 0;
    size_t len_value = 0;
    char* pszKey = NULL;
    char* pszValue = NULL;

    // skip leading whitespace
    while (pszCursor && *pszCursor && isspace((int)*pszCursor))
    {
        pszCursor++;
    }
    pszKeyMarker = pszCursor;
    if (!pszKeyMarker || !*pszKeyMarker)
    {
        err = EBADMSG;
        bail_on_error(err);
    }
    // allow only (('a'-'z') || ('A'-'Z') || ('0'-'9'))+
    while (pszCursor && *pszCursor && (isalpha((int)*pszCursor) || isdigit((int)*pszCursor)))
    {
        pszCursor++;
        len_key++;
    }
    // skip whitespace
    while (pszCursor && *pszCursor && isspace((int)*pszCursor))
    {
        pszCursor++;
    }
    // check operator
    if (!pszCursor || !*pszCursor || *pszCursor != '=')
    {
        err = EBADMSG;
        bail_on_error(err);
    }
    // skip operator
    pszCursor++;
    // skip whitespace
    while (pszCursor && *pszCursor && isspace((int)*pszCursor))
    {
        pszCursor++;
    }
    pszValueMarker = pszCursor;
    while (pszCursor && *pszCursor)
    {
        if (*pszCursor == '\n')
        {
            pszCursor = NULL;
            break;
        }
        pszCursor++;
        len_value++;
    }
    if ((pszCursor && *pszCursor) || !len_key)
    {
        err = EBADMSG;
        bail_on_error(err);
    }

    err = netmgr_alloc_string_len(pszKeyMarker, len_key, &pszKey);
    bail_on_error(err);

    if (len_value > 0)
    {
        err = netmgr_alloc_string_len(pszValueMarker, len_value, &pszValue);
        bail_on_error(err);
    }

    *ppszKey = pszKey;
    *ppszValue = pszValue;

cleanup:

    return err;

error:

    if (ppszKey)
    {
        *ppszKey = NULL;
    }
    if (ppszValue)
    {
        *ppszValue = NULL;
    }
    if (pszKey)
    {
        netmgr_free(pszKey);
    }
    if (pszValue)
    {
        netmgr_free(pszValue);
    }

    goto cleanup;
}

static
void
ini_cfg_free_section(
    PSECTION_INI pSection
    )
{
    if (pSection)
    {
        if (pSection->pszName)
        {
            netmgr_free(pSection->pszName);
        }
        while (pSection->pKeyValue)
        {
            PKEYVALUE_INI pKeyValue = pSection->pKeyValue;

            pSection->pKeyValue = pKeyValue->pNext;

            ini_cfg_free_keyvalue(pKeyValue);
        }
        netmgr_free(pSection);
    }
}

static
void
ini_cfg_free_keyvalue(
    PKEYVALUE_INI pKeyValue
    )
{
    if (pKeyValue)
    {
        if (pKeyValue->pszKey)
        {
            netmgr_free(pKeyValue->pszKey);
        }
        if (pKeyValue->pszValue)
        {
            netmgr_free(pKeyValue->pszValue);
        }
        netmgr_free(pKeyValue);
    }
}

