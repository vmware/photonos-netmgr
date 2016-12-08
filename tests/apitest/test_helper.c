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
test_read_conf_file(
    const char *pszFilename,
    char **ppszFileBuf)
{
    uint32_t err = 0;
    long len;
    FILE *fp = NULL;
    char *pszFileBuf = NULL;

    if (IS_NULL_OR_EMPTY(pszFilename) || !ppszFileBuf)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    fp = fopen(pszFilename, "r");
    if (fp == NULL)
    {
        err = errno;
        bail_on_error(err);
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        err = errno;
        bail_on_error(err);
    }
    len = ftell(fp);
    if (len == -1)
    {
        err = errno;
        bail_on_error(err);
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        err = errno;
        bail_on_error(err);
    }

    err = netmgr_alloc((len + 1), (void **)&pszFileBuf);
    bail_on_error(err);

    if (fread(pszFileBuf, len, 1, fp) != 1)
    {
        if (!feof(fp))
        {
            err = ferror(fp);
            bail_on_error(err);
        }
    }

    *ppszFileBuf = pszFileBuf;

cleanup:
    if (fp != NULL)
    {
        fclose(fp);
    }
    return err;

error:
    if (ppszFileBuf != NULL)
    {
        *ppszFileBuf = NULL;
    }
    netmgr_free(pszFileBuf);
    goto cleanup;
}

uint32_t
test_string_to_line_array(
    const char *pszStrBuf,
    size_t *pLineCount,
    char ***pppszLineBuf)
{
    uint32_t err = 0, len;
    size_t i = 0, lineCount = 0;
    char *p1, *p2, *pEnd, **ppszLineBuf = NULL;

    if (!pszStrBuf || !*pszStrBuf || !pLineCount || !pppszLineBuf)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    p1 = (char *)pszStrBuf;
    pEnd = strchr(pszStrBuf, '\0');
    do
    {
        p1 = strchr(p1, '\n');
        if (p1 == NULL)
        {
            break;
        }
        lineCount++;
        p1++;
    } while (p1 < pEnd);

    if (lineCount == 0)
    {
        err = NM_ERR_VALUE_NOT_FOUND;
        bail_on_error(err);
    }

    err = netmgr_alloc(lineCount * sizeof(char **), (void **)&ppszLineBuf);
    bail_on_error(err);

    p1 = (char *)pszStrBuf;
    do
    {
        p2 = strchr(p1, '\n');
        if (p2 == NULL)
        {
            break;
        }
        len = p2 - p1 + 1;
        err = netmgr_alloc(len + 1, (void **)&ppszLineBuf[i]);
        bail_on_error(err);
        memcpy(ppszLineBuf[i], p1, len);
        i++;
        p1 = p2 + 1;
    } while (p1 < pEnd);

    *pLineCount = lineCount;
    *pppszLineBuf = ppszLineBuf;

cleanup:
    return err;

error:
    if (pLineCount)
    {
        *pLineCount = 0;
    }
    if (pppszLineBuf)
    {
        *pppszLineBuf = NULL;
    }
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
    goto cleanup;
}

uint32_t
test_get_section_name(
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
        err = NM_ERR_BAD_CONFIG_FILE;
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
        err = NM_ERR_BAD_CONFIG_FILE;
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
        err = NM_ERR_BAD_CONFIG_FILE;
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
        err = NM_ERR_BAD_CONFIG_FILE;
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

uint32_t
test_get_key_value(
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
        err = NM_ERR_BAD_CONFIG_FILE;
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
        err = NM_ERR_BAD_CONFIG_FILE;
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
        err = NM_ERR_BAD_CONFIG_FILE;
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

uint32_t
test_space_delimited_string_to_list(
    const char *pszString,
    size_t *pCount,
    char ***pppszStringList
)
{
    uint32_t err = 0;
    size_t i = 0, count = 0;
    char *pszString1 = NULL, *pszString2 = NULL;
    char *s1, *s2, **ppszStringList = NULL;

    if (!pCount || !pppszStringList)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = netmgr_alloc_string(pszString, &pszString1);
    bail_on_error(err);
    err = netmgr_alloc_string(pszString, &pszString2);
    bail_on_error(err);

    s2 = pszString1;
    do {
        s1 = strsep(&s2, " ");
        if (strlen(s1) > 0)
        {
            count++;
        }
    } while (s2 != NULL);

    if (count > 0)
    {
        err = netmgr_alloc((count * sizeof(char *)), (void **)&ppszStringList);
        bail_on_error(err);

        s2 = pszString2;
        do {
            s1 = strsep(&s2, " ");
            if (strlen(s1) > 0)
            {
                err = netmgr_alloc_string(s1, &(ppszStringList[i++]));
                bail_on_error(err);
            }
        } while (s2 != NULL);
    }

    *pCount = count;
    *pppszStringList = ppszStringList;

cleanup:
    netmgr_free(pszString1);
    netmgr_free(pszString2);
    return err;

error:
    netmgr_list_free(count, (void **)ppszStringList);
    if (pCount != NULL)
    {
        *pCount = 0;
    }
    if (pppszStringList != NULL)
    {
        *pppszStringList = NULL;
    }
    goto cleanup;
}

uint32_t
test_file_value(
    const char *pszFilename,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue)
{
    uint32_t err = 0;
    size_t i = 0, j = 0, lineCount = 0, sectionCount = 0, keyCount = 0;
    char *pszFileBuf = NULL, *pszSectionName = NULL, *pszKeyName = NULL;
    char *pszValueName = NULL;
    char **ppszLineBuf = NULL;
    const char *pszCursor = NULL;

    if (IS_NULL_OR_EMPTY(pszFilename))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = test_read_conf_file(pszFilename, &pszFileBuf);
    bail_on_error(err);

    err = test_string_to_line_array(pszFileBuf, &lineCount, &ppszLineBuf);
    bail_on_error(err);

    for (i = 0; i < lineCount; i++)
    {
        pszCursor = ppszLineBuf[i];
        //Remove white space
        while (pszCursor && *pszCursor && isspace((int)*pszCursor))
        {
            pszCursor++;
        }
        // Ignore comments
        if (!pszCursor || !*pszCursor || *pszCursor == '#')
        {
            continue;
        }

        if (*pszCursor == '[')
        {
            netmgr_free(pszSectionName);
            pszSectionName = NULL;

            err = test_get_section_name(ppszLineBuf[i], &pszSectionName);
            bail_on_error(err);

            if (!strcmp(pszSectionName, pszSection))
            {
                if (sectionCount)
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
                sectionCount++;
            }
            else
            {
                if ((sectionCount == 1) && (keyCount == 0))
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
            }
        }
        else
        {
            netmgr_free(pszKeyName);
            pszKeyName = NULL;
            netmgr_free(pszValueName);
            pszValueName = NULL;
 
            err = test_get_key_value(ppszLineBuf[i],
                                     &pszKeyName,
                                     &pszValueName);
            bail_on_error(err);

            if (!strcmp(pszKeyName, pszKey) && !strcmp(pszValueName, pszValue))
            {
                if (keyCount)
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }

                keyCount++;

                if (!sectionCount)
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
            }
        }
    }

    if (!keyCount || !sectionCount)
    {
        err = NM_ERR_BAD_CONFIG_FILE;
        bail_on_error(err);
    }

cleanup:
    netmgr_free(pszKeyName);
    netmgr_free(pszValueName);
    netmgr_free(pszSectionName);
    netmgr_free(pszFileBuf);
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
    return err;

error:
    goto cleanup;

}

uint32_t
test_file_value_list(
    const char *pszFilename,
    const char *pszSection,
    const char *pszKey,
    const char **ppszValue,
    size_t valueCount)
{
    uint32_t err = 0;
    size_t i = 0, j = 0, lineCount = 0, sectionCount = 0, keyCount = 0;
    size_t valueListCount = 0;
    char *pszFileBuf = NULL, *pszSectionName = NULL, *pszKeyName = NULL;
    char *pszValue = NULL;
    char **ppszLineBuf = NULL, **ppszValueList = NULL;
    const char *pszCursor = NULL;

    if (IS_NULL_OR_EMPTY(pszFilename))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = test_read_conf_file(pszFilename, &pszFileBuf);
    bail_on_error(err);

    err = test_string_to_line_array(pszFileBuf, &lineCount, &ppszLineBuf);
    bail_on_error(err);

    for (i = 0; i < lineCount; i++)
    {
        pszCursor = ppszLineBuf[i];
        //Remove white space
        while (pszCursor && *pszCursor && isspace((int)*pszCursor))
        {
            pszCursor++;
        }
        // Ignore comments
        if (!pszCursor || !*pszCursor || *pszCursor == '#')
        {
            continue;
        }

        if (*pszCursor == '[')
        {
            netmgr_free(pszSectionName);
            pszSectionName = NULL;

            err = test_get_section_name(ppszLineBuf[i], &pszSectionName);
            bail_on_error(err);

            if (!strcmp(pszSectionName, pszSection))
            {
                if (sectionCount)
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
                sectionCount++;
            }
            else
            {
                if ((sectionCount == 1) && (keyCount == 0))
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
            }
        }
        else
        {
            netmgr_free(pszKeyName);
            pszKeyName = NULL;
            netmgr_free(pszValue);
            pszValue = NULL;
 
            err = test_get_key_value(ppszLineBuf[i],
                                     &pszKeyName,
                                     &pszValue);
            bail_on_error(err);

            if (!strcmp(pszKeyName, pszKey))
            {
                if (keyCount)
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
                err = test_space_delimited_string_to_list(pszValue,
                                                          &valueListCount,
                                                          &ppszValueList);
                bail_on_error(err);

                if (valueListCount != valueCount)
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
                for (j = 0; j < valueCount; j++)
                {
                    if (strcmp(ppszValueList[j], ppszValue[j]))
                    {
                        err = NM_ERR_BAD_CONFIG_FILE;
                        bail_on_error(err);
                    }
                }
                keyCount++;
            }

            if ((keyCount && !sectionCount))
            {
                err = NM_ERR_BAD_CONFIG_FILE;
                bail_on_error(err);
            }
        }
    }

    if (!keyCount || !sectionCount)
    {
        err = NM_ERR_BAD_CONFIG_FILE;
        bail_on_error(err);
    }

cleanup:
    netmgr_free(pszKeyName);
    netmgr_free(pszValue);
    netmgr_list_free(valueListCount, (void **)ppszValueList);
    netmgr_free(pszSectionName);
    netmgr_free(pszFileBuf);
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
    return err;

error:
    goto cleanup;

}

uint32_t
test_file_routes(
    const char *pszFilename,
    const char *pszSection,
    const char *pszKey,
    const char *pszValue)
{
    uint32_t err = 0, sectionFound = 0;
    size_t i = 0, j = 0, lineCount = 0, sectionCount = 0, keyCount = 0;
    char *pszFileBuf = NULL, *pszSectionName = NULL, *pszKeyName = NULL;
    char *pszValueName = NULL;
    char **ppszLineBuf = NULL;
    const char *pszCursor = NULL;

    if (IS_NULL_OR_EMPTY(pszFilename))
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    err = test_read_conf_file(pszFilename, &pszFileBuf);
    bail_on_error(err);

    err = test_string_to_line_array(pszFileBuf, &lineCount, &ppszLineBuf);
    bail_on_error(err);

    for (i = 0; i < lineCount; i++)
    {
        pszCursor = ppszLineBuf[i];
        //Remove white space
        while (pszCursor && *pszCursor && isspace((int)*pszCursor))
        {
            pszCursor++;
        }
        // Ignore comments
        if (!pszCursor || !*pszCursor || *pszCursor == '#')
        {
            continue;
        }

        if (*pszCursor == '[')
        {
            netmgr_free(pszSectionName);
            pszSectionName = NULL;

            err = test_get_section_name(ppszLineBuf[i], &pszSectionName);
            bail_on_error(err);

            if (!strcmp(pszSectionName, pszSection))
            {
                sectionFound = 1;
            }
            else
            {
                sectionFound = 0;
            }
        }
        else
        {
            netmgr_free(pszKeyName);
            pszKeyName = NULL;
            netmgr_free(pszValueName);
            pszValueName = NULL;
 
            err = test_get_key_value(ppszLineBuf[i],
                                     &pszKeyName,
                                     &pszValueName);
            bail_on_error(err);

            if (!strcmp(pszKeyName, pszKey) && !strcmp(pszValueName, pszValue))
            {
                if (sectionFound)
                {
                    keyCount++;
                }
                else if (!strcmp(pszSectionName, SECTION_NETWORK))
                {
                    continue;
                }
                else
                {
                    err = NM_ERR_BAD_CONFIG_FILE;
                    bail_on_error(err);
                }
            }
            bail_on_error(err);
        }
    }

    if (!keyCount)
    {
        err = NM_ERR_BAD_CONFIG_FILE;
        bail_on_error(err);
    }

cleanup:
    netmgr_free(pszKeyName);
    netmgr_free(pszValueName);
    netmgr_free(pszSectionName);
    netmgr_free(pszFileBuf);
    netmgr_list_free(lineCount, (void **)ppszLineBuf);
    return err;

error:
    goto cleanup;

}

uint32_t
system_command(
    const char *pszCommand)
{
    uint32_t err = 0;
    int retSystemCmd = 0;

    if (pszCommand == NULL)
    {
        err = NM_ERR_INVALID_PARAMETER;
        bail_on_error(err);
    }

    retSystemCmd = system(pszCommand);
    err = (retSystemCmd == -1) ? errno : retSystemCmd;

cleanup:
    return err;

error:
    goto cleanup;
}
