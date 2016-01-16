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

#ifndef __INI_PARSER_H
#define __INI_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _KEYVALUE_INI * PKEYVALUE_INI;
typedef struct _SECTION_INI * PSECTION_INI;
typedef struct _CONFIG_INI * PCONFIG_INI;

uint32_t
ini_cfg_read(
    const char*  pszPath,
    PCONFIG_INI* ppConfig 
    );

uint32_t
ini_cfg_create_config(
    PCONFIG_INI* ppConfig
    );

uint32_t
ini_cfg_add_section(
    PCONFIG_INI pConfig,
    const char* pszName,
    PSECTION_INI* ppSection
    );

uint32_t
ini_cfg_find_sections(
    PCONFIG_INI    pConfig,
    const char*    pszName,
    PSECTION_INI** pppSections,
    uint32_t*      pdwNumSections
    );

void
ini_cfg_free_sections(
    PSECTION_INI* ppSections,
    uint32_t      dwNumSections
    );

uint32_t
ini_cfg_delete_sections(
    PCONFIG_INI   pConfig,
    const char*   pszName
    );

PKEYVALUE_INI
ini_cfg_find_key(
    PSECTION_INI  pSection,
    const char*   pszKey
    );

uint32_t
ini_cfg_add_key(
    PSECTION_INI  pSection,
    const char*   pszKey,
    const char*   pszValue
    );

uint32_t
ini_cfg_set_value(
    PSECTION_INI  pSection,
    const char*   pszKey,
    const char*   pszValue
    );

uint32_t
ini_cfg_delete_key(
    PSECTION_INI  pSection,
    const char*   pszKey
    );
     
uint32_t
ini_cfg_save(
    const char*   pszPath,
    PCONFIG_INI   pConfig
    );

void
ini_cfg_free_config(
    PCONFIG_INI pConfig
    );

#ifdef __cplusplus
}
#endif

#endif /* _INI_PARSER_H */

