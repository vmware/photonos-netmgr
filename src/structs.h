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

typedef struct _KEYVALUE_INI
{
    char * pszKey;
    char * pszValue; 

    struct _KEYVALUE_INI * pNext;

} KEYVALUE_INI;

typedef struct _SECTION_INI
{
    char *  pszName;

    PKEYVALUE_INI pKeyValue;

    struct _SECTION_INI * pNext;

} SECTION_INI;

typedef struct _CONFIG_INI
{
    char * pszPath;

    PSECTION_INI pSection;

} CONFIG_INI;
