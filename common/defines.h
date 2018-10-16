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

#pragma once

#define bail_on_error(errcode) \
    do { \
       if (errcode) { \
          goto error; \
       } \
    } while(0)

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))

static inline void freep(void *p) {
        free(*(void **)p);
}

static inline void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static inline void fclosep(FILE **fp) {
        if (*fp)
                fclose(*fp);
}
