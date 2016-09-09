#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#define MAX_DUID_SIZE                  128
#define DEFAULT_MTU_VALUE              1500

typedef enum DUIDType {
    _DUID_TYPE_MIN      = 0,
    DUID_TYPE_LLT       = 1,
    DUID_TYPE_EN        = 2,
    DUID_TYPE_LL        = 3,
    DUID_TYPE_UUID      = 4,
    _DUID_TYPE_MAX,
} DUIDType;

static const char* const duid_type_table[_DUID_TYPE_MAX] = {
    [DUID_TYPE_LLT]  = "link-layer-time",
    [DUID_TYPE_EN]   = "vendor",
    [DUID_TYPE_LL]   = "link-layer",
    [DUID_TYPE_UUID] = "uuid",
};

#endif /* __CONSTANTS_H__ */


