#define bail_on_error(errcode) \
    if (errcode) { \
        goto error; \
    }
