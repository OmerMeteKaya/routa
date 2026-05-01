#ifndef ROUTA_HTTP_STATIC_H
#define ROUTA_HTTP_STATIC_H

#include "http/request.h"
#include "http/response.h"

typedef struct {
    char doc_root[512];
    char url_prefix[256];
    int  enable_index;
} static_config_t;

int static_serve(const http_request_t *req, http_response_t *resp,
                 const static_config_t *cfg);

#endif
