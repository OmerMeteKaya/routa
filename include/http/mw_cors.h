#ifndef ROUTA_HTTP_MW_CORS_H
#define ROUTA_HTTP_MW_CORS_H

#include "http/middleware.h"
#include "http/request.h"
#include "http/response.h"

typedef struct {
    char origin[256];
    char methods[256];
    char headers[256];
} cors_config_t;

cors_config_t *mw_cors_config_new(const char *origin,
                                   const char *methods,
                                   const char *headers);
void mw_cors_config_free(cors_config_t *cfg);

void mw_cors(middleware_chain_t *chain, const http_request_t *req,
             http_response_t *resp, next_fn_t next, void *ctx,int);

#endif /* ROUTA_HTTP_MW_CORS_H */
