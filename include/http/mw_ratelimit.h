#ifndef ROUTA_HTTP_MW_RATELIMIT_H
#define ROUTA_HTTP_MW_RATELIMIT_H

#include "request.h"
#include "response.h"
#include "http/middleware.h"

typedef struct {
    int    requests_per_second;
    int    burst;
} rate_limit_config_t;

rate_limit_config_t *mw_rate_limit_config_new(int rps, int burst);
void mw_rate_limit_config_free(rate_limit_config_t *cfg);

void mw_rate_limit(middleware_chain_t *chain, const http_request_t *req,
                   http_response_t *resp, next_fn_t next, void *ctx);

#endif //ROUTA_HTTP_MW_RATELIMIT_H
