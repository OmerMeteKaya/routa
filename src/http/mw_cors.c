#define _GNU_SOURCE
#include "http/mw_cors.h"
#include <stdlib.h>
#include <string.h>

cors_config_t *mw_cors_config_new(const char *origin,
                                   const char *methods,
                                   const char *headers) {
    cors_config_t *cfg = calloc(1, sizeof(cors_config_t));
    if (!cfg) return NULL;
    if (origin)  strncpy(cfg->origin,  origin,  sizeof(cfg->origin)  - 1);
    if (methods) strncpy(cfg->methods, methods, sizeof(cfg->methods) - 1);
    if (headers) strncpy(cfg->headers, headers, sizeof(cfg->headers) - 1);
    return cfg;
}

void mw_cors_config_free(cors_config_t *cfg) {
    free(cfg);
}

void mw_cors(middleware_chain_t *chain, const http_request_t *req,
             http_response_t *resp, next_fn_t next, void *ctx, int current) {
    cors_config_t *cfg = (cors_config_t *)ctx;

    const char *origin  = (cfg && cfg->origin[0])  ? cfg->origin  : "*";
    const char *methods = (cfg && cfg->methods[0])  ? cfg->methods : "GET, POST, OPTIONS";
    const char *headers = (cfg && cfg->headers[0])  ? cfg->headers : "Content-Type";

    http_response_set_header(resp, "Access-Control-Allow-Origin",  origin);
    http_response_set_header(resp, "Access-Control-Allow-Methods", methods);
    http_response_set_header(resp, "Access-Control-Allow-Headers", headers);

    /* OPTIONS preflight — short-circuit, no next() needed */
    if (req->method == HTTP_OPTIONS) {
        http_response_set_status(resp, 204, "No Content");
        return;
    }

    next(chain, req, resp, current);
}
