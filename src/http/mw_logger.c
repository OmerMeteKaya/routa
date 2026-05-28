#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/mw_logger.h"
#include "util/logger.h"
#include <time.h>

void mw_logger(middleware_chain_t *chain, const http_request_t *req,
               http_response_t *resp, next_fn_t next, void *ctx, int current) {
    (void)ctx;

    next(chain, req, resp, current);
}
