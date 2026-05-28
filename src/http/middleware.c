//
// Created by mete on 4.05.2026.
//

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/middleware.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>

middleware_chain_t *middleware_chain_new(void) {
    middleware_chain_t *c = calloc(1, sizeof(middleware_chain_t));
    return c;
}

int middleware_chain_use(middleware_chain_t *chain, middleware_fn_t fn, void *ctx) {
    if (!chain || !fn) {
        return -1;
    }
    
    if (chain->count >= ROUTA_MAX_MIDDLEWARES) {
        LOG_ERROR("Maximum number of middlewares reached");
        return -1;
    }
    
    chain->middlewares[chain->count].fn = fn;
    chain->middlewares[chain->count].ctx = ctx;
    chain->count++;
    
    return 0;
}

void middleware_chain_set_handler(middleware_chain_t *chain, route_handler_t handler, void *ctx) {
    if (!chain) return;
    
    chain->final_handler = handler;
    chain->final_ctx = ctx;
}

void middleware_chain_execute(middleware_chain_t *chain,
                              const http_request_t *req,
                              http_response_t *resp) {
    if (!chain || !req || !resp) return;
    if (chain->count > 0)
        middleware_next(chain, req, resp, 0);
    else if (chain->final_handler)
        chain->final_handler(req, resp, chain->final_ctx);
}

void middleware_next(middleware_chain_t *chain,
                    const http_request_t *req,
                    http_response_t *resp,
                    int current) {
    if (!chain || !req || !resp) return;
    if (current >= chain->count) {
        if (chain->final_handler)
            chain->final_handler(req, resp, chain->final_ctx);
        return;
    }
    middleware_t *mw = &chain->middlewares[current];
    mw->fn(chain, req, resp, middleware_next, mw->ctx, current + 1);
}

void middleware_chain_free(middleware_chain_t *chain) {
    free(chain);
}
