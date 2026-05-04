//
// Created by mete on 4.05.2026.
//
#ifndef ROUTA_HTTP_MIDDLEWARE_H
#define ROUTA_HTTP_MIDDLEWARE_H

#include "router.h"
#include "http/request.h"
#include "http/response.h"

/* Forward declaration */
typedef struct middleware_chain middleware_chain_t;

/* next_fn: call to pass control to next middleware */
typedef void (*next_fn_t)(middleware_chain_t *chain,
                          const http_request_t *req,
                          http_response_t *resp);

/* Middleware function signature */
typedef void (*middleware_fn_t)(middleware_chain_t *chain,
                                const http_request_t *req,
                                http_response_t *resp,
                                next_fn_t next,
                                void *ctx);

typedef struct {
    middleware_fn_t fn;
    void           *ctx;
} middleware_t;

#define ROUTA_MAX_MIDDLEWARES 32

struct middleware_chain {
    middleware_t middlewares[ROUTA_MAX_MIDDLEWARES];
    int          count;
    int          current;   /* index of currently executing middleware */
    /* final handler — called after all middlewares */
    route_handler_t final_handler;
    void           *final_ctx;
};

middleware_chain_t *middleware_chain_new(void);
int                 middleware_chain_use(middleware_chain_t *chain, middleware_fn_t fn, void *ctx);
void                middleware_chain_set_handler(middleware_chain_t *chain, route_handler_t handler, void *ctx);
void                middleware_chain_execute(middleware_chain_t *chain, const http_request_t *req, http_response_t *resp);
void                middleware_next(middleware_chain_t *chain, const http_request_t *req, http_response_t *resp);
void                middleware_chain_free(middleware_chain_t *chain);

#endif
