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
typedef void (*next_fn_t)(middleware_chain_t*, const http_request_t*, http_response_t*, int);

/* Middleware function signature */
typedef void (*middleware_fn_t)(middleware_chain_t *chain,
                                const http_request_t *req,
                                http_response_t *resp,
                                next_fn_t next,
                                void *ctx,int);

typedef struct {
    middleware_fn_t   fn;
    void * volatile   ctx;   /* hot-reloadable: see middleware_chain_update_ctx() */
} middleware_t;

#define ROUTA_MAX_MIDDLEWARES 32

struct middleware_chain {
    middleware_t middlewares[ROUTA_MAX_MIDDLEWARES];
    int          count;
    /* final handler — called after all middlewares */
    route_handler_t final_handler;
    void           *final_ctx;
};

middleware_chain_t *middleware_chain_new(void);
int                 middleware_chain_use(middleware_chain_t *chain, middleware_fn_t fn, void *ctx);
void                middleware_chain_set_handler(middleware_chain_t *chain, route_handler_t handler, void *ctx);
void                middleware_chain_execute(middleware_chain_t *chain, const http_request_t *req, http_response_t *resp);
void                middleware_next(middleware_chain_t *chain, const http_request_t *req, http_response_t *resp,int);
void                middleware_chain_free(middleware_chain_t *chain);

/* Atomically swaps the ctx pointer for the middleware at chain index idx
 * (as returned by middleware_chain_use(), which is simply the return
 * value 0, 1, 2, ... in registration order) to new_ctx. Used for
 * config hot-reload (SIGHUP): reload builds a brand-new config struct
 * for a given middleware (e.g. a fresh acl_config_t with the reloaded
 * ACL rules) and swaps it in here, rather than mutating the old struct
 * in place -- so a request concurrently mid-flight through this
 * middleware either sees the complete old config or the complete new
 * one, never a half-updated struct, without needing a lock. The old
 * ctx is deliberately NOT freed by this call (the caller may still have
 * in-flight requests referencing it) -- this does mean each reload
 * leaks the previous ctx struct, which is an accepted tradeoff (config
 * reloads are rare, the structs are small, and this whole layer is
 * slated for a full rewrite rather than adding reference counting or
 * grace-period reclamation here). Returns -1 if idx is out of range. */
int middleware_chain_update_ctx(middleware_chain_t *chain, int idx, void *new_ctx);

#endif
