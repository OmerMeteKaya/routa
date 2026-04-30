#ifndef ROUTA_HTTP_ROUTER_H
#define ROUTA_HTTP_ROUTER_H

#include "http/request.h"
#include "http/response.h"

typedef int (*route_handler_t)(const http_request_t *req,
                                http_response_t *resp, void *ctx);

typedef struct {
    char            path[256];
    http_method_t   methods[8];
    int             method_count;
    route_handler_t handler;
    void           *ctx;
} route_t;

typedef struct router router_t;

router_t *router_new(void);
void      router_free(router_t *r);

// Register a route. methods is a bitmask of (1 << http_method_t).
int router_add(router_t *r, const char *path, int methods,
               route_handler_t handler, void *ctx);

// Dispatch. Returns 0 if handled, -1 if 404, -2 if 405.
// On 405, allowed_methods bitmask is filled.
int router_dispatch(router_t *r, const http_request_t *req,
                    http_response_t *resp, int *allowed_methods);

#endif // ROUTA_HTTP_ROUTER_H
