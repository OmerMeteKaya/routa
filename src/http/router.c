#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/router.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>

#define MAX_ROUTES 256

struct router {
    route_t routes[MAX_ROUTES];
    int route_count;
};

router_t *router_new(void) {
    router_t *r = calloc(1, sizeof(router_t));
    if (!r) {
        LOG_ERROR("Failed to allocate router");
        return NULL;
    }
    return r;
}

void router_free(router_t *r) {
    free(r);
}

int router_add(router_t *r, const char *path, int methods,
               route_handler_t handler, void *ctx) {
    if (!r || !path || !handler) {
        return -1;
    }
    
    if (r->route_count >= MAX_ROUTES) {
        LOG_ERROR("Maximum number of routes reached");
        return -1;
    }
    
    route_t *route = &r->routes[r->route_count];
    
    // Copy path
    strncpy(route->path, path, sizeof(route->path) - 1);
    route->path[sizeof(route->path) - 1] = '\0';
    
    // Convert bitmask to method array
    route->method_count = 0;
    for (int i = 0; i < 8 && i < HTTP_METHOD_UNKNOWN; i++) {
        if (methods & (1 << i)) {
            route->methods[route->method_count] = (http_method_t)i;
            route->method_count++;
            if (route->method_count >= 8) break;
        }
    }
    
    route->handler = handler;
    route->ctx = ctx;
    
    r->route_count++;
    return 0;
}

int router_dispatch(router_t *r, const http_request_t *req,
                    http_response_t *resp, int *allowed_methods) {
    if (!r || !req || !resp) {
        return -1;
    }
    
    int best_match = -1;
    int prefix_match = -1;
    int exact_match = -1;
    
    // Find matching routes
    for (int i = 0; i < r->route_count; i++) {
        route_t *route = &r->routes[i];
        size_t route_path_len = strlen(route->path);
        
        // Check for exact match
        if (strcmp(route->path, req->path) == 0) {
            exact_match = i;
            break;
        }
        
        /* Check for wildcard: if route path ends with '*', match prefix */
        if (route_path_len > 0 && route->path[route_path_len - 1] == '*') {
            size_t prefix_len = route_path_len - 1;
            if (strncmp(route->path, req->path, prefix_len) == 0) {
                prefix_match = i;
            }
            if (prefix_len == 1 && route->path[0] == '/') {
                prefix_match = i;
            }
            continue;
        }
        
        // Check for prefix match (path ending with /*)
        if (route_path_len > 2 && 
            route->path[route_path_len - 2] == '/' && 
            route->path[route_path_len - 1] == '*') {
            
            size_t prefix_len = route_path_len - 2; // Exclude /*
            if (strncmp(route->path, req->path, prefix_len) == 0) {
                // Make sure the next character is either end of string or a slash
                if (req->path[prefix_len] == '\0' || req->path[prefix_len] == '/') {
                    prefix_match = i;
                }
            }
        }
    }
    
    // Determine best match
    if (exact_match >= 0) {
        best_match = exact_match;
    } else if (prefix_match >= 0) {
        best_match = prefix_match;
    }
    
    if (best_match < 0) {
        return -1; // 404 Not Found
    }
    
    // Check if method is allowed
    route_t *route = &r->routes[best_match];
    int method_allowed = 0;
    
    if (allowed_methods) {
        *allowed_methods = 0;
    }
    
    for (int i = 0; i < route->method_count; i++) {
        if (allowed_methods) {
            *allowed_methods |= (1 << route->methods[i]);
        }
        
        if (route->methods[i] == req->method) {
            method_allowed = 1;
            break;
        }
    }
    
    if (!method_allowed) {
        return -2; // 405 Method Not Allowed
    }
    
    // Call handler
    return route->handler(req, resp, route->ctx);
}

route_t *router_match(router_t *r, const http_request_t *req, int *allowed_methods) {
    if (!r || !req) return NULL;

    int best_match  = -1;
    int prefix_match = -1;
    int exact_match  = -1;
    /* Bug fix: prefix_match used to be unconditionally overwritten by
     * every matching wildcard route encountered later in the loop, so
     * whichever wildcard route happened to be registered LAST always
     * won -- regardless of specificity. In practice this meant a
     * catch-all static file route ("/ -> docroot", which matches every
     * path via the "prefix_len == 1 && route->path[0] == '/'" special
     * case below) registered after a more specific proxy/API route like
     * "/proxy/*" would silently steal every request meant for that more
     * specific route, since pool routes are registered before
     * static_dir routes in server_from_config() (see server.c). Now we
     * track the matched route's actual prefix length and only replace
     * prefix_match when a LONGER (more specific) prefix is found, so
     * "/proxy/*" (prefix length 6) always beats "/*" (prefix length 0)
     * for a request to "/proxy/anything", irrespective of registration
     * order. */
    size_t best_prefix_len = 0;

    for (int i = 0; i < r->route_count; i++) {
        route_t *route = &r->routes[i];
        size_t route_path_len = strlen(route->path);

        if (strcmp(route->path, req->path) == 0) {
            exact_match = i;
            break;
        }

        if (route_path_len > 0 && route->path[route_path_len - 1] == '*') {
            size_t prefix_len = route_path_len - 1;
            int matched = 0;
            if (strncmp(route->path, req->path, prefix_len) == 0)
                matched = 1;
            if (prefix_len == 1 && route->path[0] == '/')
                matched = 1;
            if (matched && (prefix_match < 0 || prefix_len > best_prefix_len)) {
                prefix_match = i;
                best_prefix_len = prefix_len;
            }
            continue;
        }

        if (route_path_len > 2 &&
            route->path[route_path_len - 2] == '/' &&
            route->path[route_path_len - 1] == '*') {
            size_t prefix_len = route_path_len - 2;
            if (strncmp(route->path, req->path, prefix_len) == 0 &&
                (req->path[prefix_len] == '\0' || req->path[prefix_len] == '/')) {
                if (prefix_match < 0 || prefix_len > best_prefix_len) {
                    prefix_match = i;
                    best_prefix_len = prefix_len;
                }
            }
        }
    }

    best_match = (exact_match >= 0) ? exact_match : prefix_match;
    if (best_match < 0) return NULL;

    route_t *route = &r->routes[best_match];

    if (allowed_methods) {
        *allowed_methods = 0;
        for (int i = 0; i < route->method_count; i++)
            *allowed_methods |= (1 << route->methods[i]);
    }

    /* Check method is allowed — return NULL with allowed_methods filled = 405 signal */
    for (int i = 0; i < route->method_count; i++)
        if (route->methods[i] == req->method)
            return route;

    return NULL; /* method not allowed */
}


