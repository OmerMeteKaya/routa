#ifndef ROUTA_CORE_SERVER_H
#define ROUTA_CORE_SERVER_H

#include "http/router.h"
#include "http/static.h"
#include "core/config.h"
#include "http/middleware.h"
#include "lb/lb.h"
#include <stdatomic.h>

extern atomic_int g_drain_flag;

struct event_loop;

/* One independently-configured load-balancer pool bound to a path pattern.
 * Introduced to support multiple upstream pools per server (e.g. /api/*
 * -> pool A, /static-proxy/* -> pool B), instead of the previous design
 * where a server could only ever have a single global lb_t. */
typedef struct {
    lb_t *lb;
    void *route_ctx;   /* lb_handler_ctx_t, freed in server_free */
} lb_pool_entry_t;

/* ctx passed to the internal route handler that marks a path as "proxy to
 * this lb" (see server.c's lb_route_handler / server_lb_route()).
 * Public so event_loop.c's request-dispatch loop can read ctx->lb to
 * find the correct pool for a matched route, instead of assuming a
 * single server-wide lb_t. */
typedef struct {
    lb_t *lb;
    void *acl;   /* acl_config_t*, or NULL if this pool has no ACL rules.
                 * Declared void* to avoid a header dependency on
                 * mw_acl.h from server.h. */
} lb_handler_ctx_t;

typedef struct {
    struct event_loop  *loop;
    void               *static_configs[16];
    int                 static_config_count;
    middleware_chain_t *chain;

    /* Legacy single-pool fields. Kept for source compatibility with
     * existing callers of server_enable_lb()/server_lb_add_upstream() that
     * only ever want one pool: they operate on lb_pools[0]. New code that
     * needs multiple pools should prefer server_enable_lb_named() /
     * server_lb_add_upstream_named() / server_lb_route() with distinct
     * pool names. */
    lb_t               *lb;           /* NULL when load balancer disabled; == lb_pools[0].lb */
    void               *lb_route_ctx; /* == lb_pools[0].route_ctx */

    lb_pool_entry_t     lb_pools[ROUTA_MAX_LB_POOLS];
    int                 lb_pool_count;
    /* Metrics endpoint, set by server_from_config(); server_run() reads
     * these to decide whether/where to register the /metrics route.
     * Defaults (metrics_enabled=1, metrics_path="/metrics") match the
     * previous hardcoded behavior for servers built with server_new()
     * directly instead of server_from_config(). */
    int  metrics_enabled;
    char metrics_path[256];

    /* ── Hot-reload bookkeeping ────────────────────────────────────────────
     * Chain index of each config-driven middleware, as returned by
     * server_use() -- -1 if that middleware was never enabled (so this
     * server has no such slot to reload into; the reload logic simply
     * skips it, same as at startup). Populated once by server_from_config()
     * and never changes afterward (the middleware TYPES present don't
     * change on reload, only their config content does -- e.g. you can't
     * newly enable ACL via a SIGHUP reload if it wasn't enabled at
     * startup; that would require restructuring the chain, which stays a
     * restart-only operation). */
    int acl_mw_idx;
    int cors_mw_idx;
    int basic_auth_mw_idx;
    int jwt_auth_mw_idx;
    int rate_limit_mw_idx;
    int compress_mw_idx;
} server_t;

server_t *server_new(int port, int n_threads);
void      server_run(server_t *s);
void      server_free(server_t *s);
/* Returns the middleware's chain index (registration order, 0-based),
 * or -1 on failure. Used by server_from_config() to remember which
 * chain slot each config-driven middleware landed in, for hot reload --
 * see middleware_chain_update_ctx(). */
int       server_use(server_t *s, middleware_fn_t fn, void *ctx);
void      server_route(server_t *s, const char *path, int methods,
                       route_handler_t handler, void *ctx);
int       server_static(server_t *s, const char *url_prefix,
                        const char *doc_root, int enable_index);
int       server_enable_tls(server_t *s,
                            const char *cert_file, const char *key_file);
int       server_enable_ocsp_stapling(server_t *s, const char *ocsp_file);

/* Load balancer — call before server_run() */
int  server_enable_lb(server_t *s, const lb_config_t *cfg);
int  server_lb_add_upstream(server_t *s,
                             const char *host, uint16_t port, int weight);
int  server_lb_add_upstream_tls(server_t *s,
                                 const char *host, uint16_t port, int weight);

/* Create server from config struct / file */
server_t *server_from_config(const routa_config_t *cfg);
server_t *server_from_config_file(const char *path);
/* Sets the config file path used for SIGHUP hot-reload -- required if you
 * load config manually (routa_config_load() + server_from_config()),
 * since server_from_config() alone has no way to know which file to
 * re-read on SIGHUP. server_from_config_file() calls this internally;
 * callers using the manual two-step path must call it themselves before
 * server_run(), or SIGHUP hot-reload will be silently disabled (this was
 * previously the case for src/main.c itself -- see server_set_config_path()
 * in server.c for the full story). */
void server_set_config_path(const char *path);
int server_lb_route(server_t *s, const char *path, int methods);
void server_lb_set_acl(server_t *s, void *acl);

#define HTTP_GET_M     (1 << HTTP_GET)
#define HTTP_POST_M    (1 << HTTP_POST)
#define HTTP_PUT_M     (1 << HTTP_PUT)
#define HTTP_PATCH_M   (1 << HTTP_PATCH)
#define HTTP_DELETE_M  (1 << HTTP_DELETE)
#define HTTP_HEAD_M    (1 << HTTP_HEAD)
#define HTTP_OPTIONS_M (1 << HTTP_OPTIONS)

#endif /* ROUTA_CORE_SERVER_H */