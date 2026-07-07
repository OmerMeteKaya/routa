#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/server.h"
#include "core/event_loop.h"
#include "util/logger.h"
#include "http/middleware.h"
#include "http/file_cache.h"
#include "lb/lb.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "util/metrics.h"
#include "http/mw_metrics.h"
#include "http/mw_cors.h"
#include "http/mw_auth.h"
#include "http/mw_compress.h"
#include "http/mw_logger.h"
#include "http/mw_ratelimit.h"

#include <stdatomic.h>
atomic_int g_drain_flag = 0;
static struct event_loop  *g_loop        = NULL;
static volatile sig_atomic_t g_reload_flag = 0;
static char                g_config_path[512] = {0};

/* SIGTERM / SIGINT — initiate graceful drain */
static void signal_handler(int sig) {
    (void)sig;
    g_drain_flag = 1;
}
/* SIGHUP — hot reload: set flag, worker 0 processes it asynchronously */
static void sighup_handler(int sig) {
    (void)sig;
    g_reload_flag = 1;
}

/* ── server_new ─────────────────────────────────────────────────────────────*/
server_t *server_new(int port, int n_threads) {
    server_t *s = calloc(1, sizeof(server_t));
    if (!s) { LOG_ERROR("Failed to allocate server"); return NULL; }

    s->loop = (struct event_loop *)event_loop_new(port, n_threads);
    if (!s->loop) {
        LOG_ERROR("Failed to create event loop");
        free(s);
        return NULL;
    }

    event_loop_set_max_connections((event_loop_t *)s->loop, 10000);
    g_loop = s->loop;

    /* Metrics defaults, overridden by server_from_config() if used */
    s->metrics_enabled = 1;
    strncpy(s->metrics_path, "/metrics", sizeof(s->metrics_path) - 1);

    return s;
}

/* ── Static file serving ────────────────────────────────────────────────────*/
static int static_route_handler(const http_request_t *req,
                                 http_response_t *resp, void *ctx) {
    return static_serve(req, resp, (static_config_t *)ctx);
}

int server_static(server_t *s, const char *url_prefix,
                  const char *doc_root, int enable_index) {
    if (!s || !s->loop || !url_prefix || !doc_root) return -1;

    static_config_t *cfg = calloc(1, sizeof(static_config_t));
    if (!cfg) return -1;

    if (s->static_config_count < 16)
        s->static_configs[s->static_config_count++] = cfg;

    char *resolved_root = realpath(doc_root, NULL);
    if (resolved_root) {
        strncpy(cfg->doc_root, resolved_root, sizeof(cfg->doc_root) - 1);
        free(resolved_root);
    }  else {
        strncpy(cfg->doc_root, doc_root, sizeof(cfg->doc_root) - 1);
    }
    cfg->doc_root[sizeof(cfg->doc_root) - 1] = '\0';

    strncpy(cfg->url_prefix, url_prefix, sizeof(cfg->url_prefix) - 1);
    cfg->url_prefix[sizeof(cfg->url_prefix) - 1] = '\0';
    cfg->enable_index = enable_index;

    char pattern[258];
    if (strcmp(url_prefix, "/") == 0) strcpy(pattern, "/*");
    else (void)snprintf(pattern, sizeof(pattern), "%s/*", url_prefix);

    event_loop_add_route((event_loop_t *)s->loop, pattern,
                         HTTP_GET_M | HTTP_HEAD_M, static_route_handler, cfg);
    event_loop_add_route((event_loop_t *)s->loop, url_prefix,
                         HTTP_GET_M | HTTP_HEAD_M, static_route_handler, cfg);
    return 0;
}

/* ── TLS ────────────────────────────────────────────────────────────────────*/
int server_enable_tls(server_t *s,
                      const char *cert_file, const char *key_file) {
    if (!s || !cert_file || !key_file) return -1;
    tls_init();
    event_loop_set_tls((event_loop_t *)s->loop, cert_file, key_file);
    return 0;
}

int server_enable_ocsp_stapling(server_t *s, const char *ocsp_file) {
    if (!s || !s->loop || !ocsp_file) return -1;
    event_loop_t *loop = (event_loop_t *)s->loop;
    if (!event_loop_get_tls_ctx(loop)) {
        LOG_ERROR("TLS must be enabled before OCSP stapling");
        return -1;
    }
    return tls_context_enable_ocsp_stapling(
        event_loop_get_tls_ctx(loop), ocsp_file);
}

/* ── Routing ────────────────────────────────────────────────────────────────*/
void server_route(server_t *s, const char *path, int methods,
                  route_handler_t handler, void *ctx) {
    if (!s || !s->loop) return;
    event_loop_add_route((event_loop_t *)s->loop, path, methods, handler, ctx);
}

/* ── Middleware ─────────────────────────────────────────────────────────────*/
void server_use(server_t *s, middleware_fn_t fn, void *ctx) {
    if (!s) return;
    if (!s->chain) {
        s->chain = middleware_chain_new();
        if (!s->chain) { LOG_ERROR("Failed to create middleware chain"); return; }
    }
    middleware_chain_use(s->chain, fn, ctx);
}

/* ── Load balancer ──────────────────────────────────────────────────────────*/

/* Internal route handler that forwards to LB */

static int lb_route_handler(const http_request_t *req,
                             http_response_t *resp, void *ctx) {
    (void)req; (void)resp; (void)ctx;
    return 0;
}

/* Adds a NEW load-balancer pool every time it's called (does not require
 * -- or reuse -- a previously created pool). This supports servers with
 * multiple independent upstream pools, each later bound to its own path
 * via server_lb_route(). The legacy single-pool fields (s->lb,
 * s->lb_route_ctx) always mirror the MOST RECENTLY added pool, so old
 * call sites that only ever call this once keep working unmodified. */
int server_enable_lb(server_t *s, const lb_config_t *cfg) {
    if (!s) return -1;
    if (s->lb_pool_count >= ROUTA_MAX_LB_POOLS) {
        LOG_ERROR("server_enable_lb: max %d LB pools per server exceeded",
                  ROUTA_MAX_LB_POOLS);
        return -1;
    }

    lb_t *lb = lb_new(cfg);
    if (!lb) { LOG_ERROR("Failed to create load balancer"); return -1; }

    int idx = s->lb_pool_count++;
    s->lb_pools[idx].lb        = lb;
    s->lb_pools[idx].route_ctx = NULL;

    /* Legacy mirror: always points at the most recently added pool */
    s->lb           = lb;
    s->lb_route_ctx = NULL;
    return 0;
}

/* Adds an upstream to the MOST RECENTLY added pool (server_enable_lb()'s
 * last call). To add upstreams to an earlier pool, finish configuring and
 * route it (server_lb_route()) before calling server_enable_lb() again
 * for the next pool -- pools are configured and routed one at a time,
 * left to right, matching how server_from_config()/the config file loader
 * builds them. */
int server_lb_add_upstream(server_t *s,
                            const char *host, uint16_t port, int weight) {
    if (!s || s->lb_pool_count == 0) {
        LOG_ERROR("server_lb_add_upstream: LB not enabled");
        return -1;
    }
    lb_t *lb = s->lb_pools[s->lb_pool_count - 1].lb;
    return lb_add_upstream(lb, host, port, weight);
}

int server_lb_add_upstream_tls(server_t *s,
                                const char *host, uint16_t port, int weight) {
    if (!s || s->lb_pool_count == 0) {
        LOG_ERROR("server_lb_add_upstream_tls: LB not enabled");
        return -1;
    }
    lb_t *lb = s->lb_pools[s->lb_pool_count - 1].lb;
    return lb_add_upstream_tls(lb, host, port, weight);
}

/* Register a route that proxies to the LB.
 * Call after all upstreams are added.
 * path: e.g. "/api/"  methods: HTTP_GET_M|HTTP_POST_M|...             */
int server_lb_route(server_t *s, const char *path, int methods) {
    if (!s || !s->lb || !s->loop) return -1;

    if (lb_start(s->lb) < 0) return -1;

    /* Wire LB into event loop for async upstream handling */
    event_loop_set_lb((event_loop_t *)s->loop, s->lb);

    lb_handler_ctx_t *ctx = calloc(1, sizeof(lb_handler_ctx_t));
    if (!ctx) return -1;
    ctx->lb = s->lb;
    s->lb_route_ctx = ctx;

    event_loop_add_route((event_loop_t *)s->loop,
                         path, methods, lb_route_handler, ctx);
    return 0;
}

/* ── server_run ─────────────────────────────────────────────────────────────*/
void server_run(server_t *s) {
    if (!s || !s->loop) return;
    signal(SIGPIPE, SIG_IGN);
    /* SIGTERM / SIGINT → graceful drain */
    struct sigaction sa = { .sa_handler = signal_handler, .sa_flags = 0 };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* SIGHUP → hot reload (worker 0 picks up g_reload_flag) */
    struct sigaction sa_hup = { .sa_handler = sighup_handler, .sa_flags = 0 };
    sigemptyset(&sa_hup.sa_mask);
    sigaction(SIGHUP, &sa_hup, NULL);

    /* Wire reload flag into event loop; path may be empty if server_new() was
     * used directly — reload_flag is always registered so SIGHUP is handled  */
    event_loop_set_config_reload((event_loop_t *)s->loop,
                                 &g_reload_flag,
                                 g_config_path[0] ? g_config_path : NULL);

    if (s->chain)
        event_loop_set_chain((event_loop_t *)s->loop, s->chain);

    file_cache_config_t fc_cfg = {
        .enabled     = 1,
        .max_entries = 512,
        .ttl_seconds = 5,
        .strategy    = FILE_CACHE_STAT_TTL,
    };
    file_cache_init(&fc_cfg);

    /* ── Observability ── */
    routa_metrics_init();
    if (s->metrics_enabled) {
        const char *mpath = s->metrics_path[0] ? s->metrics_path : "/metrics";
        event_loop_add_route((event_loop_t *)s->loop, mpath,
                             1 << HTTP_GET, routa_metrics_handler, NULL);
    }
    
    event_loop_run((event_loop_t *)s->loop);
}

/* ── server_from_config ─────────────────────────────────────────────────────*/
server_t *server_from_config(const routa_config_t *cfg) {
    if (routa_config_validate(cfg) < 0) return NULL;

    log_set_level((log_level_t)cfg->log_level);

    server_t *s = server_new(cfg->port, cfg->n_workers);
    if (!s) return NULL;

    event_loop_set_max_connections((event_loop_t *)s->loop,
                                   cfg->max_connections);
    event_loop_set_timeouts((event_loop_t *)s->loop,
                            cfg->keepalive_timeout_ms, cfg->request_timeout_ms);
    event_loop_set_global_response_headers(
        cfg->response_header_add, cfg->response_header_add_count,
        cfg->response_header_remove, cfg->response_header_remove_count);

    if (cfg->tls_enabled)
        server_enable_tls(s, cfg->tls_cert, cfg->tls_key);

    s->metrics_enabled = cfg->metrics_enabled;
    if (cfg->metrics_path[0])
        strncpy(s->metrics_path, cfg->metrics_path, sizeof(s->metrics_path) - 1);

    /* ── Middleware, applied in the order registered (outermost first):
     * logger -> cors -> auth (basic or jwt) -> ratelimit -> compress ──── */
    if (cfg->logger_enabled) {
        server_use(s, mw_logger, NULL);
    }
    if (cfg->cors_enabled) {
        cors_config_t *cors_cfg = mw_cors_config_new(
            cfg->cors_origin, cfg->cors_methods, cfg->cors_headers);
        if (cors_cfg) server_use(s, mw_cors, cors_cfg);
        /* Note: cors_cfg is intentionally leaked for the process lifetime
         * (freed at exit) -- mirrors the existing lifetime pattern for
         * static_configs[] in this same function; server_free() doesn't
         * currently track middleware ctx pointers for cleanup. */
    }
    if (cfg->auth_basic_enabled) {
        basic_auth_config_t *auth_cfg = basic_auth_config_new(cfg->auth_basic_realm);
        if (auth_cfg) {
            for (int i = 0; i < cfg->auth_basic_user_count; i++) {
                basic_auth_config_add_user(auth_cfg,
                    cfg->auth_basic_users[i].username,
                    cfg->auth_basic_users[i].password);
            }
            server_use(s, mw_basic_auth, auth_cfg);
        }
    }
    if (cfg->auth_jwt_enabled) {
        jwt_config_t *jwt_cfg = NULL;
        if (cfg->auth_jwt_secret[0]) {
            jwt_cfg = jwt_config_new_hs256(cfg->auth_jwt_secret);
        } else if (cfg->auth_jwt_pubkey_path[0]) {
            FILE *pkf = fopen(cfg->auth_jwt_pubkey_path, "r");
            if (pkf) {
                char pembuf[8192];
                size_t n = fread(pembuf, 1, sizeof(pembuf) - 1, pkf);
                pembuf[n] = '\0';
                fclose(pkf);
                jwt_cfg = jwt_config_new_rs256(pembuf);
            } else {
                LOG_ERROR("server_from_config: cannot open auth_jwt_pubkey_path '%s'",
                          cfg->auth_jwt_pubkey_path);
            }
        } else {
            LOG_ERROR("server_from_config: auth_jwt_enabled but neither "
                      "auth_jwt_secret nor auth_jwt_pubkey_path set");
        }
        if (jwt_cfg) {
            jwt_cfg->verify_exp = cfg->auth_jwt_verify_exp;
            if (cfg->auth_jwt_issuer[0])
                strncpy(jwt_cfg->issuer, cfg->auth_jwt_issuer, sizeof(jwt_cfg->issuer) - 1);
            if (cfg->auth_jwt_audience[0])
                strncpy(jwt_cfg->audience, cfg->auth_jwt_audience, sizeof(jwt_cfg->audience) - 1);
            server_use(s, mw_jwt_auth, jwt_cfg);
        }
    }
    if (cfg->rate_limit_enabled) {
        rate_limit_config_t *rl_cfg = mw_rate_limit_config_new(
            cfg->rate_limit_requests_per_second, cfg->rate_limit_burst);
        if (rl_cfg) server_use(s, mw_rate_limit, rl_cfg);
    }
    if (cfg->compress_enabled) {
        compress_config_t *cc = calloc(1, sizeof(compress_config_t));
        if (cc) {
            cc->min_size = cfg->compress_min_size;
            cc->level    = cfg->compress_level;
            cc->prefer   = COMPRESS_PREFER_GZIP;
            server_use(s, mw_compress, cc);
        }
    }

    for (int i = 0; i < cfg->static_count; i++)
        server_static(s, cfg->static_dirs[i].url_prefix,
                      cfg->static_dirs[i].doc_root,
                      cfg->static_dirs[i].enable_index);

    /* Load balancer(s) -- one server_enable_lb()/add_upstream/route()
     * sequence per configured pool (cfg->pools[]). Each pool gets its own
     * independent lb_t bound to its own route pattern; see the multi-pool
     * architecture in server.h/event_loop.c/proxy.c. */
    for (int p = 0; p < cfg->pool_count; p++) {
        const lb_pool_config_t *pcfg = &cfg->pools[p];
        if (!pcfg->lb_enabled || pcfg->upstream_count == 0) continue;

        lb_config_t lbc;
        lb_config_init(&lbc);
        lbc.algo                      = (lb_algo_t)pcfg->lb_algo;
        lbc.pool_max_per_node         = pcfg->lb_pool_max_per_node;
        lbc.pool_connect_timeout_ms   = pcfg->lb_pool_connect_timeout_ms;
        lbc.upstream_read_timeout_ms  = pcfg->lb_upstream_read_timeout_ms;
        lbc.upstream_write_timeout_ms = pcfg->lb_upstream_write_timeout_ms;
        lbc.pool_idle_timeout_s       = pcfg->lb_pool_idle_timeout_s;
        lbc.passive_fail_threshold    = pcfg->lb_passive_fail_threshold;
        lbc.passive_recover_threshold = pcfg->lb_passive_recover_threshold;
        lbc.max_retries               = pcfg->lb_max_retries;
        lbc.retry_on_5xx              = pcfg->lb_retry_on_5xx;
        lbc.consistent_hash_vnodes    = pcfg->lb_consistent_hash_vnodes;
        lbc.hc.type                   = (health_check_type_t)pcfg->lb_hc_type;
        lbc.hc.interval_ms            = pcfg->lb_hc_interval_ms;
        lbc.hc.timeout_ms             = pcfg->lb_hc_timeout_ms;
        lbc.hc.threshold_up           = pcfg->lb_hc_threshold_up;
        lbc.hc.threshold_down         = pcfg->lb_hc_threshold_down;
        strncpy(lbc.hc.path, pcfg->lb_hc_path, sizeof(lbc.hc.path) - 1);

        if (server_enable_lb(s, &lbc) != 0) {
            LOG_ERROR("server_from_config: failed to enable pool '%s'",
                      pcfg->name[0] ? pcfg->name : "(default)");
            continue;
        }
        for (int i = 0; i < pcfg->upstream_count; i++) {
            if (pcfg->upstreams[i].use_tls) {
                server_lb_add_upstream_tls(s,
                    pcfg->upstreams[i].host,
                    (uint16_t)pcfg->upstreams[i].port,
                    pcfg->upstreams[i].weight);
            } else {
                server_lb_add_upstream(s,
                    pcfg->upstreams[i].host,
                    (uint16_t)pcfg->upstreams[i].port,
                    pcfg->upstreams[i].weight);
            }
        }
        const char *route = pcfg->route[0] ? pcfg->route : "/*";
        server_lb_route(s, route, 0xFF);
    }

    return s;
}

server_t *server_from_config_file(const char *path) {
    routa_config_t cfg;
    routa_config_init(&cfg);
    if (routa_config_load(&cfg, path) < 0) return NULL;

    /* Store path so server_run() can wire SIGHUP hot-reload */
    if (path)
        strncpy(g_config_path, path, sizeof(g_config_path) - 1);

    return server_from_config(&cfg);
}

/* ── server_free ────────────────────────────────────────────────────────────*/
void server_free(server_t *s) {
    if (!s) return;
    if (s->loop)  event_loop_free((event_loop_t *)s->loop);
    if (s->chain) middleware_chain_free(s->chain);
    if (s->lb)    lb_free(s->lb);
    free(s->lb_route_ctx);
    for (int i = 0; i < s->static_config_count; i++)
        free(s->static_configs[i]);
    file_cache_free();
    free(s);
}