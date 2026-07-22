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
#include "http/mw_acl.h"

#include <stdatomic.h>
atomic_int g_drain_flag = 0;
static struct event_loop  *g_loop        = NULL;
static volatile sig_atomic_t g_reload_flag = 0;
static char                g_config_path[512] = {0};

/* Public setter for g_config_path -- server_from_config_file() sets this
 * internally, but callers that load config manually (routa_config_load()
 * + server_from_config(), rather than the all-in-one
 * server_from_config_file()) previously had no way to enable SIGHUP hot-
 * reload at all: g_config_path stayed empty, event_loop_set_config_reload()
 * (called from server_run(), see below) received NULL, and every SIGHUP
 * was silently ignored with a "hot reload: no config path stored,
 * skipping" log line. This affected src/main.c itself -- the actual
 * production `routa` binary -- meaning hot-reload was completely
 * non-functional in production despite being fully implemented and
 * exercised by unit tests that go through server_from_config_file().
 * Confirmed via bench testing under load: 5 consecutive SIGHUPs during
 * sustained traffic produced "no config path stored, skipping" every
 * time, with zero actual reload occurring. */
void server_set_config_path(const char *path) {
    if (path) strncpy(g_config_path, path, sizeof(g_config_path) - 1);
}

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
int server_use(server_t *s, middleware_fn_t fn, void *ctx) {
    if (!s) return -1;
    if (!s->chain) {
        s->chain = middleware_chain_new();
        if (!s->chain) { LOG_ERROR("Failed to create middleware chain"); return -1; }
    }
    /* Return value is the middleware's index within the chain (0-based,
     * registration order) -- server_from_config() records these per
     * middleware type (s->acl_mw_idx, s->rate_limit_mw_idx, etc.) so hot
     * reload (SIGHUP) can later swap in a freshly-built ctx for exactly
     * the right chain slot via middleware_chain_update_ctx(). -1 means
     * "not registered" (e.g. that middleware type was never enabled). */
    int idx = s->chain->count;
    if (middleware_chain_use(s->chain, fn, ctx) < 0) return -1;
    return idx;
}

/* ── Load balancer ──────────────────────────────────────────────────────────*/

/* Internal route handler that forwards to LB */

static int lb_route_handler(const http_request_t *req,
                             http_response_t *resp, void *ctx) {
    lb_handler_ctx_t *hctx = (lb_handler_ctx_t *)ctx;
    /* Pool-scoped ACL check. Runs in addition to (after) any global ACL
     * middleware -- a request that passed the global ACL can still be
     * blocked here by a pool-specific rule. resp->status is left at 0
     * (its initialized default) on success -- the event loop's
     * dispatch code (see handle_events_worker()) interprets
     * resp.status == 0 plus a matched route with an lb bound to it as
     * "hand this off to the proxy", so leaving it untouched here is
     * what allows the request to actually reach the upstream. */
    if (hctx && hctx->acl) {
        if (!acl_check((const acl_config_t *)hctx->acl, req->remote_ip)) {
            /* Pool-scoped ACL denial -- a separate code path from
             * mw_acl.c's global ACL middleware (this one lives in the
             * proxy route handler, checked via server_lb_set_acl()), but
             * the same acl_denied_total counter applies: an operator
             * scraping /metrics doesn't need to know WHICH of the two
             * ACL layers rejected a request, just that ACL did. Found
             * missing during Faz D observability testing -- the global
             * mw_acl.c path was instrumented but this one was initially
             * overlooked. */
            ROUTA_METRIC_INC(acl_denied_total);
            http_response_set_status(resp, 403, "Forbidden");
            http_response_set_header(resp, "Content-Type", "text/plain");
            http_response_set_body(resp, "Forbidden\n", 10);
        }
    }
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

    /* Record which pool entry this ctx belongs to, so
     * server_lb_set_acl() (called after this, for the same pool) can
     * find and update it. */
    for (int i = 0; i < s->lb_pool_count; i++) {
        if (s->lb_pools[i].lb == s->lb && s->lb_pools[i].route_ctx == NULL) {
            s->lb_pools[i].route_ctx = ctx;
            break;
        }
    }

    event_loop_add_route((event_loop_t *)s->loop,
                         path, methods, lb_route_handler, ctx);
    return 0;
}

/* Attaches an ACL to the most recently routed pool (the one from the
 * immediately preceding server_lb_route() call). Must be called AFTER
 * server_lb_route() for that pool, since the route_ctx it updates is
 * only created there. Ownership of acl passes to the server; it is not
 * currently freed by server_free() (mirrors the existing leak-until-exit
 * pattern for other middleware configs in this file). */
void server_lb_set_acl(server_t *s, void *acl) {
    if (!s || s->lb_pool_count == 0) return;
    lb_handler_ctx_t *ctx = (lb_handler_ctx_t *)s->lb_pools[s->lb_pool_count - 1].route_ctx;
    if (ctx) ctx->acl = acl;
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
    event_loop_set_middleware_reload_indices((event_loop_t *)s->loop,
        s->acl_mw_idx, s->cors_mw_idx, s->basic_auth_mw_idx,
        s->jwt_auth_mw_idx, s->rate_limit_mw_idx, s->compress_mw_idx);

    if (s->chain)
        event_loop_set_chain((event_loop_t *)s->loop, s->chain);

    /* Default file_cache config for programmatic use (server_new()
     * called directly, without a routa_config_t -- e.g. hello_world.c,
     * test_proxy_lb.c's test harnesses). server_from_config() below
     * re-initializes this with real config values when a config file
     * is used; this is only the fallback for callers that skip that
     * path entirely. shared_metadata + sharded lock + LRU is a safe,
     * reasonable default even without explicit tuning. */
    file_cache_config_t fc_cfg = {0};
    fc_cfg.enabled          = 1;
    fc_cfg.max_entries      = 512;
    fc_cfg.ttl_seconds      = 5;
    fc_cfg.strategy         = FILE_CACHE_STAT_TTL;
    fc_cfg.mode             = FILE_CACHE_MODE_SHARED_METADATA;
    fc_cfg.lock_kind        = FILE_CACHE_LOCK_SHARDED;
    fc_cfg.n_shards         = 16;
    fc_cfg.eviction         = FILE_CACHE_EVICT_LRU;
    fc_cfg.negative_ttl_seconds = 0;
    fc_cfg.mmap_threshold   = FILE_CACHE_DEFAULT_MMAP_THRESHOLD;
    fc_cfg.max_memory_mb    = 0;
    fc_cfg.watch            = FILE_CACHE_WATCH_NONE;
    file_cache_init(&fc_cfg);

    /* ── Observability ── */
    routa_metrics_init();
    if (s->metrics_enabled) {
        const char *mpath = s->metrics_path[0] ? s->metrics_path : "/metrics";
        /* ctx = s (not NULL): routa_metrics_handler() forwards this to
         * routa_metrics_prometheus_lb() so per-pool/upstream metrics can
         * be rendered too, not just the global counters. See
         * mw_metrics.c's routa_metrics_handler() and metrics.h's
         * routa_metrics_prometheus_lb() doc comments. */
        event_loop_add_route((event_loop_t *)s->loop, mpath,
                             1 << HTTP_GET, routa_metrics_handler, s);
    }
    
    event_loop_run((event_loop_t *)s->loop);
}

/* ── server_from_config ─────────────────────────────────────────────────────*/
server_t *server_from_config(const routa_config_t *cfg) {
    if (routa_config_validate(cfg) < 0) return NULL;

    log_set_level((log_level_t)cfg->log_level);
    /* BUG FIX (config ghost-key audit): log_file was parsed but
     * never actually opened/redirected to -- see log_set_file()'s
     * doc comment in logger.h. Empty string (the default when the
     * key isn't set) is handled by log_set_file() itself (stays on
     * stderr). */
    log_set_file(cfg->log_file);

    server_t *s = server_new(cfg->port, cfg->n_workers);
    if (!s) return NULL;

    /* -1 = "this middleware type isn't enabled" -- see the doc comment
     * on these fields in server.h. Set before any server_use() calls
     * below so an early-return path can't leave them uninitialized. */
    s->acl_mw_idx         = -1;
    s->cors_mw_idx        = -1;
    s->basic_auth_mw_idx  = -1;
    s->jwt_auth_mw_idx    = -1;
    s->rate_limit_mw_idx  = -1;
    s->compress_mw_idx    = -1;

    event_loop_set_max_connections((event_loop_t *)s->loop,
                                   cfg->max_connections);
    event_loop_set_timeouts((event_loop_t *)s->loop,
                            cfg->keepalive_timeout_ms, cfg->request_timeout_ms);
    /* BUG FIX (config ghost-key audit): max_request_size was parsed into
     * routa_config_t but never actually wired to anything that enforced
     * it -- see http_request_parse()'s max_body_size parameter and
     * event_loop_set_max_request_size() for the actual enforcement
     * chain this now completes. cfg->max_request_size is declared `int`
     * (see config.h) but represents a byte SIZE, which is unsigned by
     * nature -- cast to size_t here at the boundary into the
     * size_t-typed setter/worker field/parser parameter. A negative
     * config value (which cfg_size_mb()'s parsing shouldn't produce, but
     * defensively) would wrap to a huge size_t and effectively disable
     * the limit -- treat that as "unlimited" explicitly via the <= 0
     * check rather than let it silently wrap. */
    event_loop_set_max_request_size((event_loop_t *)s->loop,
        cfg->max_request_size > 0 ? (size_t)cfg->max_request_size : 0);
    /* BUG FIX (cache revision follow-up): file_cache_init() was
     * previously only ever called once, from server_new(), with
     * hardcoded values -- every file_cache_* config key
     * (file_cache_enabled, file_cache_max_entries, file_cache_ttl,
     * file_cache_strategy, and all the new mode/lock/shards/eviction/
     * negative_ttl/mmap_threshold/max_memory_mb/watch keys added in
     * this revision) was parsed into routa_config_t but never actually
     * reached file_cache_init(). Re-initializing here with the real
     * parsed config is safe: file_cache_free() tears down whatever
     * server_new()'s default init set up (shards, worker mmap tables,
     * any inotify fd) before the real one takes over, and this runs
     * once at startup before any worker thread exists, so there's no
     * concurrent access to the structures being replaced. */
    file_cache_free();
    file_cache_config_t fc_cfg2 = {0};
    fc_cfg2.enabled              = cfg->file_cache_enabled;
    fc_cfg2.max_entries          = cfg->file_cache_max_entries;
    fc_cfg2.ttl_seconds          = cfg->file_cache_ttl;
    fc_cfg2.strategy             = (file_cache_strategy_t)cfg->file_cache_strategy;
    fc_cfg2.mode                 = (file_cache_mode_t)cfg->file_cache_mode;
    fc_cfg2.lock_kind            = (file_cache_lock_t)cfg->file_cache_lock;
    fc_cfg2.n_shards             = cfg->file_cache_shards;
    fc_cfg2.eviction             = (file_cache_eviction_t)cfg->file_cache_eviction;
    fc_cfg2.negative_ttl_seconds = cfg->file_cache_negative_ttl;
    fc_cfg2.mmap_threshold       = (size_t)cfg->file_cache_mmap_threshold;
    fc_cfg2.max_memory_mb        = (size_t)cfg->file_cache_max_memory_mb;
    fc_cfg2.watch                = (file_cache_watch_t)cfg->file_cache_watch;
    file_cache_init(&fc_cfg2);
    event_loop_set_global_response_headers(
        cfg->response_header_add, cfg->response_header_add_count,
        cfg->response_header_remove, cfg->response_header_remove_count);
    event_loop_set_socket_buffers((event_loop_t *)s->loop,
                                  cfg->socket_recv_buf_size, cfg->socket_send_buf_size);
    event_loop_set_cpu_affinity((event_loop_t *)s->loop,
                                cfg->cpu_affinity_enabled, cfg->cpu_affinity_start_core);
    event_loop_set_memory_limits((event_loop_t *)s->loop,
                                 cfg->memory_soft_limit_mb, cfg->memory_hard_limit_mb);
    event_loop_set_numa_aware((event_loop_t *)s->loop, cfg->numa_aware_enabled);
    /* Bug fix: this was previously never called from server_from_config(),
     * meaning every h2_* key in the config file was parsed into
     * routa_config_t.h2 but had zero effect on actual runtime behavior --
     * event_loop_t always ran with h2_cfg's zero-initialized (all-default)
     * values instead. */
    event_loop_set_h2_config((event_loop_t *)s->loop, &cfg->h2);
    /* Same bug as h2 above: previously never wired up, so every ws_* key
     * in the config file had zero effect on actual runtime behavior. */
    event_loop_set_ws_config((event_loop_t *)s->loop, &cfg->ws);

    if (cfg->tls_enabled) {
        server_enable_tls(s, cfg->tls_cert, cfg->tls_key);
        /* BUG FIX (config ghost-key audit): tls_session_timeout and
         * tls_ocsp_response were both parsed into routa_config_t but
         * never actually applied anywhere -- tls_context_enable_
         * session_cache() and server_enable_ocsp_stapling() already
         * existed and did exactly what these keys imply, they were just
         * never called from config-driven startup. Wire both up here,
         * next to the SNI registration this same block already does
         * via the same tls_ctx lookup pattern. */
        tls_context_t *tls_ctx = event_loop_get_tls_ctx((event_loop_t *)s->loop);
        if (!tls_ctx) {
            LOG_ERROR("server_from_config: TLS context missing, cannot apply TLS options");
        } else {
            if (cfg->tls_session_timeout > 0) {
                tls_context_enable_session_cache(tls_ctx, cfg->tls_session_timeout);
            }
            if (cfg->tls_ocsp_response[0]) {
                server_enable_ocsp_stapling(s, cfg->tls_ocsp_response);
            }
            for (int i = 0; i < cfg->sni_cert_count; i++) {
                tls_context_add_sni_cert(tls_ctx,
                    cfg->sni_certs[i].hostname,
                    cfg->sni_certs[i].cert,
                    cfg->sni_certs[i].key);
            }
        }
    }

    s->metrics_enabled = cfg->metrics_enabled;
    if (cfg->metrics_path[0])
        strncpy(s->metrics_path, cfg->metrics_path, sizeof(s->metrics_path) - 1);

    /* ── Middleware, applied in the order registered (outermost first):
     * logger -> cors -> auth (basic or jwt) -> ratelimit -> compress ──── */
    if (cfg->logger_enabled) {
        server_use(s, mw_logger, NULL);
    }
    if (cfg->acl_enabled) {
        acl_config_t *acl_cfg = acl_config_new(cfg->acl_default_allow);
        if (acl_cfg) {
            for (int i = 0; i < cfg->acl_rule_count; i++) {
                acl_config_add_rule(acl_cfg, cfg->acl_rules[i].rule,
                                    cfg->acl_rules[i].action == 0 ? ACL_ACTION_ALLOW : ACL_ACTION_DENY);
            }
            s->acl_mw_idx = server_use(s, mw_acl, acl_cfg);
        }
    }
    if (cfg->cors_enabled) {
        cors_config_t *cors_cfg = mw_cors_config_new(
            cfg->cors_origin, cfg->cors_methods, cfg->cors_headers);
        if (cors_cfg) s->cors_mw_idx = server_use(s, mw_cors, cors_cfg);
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
            s->basic_auth_mw_idx = server_use(s, mw_basic_auth, auth_cfg);
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
            s->jwt_auth_mw_idx = server_use(s, mw_jwt_auth, jwt_cfg);
        }
    }
    if (cfg->rate_limit_enabled) {
        rate_limit_config_t *rl_cfg = mw_rate_limit_config_new(
            cfg->rate_limit_requests_per_second, cfg->rate_limit_burst);
        if (rl_cfg) s->rate_limit_mw_idx = server_use(s, mw_rate_limit, rl_cfg);
    }
    if (cfg->compress_enabled) {
        compress_config_t *cc = calloc(1, sizeof(compress_config_t));
        if (cc) {
            cc->min_size = cfg->compress_min_size;
            cc->level    = cfg->compress_level;
            cc->prefer   = COMPRESS_PREFER_GZIP;
            s->compress_mw_idx = server_use(s, mw_compress, cc);
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
        lbc.sticky_session_enabled    = pcfg->sticky_session_enabled;
        strncpy(lbc.sticky_cookie_name, pcfg->sticky_cookie_name, sizeof(lbc.sticky_cookie_name) - 1);
        lbc.pool_idle_timeout_s       = pcfg->lb_pool_idle_timeout_s;
        lbc.passive_fail_threshold    = pcfg->lb_passive_fail_threshold;
        lbc.passive_recover_threshold = pcfg->lb_passive_recover_threshold;
        lbc.half_open_retry_after_ms  = pcfg->lb_half_open_retry_after_ms;
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
        /* Record the pool's config-file name for observability -- see
         * lb_pool_entry_t.name's doc comment in server.h. server_enable_lb()
         * always appends to the end of s->lb_pools[], so the just-added
         * entry is at lb_pool_count-1 right after a successful call. */
        strncpy(s->lb_pools[s->lb_pool_count - 1].name, pcfg->name,
                sizeof(s->lb_pools[s->lb_pool_count - 1].name) - 1);

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

        if (pcfg->acl_enabled) {
            acl_config_t *pool_acl = acl_config_new(pcfg->acl_default_allow);
            if (pool_acl) {
                for (int i = 0; i < pcfg->acl_rule_count; i++) {
                    acl_config_add_rule(pool_acl, pcfg->acl_rules[i].rule,
                                        pcfg->acl_rules[i].action == 0 ? ACL_ACTION_ALLOW : ACL_ACTION_DENY);
                }
                server_lb_set_acl(s, pool_acl);
            }
        }
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