#define _GNU_SOURCE
#include "core/server.h"
#include "core/event_loop.h"
#include "util/logger.h"
#include "http/middleware.h"
#include "http/file_cache.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static struct event_loop *g_loop = NULL;

static void signal_handler(int sig) {
    LOG_INFO("Received signal %d", sig);
    if (g_loop) {
        event_loop_stop(g_loop);
    }
}

server_t *server_new(int port, int n_threads) {
    server_t *s = calloc(1, sizeof(server_t));
    if (!s) {
        LOG_ERROR("Failed to allocate server");
        return NULL;
    }
    
    s->loop = (struct event_loop *)event_loop_new(port, n_threads);
    if (!s->loop) {
        LOG_ERROR("Failed to create event loop");
        free(s);
        return NULL;
    }
    
    g_loop = s->loop;
    
    return s;
}

static int static_route_handler(const http_request_t *req,
                                http_response_t *resp, void *ctx) {
    static_config_t *cfg = (static_config_t *)ctx;
    return static_serve(req, resp, cfg);
}

int server_static(server_t *s, const char *url_prefix,
                  const char *doc_root, int enable_index) {
    if (!s || !s->loop || !url_prefix || !doc_root) {
        return -1;
    }
    
    static_config_t *cfg = calloc(1, sizeof(static_config_t));
    if (!cfg) return -1;
    
    if (s->static_config_count < 16) {
        s->static_configs[s->static_config_count++] = cfg;
    }
    
    char resolved_root[1024];
    if (!realpath(doc_root, resolved_root)) {
        /* fallback to raw path if realpath fails */
        strncpy(cfg->doc_root, doc_root, sizeof(cfg->doc_root) - 1);
    } else {
        strncpy(cfg->doc_root, resolved_root, sizeof(cfg->doc_root) - 1);
    }
    cfg->doc_root[sizeof(cfg->doc_root) - 1] = '\0';
    
    strncpy(cfg->url_prefix, url_prefix, sizeof(cfg->url_prefix) - 1);
    cfg->url_prefix[sizeof(cfg->url_prefix) - 1] = '\0';
    
    cfg->enable_index = enable_index;

    char pattern[258];
    
    

    if (strcmp(url_prefix, "/") == 0) {
        strcpy(pattern, "/*");
    } else {
        snprintf(pattern, sizeof(pattern), "%s/*", url_prefix);
    }

    event_loop_add_route((event_loop_t *)s->loop, pattern,
                         HTTP_GET_M | HTTP_HEAD_M,
                         static_route_handler, cfg);

    /* Also register exact prefix match for the prefix itself */
    event_loop_add_route((event_loop_t *)s->loop, url_prefix,
                         HTTP_GET_M | HTTP_HEAD_M,
                         static_route_handler, cfg);
    return 0;
}

int server_enable_tls(server_t *s,
                      const char *cert_file, const char *key_file) {
    if (!s || !cert_file || !key_file) {
        return -1;
    }
    
    tls_init();
    event_loop_set_tls((event_loop_t *)s->loop, cert_file, key_file);
    /* Session resumption is enabled by default in tls_context_new().
       OCSP stapling activated via server_enable_ocsp_stapling(). */
    return 0;
}

void server_route(server_t *s, const char *path, int methods,
                  route_handler_t handler, void *ctx) {
    if (!s || !s->loop) {
        return;
    }
    
    event_loop_add_route((event_loop_t *)s->loop, path, methods, handler, ctx);
}

int server_enable_ocsp_stapling(server_t *s, const char *ocsp_file) {
    if (!s || !s->loop || !ocsp_file) return -1;
    event_loop_t *loop = (event_loop_t *)s->loop;
    if (!event_loop_get_tls_ctx(loop)) {
        LOG_ERROR("TLS must be enabled before OCSP stapling");
        return -1;
    }
    return tls_context_enable_ocsp_stapling(event_loop_get_tls_ctx(loop), ocsp_file);
}

void server_run(server_t *s) {
    if (!s || !s->loop) {
        return;
    }
    
    // Set up signal handlers
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGINT handler");
        return;
    }
    
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGTERM handler");
        return;
    }
    
    // Run event loop
    if (s->chain) {
        event_loop_set_chain((event_loop_t *)s->loop, s->chain);
    }

    /* Initialize file cache */
    file_cache_config_t fc_cfg = {
        .enabled     = 0,
        .max_entries = 512,
        .ttl_seconds = 5,
        .strategy    = FILE_CACHE_STAT_TTL
    };
    file_cache_init(&fc_cfg);

    event_loop_run((event_loop_t *)s->loop);
}

server_t *server_from_config(const routa_config_t *cfg) {
    if (routa_config_validate(cfg) < 0) return NULL;

    log_set_level((log_level_t)cfg->log_level);

    server_t *s = server_new(cfg->port, cfg->n_workers);
    if (!s) return NULL;

    if (cfg->tls_enabled) {
        server_enable_tls(s, cfg->tls_cert, cfg->tls_key);
    }

    for (int i = 0; i < cfg->static_count; i++) {
        server_static(s, cfg->static_dirs[i].url_prefix,
                      cfg->static_dirs[i].doc_root,
                      cfg->static_dirs[i].enable_index);
    }

    return s;
}

server_t *server_from_config_file(const char *path) {
    routa_config_t cfg;
    routa_config_init(&cfg);
    if (routa_config_load(&cfg, path) < 0) return NULL;
    return server_from_config(&cfg);
}

void server_free(server_t *s) {
    if (!s) return;
    if (s->loop)
        event_loop_free((event_loop_t *)s->loop);
    if (s->chain)
        middleware_chain_free(s->chain);
    for (int i = 0; i < s->static_config_count; i++)
        free(s->static_configs[i]);
    file_cache_free();
    free(s);
}

void server_use(server_t *s, middleware_fn_t fn, void *ctx) {
    if (!s) return;
    if (!s->chain) {
        s->chain = middleware_chain_new();
        if (!s->chain) {
            LOG_ERROR("Failed to create middleware chain");
            return;
        }
    }
    middleware_chain_use(s->chain, fn, ctx);
}
