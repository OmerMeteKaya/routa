#define _GNU_SOURCE
#include "core/server.h"
#include "core/event_loop.h"
#include "util/logger.h"
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
    
    strncpy(cfg->doc_root, doc_root, sizeof(cfg->doc_root) - 1);
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

void server_route(server_t *s, const char *path, int methods,
                  route_handler_t handler, void *ctx) {
    if (!s || !s->loop) {
        return;
    }
    
    event_loop_add_route((event_loop_t *)s->loop, path, methods, handler, ctx);
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
    event_loop_run((event_loop_t *)s->loop);
}

void server_free(server_t *s) {
    if (s) {
        if (s->loop) {
            event_loop_free((event_loop_t *)s->loop);
        }
        for (int i = 0; i < s->static_config_count; i++) {
            free(s->static_configs[i]);
        }
        free(s);
    }
    
    g_loop = NULL;
}
