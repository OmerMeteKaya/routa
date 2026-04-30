#define _GNU_SOURCE
#include "core/server.h"
#include "core/event_loop.h"
#include "util/logger.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

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
        free(s);
    }
    
    g_loop = NULL;
}
