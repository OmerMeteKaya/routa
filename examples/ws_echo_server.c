#define _GNU_SOURCE
#include "core/event_loop.h"
#include "http/ws.h"
#include "util/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static event_loop_t *g_loop = NULL;

static void on_sigint(int sig) {
    (void)sig;
    if (g_loop) event_loop_stop(g_loop);
}

static void on_open(conn_t *conn, void *ctx) {
    (void)ctx;
    LOG_INFO("ws: client connected fd=%d\n", conn->fd);
}

static void on_message(conn_t *conn, const uint8_t *data,
                       size_t len, ws_opcode_t opcode, void *ctx) {
    (void)ctx;
    /* Echo back verbatim */
    ws_send(conn, data, len, opcode);
}

static void on_close(conn_t *conn, ws_close_code_t code,
                     const char *reason, void *ctx) {
    (void)ctx;
    LOG_INFO("ws: client closed fd=%d code=%d reason=%s\n",
             conn->fd, code, reason ? reason : "");
}

static void on_error(conn_t *conn, const char *msg, void *ctx) {
    (void)ctx;
    LOG_WARN("ws: error fd=%d: %s\n", conn->fd, msg);
}

static event_loop_t *g_loop_ref = NULL;

static int handle_broadcast(const http_request_t *req,
                             http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    const uint8_t *msg = (const uint8_t *)"hello from broadcast";
    int r = event_loop_broadcast(g_loop_ref, msg, 20, WS_OP_TEXT);
    http_response_set_status(resp, 200, "OK");
    http_response_set_body(resp, "broadcast sent\n", 15);
    return 0;
}
int main(void) {
    signal(SIGINT, on_sigint);

    g_loop = event_loop_new(8080, 12);
    g_loop_ref = g_loop;
    event_loop_add_route(g_loop, "/broadcast", 1 << HTTP_GET,
                         handle_broadcast, NULL);
    if (!g_loop) { fprintf(stderr, "event_loop_new failed\n"); return 1; }

    ws_handler_t handler = {0};
    ws_config_init(&handler.cfg);
    handler.on_open    = on_open;
    handler.on_message = on_message;
    handler.on_close   = on_close;
    handler.on_error   = on_error;

    event_loop_add_ws_route(g_loop, "/ws", &handler);
    fprintf(stderr, "ws echo server listening on :8080/ws\n");
    event_loop_run(g_loop);
    event_loop_free(g_loop);
    return 0;
}
