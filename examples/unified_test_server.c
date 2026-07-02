#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/event_loop.h"
#include "core/config.h"
#include "http/request.h"
#include "http/response.h"
#include "http/ws.h"
#include "util/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "core/server.h"
#include "util/metrics.h"
#include "http/mw_metrics.h"
#include "core/proxy.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * unified_test_server — combines everything ws_echo_server.c and
 * h2_test_server.c did separately, on ONE port, so RFC 8441 (WS-over-H2,
 * which requires TLS+H2) can be tested alongside local WS, plain HTTP/1.1,
 * HTTP/2, and reverse proxy (H1 + H2 upstream, including WS proxy) routes.
 *
 * Routes:
 *   GET  /hello          — plain text, smallest possible response
 *   GET  /small,/medium,/larger — fixed-size bodies for throughput tests
 *   GET  /large           — 128KB body
 *   POST /echo            — echoes request body
 *   GET  /metrics          — Prometheus metrics
 *   GET  /broadcast       — triggers a WS broadcast to all LOCAL /ws clients
 *   WS   /ws               — LOCAL websocket echo (works over H1 upgrade AND
 *                            over H2 Extended CONNECT per RFC 8441)
 *   ANY  /proxy/*          — reverse-proxied to upstream on :9001
 *                            (plain HTTP requests; H1 or H2 upstream depending
 *                            on --h2-upstream flag)
 *   WS   /wsproxy           — reverse-proxied WebSocket: H2 frontend Extended
 *                            CONNECT -> routa -> RFC 6455 upgrade to upstream
 *                            on :9002 (use ws_echo_upstream.go there)
 *
 * Usage:
 *   ./unified_test_server                    # TLS, port 18443, H1 upstream :9001
 *   ./unified_test_server --h2-upstream       # TLS, H2 upstream :9001
 *   ./unified_test_server --no-tls            # h2c cleartext, port 18080
 *   ./unified_test_server --port 9443         # custom port
 * ═══════════════════════════════════════════════════════════════════════════*/

static char small_buf[4096];
static char medium_buf[65536];
static char larger_buf[1048576];
static int  bench_bufs_init = 0;

static void init_bench_bufs(void) {
    if (bench_bufs_init) return;
    memset(small_buf,  'S', sizeof(small_buf));
    memset(medium_buf, 'M', sizeof(medium_buf));
    memset(larger_buf, 'L', sizeof(larger_buf));
    bench_bufs_init = 1;
}

static int handle_small(const http_request_t *req,
                         http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    init_bench_bufs();
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "application/octet-stream");
    http_response_set_body(resp, small_buf, sizeof(small_buf));
    return 0;
}

static int handle_medium(const http_request_t *req,
                          http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    init_bench_bufs();
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "application/octet-stream");
    http_response_set_body(resp, medium_buf, sizeof(medium_buf));
    return 0;
}

static int handle_larger(const http_request_t *req,
                          http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    init_bench_bufs();
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "application/octet-stream");
    http_response_set_body(resp, larger_buf, sizeof(larger_buf));
    return 0;
}

static int handle_echo(const http_request_t *req,
                        http_response_t *resp, void *ctx) {
    (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "text/plain");
    if (req->body && req->body_len > 0)
        http_response_set_body(resp, req->body, req->body_len);
    else
        http_response_set_body(resp, "(empty)\n", 8);
    return 0;
}

static int handle_large(const http_request_t *req,
                          http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    static char   large_buf[131072];
    static int    initialized = 0;
    if (!initialized) {
        memset(large_buf, 'X', sizeof(large_buf));
        initialized = 1;
    }
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "application/octet-stream");
    http_response_set_body(resp, large_buf, sizeof(large_buf));
    return 0;
}

static int handle_hello(const http_request_t *req,
                         http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "text/plain");
    http_response_set_body(resp, "hello http2\n", 12);
    return 0;
}

/* ── Local WebSocket handler (works over H1 upgrade AND H2 Extended CONNECT) ── */

static event_loop_t *g_loop_ref = NULL;

static void on_ws_open(conn_t *conn, void *ctx) {
    (void)ctx;
    LOG_INFO("ws: client connected fd=%d", conn->fd);
}

static void on_ws_message(conn_t *conn, const uint8_t *data,
                           size_t len, ws_opcode_t opcode, void *ctx) {
    (void)ctx;
    /* Echo back verbatim */
    ws_send(conn, data, len, opcode);
}

static void on_ws_close(conn_t *conn, ws_close_code_t code,
                         const char *reason, void *ctx) {
    (void)ctx;
    LOG_INFO("ws: client closed fd=%d code=%d reason=%s",
             conn->fd, code, reason ? reason : "");
}

static void on_ws_error(conn_t *conn, const char *msg, void *ctx) {
    (void)ctx;
    LOG_WARN("ws: error fd=%d: %s", conn->fd, msg);
}

static int handle_broadcast(const http_request_t *req,
                             http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    const uint8_t *msg = (const uint8_t *)"hello from broadcast";
    (void)event_loop_broadcast(g_loop_ref, msg, 20, WS_OP_TEXT);
    http_response_set_status(resp, 200, "OK");
    http_response_set_body(resp, "broadcast sent\n", 15);
    return 0;
}

#define MAX_UPSTREAMS 16
typedef struct { char host[256]; int port; int weight; int tls; } upstream_spec_t;
static upstream_spec_t g_upstreams[MAX_UPSTREAMS];
static int g_upstream_count = 0;

static int parse_upstream_spec(const char *s, int tls) {
    if (g_upstream_count >= MAX_UPSTREAMS) {
        fprintf(stderr, "too many upstreams (max %d)\n", MAX_UPSTREAMS);
        return -1;
    }
    upstream_spec_t *u = &g_upstreams[g_upstream_count];
    u->tls = tls;
    u->weight = 1;

    char buf[300];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *colon1 = strchr(buf, ':');
    if (!colon1) {
        fprintf(stderr, "invalid upstream spec '%s' (need HOST:PORT)\n", s);
        return -1;
    }
    *colon1 = '\0';
    char *port_str = colon1 + 1;

    char *colon2 = strchr(port_str, ':');
    if (colon2) {
        *colon2 = '\0';
        int w = atoi(colon2 + 1);
        u->weight = (w > 0) ? w : 1;
    }

    strncpy(u->host, buf, sizeof(u->host) - 1);
    u->port = atoi(port_str);
    g_upstream_count++;
    return 0;
}

int main(int argc, char **argv) {
    int no_tls      = 0;
    int h2_upstream = 0;
    int port        = 18443;
    int passive_fail    = 1000;   /* default: korumalı (pool-exhaustion false-DOWN'a düşmesin) */
    int passive_recover = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-tls") == 0)           { no_tls = 1; port = 18080; }
        else if (strcmp(argv[i], "--h2-upstream") == 0) { h2_upstream = 1; }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--upstream") == 0 && i + 1 < argc)
            parse_upstream_spec(argv[++i], 0);
        else if (strcmp(argv[i], "--upstream-tls") == 0 && i + 1 < argc)
            parse_upstream_spec(argv[++i], 1);
        else if (strcmp(argv[i], "--passive-fail") == 0 && i + 1 < argc)
            passive_fail = atoi(argv[++i]);
        else if (strcmp(argv[i], "--passive-recover") == 0 && i + 1 < argc)
            passive_recover = atoi(argv[++i]);
    }

    if (!no_tls) {
        system("mkdir -p /tmp/routa_certs && "
               "[ -f /tmp/routa_certs/test.crt ] || "
               "openssl req -x509 -newkey rsa:2048 "
               "-keyout /tmp/routa_certs/test.key "
               "-out /tmp/routa_certs/test.crt "
               "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null");
    }

    server_t *s = server_new(port, 48);
    if (!s) { fprintf(stderr, "server failed\n"); return 1; }
    event_loop_t *loop = (event_loop_t *)s->loop;
    g_loop_ref = loop;

    if (!no_tls)
        server_enable_tls(s, "/tmp/routa_certs/test.crt",
                             "/tmp/routa_certs/test.key");

    routa_config_t cfg;
    routa_config_init(&cfg);
    cfg.h2.initial_window_size    = 1048576;   /* 1MB */
    cfg.h2.max_frame_size         = 65536;     /* 64KB  */
    cfg.h2.max_concurrent_streams = 200;
    event_loop_set_h2_config(loop, &cfg.h2);

    /* ── Plain HTTP routes ── */
    event_loop_add_route(loop, "/hello",  1 << HTTP_GET,  handle_hello,  NULL);
    event_loop_add_route(loop, "/echo",   1 << HTTP_POST, handle_echo,   NULL);
    event_loop_add_route(loop, "/large",  1 << HTTP_GET,  handle_large,  NULL);
    event_loop_add_route(loop, "/small",  1 << HTTP_GET,  handle_small,  NULL);
    event_loop_add_route(loop, "/medium", 1 << HTTP_GET,  handle_medium, NULL);
    event_loop_add_route(loop, "/larger", 1 << HTTP_GET,  handle_larger, NULL);
    event_loop_add_route(loop, "/broadcast", 1 << HTTP_GET, handle_broadcast, NULL);

    routa_metrics_init();
    event_loop_add_route(loop, "/metrics", 1 << HTTP_GET,
                         routa_metrics_handler, NULL);

    /* ── Local WebSocket route (RFC 6455 over H1, RFC 8441 over H2) ── */
    ws_handler_t handler = {0};
    ws_config_init(&handler.cfg);
    handler.on_open    = on_ws_open;
    handler.on_message = on_ws_message;
    handler.on_close   = on_ws_close;
    handler.on_error   = on_ws_error;
    event_loop_add_ws_route(loop, "/ws", &handler);

    /* ── Reverse proxy: plain HTTP ── */
    server_enable_lb(s, &(lb_config_t){
        .algo = LB_ROUND_ROBIN,
        .pool_max_per_node = 150000,
        .pool_connect_timeout_ms = 2000,
        .pool_idle_timeout_s = 60,
        .passive_fail_threshold = passive_fail,
        .passive_recover_threshold = passive_recover,
        .max_retries = 1,
        .retry_on_connect_fail = 1,
    });
    if (g_upstream_count > 0) {
        for (int i = 0; i < g_upstream_count; i++) {
            upstream_spec_t *u = &g_upstreams[i];
            if (u->tls)
                server_lb_add_upstream_tls(s, u->host, (uint16_t)u->port, u->weight);
            else
                server_lb_add_upstream(s, u->host, (uint16_t)u->port, u->weight);
            printf("  upstream[%d]: %s:%d weight=%d (%s)\n",
                   i, u->host, u->port, u->weight, u->tls ? "TLS/H2" : "H1");
        }
    } else if (h2_upstream) {
        server_lb_add_upstream_tls(s, "127.0.0.1", 9001, 1);
    } else {
        server_lb_add_upstream(s, "127.0.0.1", 9001, 1);
    }
    server_lb_route(s, "/proxy/*", 0xFF);

    printf("\nunified_test_server listening on %d (%s)\n",
           port, no_tls ? "h2c cleartext" : "TLS");
    printf("  /hello /small /medium /larger /large /echo /metrics /broadcast\n");
    printf("  /ws            — local WebSocket (H1 upgrade + RFC 8441 over H2)\n");
    if (g_upstream_count > 0) {
        printf("  /proxy/*       — reverse proxy to %d upstream nodes\n", g_upstream_count);
    } else {
        printf("  /proxy/*       — reverse proxy to 127.0.0.1:9001 (%s upstream)\n",
               h2_upstream ? "H2" : "H1");
    }

    server_run(s);
    server_free(s);
    return 0;
}
