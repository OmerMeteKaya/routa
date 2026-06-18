
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/event_loop.h"
#include "core/config.h"
#include "http/request.h"
#include "http/response.h"
#include <stdio.h>
#include <stdlib.h>

#include "core/server.h"
#include "util/metrics.h"
#include "http/mw_metrics.h"
#include "core/proxy.h"

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

int main(int argc, char **argv) {
    int no_tls = 0;
    int port   = 18443;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-tls") == 0) { no_tls = 1; port = 18080; }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
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
    if (!no_tls)
        server_enable_tls(s, "/tmp/routa_certs/test.crt",
                             "/tmp/routa_certs/test.key");

    routa_config_t cfg;
    routa_config_init(&cfg);
    cfg.h2.initial_window_size    = 1048576;   /* 1MB */
    cfg.h2.max_frame_size         = 65536;     /* 64KB  */
    cfg.h2.max_concurrent_streams = 200;
    event_loop_set_h2_config(loop, &cfg.h2);

    event_loop_add_route(loop, "/hello", 1 << HTTP_GET, handle_hello, NULL);
    event_loop_add_route(loop, "/echo",
                     1 << HTTP_POST, handle_echo, NULL);
    event_loop_add_route(loop, "/large",
                         1 << HTTP_GET, handle_large, NULL);
    event_loop_add_route(loop, "/small",  1 << HTTP_GET, handle_small,  NULL);
    event_loop_add_route(loop, "/medium", 1 << HTTP_GET, handle_medium, NULL);
    event_loop_add_route(loop, "/larger", 1 << HTTP_GET, handle_larger, NULL);
    printf("\nListening on %d (%s)...\n", port, no_tls ? "h2c cleartext" : "TLS");

    routa_metrics_init();
    event_loop_add_route(loop, "/metrics", 1 << HTTP_GET,
                         routa_metrics_handler, NULL);
    server_enable_lb(s, &(lb_config_t){
        .algo = LB_ROUND_ROBIN,
        .pool_max_per_node = 16384,
        .pool_connect_timeout_ms = 2000,
        .pool_idle_timeout_s = 60,
        .passive_fail_threshold = 10,
        .passive_recover_threshold = 2,
        .max_retries = 1,
        .retry_on_connect_fail = 1,
    });
    server_lb_add_upstream(s, "127.0.0.1", 9001, 1);
   server_lb_route(s, "/proxy/*", 0xFF);
    server_run(s);
    server_free(s);
    return 0;
}
