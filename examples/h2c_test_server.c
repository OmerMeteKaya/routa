/*
 * h2c_test_server.c — cleartext HTTP/2 benchmark server (h2c, RFC 7540 §3.4)
 *
 * Runs on port 18080 (no TLS).  Use for benchmarking raw H2 throughput
 * without TLS overhead.
 *
 * Benchmark TLS vs cleartext:
 *   h2load -n100000 -c100 -m10 https://localhost:18443/hello   # TLS (h2_test_server)
 *   h2load -n100000 -c100 -m10 http://localhost:18080/hello    # h2c (this server)
 *
 * The event loop already detects the H2 client preface on plain TCP and
 * switches the connection to H2 mode automatically (event_loop.c CONN_READING
 * path).  No special flag is required beyond not setting TLS.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/event_loop.h"
#include "core/config.h"
#include "http/request.h"
#include "http/response.h"
#include "util/metrics.h"
#include "http/mw_metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int handle_hello(const http_request_t *req,
                        http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "text/plain");
    http_response_set_body(resp, "hello h2c\n", 10);
    return 0;
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

int main(int argc, char **argv) {
    int port = 18080;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
    }

    event_loop_t *loop = event_loop_new(port, 4);
    if (!loop) { fprintf(stderr, "event_loop_new failed\n"); return 1; }

    /* No TLS — h2c direct (RFC 7540 §3.4).  The event loop detects the H2
     * client preface ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") and upgrades
     * automatically.  h2load will use h2c when given an http:// URL. */

    routa_config_t cfg;
    routa_config_init(&cfg);
    cfg.h2.initial_window_size    = 1048576;   /* 1 MB */
    cfg.h2.max_frame_size         = 65536;     /* 64 KB */
    cfg.h2.max_concurrent_streams = 200;
    event_loop_set_h2_config(loop, &cfg.h2);

    event_loop_add_route(loop, "/hello",  1 << HTTP_GET, handle_hello,  NULL);
    event_loop_add_route(loop, "/small",  1 << HTTP_GET, handle_small,  NULL);
    event_loop_add_route(loop, "/medium", 1 << HTTP_GET, handle_medium, NULL);
    event_loop_add_route(loop, "/larger", 1 << HTTP_GET, handle_larger, NULL);

    routa_metrics_init();
    event_loop_add_route(loop, "/metrics", 1 << HTTP_GET,
                         routa_metrics_handler, NULL);

    printf("h2c server listening on port %d (no TLS)\n", port);
    printf("benchmark: h2load -n100000 -c100 -m10 http://localhost:%d/hello\n", port);

    event_loop_run(loop);
    event_loop_free(loop);
    return 0;
}
