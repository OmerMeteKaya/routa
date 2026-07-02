#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/event_loop.h"
#include "core/config.h"
#include "http/request.h"
#include "http/response.h"
#include "util/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/server.h"
#include "core/proxy.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * ws_proxy_test_server — ISOLATED server whose ONLY job is to reverse-proxy
 * RFC 8441 (WS-over-H2) connections to a single H1 WebSocket upstream.
 *
 * Why isolated: routa's current LB API (server_lb_route + server_lb_add_upstream)
 * is single-pool — it doesn't support routing different paths to different
 * upstream pools. Mixing this with unified_test_server's /proxy/* (port 9001)
 * would cause /wsproxy requests to round-robin into the wrong upstream.
 * This keeps WS proxy testing isolated and unambiguous.
 *
 * Pair with: ws_echo_upstream.go (plain HTTP/1.1 RFC 6455 echo, no TLS)
 *
 * Usage:
 *   go run ws_echo_upstream.go -addr :9002 &
 *   ./ws_proxy_test_server                  # TLS, port 18444, upstream :9002
 *   ./ws_proxy_test_server --port 18445 --upstream-port 9003
 *
 * Test:
 *   python3 ws_over_h2_client.py localhost 18444 /wsproxy
 * ═══════════════════════════════════════════════════════════════════════════*/

int main(int argc, char **argv) {
    int port          = 18444;
    int upstream_port = 9002;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--upstream-port") == 0 && i + 1 < argc)
            upstream_port = atoi(argv[++i]);
    }

    system("mkdir -p /tmp/routa_certs && "
           "[ -f /tmp/routa_certs/test.crt ] || "
           "openssl req -x509 -newkey rsa:2048 "
           "-keyout /tmp/routa_certs/test.key "
           "-out /tmp/routa_certs/test.crt "
           "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null");

    server_t *s = server_new(port, 8);
    if (!s) { fprintf(stderr, "server failed\n"); return 1; }
    event_loop_t *loop = (event_loop_t *)s->loop;

    server_enable_tls(s, "/tmp/routa_certs/test.crt",
                          "/tmp/routa_certs/test.key");

    routa_config_t cfg;
    routa_config_init(&cfg);
    cfg.h2.initial_window_size    = 1048576;
    cfg.h2.max_frame_size         = 65536;
    cfg.h2.max_concurrent_streams = 200;
    event_loop_set_h2_config(loop, &cfg.h2);

    server_enable_lb(s, &(lb_config_t){
        .algo = LB_ROUND_ROBIN,
        .pool_max_per_node = 4096,
        .pool_connect_timeout_ms = 2000,
        .pool_idle_timeout_s = 60,
        .passive_fail_threshold = 1000,
        .passive_recover_threshold = 1,
        .max_retries = 1,
        .retry_on_connect_fail = 1,
    });
    server_lb_add_upstream(s, "127.0.0.1", upstream_port, 1);
    server_lb_route(s, "/wsproxy", 0xFF);

    printf("\nws_proxy_test_server listening on %d (TLS)\n", port);
    printf("  /wsproxy — WebSocket reverse proxy to 127.0.0.1:%d (H1 upstream)\n",
           upstream_port);
    printf("  Test with: python3 ws_over_h2_client.py localhost %d /wsproxy\n\n",
           port);

    server_run(s);
    server_free(s);
    return 0;
}