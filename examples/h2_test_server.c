
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "core/event_loop.h"
#include "core/config.h"
#include "http/request.h"
#include "http/response.h"
#include <stdio.h>
#include <stdlib.h>


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
    size_t sz  = 131072;
    char  *buf = malloc(sz);
    if (!buf) return -1;
    memset(buf, 'X', sz);
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "application/octet-stream");
    http_response_set_body(resp, buf, sz);
    free(buf);
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

int main(void) {
    /* Generate test cert if missing */
    system("mkdir -p /tmp/routa_certs && "
           "[ -f /tmp/routa_certs/test.crt ] || "
           "openssl req -x509 -newkey rsa:2048 "
           "-keyout /tmp/routa_certs/test.key "
           "-out /tmp/routa_certs/test.crt "
           "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null");

    event_loop_t *loop = event_loop_new(18443, 12);
    if (!loop) { fprintf(stderr, "loop failed\n"); return 1; }

    event_loop_set_tls(loop, "/tmp/routa_certs/test.crt",
                              "/tmp/routa_certs/test.key");

    routa_config_t cfg;
    routa_config_init(&cfg);
    event_loop_set_h2_config(loop, &cfg.h2);

    event_loop_add_route(loop, "/hello", 1 << HTTP_GET, handle_hello, NULL);
    event_loop_add_route(loop, "/echo",
                     1 << HTTP_POST, handle_echo, NULL);
    event_loop_add_route(loop, "/large",
                         1 << HTTP_GET, handle_large, NULL);

    printf("\nListening on 18443...\n");
    event_loop_run(loop);
    event_loop_free(loop);
    return 0;
}
#endif