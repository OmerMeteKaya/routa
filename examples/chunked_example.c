//
// Created by mete on 6.05.2026.
//
#include "core/server.h"
#include "http/response.h"

static int chunked_handler(const http_request_t *req,
                           http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    resp->chunked = 1;
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "Content-Type", "text/plain");
    http_response_set_body(resp, "Hello from chunked response!", 28);
    return 0;
}

int main(void) {
    server_t *s = server_new(8080, 4);
    server_route(s, "/chunked", HTTP_GET_M, chunked_handler, NULL);
    server_run(s);
    server_free(s);
    return 0;
}
