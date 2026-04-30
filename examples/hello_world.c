#include "core/server.h"
#include "http/request.h"
#include "http/response.h"

static int handle_hello(const http_request_t *req,
                         http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_body(resp, "hello from routa\n", 17);
    http_response_set_header(resp, "Content-Type", "text/plain");
    return 0;
}

int main(void) {
    server_t *s = server_new(8080, 4);
    server_route(s, "/", HTTP_GET_M | HTTP_HEAD_M, handle_hello, NULL);
    server_run(s);
    server_free(s);
    return 0;
}
