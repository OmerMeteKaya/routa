#include "core/server.h"
#include "http/request.h"
#include "http/response.h"
#include "http/static.h"
#include "http/middleware.h"
#include "http/mw_logger.h"
#include "http/mw_cors.h"
#include "http/mw_ratelimit.h"

static int handle_hello(const http_request_t *req,
                         http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_body(resp, "hello from routa\n", 17);
    http_response_set_header(resp, "Content-Type", "text/plain");
    return 0;
}

int main(void) {
    server_t *s = server_new(8080, 12);

    cors_config_t       *cors_cfg = mw_cors_config_new("*",
        "GET, POST, PUT, DELETE, OPTIONS",
        "Content-Type, Authorization");
    rate_limit_config_t *rl_cfg   = mw_rate_limit_config_new(1999000, 2999000); // 1000 2000

    server_use(s, mw_logger,     NULL);
    server_use(s, mw_cors,       cors_cfg);
    server_use(s, mw_rate_limit, rl_cfg);

    server_route(s, "/api/hello", HTTP_GET_M | HTTP_HEAD_M | HTTP_OPTIONS_M,
                 handle_hello, NULL);
    server_static(s, "/", "./public", 1);

    server_run(s);
    server_free(s);

    mw_cors_config_free(cors_cfg);
    mw_rate_limit_config_free(rl_cfg);
    return 0;
}
