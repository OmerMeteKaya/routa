#include "core/server.h"
#include "core/config.h"
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

int main(int argc, char *argv[]) {
    const char *config_path = argc > 1 ? argv[1] : "routa.conf";

    /* Load config from file */
    routa_config_t cfg;
    routa_config_init(&cfg);
    routa_config_load(&cfg, config_path);  /* falls back to defaults if missing */
    routa_config_dump(&cfg);

    /* Create server from config */
    server_t *s = server_from_config_file(config_path);
    if (!s) return 1;

    /* Add programmatic routes on top */
    server_route(s, "/api/hello", HTTP_GET_M | HTTP_HEAD_M, handle_hello, NULL);

    server_run(s);
    server_free(s);
    return 0;
}
