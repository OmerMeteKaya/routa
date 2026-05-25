#include "http/h2.h"
#include "core/conn.h"
#include "core/config.h"
#include "util/buf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "http/router.h"
#include "http/response.h"
#include "util/logger.h"

static void __attribute__((constructor)) suppress_logs(void) {
    log_set_level(LOG_ERROR);
}


static int fuzz_handler(const http_request_t *req,
                         http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_body(resp, "ok", 2);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd          = -1;
    conn.sendfile_fd = -1;
    buf_init(&conn.read_buf);
    buf_init(&conn.write_buf);
    buf_init(&conn.hdr_buf);

    routa_h2_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.stream_lookup          = H2_STREAM_LOOKUP_LINEAR;
    cfg.header_table_size      = 4096;
    cfg.max_concurrent_streams = 32;
    cfg.initial_window_size    = 65535;
    cfg.max_frame_size         = 16384;
    cfg.max_header_list_size   = 65536;
    cfg.huffman_encoding       = 0;
    cfg.dynamic_table_update   = 0;
    cfg.server_push_enabled    = 0;
    cfg.stream_timeout_ms      = 30000;
    cfg.keepalive_timeout_ms   = 120000;

    struct router *router = router_new();
    if (!router) goto done;
    router_add(router, "/", HTTP_GET, fuzz_handler, NULL);
    router_add(router, "/", HTTP_POST, fuzz_handler, NULL);

    h2_conn_t *hc = h2_conn_new(&conn, &cfg);
    if (!hc) { router_free(router); goto done; }

    static const uint8_t preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    buf_append(&conn.read_buf, preface, 24);
    buf_append(&conn.read_buf, data, size);

    h2_conn_recv(hc, router, NULL);
    h2_conn_free(hc);
    router_free(router);

    done:
        buf_free(&conn.read_buf);
    buf_free(&conn.write_buf);
    buf_free(&conn.hdr_buf);
    return 0;
}
