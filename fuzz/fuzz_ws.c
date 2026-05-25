#include "http/ws.h"
#include "core/conn.h"
#include "util/buf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "util/logger.h"
static void __attribute__((constructor)) suppress_logs(void) {
    log_set_level(LOG_ERROR);
}
/* Minimal no-op handlers */
static void on_message(conn_t *c, const uint8_t *d, size_t l,
                        ws_opcode_t op, void *ctx) {
    (void)c; (void)d; (void)l; (void)op; (void)ctx;
}
static void on_close(conn_t *c, ws_close_code_t code,
                      const char *reason, void *ctx) {
    (void)c; (void)code; (void)reason; (void)ctx;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /* Build a minimal conn_t on the stack */
    conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd       = -1;
    conn.ws_state = WS_STATE_OPEN;
    ws_frame_state_init(&conn.ws_fs);
    buf_init(&conn.read_buf);
    buf_init(&conn.write_buf);

    if (buf_append(&conn.read_buf, data, size) < 0) goto done;

    ws_handler_t handler;
    memset(&handler, 0, sizeof(handler));
    handler.on_message = on_message;
    handler.on_close   = on_close;

    ws_config_t cfg;
    ws_config_init(&cfg);
    cfg.require_masking = 0;   /* fuzz unmasked frames too */
    cfg.max_frame_size  = 65536;
    cfg.max_message_size = 1024 * 1024;
    ws_recv(&conn, &handler, &cfg);

    done:
        ws_frame_state_free(&conn.ws_fs);
    buf_free(&conn.read_buf);
    buf_free(&conn.write_buf);
    return 0;
}