#include "util/buf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "http/request.h"
#include "util/logger.h"

static void __attribute__((constructor)) suppress_logs(void) {
    log_set_level(LOG_ERROR);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    if (memchr(data, 0, size) != NULL) return 0;
    buf_t buf;
    buf_init(&buf);
    if (buf_append(&buf, data, size) < 0) {
        buf_free(&buf);
        return 0;
    }

    http_request_t req;
    size_t consumed = 0;
    int rc = http_request_parse(&req, &buf, &consumed);

    if (rc == 0)
        http_request_free(&req);

    buf_free(&buf);
    return 0;
}
