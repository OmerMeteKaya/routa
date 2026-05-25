#include "http/h2_hpack.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 0, 65536);

    hpack_header_t headers[64];
    memset(headers, 0, sizeof(headers));
    int n = hpack_decode(&ctx, data, size, headers, 64);
    if (n > 0)
        hpack_headers_free(headers, n);

    hpack_ctx_free(&ctx);
    return 0;
}