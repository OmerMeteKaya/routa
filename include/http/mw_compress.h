//
// Created by mete on 4.05.2026.
//

#ifndef ROUTA_HTTP_MW_COMPRESS_H
#define ROUTA_HTTP_MW_COMPRESS_H

#include "http/middleware.h"

/* Compression algorithm preference order (client's Accept-Encoding decides) */
typedef enum {
    COMPRESS_PREFER_GZIP   = 0,   /* default */
    COMPRESS_PREFER_ZSTD   = 1,   /* future */
} compress_prefer_t;

typedef struct {
    size_t           min_size;      /* skip compression below this (bytes), default 256  */
    int              level;         /* zlib level 1-9, default 6                          */
    compress_prefer_t prefer;
} compress_config_t;

/* Returns a static default config — safe to pass directly to middleware_chain_use */
const compress_config_t *compress_config_default(void);

/* Middleware entry point — register with:
 *   middleware_chain_use(chain, mw_compress, &your_config);
 * Pass NULL ctx to use defaults.                                              */
void mw_compress(middleware_chain_t *chain,
                 const http_request_t *req,
                 http_response_t *resp,
                 next_fn_t next,
                 void *ctx);

#endif /* ROUTA_HTTP_MW_COMPRESS_H */