//
// Created by mete on 4.05.2026.
//
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/mw_compress.h"
#include "http/response.h"
#include "http/request.h"
#include "util/logger.h"
#include <zlib.h>
#include <stdlib.h>
#include <string.h>

/* ── Defaults ───────────────────────────────────────────────────────────────*/
#define DEFAULT_MIN_SIZE  256u
#define DEFAULT_LEVEL     6
#define CHUNK             16384u   /* zlib deflate chunk size */

static const compress_config_t g_default_cfg = {
    .min_size = DEFAULT_MIN_SIZE,
    .level    = DEFAULT_LEVEL,
    .prefer   = COMPRESS_PREFER_GZIP,
};

const compress_config_t *compress_config_default(void) {
    return &g_default_cfg;
}

/* ── MIME whitelist — only compress text / structured data ─────────────────*/
static int should_compress_mime(const char *mime) {
    if (!mime) return 0;
    /* prefix match is enough; charset suffixes don't matter */
    static const char * const compressible[] = {
        "text/",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/xhtml",
        "image/svg",
        NULL
    };
    for (int i = 0; compressible[i]; i++)
        if (strncmp(mime, compressible[i], strlen(compressible[i])) == 0)
            return 1;
    return 0;
}

/* ── Accept-Encoding parser — returns 1 if "gzip" accepted ────────────────*/
static int client_accepts_gzip(const http_request_t *req) {
    const char *ae = http_request_get_header(req, "Accept-Encoding");
    if (!ae) return 0;
    /* strstr is fine — header values are short */
    return strstr(ae, "gzip") != NULL;
}

/* ── gzip compress — returns heap-alloc'd buffer, sets *out_len ────────────
 * Returns NULL on failure.                                                   */
static char *gzip_compress(const char *src, size_t src_len,
                            int level, size_t *out_len)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    /* deflateInit2 with gzip wrapper (windowBits = 15 | 16) */
    if (deflateInit2(&zs, level, Z_DEFLATED,
                     15 | 16,   /* gzip envelope */
                     8,         /* default mem level */
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        LOG_ERROR("mw_compress: deflateInit2 failed");
        return NULL;
    }

    /* Worst-case output bound */
    size_t bound = deflateBound(&zs, (uLong)src_len);
    char  *dst   = malloc(bound);
    if (!dst) {
        deflateEnd(&zs);
        return NULL;
    }

    zs.next_in   = (Bytef *)src;
    zs.avail_in  = (uInt)src_len;
    zs.next_out  = (Bytef *)dst;
    zs.avail_out = (uInt)bound;

    int ret = deflate(&zs, Z_FINISH);
    if (ret != Z_STREAM_END) {
        LOG_ERROR("mw_compress: deflate failed (%d)", ret);
        free(dst);
        deflateEnd(&zs);
        return NULL;
    }

    *out_len = (size_t)zs.total_out;
    deflateEnd(&zs);
    return dst;
}

/* ── Middleware ─────────────────────────────────────────────────────────────*/
void mw_compress(middleware_chain_t *chain,
                 const http_request_t *req,
                 http_response_t *resp,
                 next_fn_t next,
                 void *ctx,int current)
{
    const compress_config_t *cfg = ctx ? (const compress_config_t *)ctx
                                       : &g_default_cfg;

    /* Run the rest of the chain first — we compress the final response */
    next(chain, req, resp, current);

    /* ── Guard conditions ── */

    /* Already encoded or chunked — skip */
    for (int i = 0; i < resp->header_count; i++) {
        if (strcasecmp(resp->headers[i][0], "Content-Encoding") == 0)
            return;
        if (strcasecmp(resp->headers[i][0], "Transfer-Encoding") == 0)
            return;
    }

    /* No in-memory body (e.g. sendfile path) — skip.
     * Compressing a stream via body_fd would require reading the whole
     * file into memory; for large files sendfile is preferable anyway. */
    if (!resp->body || resp->body_len == 0)
        return;

    /* Below minimum size threshold */
    if (resp->body_len < cfg->min_size)
        return;

    /* Client doesn't speak gzip */
    if (!client_accepts_gzip(req))
        return;

    /* Non-compressible MIME type — find Content-Type header */
    const char *mime = NULL;
    for (int i = 0; i < resp->header_count; i++)
        if (strcasecmp(resp->headers[i][0], "Content-Type") == 0) {
            mime = resp->headers[i][1];
            break;
        }
    if (!should_compress_mime(mime))
        return;

    /* ── Compress ── */
    size_t comp_len = 0;
    char  *comp     = gzip_compress(resp->body, resp->body_len,
                                    cfg->level, &comp_len);
    if (!comp) return;   /* fall through uncompressed on error */

    /* Only use if actually smaller */
    if (comp_len >= resp->body_len) {
        free(comp);
        return;
    }

    /* ── Swap body ── */
    free(resp->body);
    resp->body     = comp;
    resp->body_len = comp_len;

    /* Update headers */
    http_response_set_header(resp, "Content-Encoding", "gzip");

    /* Rewrite Content-Length */
    char len_str[32];
    (void)snprintf(len_str, sizeof(len_str), "%zu", comp_len);
    http_response_set_header(resp, "Content-Length", len_str);

    /* Vary header — required for correct proxy caching */
    http_response_set_header(resp, "Vary", "Accept-Encoding");
}
