#ifndef ROUTA_HTTP_H2_HPACK_H
#define ROUTA_HTTP_H2_HPACK_H

#include <stdint.h>
#include <stddef.h>

/* ── Header pair ─────────────────────────────────────────────────────────── */
typedef struct {
    char   *name;
    char   *value;
} hpack_header_t;

/* ── Dynamic table entry ─────────────────────────────────────────────────── */
typedef struct {
    char   *name;
    char   *value;
    size_t  size;   /* name_len + value_len + 32 (RFC 7541 §4.1)            */
} hpack_entry_t;

/* ── Dynamic table ───────────────────────────────────────────────────────── */
typedef struct {
    hpack_entry_t *entries;    /* ring buffer                                */
    size_t         cap;        /* allocated entry slots                      */
    size_t         head;       /* oldest entry index                         */
    size_t         count;      /* live entry count                           */
    size_t         size;       /* current byte size                          */
    size_t         max_size;   /* set by SETTINGS_HEADER_TABLE_SIZE          */
} hpack_dynamic_table_t;

/* ── Context (one per direction per h2_conn) ─────────────────────────────── */
typedef struct {
    hpack_dynamic_table_t table;
    int                   huffman_encode;    /* outbound: from config        */
    int                   dynamic_table_update; /* outbound: from config     */
} hpack_ctx_t;

/* ── Init / free ─────────────────────────────────────────────────────────── */
int  hpack_ctx_init(hpack_ctx_t *ctx, size_t max_size,
                    int huffman_encode, int dynamic_table_update);
void hpack_ctx_free(hpack_ctx_t *ctx);

/* ── Dynamic table resize (on SETTINGS_HEADER_TABLE_SIZE update) ─────────── */
int  hpack_dynamic_table_resize(hpack_ctx_t *ctx, size_t new_max);

/* ── Decode ──────────────────────────────────────────────────────────────── */
/* Decodes a HEADERS block into headers[].
 * Returns number of headers decoded, -1 on error.
 * Caller owns name/value strings — call hpack_headers_free when done.      */
int  hpack_decode(hpack_ctx_t *ctx,
                  const uint8_t *src, size_t src_len,
                  hpack_header_t *headers, int max_headers);

/* ── Encode ──────────────────────────────────────────────────────────────── */
/* Encodes headers[] into dst.
 * Returns bytes written, -1 on error.                                       */
int  hpack_encode(hpack_ctx_t *ctx,
                  const hpack_header_t *headers, int count,
                  uint8_t *dst, size_t dst_len);

/* ── Helpers ─────────────────────────────────────────────────────────────── */
void hpack_headers_free(hpack_header_t *headers, int count);

#endif /* ROUTA_HTTP_H2_HPACK_H */