#ifndef ROUTA_HTTP_REQUEST_H
#define ROUTA_HTTP_REQUEST_H

#include "util/buf.h"
#include <stdlib.h>

typedef enum {
    HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE, HTTP_HEAD,
    HTTP_PATCH, HTTP_OPTIONS, HTTP_TRACE, HTTP_CONNECT,
    HTTP_METHOD_UNKNOWN
} http_method_t;

typedef struct {
    char *key;
    char *value;
} http_header_t;

typedef struct {
    http_method_t  method;
    char          *path;        // heap allocated, url-decoded, normalized
    char          *query;       // heap allocated, raw query string or NULL
    struct {
        char *key;
        char *value;
    }              query_params[32];
    int            query_param_count;
    int            version_major;
    int            version_minor;
    http_header_t  headers[64];
    int            header_count;
    char          *body;        // heap allocated or NULL
    size_t         body_len;
    int            keep_alive; // 1 if connection should persist
    char remote_ip[46];
    /* ── Observability ─────────────────────────────────────── */
    char     trace_id[17];   /* 16 hex chars + NUL, set at parse time */
    uint64_t start_us;       /* routa_now_us() at parse completion    */
    int headers_owned; /* 0 = borrowed/stolen, 1 = malloc'd (default) */
    /* ── HTTP/2 trailers (RFC 7540 8.1) ────────────────────────
     * A second HEADERS frame sent after the body, carrying additional
     * header fields discovered only after the body was generated (e.g.
     * a checksum, or gRPC's grpc-status/grpc-message). Only meaningful
     * for H2 (and H2-over-H1-upgrade); H1 has no equivalent mechanism
     * routa parses (chunked trailers exist in the HTTP/1.1 spec too, but
     * are not currently parsed on the H1 path -- trailer_count stays 0
     * there). trailer_count == 0 is the common case and callers should
     * treat it exactly like "no trailers were sent," not as an error. */
    http_header_t  trailers[16];
    int            trailer_count;
} http_request_t;

// Parse from buf_t. Returns 0 on success, -1 on error, 1 if incomplete
// (need more data). Does NOT modify the buffer — works on a copy internally.
int  http_request_parse(http_request_t *req, const buf_t *buf, size_t *consumed);
void http_request_free(http_request_t *req);
int  http_request_clone(const http_request_t *src, http_request_t *dst);
const char *http_request_get_header(const http_request_t *req, const char *key);
const char *http_request_get_query(const http_request_t *req, const char *key);

#endif // ROUTA_HTTP_REQUEST_H
