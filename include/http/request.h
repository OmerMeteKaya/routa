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
    int            version_major;
    int            version_minor;
    http_header_t  headers[64];
    int            header_count;
    char          *body;        // heap allocated or NULL
    size_t         body_len;
    int            keep_alive;  // 1 if connection should persist
} http_request_t;

// Parse from buf_t. Returns 0 on success, -1 on error, 1 if incomplete
// (need more data). Does NOT modify the buffer — works on a copy internally.
int  http_request_parse(http_request_t *req, const buf_t *buf, size_t *consumed);
void http_request_free(http_request_t *req);
const char *http_request_get_header(const http_request_t *req, const char *key);

#endif // ROUTA_HTTP_REQUEST_H
