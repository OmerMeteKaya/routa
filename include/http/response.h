#ifndef ROUTA_HTTP_RESPONSE_H
#define ROUTA_HTTP_RESPONSE_H

#include "util/buf.h"
#include <stdlib.h>

typedef struct {
    int    status;
    char  *reason;      // heap or literal — use flag
    char   headers[32][2][256]; // [i][0]=key [i][1]=value
    int    header_count;
    char  *body;        // heap allocated or NULL
    size_t body_len;
} http_response_t;

void http_response_init(http_response_t *r);
void http_response_set_status(http_response_t *r, int status, const char *reason);
void http_response_set_header(http_response_t *r, const char *key, const char *val);
void http_response_set_body(http_response_t *r, const char *data, size_t len);
    // copies data into heap; sets Content-Length automatically
int  http_response_serialize(const http_response_t *r, buf_t *out);
    // writes full HTTP/1.1 response into out buf_t; returns 0 ok -1 err
void http_response_destroy(http_response_t *r);

// Convenience: write a complete response in one call
int http_response_simple(buf_t *out, int status, const char *reason,
                         const char *content_type, const char *body);

#endif // ROUTA_HTTP_RESPONSE_H
