#ifndef ROUTA_HTTP_RESPONSE_H
#define ROUTA_HTTP_RESPONSE_H

#include "util/buf.h"
#include "net/tls.h"
#include <stdlib.h>

typedef struct {
    int    status;
    char  *reason;      // heap or literal — use flag
    char   headers[32][2][256]; // [i][0]=key [i][1]=value
    int    header_count;
    char  *body;        // heap allocated or NULL
    size_t body_len;
    int    body_fd;      /* -1 = no fd body, >= 0 = use sendfile() */
    off_t  body_fd_off;  /* offset to start from */
    size_t body_fd_len; /* number of bytes to send */
} http_response_t;

void http_response_init(http_response_t *r);
void http_response_set_status(http_response_t *r, int status, const char *reason);
void http_response_set_header(http_response_t *r, const char *key, const char *val);
void http_response_set_body(http_response_t *r, const char *data, size_t len);
    // copies data into heap; sets Content-Length automatically
void http_response_set_body_fd(http_response_t *r, int fd, off_t offset, size_t len);
    // Sets body_fd for zero-copy sending. Caller must not close fd —
    // http_response_destroy() will close it. Content-Length is set
    // automatically from len.
int  http_response_serialize(const http_response_t *r, buf_t *out);
    // writes full HTTP/1.1 response into out buf_t; returns 0 ok -1 err
int  http_response_send(const http_response_t *r, int client_fd, tls_conn_t *tls);
    // Serializes headers into a stack buffer and writes them, then:
    // - If body_fd >= 0 and tls == NULL: use sendfile(client_fd,
    //   body_fd, &off, body_fd_len) in a loop until all bytes sent.
    // - If body_fd >= 0 and tls != NULL: fall back to read+tls_write
    //   (sendfile does not work with TLS).
    // - If body (malloc'd): write normally.
    // Returns 0 on success, -1 on error.
void http_response_destroy(http_response_t *r);

// Convenience: write a complete response in one call
int http_response_simple(buf_t *out, int status, const char *reason,
                         const char *content_type, const char *body);

#endif // ROUTA_HTTP_RESPONSE_H
