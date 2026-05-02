#ifndef ROUTA_NET_TLS_H
#define ROUTA_NET_TLS_H

#include <openssl/ssl.h>
#include <stddef.h>
#include <sys/types.h>
#include "util/buf.h"

typedef struct {
    SSL_CTX *ctx;
} tls_context_t;

typedef struct {
    SSL     *ssl;
    int      fd;
    int      handshake_done;
} tls_conn_t;

/* Initialize OpenSSL library (call once at startup) */
void tls_init(void);

/* Create a server TLS context from cert and key PEM files.
   Returns NULL on error. */
tls_context_t *tls_context_new(const char *cert_file, const char *key_file);
void           tls_context_free(tls_context_t *ctx);

/* Wrap an accepted fd with TLS. Returns NULL on error. */
tls_conn_t *tls_conn_new(tls_context_t *ctx, int fd);
void        tls_conn_free(tls_conn_t *tc);

/* Perform TLS handshake. Returns:
    0  — handshake complete
    1  — want read (call again when fd readable)
   -1  — want write (call again when fd writable)
   -2  — fatal error */
int tls_handshake(tls_conn_t *tc);

/* Read/write — same semantics as read()/write() but over TLS.
   Return bytes transferred, 0 on close, -1 on error/want-more. */
ssize_t tls_read(tls_conn_t *tc, void *buf, size_t len);
ssize_t tls_write(tls_conn_t *tc, const void *buf, size_t len);

/* Graceful shutdown */
void tls_shutdown(tls_conn_t *tc);

#endif
