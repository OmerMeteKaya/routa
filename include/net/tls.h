#ifndef ROUTA_NET_TLS_H
#define ROUTA_NET_TLS_H

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>
#include "util/buf.h"

/* ── Context ───────────────────────────────────────────────────────────────*/
typedef struct {
    SSL_CTX        *ctx;

    /* OCSP stapling response – guarded by ocsp_lock */
    unsigned char  *ocsp_response;
    long            ocsp_response_len;
    pthread_rwlock_t ocsp_lock;
    unsigned char   ticket_key[80];

    /* SNI: additional per-hostname SSL_CTX entries. ctx (above) remains
     * the default for unmatched/no-SNI handshakes. Read-only after startup
     * (populated via tls_context_add_sni_cert before serving traffic), so
     * no locking is needed in the servername callback's lookup path. */
#define TLS_MAX_SNI_CERTS 32
    struct {
        char     hostname[256];   /* exact hostname, or "*.suffix" wildcard */
        int      is_wildcard;     /* 1 if hostname starts with "*." */
        SSL_CTX *ctx;
    } sni_entries[TLS_MAX_SNI_CERTS];
    int sni_entry_count;
} tls_context_t;

typedef struct {
    SSL *ssl;
    int  fd;
    int  handshake_done;
    int  resumed;          /* 1 if session was resumed */
} tls_conn_t;

/* ── Library init (call once at startup) ───────────────────────────────────*/
void tls_init(void);

/* ── Context lifetime ──────────────────────────────────────────────────────*/
tls_context_t *tls_context_new(const char *cert_file, const char *key_file);
void           tls_context_free(tls_context_t *ctx);

/* Hot-reload TLS certificates without disrupting existing connections.
 * Caller MUST hold an exclusive write lock before calling (e.g. a
 * pthread_rwlock_t owned by the event loop) to prevent concurrent SSL_new()
 * calls from racing with the SSL_CTX swap.
 * Returns 0 on success, -1 on error (original ctx is left intact).         */
int tls_context_reload(tls_context_t *ctx,
                       const char *cert_file, const char *key_file);

/* ── Session cache (TLS 1.2 session IDs, optional) ─────────────────────── */
int tls_context_enable_session_cache(tls_context_t *ctx, int timeout_seconds);

/* ── OCSP stapling ─────────────────────────────────────────────────────────
 * Load a pre-fetched DER-encoded OCSP response from file.
 * Thread-safe: safe to call while workers are running (hot reload). */
int tls_context_enable_ocsp_stapling(tls_context_t *ctx, const char *ocsp_file);

/* ── SNI (multi-certificate) ───────────────────────────────────────────────
 * Register an additional certificate for a specific hostname (or wildcard
 * pattern like "*.example.com" -- single label only, matches "foo.example.com"
 * but not "example.com" or "a.b.example.com", per RFC 6125).
 * The context's original cert/key (from tls_context_new) remains the
 * default, used when the client sends no SNI or an unmatched hostname.
 * Must be called before any connections are accepted on this context (not
 * safe to race with concurrent tls_conn_new()/handshakes -- call during
 * startup/config-load only, same constraint as tls_context_new itself).
 * Returns 0 on success, -1 on error (invalid args, bad cert/key, or max
 * SNI certs exceeded).                                                     */
int tls_context_add_sni_cert(tls_context_t *ctx, const char *hostname,
                             const char *cert_file, const char *key_file);

/* ── Connection lifetime ───────────────────────────────────────────────────*/
tls_conn_t *tls_conn_new(tls_context_t *ctx, int fd);
void        tls_conn_free(tls_conn_t *tc);

/* Handshake — returns:
    0  complete
    1  want read
   -1  want write
   -2  fatal */
int tls_handshake(tls_conn_t *tc);

/* Read / write — same semantics as read()/write(). */
ssize_t tls_read (tls_conn_t *tc, void *buf,       size_t len);
ssize_t tls_write(tls_conn_t *tc, const void *buf, size_t len);

void tls_shutdown(tls_conn_t *tc);

/* Returns "h2" or "http/1.1" after handshake, NULL if unknown.
 * Returned string is static — do not free.                                */
const char *tls_negotiated_protocol(const tls_conn_t *tc);

/* Returns 1 if the last handshake resumed a previous session. */
int tls_session_resumed(const tls_conn_t *tc);

/* Returns 1 when OpenSSL holds buffered records/plaintext that will never
 * trigger another epoll edge — caller must drain via tls_read(). */
int tls_has_pending(const tls_conn_t *tc);

#endif /* ROUTA_NET_TLS_H */