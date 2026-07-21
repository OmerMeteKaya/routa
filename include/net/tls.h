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
    /* BUG FIX (H2-over-TLS large-file concurrent-stream stall):
     * OpenSSL's SSL_write() retry contract requires that after a call
     * returns SSL_ERROR_WANT_READ/WANT_WRITE, the NEXT call on this SSL*
     * must be made with the exact same buffer contents and the exact
     * same length as the failed attempt (SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
     * only relaxes the pointer-identity requirement, not length/content).
     * This codebase flushes hc->write_buf (a single shared, freely-growing
     * buffer) from many independent call sites in h2.c, each of which can
     * append more H2 frames to it and then call tls_write() again -- with
     * a LARGER length than a still-outstanding WANT_WRITE retry expected.
     * Confirmed via live instrumentation: tls_write() was observed being
     * called repeatedly on one connection with a monotonically growing
     * `len` (e.g. 1104512, then 1104605, then 1104698, ... each ~93 bytes
     * larger than the last) while every call kept returning WANT_WRITE --
     * i.e. the retry was never actually satisfied with consistent
     * arguments, so forward progress on that connection's write side
     * silently stalled forever (until a 30s stream idle timeout fired),
     * while write_buf kept growing unboundedly in the meantime (this is
     * also the root cause of the ~400-450MB RSS spikes observed in
     * concurrent-H2-over-TLS large-file benchmarks -- the buffer that
     * should have drained as fast as it filled instead only ever grew).
     * Fix: remember the length that was actually handed to the last
     * failed SSL_write() call, and ignore any larger `len` a caller
     * passes on a subsequent tls_write() call until that exact pending
     * write succeeds -- honoring OpenSSL's retry contract regardless of
     * how much unrelated code appended to the caller's buffer in the
     * meantime. 0 means no retry is currently pending. */
    size_t pending_write_len;
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