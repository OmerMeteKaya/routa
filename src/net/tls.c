#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "net/tls.h"
#include "util/logger.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Helpers ───────────────────────────────────────────────────────────────*/
const char *tls_negotiated_protocol(const tls_conn_t *tc) {
    if (!tc || !tc->ssl || !tc->handshake_done) return NULL;

    const unsigned char *proto = NULL;
    unsigned int         len   = 0;

    SSL_get0_alpn_selected(tc->ssl, &proto, &len);

    if (!proto || len == 0) return NULL;

    /* Return a static string — caller does not free                       */
    if (len == 2 && memcmp(proto, "h2", 2) == 0)       return "h2";
    if (len == 8 && memcmp(proto, "http/1.1", 8) == 0) return "http/1.1";

    return NULL;
}
static void log_ssl_error(const char *prefix) {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    LOG_ERROR("%s: %s", prefix, buf);
}
static int alpn_select_cb(SSL *ssl,
                           const unsigned char **out, unsigned char *outlen,
                           const unsigned char *in,  unsigned int inlen,
                           void *arg) {
    (void)ssl; (void)arg;

    /* Preferred: h2, fallback: http/1.1 */
    static const unsigned char protos[] =
        "\x02h2\x08http/1.1";   /* length-prefixed wire format */

    if (SSL_select_next_proto(
            (unsigned char **)out, outlen,
            protos, sizeof(protos) - 1,
            in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
            }
    return SSL_TLSEXT_ERR_NOACK;
}

/* ── SNI servername callback ───────────────────────────────────────────────
 * Called during ClientHello parsing, before the rest of the handshake
 * proceeds. Looks up the requested hostname against tls_ctx->sni_entries
 * (exact match first, then single-label wildcard match per RFC 6125) and
 * swaps in the matching SSL_CTX via SSL_set_SSL_CTX. If no SNI was sent,
 * or the hostname doesn't match any registered entry, the connection
 * keeps using whatever SSL_CTX it was created with (the default). */
static int sni_matches_wildcard(const char *pattern, const char *host) {
    /* pattern is like "*.example.com". Match host against ".example.com"
     * suffix, but only when host has exactly one label before that
     * suffix (i.e. host itself is not just "example.com" and does not
     * have extra dots before the suffix starts). */
    const char *suffix = pattern + 1; /* skip '*', keep leading '.' */
    size_t suffix_len = strlen(suffix);
    size_t host_len   = strlen(host);
    if (host_len <= suffix_len) return 0;
    const char *host_suffix = host + (host_len - suffix_len);
    if (strcasecmp(host_suffix, suffix) != 0) return 0;
    /* Everything before host_suffix must be a single label: no dots. */
    size_t label_len = host_len - suffix_len;
    for (size_t i = 0; i < label_len; i++) {
        if (host[i] == '.') return 0;
    }
    return label_len > 0;
}

static int sni_select_cb(SSL *ssl, int *al, void *arg) {
    (void)al;
    tls_context_t *tls_ctx = (tls_context_t *)arg;
    if (!tls_ctx || tls_ctx->sni_entry_count == 0) return SSL_TLSEXT_ERR_OK;

    const char *host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!host || !*host) return SSL_TLSEXT_ERR_OK; /* no SNI: use default */

    /* Exact match first */
    for (int i = 0; i < tls_ctx->sni_entry_count; i++) {
        if (!tls_ctx->sni_entries[i].is_wildcard &&
            strcasecmp(tls_ctx->sni_entries[i].hostname, host) == 0) {
            SSL_set_SSL_CTX(ssl, tls_ctx->sni_entries[i].ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }
    /* Wildcard match second */
    for (int i = 0; i < tls_ctx->sni_entry_count; i++) {
        if (tls_ctx->sni_entries[i].is_wildcard &&
            sni_matches_wildcard(tls_ctx->sni_entries[i].hostname, host)) {
            SSL_set_SSL_CTX(ssl, tls_ctx->sni_entries[i].ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }
    /* No match: keep the default SSL_CTX this SSL object already has. */
    return SSL_TLSEXT_ERR_OK;
}

/* ── OCSP stapling callback ────────────────────────────────────────────────*/

static int ocsp_stapling_cb(SSL *ssl, void *arg) {
    tls_context_t *tls_ctx = (tls_context_t *)arg;
    if (!tls_ctx) return SSL_TLSEXT_ERR_NOACK;

    pthread_rwlock_rdlock(&tls_ctx->ocsp_lock);

    if (!tls_ctx->ocsp_response || tls_ctx->ocsp_response_len <= 0) {
        pthread_rwlock_unlock(&tls_ctx->ocsp_lock);
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* OpenSSL takes ownership of this copy */
    unsigned char *copy = OPENSSL_malloc((size_t)tls_ctx->ocsp_response_len);
    if (!copy) {
        pthread_rwlock_unlock(&tls_ctx->ocsp_lock);
        return SSL_TLSEXT_ERR_NOACK;
    }
    memcpy(copy, tls_ctx->ocsp_response, (size_t)tls_ctx->ocsp_response_len);
    long len = tls_ctx->ocsp_response_len;

    pthread_rwlock_unlock(&tls_ctx->ocsp_lock);

    SSL_set_tlsext_status_ocsp_resp(ssl, copy, len);
    return SSL_TLSEXT_ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════*/

void tls_init(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

/* ── tls_context_new ───────────────────────────────────────────────────────*/

tls_context_t *tls_context_new(const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) return NULL;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log_ssl_error("SSL_CTX_new");
        return NULL;
    }

    /* ── TLS 1.3 only ── */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        log_ssl_error("set TLS version");
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_session_id_context(ctx,
        (const unsigned char *)"routa", 5);
    SSL_CTX_set_max_early_data(ctx, 16384);
    SSL_CTX_set_post_handshake_auth(ctx, 0);
    SSL_CTX_set_timeout(ctx, 14400);


    /* ── Load cert + key ── */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("load certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("load private key");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        log_ssl_error("check private key");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* ── Allocate our context ── */
    tls_context_t *tls_ctx = calloc(1, sizeof(tls_context_t));
    if (!tls_ctx) {
        LOG_ERROR("tls_context_new: calloc failed");
        SSL_CTX_free(ctx);
        return NULL;
    }

    pthread_rwlock_init(&tls_ctx->ocsp_lock, NULL);
    tls_ctx->ctx = ctx;
    /* Generate ticket key once — survives cert hot-reload */
    if (RAND_bytes(tls_ctx->ticket_key, sizeof(tls_ctx->ticket_key)) != 1) {
        log_ssl_error("RAND_bytes ticket_key");
        SSL_CTX_free(ctx);
        free(tls_ctx);
        return NULL;
    }
    SSL_CTX_set_tlsext_ticket_keys(ctx,
        tls_ctx->ticket_key, sizeof(tls_ctx->ticket_key));
    /* ── Store back-pointer so ticket callback can reach us ── */
    SSL_CTX_set_app_data(ctx, tls_ctx);

    /* ── ALPN: prefer h2, fall back to http/1.1 ── */
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

    /* ── SNI: dispatch to a per-hostname SSL_CTX if one was registered via
     * tls_context_add_sni_cert. Installed unconditionally (cheap no-op via
     * sni_entry_count == 0 check) so certs can be added any time after
     * context creation without re-installing the callback. ── */
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_select_cb);
    SSL_CTX_set_tlsext_servername_arg(ctx, tls_ctx);

    return tls_ctx;
}

/* ── tls_context_free ──────────────────────────────────────────────────────*/

void tls_context_free(tls_context_t *ctx) {
    if (!ctx) return;

    for (int i = 0; i < ctx->sni_entry_count; i++) {
        SSL_CTX_free(ctx->sni_entries[i].ctx);
    }

    SSL_CTX_free(ctx->ctx);

    pthread_rwlock_wrlock(&ctx->ocsp_lock);
    if (ctx->ocsp_response) {
        OPENSSL_free(ctx->ocsp_response);
        ctx->ocsp_response     = NULL;
        ctx->ocsp_response_len = 0;
    }
    pthread_rwlock_unlock(&ctx->ocsp_lock);

    pthread_rwlock_destroy(&ctx->ocsp_lock);
    free(ctx);
}

/* ── tls_context_reload ────────────────────────────────────────────────────
 * Atomically swaps the SSL_CTX with one loaded from new cert/key files.
 * Caller must hold an exclusive write lock to prevent concurrent SSL_new()
 * from racing the ctx pointer swap.
 * Existing tls_conn_t objects are unaffected: each SSL* holds its own
 * internal reference to the old SSL_CTX, which OpenSSL frees when the last
 * SSL* referencing it is freed.                                              */

int tls_context_reload(tls_context_t *tls_ctx,
                       const char *cert_file, const char *key_file) {
    if (!tls_ctx || !cert_file || !key_file) return -1;

    SSL_CTX *new_ctx = SSL_CTX_new(TLS_server_method());
    if (!new_ctx) { log_ssl_error("reload: SSL_CTX_new"); return -1; }

    if (!SSL_CTX_set_min_proto_version(new_ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(new_ctx, TLS1_3_VERSION)) {
        log_ssl_error("reload: set TLS version");
        SSL_CTX_free(new_ctx);
        return -1;
    }

    SSL_CTX_set_mode(new_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                           SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(new_ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(new_ctx, 0);
    SSL_CTX_set_session_id_context(new_ctx,
        (const unsigned char *)"routa", 5);
    SSL_CTX_set_max_early_data(new_ctx, 16384);
    SSL_CTX_set_post_handshake_auth(new_ctx, 0);
    SSL_CTX_set_timeout(new_ctx, 14400);

    if (SSL_CTX_use_certificate_file(new_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("reload: load certificate");
        SSL_CTX_free(new_ctx);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(new_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("reload: load private key");
        SSL_CTX_free(new_ctx);
        return -1;
    }
    if (!SSL_CTX_check_private_key(new_ctx)) {
        log_ssl_error("reload: check private key");
        SSL_CTX_free(new_ctx);
        return -1;
    }

    /* ALPN: prefer h2, fall back to http/1.1 */
    SSL_CTX_set_alpn_select_cb(new_ctx, alpn_select_cb, NULL);

    /* Update back-pointer so OCSP callback reaches tls_ctx */
    SSL_CTX_set_app_data(new_ctx, tls_ctx);

    /* Re-attach OCSP stapling callback if a response is loaded */
    pthread_rwlock_rdlock(&tls_ctx->ocsp_lock);
    int has_ocsp = (tls_ctx->ocsp_response != NULL);
    pthread_rwlock_unlock(&tls_ctx->ocsp_lock);
    if (has_ocsp) {
        SSL_CTX_set_tlsext_status_cb(new_ctx,  ocsp_stapling_cb);
        SSL_CTX_set_tlsext_status_arg(new_ctx, tls_ctx);
    }

    /* Swap — caller holds the exclusive lock, so no concurrent SSL_new() */
    SSL_CTX *old_ctx = tls_ctx->ctx;
    tls_ctx->ctx     = new_ctx;

    /* SSL_CTX_free decrements the refcount; existing SSL* objects each hold
     * their own reference and will keep old_ctx alive until freed.          */
    SSL_CTX_set_tlsext_ticket_keys(new_ctx,
    tls_ctx->ticket_key, sizeof(tls_ctx->ticket_key));
    SSL_CTX_free(old_ctx);

    LOG_INFO("TLS context reloaded (cert: %s)", cert_file);
    return 0;
}

/* ── tls_context_enable_session_cache ─────────────────────────────────────
 * TLS 1.3 doesn't use session IDs but keep this for forward compatibility
 * if someone re-enables 1.2 later.                                         */

int tls_context_enable_session_cache(tls_context_t *ctx, int timeout_seconds) {
    if (!ctx || !ctx->ctx) return -1;
    SSL_CTX_set_session_cache_mode(ctx->ctx,
        SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);
    SSL_CTX_set_timeout(ctx->ctx, timeout_seconds > 0 ? timeout_seconds : 3600);
    return 0;
}

/* ── tls_context_enable_ocsp_stapling ─────────────────────────────────────
 * Hot-reloadable: call again any time to swap in a fresh OCSP response.    */

int tls_context_enable_ocsp_stapling(tls_context_t *ctx, const char *ocsp_file) {
    if (!ctx || !ctx->ctx || !ocsp_file) return -1;

    FILE *f = fopen(ocsp_file, "rb");
    if (!f) { LOG_ERROR("OCSP: cannot open %s", ocsp_file); return -1; }

    (void)fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (fseek(f, 0, SEEK_SET) != 0) { (void)fclose(f); return -1; }

    if (len <= 0 || len > 65536) {
        LOG_ERROR("OCSP: invalid file size %ld", len);
        (void)fclose(f);
        return -1;
    }

    unsigned char *buf = OPENSSL_malloc((size_t)len);
    if (!buf) { (void)fclose(f); return -1; }

    if ((long)fread(buf, 1, (size_t)len, f) != len) {
        LOG_ERROR("OCSP: read error");
        OPENSSL_free(buf);
        (void)fclose(f);
        return -1;
    }
    (void)fclose(f);

    /* Swap under write-lock — zero window for readers to see torn state */
    pthread_rwlock_wrlock(&ctx->ocsp_lock);
    unsigned char *old = ctx->ocsp_response;
    ctx->ocsp_response     = buf;
    ctx->ocsp_response_len = len;
    pthread_rwlock_unlock(&ctx->ocsp_lock);

    if (old) OPENSSL_free(old);

    /* Install callback only once (idempotent) */
    SSL_CTX_set_tlsext_status_cb(ctx->ctx,  ocsp_stapling_cb);
    SSL_CTX_set_tlsext_status_arg(ctx->ctx, ctx);   /* pass tls_context_t* */

    LOG_INFO("OCSP stapling loaded, response=%ld bytes", len);
    return 0;
}

/* ── SNI: add a per-hostname certificate ──────────────────────────────────*/

int tls_context_add_sni_cert(tls_context_t *tls_ctx, const char *hostname,
                             const char *cert_file, const char *key_file) {
    if (!tls_ctx || !hostname || !*hostname || !cert_file || !key_file) return -1;

    if (tls_ctx->sni_entry_count >= TLS_MAX_SNI_CERTS) {
        LOG_ERROR("SNI: max %d certs exceeded, ignoring '%s'",
                  TLS_MAX_SNI_CERTS, hostname);
        return -1;
    }

    SSL_CTX *sni_ctx = SSL_CTX_new(TLS_server_method());
    if (!sni_ctx) { log_ssl_error("SNI: SSL_CTX_new"); return -1; }

    if (!SSL_CTX_set_min_proto_version(sni_ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(sni_ctx, TLS1_3_VERSION)) {
        log_ssl_error("SNI: set TLS version");
        SSL_CTX_free(sni_ctx);
        return -1;
    }
    SSL_CTX_set_mode(sni_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                             SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(sni_ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(sni_ctx, 0);
    SSL_CTX_set_session_id_context(sni_ctx, (const unsigned char *)"routa", 5);
    SSL_CTX_set_max_early_data(sni_ctx, 16384);
    SSL_CTX_set_post_handshake_auth(sni_ctx, 0);
    SSL_CTX_set_timeout(sni_ctx, 14400);

    if (SSL_CTX_use_certificate_file(sni_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("SNI: load certificate");
        SSL_CTX_free(sni_ctx);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(sni_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("SNI: load private key");
        SSL_CTX_free(sni_ctx);
        return -1;
    }
    if (!SSL_CTX_check_private_key(sni_ctx)) {
        log_ssl_error("SNI: check private key");
        SSL_CTX_free(sni_ctx);
        return -1;
    }

    /* ALPN must be re-selected on the SNI ctx too -- SSL_set_SSL_CTX swaps
     * which ctx's callbacks/config apply mid-handshake, so if this ctx
     * lacks its own ALPN callback, ALPN negotiation for SNI-matched
     * connections would silently stop working. */
    SSL_CTX_set_alpn_select_cb(sni_ctx, alpn_select_cb, NULL);

    int idx = tls_ctx->sni_entry_count++;
    strncpy(tls_ctx->sni_entries[idx].hostname, hostname,
           sizeof(tls_ctx->sni_entries[idx].hostname) - 1);
    tls_ctx->sni_entries[idx].is_wildcard =
        (strncmp(hostname, "*.", 2) == 0) ? 1 : 0;
    tls_ctx->sni_entries[idx].ctx = sni_ctx;

    LOG_INFO("SNI cert registered for '%s'", hostname);
    return 0;
}

/* ── Connection ────────────────────────────────────────────────────────────*/

tls_conn_t *tls_conn_new(tls_context_t *ctx, int fd) {
    if (!ctx || fd < 0) return NULL;

    SSL *ssl = SSL_new(ctx->ctx);
    if (!ssl) { log_ssl_error("SSL_new"); return NULL; }

    if (!SSL_set_fd(ssl, fd)) {
        log_ssl_error("SSL_set_fd");
        SSL_free(ssl);
        return NULL;
    }
    SSL_set_accept_state(ssl);

    tls_conn_t *tc = calloc(1, sizeof(tls_conn_t));
    if (!tc) {
        LOG_ERROR("tls_conn_new: calloc failed");
        SSL_free(ssl);
        return NULL;
    }
    tc->ssl = ssl;
    tc->fd  = fd;
    return tc;
}

void tls_conn_free(tls_conn_t *tc) {
    if (tc) {
        SSL_free(tc->ssl);
        free(tc);
    }
}

/* ── Handshake ─────────────────────────────────────────────────────────────*/

int tls_handshake(tls_conn_t *tc) {
    if (!tc) return -2;

    if (tc->handshake_done) return 0;

    /* BUG FIX (H2/TLS failover flakiness): SSL_get_error()'s contract
     * requires the calling thread's OpenSSL error queue to be empty
     * before the SSL_* I/O call, or it misreports what actually
     * happened. In routa's thread-per-worker model, this worker thread
     * may have just serviced a DIFFERENT (possibly dead/failing)
     * connection and left a real error on the queue; without clearing
     * it here, a benign WANT_READ/WANT_WRITE on THIS handshake can get
     * misclassified as SSL_ERROR_SSL, causing an async H2 connection
     * establishment to spuriously fail even though the peer is healthy
     * and the handshake simply isn't done yet. */
    ERR_clear_error();
    int ret = SSL_do_handshake(tc->ssl);
    if (ret == 1) {
        tc->handshake_done = 1;
        tc->resumed = SSL_session_reused(tc->ssl) ? 1 : 0;
        return 0;
    }

    int err = SSL_get_error(tc->ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:  return  1;
        case SSL_ERROR_WANT_WRITE: return -1;
        default:
            log_ssl_error("TLS handshake");
            return -2;
    }
}

/* ── I/O ───────────────────────────────────────────────────────────────────*/

ssize_t tls_read(tls_conn_t *tc, void *buf, size_t len) {
    if (!tc || !buf || !tc->handshake_done) return -2;

    /* BUG FIX (H2/TLS failover flakiness -- root cause of nodes A/C
     * being spuriously marked NODE_DOWN during the failover test even
     * though only node B was ever killed): see tls_handshake()'s
     * matching comment for the full contract explanation. Confirmed via
     * instrumentation: SSL_read() returning -1 with errno==EAGAIN (a
     * completely normal "no data yet" on a non-blocking socket) was
     * being reported by SSL_get_error() as SSL_ERROR_SSL instead of
     * SSL_ERROR_WANT_READ, whenever this worker thread's error queue
     * still held a stale entry from a genuinely failed connection
     * (e.g. the just-killed node) serviced earlier in the same epoll
     * batch. That misclassification made tls_read() return -2
     * ("permanent error") for a perfectly healthy connection, which
     * h2up_on_readable() then force-closed, charging the healthy
     * node's circuit breaker with a bogus failure -- three of those in
     * a row tripped it to NODE_DOWN despite the node never having
     * failed a single real request. */
    ERR_clear_error();
    int n = SSL_read(tc->ssl, buf, (int)len);
    if (n > 0) return n;

    switch (SSL_get_error(tc->ssl, n)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:  return -1;
        case SSL_ERROR_ZERO_RETURN: return  0;
        default:
            if (ERR_peek_last_error() != 0)
                log_ssl_error("TLS read");
            else
                ERR_clear_error();
            return -2;
    }
}

ssize_t tls_write(tls_conn_t *tc, const void *buf, size_t len) {
    if (!tc || !buf || !tc->handshake_done) return -2;

    /* BUG FIX: honor OpenSSL's SSL_write() retry contract -- see the
     * detailed comment on tls_conn_t.pending_write_len in tls.h for the
     * full investigation/root-cause writeup. If a previous call on this
     * SSL* returned WANT_READ/WANT_WRITE, the retry MUST use the exact
     * same length as that failed call -- not whatever `len` the caller
     * (whose buffer may have grown since, e.g. hc->write_buf gaining new
     * H2 frames from an unrelated stream/flush) happens to pass now.
     * Clamp down to the pending length; `buf`'s pointer is allowed to
     * have moved (SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER covers that) but
     * its first pending_write_len bytes MUST be unchanged, which holds
     * here because callers only ever APPEND to write_buf, never mutate
     * already-buffered bytes ahead of the current read offset. */
    size_t call_len = len;
    if (tc->pending_write_len > 0) {
        if (tc->pending_write_len < call_len) {
            call_len = tc->pending_write_len;
        }
        /* If the caller's buffer somehow shrank below what we're still
         * retrying (shouldn't happen given write_buf is append-only, but
         * guard rather than pass a length OpenSSL never asked for), fall
         * through with call_len == len and let SSL_write's own bounds
         * checking handle it -- this is a defensive fallback, not the
         * expected path. */
    }

    /* BUG FIX (H2/TLS failover flakiness): same OpenSSL error-queue
     * contract issue as tls_read()/tls_handshake() -- see
     * tls_handshake()'s comment for the full explanation. Clearing here
     * does not interact with the pending_write_len retry-length clamp
     * above (that's about matching the byte length OpenSSL expects on
     * retry, unrelated to the error queue). */
    ERR_clear_error();
    int n = SSL_write(tc->ssl, buf, (int)call_len);
    if (n > 0) {
        tc->pending_write_len = 0;
        return n;
    }
    switch (SSL_get_error(tc->ssl, n)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            tc->pending_write_len = call_len;
            return -1;
        case SSL_ERROR_ZERO_RETURN:
            tc->pending_write_len = 0;
            return  0;
        default: {
            tc->pending_write_len = 0;
            unsigned long ssl_err = ERR_peek_last_error();
            /* Treat a genuinely empty error queue the same as a syscall-level
             * disconnect: log nothing and just drain/clear. Calling
             * log_ssl_error() here would call ERR_get_error() on an empty
             * queue, which returns 0 and formats as a meaningless
             * "error:00000000:lib(0)::reason(0)" string — and since it
             * doesn't consume a real error, every future write on this
             * same broken connection re-triggers the identical empty log
             * line, potentially without bound. */
            if (ssl_err == 0 || ERR_GET_REASON(ssl_err) == ERR_R_SYS_LIB ||
                errno == EPIPE || errno == ECONNRESET) {
                ERR_clear_error();
            } else {
                log_ssl_error("TLS write");
            }
            return -2;
        }
    }
}

void tls_shutdown(tls_conn_t *tc) {
    if (tc && tc->ssl) SSL_shutdown(tc->ssl);
}

int tls_session_resumed(const tls_conn_t *tc) {
    return (tc && tc->ssl) ? SSL_session_reused(tc->ssl) : 0;
}

int tls_has_pending(const tls_conn_t *tc) {
    return (tc && tc->ssl) ? SSL_has_pending(tc->ssl) : 0;
}
