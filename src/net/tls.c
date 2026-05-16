#define _GNU_SOURCE
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
    // RFC 7301: server picks from client's list
    // Prefer h2, fall back to http/1.1
    static const unsigned char h2[]       = {2, 'h', '2'};
    static const unsigned char http11[]   = {8, 'h','t','t','p','/','1','.','1'};

    const unsigned char *p = in;
    while (p < in + inlen) {
        unsigned int len = *p++;
        if (len == 2 && memcmp(p, "h2", 2) == 0) {
            *out = h2 + 1; *outlen = 2; return SSL_TLSEXT_ERR_OK;
        }
        p += len;
    }
    // fallback
    *out = http11 + 1; *outlen = 8; return SSL_TLSEXT_ERR_OK;
}

/* ── STEK ticket-key callback ──────────────────────────────────────────────
 *
 * OpenSSL calls this for every TLS 1.3 ticket encrypt/decrypt.
 * enc == 1 → encrypt (new ticket)   enc == 0 → decrypt (resumption attempt)
 *
 * We store a pointer to tls_context_t in the SSL_CTX app-data slot so the
 * callback can reach the current STEK without a global variable.
 */
static int stek_ticket_cb(SSL *ssl,
                           unsigned char *key_name,   /* 16 bytes */
                           unsigned char *iv,
                           EVP_CIPHER_CTX *ectx,
                           EVP_MAC_CTX    *hctx,       /* OpenSSL 3.x */
                           int             enc)
{
    (void)ssl;
    /* Retrieve our context from SSL_CTX app-data */
    SSL_CTX        *ssl_ctx = SSL_get_SSL_CTX(ssl);
    tls_context_t  *tls_ctx = SSL_CTX_get_app_data(ssl_ctx);
    if (!tls_ctx) return -1;

    pthread_rwlock_rdlock(&tls_ctx->stek_lock);
    tls_stek_t stek = tls_ctx->stek;           /* local copy under read-lock */
    pthread_rwlock_unlock(&tls_ctx->stek_lock);

    if (enc) {
        /* ── Encrypt path ── */
        memcpy(key_name, stek.name, TLS_STEK_NAME_LEN);
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) return -1;

        if (!EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL,
                                stek.aes_key, iv))
            return -1;

        /* HMAC params for OpenSSL 3.x OSSL_PARAM style */
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_octet_string(
            "key", stek.hmac_key, TLS_STEK_HMAC_LEN);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_MAC_CTX_set_params(hctx, params)) return -1;

        return 1;
    } else {
        /* ── Decrypt path ── */
        if (memcmp(key_name, stek.name, TLS_STEK_NAME_LEN) != 0)
            return 0;   /* key mismatch → full handshake */

        if (!EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL,
                                stek.aes_key, iv))
            return -1;

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_octet_string(
            "key", stek.hmac_key, TLS_STEK_HMAC_LEN);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_MAC_CTX_set_params(hctx, params)) return -1;

        return 1;
    }
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

    /* One ticket per handshake is enough */
    SSL_CTX_set_num_tickets(ctx, 1);

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

    pthread_rwlock_init(&tls_ctx->stek_lock, NULL);
    pthread_rwlock_init(&tls_ctx->ocsp_lock, NULL);
    tls_ctx->ctx = ctx;

    /* ── Store back-pointer so ticket callback can reach us ── */
    SSL_CTX_set_app_data(ctx, tls_ctx);

    /* ── Generate initial STEK ── */
    if (tls_context_rotate_stek(tls_ctx) != 0) {
        LOG_ERROR("tls_context_new: initial STEK generation failed");
        SSL_CTX_free(ctx);
        free(tls_ctx);
        return NULL;
    }

    /* ── Install STEK callback ── */
    SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, stek_ticket_cb);
    /* ── ALPN: prefer h2, fall back to http/1.1 ── */
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

    return tls_ctx;
}

/* ── tls_context_free ──────────────────────────────────────────────────────*/

void tls_context_free(tls_context_t *ctx) {
    if (!ctx) return;

    SSL_CTX_free(ctx->ctx);

    pthread_rwlock_wrlock(&ctx->ocsp_lock);
    if (ctx->ocsp_response) {
        OPENSSL_free(ctx->ocsp_response);
        ctx->ocsp_response     = NULL;
        ctx->ocsp_response_len = 0;
    }
    pthread_rwlock_unlock(&ctx->ocsp_lock);

    pthread_rwlock_destroy(&ctx->stek_lock);
    pthread_rwlock_destroy(&ctx->ocsp_lock);
    free(ctx);
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

/* ── tls_context_rotate_stek ───────────────────────────────────────────────
 * Generate a fresh STEK.  Safe to call from any thread while workers run.  */

int tls_context_rotate_stek(tls_context_t *ctx) {
    if (!ctx) return -1;

    tls_stek_t fresh;
    if (RAND_bytes(fresh.name,    TLS_STEK_NAME_LEN) != 1 ||
        RAND_bytes(fresh.aes_key, TLS_STEK_AES_LEN)  != 1 ||
        RAND_bytes(fresh.hmac_key,TLS_STEK_HMAC_LEN) != 1) {
        LOG_ERROR("tls_context_rotate_stek: RAND_bytes failed");
        return -1;
    }

    pthread_rwlock_wrlock(&ctx->stek_lock);
    ctx->stek = fresh;
    pthread_rwlock_unlock(&ctx->stek_lock);

    LOG_INFO("TLS STEK rotated");
    return 0;
}

/* ── tls_context_enable_ocsp_stapling ─────────────────────────────────────
 * Hot-reloadable: call again any time to swap in a fresh OCSP response.    */

int tls_context_enable_ocsp_stapling(tls_context_t *ctx, const char *ocsp_file) {
    if (!ctx || !ctx->ctx || !ocsp_file) return -1;

    FILE *f = fopen(ocsp_file, "rb");
    if (!f) { LOG_ERROR("OCSP: cannot open %s", ocsp_file); return -1; }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    if (len <= 0 || len > 65536) {
        LOG_ERROR("OCSP: invalid file size %ld", len);
        fclose(f);
        return -1;
    }

    unsigned char *buf = OPENSSL_malloc((size_t)len);
    if (!buf) { fclose(f); return -1; }

    if ((long)fread(buf, 1, (size_t)len, f) != len) {
        LOG_ERROR("OCSP: read error");
        OPENSSL_free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

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

    int ret = SSL_do_handshake(tc->ssl);
    if (ret == 1) {
        tc->handshake_done = 1;
        tc->resumed = SSL_session_reused(tc->ssl) ? 1 : 0;
        return 0;
    }

    switch (SSL_get_error(tc->ssl, ret)) {
        case SSL_ERROR_WANT_READ:  return  1;
        case SSL_ERROR_WANT_WRITE: return -1;
        default:
            log_ssl_error("TLS handshake");
            return -2;
    }
}

/* ── I/O ───────────────────────────────────────────────────────────────────*/

ssize_t tls_read(tls_conn_t *tc, void *buf, size_t len) {
    if (!tc || !buf || !tc->handshake_done) return -1;

    int n = SSL_read(tc->ssl, buf, (int)len);
    if (n > 0) return n;

    switch (SSL_get_error(tc->ssl, n)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:  return -1;
        case SSL_ERROR_ZERO_RETURN: return  0;
        default:
            log_ssl_error("TLS read");
            return -1;
    }
}

ssize_t tls_write(tls_conn_t *tc, const void *buf, size_t len) {
    if (!tc || !buf || !tc->handshake_done) return -1;

    int n = SSL_write(tc->ssl, buf, (int)len);
    if (n > 0) return n;

    switch (SSL_get_error(tc->ssl, n)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:  return -1;
        case SSL_ERROR_ZERO_RETURN: return  0;
        default:
            log_ssl_error("TLS write");
            return -1;
    }
}

void tls_shutdown(tls_conn_t *tc) {
    if (tc && tc->ssl) SSL_shutdown(tc->ssl);
}

int tls_session_resumed(const tls_conn_t *tc) {
    return (tc && tc->ssl) ? SSL_session_reused(tc->ssl) : 0;
}