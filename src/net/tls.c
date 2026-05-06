#define _GNU_SOURCE
#include "net/tls.h"
#include "util/logger.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

/* OCSP stapling callback data */
static unsigned char *g_ocsp_response     = NULL;
static long           g_ocsp_response_len = 0;

static int ocsp_stapling_cb(SSL *ssl, void *arg) {
    (void)ssl; (void)arg;
    if (!g_ocsp_response || g_ocsp_response_len <= 0)
        return SSL_TLSEXT_ERR_NOACK;
    unsigned char *copy = OPENSSL_malloc((size_t)g_ocsp_response_len);
    if (!copy) return SSL_TLSEXT_ERR_NOACK;
    memcpy(copy, g_ocsp_response, (size_t)g_ocsp_response_len);
    SSL_set_tlsext_status_ocsp_resp(ssl, copy, g_ocsp_response_len);
    return SSL_TLSEXT_ERR_OK;
}

void tls_init(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

tls_context_t *tls_context_new(const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) {
        return NULL;
    }

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("Failed to create SSL context");
        return NULL;
    }

    // Set minimum protocol version to TLS 1.2
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        LOG_ERROR("Failed to set minimum TLS version");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set SSL modes
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* Session cache — server side, TLS 1.2 session IDs */
    SSL_CTX_set_session_cache_mode(ctx,
        SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);
    SSL_CTX_set_timeout(ctx, 3600); /* 1 hour */
    SSL_CTX_set_session_id_context(ctx,
        (const unsigned char *)"routa", 5);

    /* TLS 1.3 session tickets — enabled by default, set ticket lifetime */
    SSL_CTX_set_num_tickets(ctx, 2);

    // Load certificate file
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        LOG_ERROR("Failed to load certificate file: %s", err_buf);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load private key file
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        LOG_ERROR("Failed to load private key file: %s", err_buf);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        LOG_ERROR("Private key does not match certificate: %s", err_buf);
        SSL_CTX_free(ctx);
        return NULL;
    }

    tls_context_t *tls_ctx = calloc(1, sizeof(tls_context_t));
    if (!tls_ctx) {
        LOG_ERROR("Failed to allocate TLS context");
        SSL_CTX_free(ctx);
        return NULL;
    }

    tls_ctx->ctx = ctx;
    return tls_ctx;
}

int tls_context_enable_session_cache(tls_context_t *ctx, int timeout_seconds) {
    if (!ctx || !ctx->ctx) return -1;
    SSL_CTX_set_session_cache_mode(ctx->ctx,
        SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);
    SSL_CTX_set_timeout(ctx->ctx,
        timeout_seconds > 0 ? timeout_seconds : 3600);
    LOG_INFO("TLS session cache enabled, timeout=%ds", timeout_seconds);
    return 0;
}

int tls_context_enable_ocsp_stapling(tls_context_t *ctx, const char *ocsp_file) {
    if (!ctx || !ctx->ctx || !ocsp_file) return -1;

    FILE *f = fopen(ocsp_file, "rb");
    if (!f) {
        LOG_ERROR("OCSP: cannot open %s", ocsp_file);
        return -1;
    }

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
        LOG_ERROR("OCSP: read failed");
        OPENSSL_free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Free previous if any */
    if (g_ocsp_response) {
        OPENSSL_free(g_ocsp_response);
    }
    g_ocsp_response     = buf;
    g_ocsp_response_len = len;

    SSL_CTX_set_tlsext_status_cb(ctx->ctx, ocsp_stapling_cb);
    SSL_CTX_set_tlsext_status_arg(ctx->ctx, NULL);

    LOG_INFO("OCSP stapling enabled, response=%ld bytes", len);
    return 0;
}

int tls_session_resumed(const tls_conn_t *tc) {
    if (!tc || !tc->ssl) return 0;
    return SSL_session_reused(tc->ssl) ? 1 : 0;
}

void tls_context_free(tls_context_t *ctx) {
    if (ctx) {
        if (ctx->ctx) {
            SSL_CTX_free(ctx->ctx);
        }
        if (g_ocsp_response) {
            OPENSSL_free(g_ocsp_response);
            g_ocsp_response     = NULL;
            g_ocsp_response_len = 0;
        }
        free(ctx);
    }
}

tls_conn_t *tls_conn_new(tls_context_t *ctx, int fd) {
    if (!ctx || fd < 0) {
        return NULL;
    }

    SSL *ssl = SSL_new(ctx->ctx);
    if (!ssl) {
        LOG_ERROR("Failed to create SSL connection");
        return NULL;
    }

    if (!SSL_set_fd(ssl, fd)) {
        LOG_ERROR("Failed to set SSL file descriptor");
        SSL_free(ssl);
        return NULL;
    }

    SSL_set_accept_state(ssl);

    tls_conn_t *tc = calloc(1, sizeof(tls_conn_t));
    if (!tc) {
        LOG_ERROR("Failed to allocate TLS connection");
        SSL_free(ssl);
        return NULL;
    }

    tc->ssl = ssl;
    tc->fd = fd;
    tc->handshake_done = 0;

    return tc;
}

void tls_conn_free(tls_conn_t *tc) {
    if (tc) {
        if (tc->ssl) {
            SSL_free(tc->ssl);
        }
        free(tc);
    }
}

int tls_handshake(tls_conn_t *tc) {
    if (!tc) {
        return -2;
    }

    int ret = SSL_do_handshake(tc->ssl);
    if (ret == 1) {
        tc->handshake_done = 1;
        tc->resumed = SSL_session_reused(tc->ssl);
        if (tc->resumed)
            LOG_INFO("TLS session resumed");
        return 0;
    }

    int err = SSL_get_error(tc->ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            return 1;
        case SSL_ERROR_WANT_WRITE:
            return -1;
        default:
            {
                char err_buf[256];
                ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                LOG_ERROR("TLS handshake failed: %s", err_buf);
            }
            return -2;
    }
}

ssize_t tls_read(tls_conn_t *tc, void *buf, size_t len) {
    if (!tc || !buf || !tc->handshake_done) {
        return -1;
    }

    int n = SSL_read(tc->ssl, buf, (int)len);
    if (n > 0) {
        return n;
    }

    int err = SSL_get_error(tc->ssl, n);
    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return -1;
        case SSL_ERROR_ZERO_RETURN:
            return 0;
        default:
            {
                char err_buf[256];
                ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                LOG_ERROR("TLS read failed: %s", err_buf);
            }
            return -1;
    }
}

ssize_t tls_write(tls_conn_t *tc, const void *buf, size_t len) {
    if (!tc || !buf || !tc->handshake_done) {
        return -1;
    }

    int n = SSL_write(tc->ssl, buf, (int)len);
    if (n > 0) {
        return n;
    }

    int err = SSL_get_error(tc->ssl, n);
    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return -1;
        case SSL_ERROR_ZERO_RETURN:
            return 0;
        default:
            {
                char err_buf[256];
                ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                LOG_ERROR("TLS write failed: %s", err_buf);
            }
            return -1;
    }
}

void tls_shutdown(tls_conn_t *tc) {
    if (tc && tc->ssl) {
        SSL_shutdown(tc->ssl);
    }
}
