#define _GNU_SOURCE
#include "net/tls.h"
#include "util/logger.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

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

void tls_context_free(tls_context_t *ctx) {
    if (ctx) {
        if (ctx->ctx) {
            SSL_CTX_free(ctx->ctx);
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
