#ifndef ROUTA_NET_IO_H
#define ROUTA_NET_IO_H

#include "util/buf.h"
#include "net/tls.h"
#include "http/response.h"
#include <sys/uio.h>
#include <unistd.h>

/* Read from fd (or TLS) into buf.
 * Returns bytes read, 0 on EAGAIN/EOF, -1 on error. */
ssize_t io_read_into_buf(int fd, buf_t *b, tls_conn_t *tls);

/* Write buf to fd (or TLS), consuming bytes written.
 * Returns bytes written, 0 on EAGAIN, -1 on error. */
ssize_t io_write_from_buf(int fd, buf_t *b, tls_conn_t *tls);

/* ── writev path ────────────────────────────────────────────────────────────
 *
 * Serialize response headers into an internal heap buffer and send headers +
 * body in a single writev(2) syscall (plain) or two tls_write calls (TLS).
 *
 * Behaviour:
 *   - If resp->body != NULL and resp->body_len > 0:
 *       iovec[0] = serialized headers
 *       iovec[1] = resp->body  (zero-copy: no extra malloc)
 *       → single writev() for plain, two tls_write() for TLS
 *   - If resp->body_fd >= 0 (sendfile path):
 *       sends headers only via writev/write; caller must TCP_CORK +
 *       sendfile() the body separately.
 *   - Partial writes are handled: returns total bytes written so far.
 *     Caller should loop until return value == total expected or error.
 *
 * hdr_buf  : caller-supplied scratch buf_t (must be init'd, will be reset).
 * written  : in/out — how many bytes already sent (for partial write resume).
 *
 * Returns bytes written this call, 0 on EAGAIN, -1 on error.             */
ssize_t io_writev_response(int fd, tls_conn_t *tls,
                           const http_response_t *resp,
                           buf_t *hdr_buf,
                           size_t *written);

int io_cork(int fd);
int io_uncork(int fd);

#endif /* ROUTA_NET_IO_H */