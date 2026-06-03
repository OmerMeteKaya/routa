#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "net/io.h"
#include "http/response.h"
#include "util/logger.h"
#include "net/tls.h"
#include <openssl/ssl.h>

#define IO_READ_BUF_SZ 8192

/* ── io_read_into_buf ───────────────────────────────────────────────────────*/
ssize_t io_read_into_buf(int fd, buf_t *b, tls_conn_t *tls) {
    if (!b) return -1;

    if (tls) {
        ssize_t total = 0;
        while (1) {
            /* Ensure space — at least 8KB available */
            size_t avail = b->cap - b->off - b->len;
            if (avail < 8192) {
                /* Compact first */
                if (b->off > 0) {
                    memmove(b->data, b->data + b->off, b->len);
                    b->off = 0;
                    avail = b->cap - b->len;
                }
                if (avail < 8192) {
                    size_t new_cap = b->cap == 0 ? 16384 : b->cap * 2;
                    while (new_cap < b->off + b->len + 8192) new_cap *= 2;
                    uint8_t *nd = realloc(b->data, new_cap);
                    if (!nd) return total > 0 ? total : -1;
                    b->data = nd;
                    b->cap  = new_cap;
                    avail   = b->cap - b->off - b->len;
                }
            }

            /* Read directly into buf — zero extra copy */
            ssize_t n = tls_read(tls,
                                 b->data + b->off + b->len,
                                 avail);
            if (n < 0) return total > 0 ? total : -1;
            if (n == 0) return total > 0 ? total : 0;
            b->len += (size_t)n;
            total  += n;
            if (SSL_pending(tls->ssl) == 0) break;
        }
        return total;
    } else {
        /* Plain fd — same approach */
        size_t avail = b->cap - b->off - b->len;
        if (avail < 8192) {
            if (b->off > 0) {
                memmove(b->data, b->data + b->off, b->len);
                b->off = 0;
                avail  = b->cap - b->len;
            }
            if (avail < 8192) {
                size_t new_cap = b->cap == 0 ? 16384 : b->cap * 2;
                while (new_cap < b->off + b->len + 8192) new_cap *= 2;
                uint8_t *nd = realloc(b->data, new_cap);
                if (!nd) return -1;
                b->data = nd;
                b->cap  = new_cap;
            }
        }
        ssize_t n = read(fd,
                         b->data + b->off + b->len,
                         b->cap - b->off - b->len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            return -1;
        }
        if (n == 0) return 0;
        b->len += (size_t)n;
        return n;
    }
}

/* ── io_write_from_buf ──────────────────────────────────────────────────────*/
ssize_t io_write_from_buf(int fd, buf_t *b, tls_conn_t *tls) {
    if (!b || b->len == 0) return 0;

    ssize_t total = 0;

    if (tls) {
        while (b->len > 0) {
            ssize_t n = tls_write(tls, b->data, b->len);
            if (n < 0) return total > 0 ? total : 0;
            if (n == 0) break;
            buf_consume(b, (size_t)n);
            total += n;
        }
        return total;
    } else {
        while (b->len > 0) {
            ssize_t n = write(fd, b->data, b->len);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return total > 0 ? total : 0;
                LOG_ERROR("io_write: %s", strerror(errno));
                return -1;
            }
            if (n == 0) break;
            buf_consume(b, (size_t)n);
            total += n;
        }
        return total;
    }
}
/* ── Header serialization (headers only, no body) ───────────────────────────
 * Writes status line + headers + "\r\n" into hdr_buf.
 * Does NOT include body — caller appends body via iovec or sendfile.       */
static int serialize_headers_only(const http_response_t *r, buf_t *hdr_buf) {
    /* Date */
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char date_str[64];
    (void)strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);

    /* Presence flags */
    int has_date = 0, has_server = 0, has_connection = 0;
    int has_transfer_encoding = 0;
    for (int i = 0; i < r->header_count; i++) {
        const char *k = r->headers[i][0];
        if (!k) continue;
        if (strcasecmp(k, "Date") == 0)              has_date = 1;
        else if (strcasecmp(k, "Server") == 0)       has_server = 1;
        else if (strcasecmp(k, "Connection") == 0)   has_connection = 1;
        else if (strcasecmp(k, "Transfer-Encoding") == 0) has_transfer_encoding = 1;
    }

    /* Status line */
    char sl[256];
    int sl_len = snprintf(sl, sizeof(sl), "HTTP/1.1 %d %s\r\n",
                          r->status, r->reason ? r->reason : "OK");
    if (buf_append(hdr_buf, sl, (size_t)sl_len) < 0) return -1;

    /* Required headers */
    if (!has_date) {
        char dh[80];
        int dl = snprintf(dh, sizeof(dh), "Date: %s\r\n", date_str);
        if (buf_append(hdr_buf, dh, (size_t)dl) < 0) return -1;
    }
    if (!has_server)
        if (buf_append(hdr_buf, "Server: routa/0.1\r\n", 19) < 0) return -1;
    if (!has_connection)
        if (buf_append(hdr_buf, "Connection: close\r\n", 19) < 0) return -1;
    if (r->chunked && !has_transfer_encoding)
        if (buf_append(hdr_buf, "Transfer-Encoding: chunked\r\n", 28) < 0) return -1;

    /* Caller-set headers */
    for (int i = 0; i < r->header_count; i++) {
        if (!r->headers[i][0] || !r->headers[i][1]) continue;
        if (r->chunked &&
            strcasecmp(r->headers[i][0], "Content-Length") == 0) continue;
        char hl[512];
        int hl_len = snprintf(hl, sizeof(hl), "%s: %s\r\n",
                              r->headers[i][0], r->headers[i][1]);
        if (buf_append(hdr_buf, hl, (size_t)hl_len) < 0) return -1;
    }

    /* End of headers */
    return buf_append(hdr_buf, "\r\n", 2);
}

/* ── io_writev_response ─────────────────────────────────────────────────────*/
ssize_t io_writev_response(int fd, tls_conn_t *tls,
                           const http_response_t *resp,
                           buf_t *hdr_buf,
                           size_t *written)
{
    /* hdr_buf must already be populated by conn_prepare_writev */
    if (hdr_buf->len == 0) return -1;

    size_t hdr_len  = hdr_buf->len;
    size_t body_len = (resp->body && resp->body_len > 0) ? resp->body_len : 0;
    size_t total    = hdr_len + body_len;

    if (*written >= total) return 0;

    size_t remaining = total - *written;

    /* ── TLS path: two sequential writes ── */
    if (tls) {
        ssize_t n = 0;

        /* Headers portion */
        if (*written < hdr_len) {
            size_t hdr_off  = *written;
            size_t hdr_rem  = hdr_len - hdr_off;
            n = tls_write(tls,
                          (const char *)hdr_buf->data + hdr_off,
                          hdr_rem);
            if (n < 0) return 0;   /* want-read/write */
            *written += (size_t)n;
            if ((size_t)n < hdr_rem) return n;   /* partial */
        }

        /* Body portion */
        if (body_len > 0 && *written >= hdr_len) {
            size_t body_off = *written - hdr_len;
            size_t body_rem = body_len - body_off;
            n = tls_write(tls,
                          (const char *)resp->body + body_off,
                          body_rem);
            if (n < 0) return 0;
            *written += (size_t)n;
            return n;
        }
        return 0;
    }

    /* ── Plain path: writev ── */
    if (body_len > 0) {
        /* Two iovec: headers + body */
        size_t hdr_off  = (*written < hdr_len) ? *written : hdr_len;
        size_t body_off = (*written > hdr_len) ? (*written - hdr_len) : 0;

        struct iovec iov[2];
        int    iovcnt = 0;

        if (hdr_off < hdr_len) {
            iov[iovcnt].iov_base = (char *)hdr_buf->data + hdr_off;
            iov[iovcnt].iov_len  = hdr_len - hdr_off;
            iovcnt++;
        }
        if (body_off < body_len) {
            iov[iovcnt].iov_base = (char *)resp->body + body_off;
            iov[iovcnt].iov_len  = body_len - body_off;
            iovcnt++;
        }

        if (iovcnt == 0) return 0;

        ssize_t n = writev(fd, iov, iovcnt);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            LOG_ERROR("io_writev: %s", strerror(errno));
            return -1;
        }
        *written += (size_t)n;
        return n;
    }

    /* Headers only (body_fd case or empty body) */
    if (*written < hdr_len) {
        size_t off = *written;
        ssize_t n = write(fd,
                          (const char *)hdr_buf->data + off,
                          hdr_len - off);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            LOG_ERROR("io_write_hdr: %s", strerror(errno));
            return -1;
        }
        *written += (size_t)n;
        return n;
    }

    (void)remaining;
    return 0;
}

/* ── TCP_CORK / TCP_NOPUSH ──────────────────────────────────────────────────*/
int io_cork(int fd) {
    int v = 1;
#if defined(__linux__)
    return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &v, sizeof(v));
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    return setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &v, sizeof(v));
#else
    (void)fd; (void)v; return 0;
#endif
}

int io_uncork(int fd) {
    int v = 0;
#if defined(__linux__)
    return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &v, sizeof(v));
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    return setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &v, sizeof(v));
#else
    (void)fd; (void)v; return 0;
#endif
}