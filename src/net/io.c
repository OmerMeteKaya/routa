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
            /* Ensure space — at least 8KB available after current data     */
            size_t avail = b->cap - b->off - b->len;
            if (avail < 8192) {
                /* Compact: move data to front of buffer, reset offset      */
                if (b->off > 0) {
                    memmove(b->data, b->data + b->off, b->len);
                    b->off = 0;
                    avail  = b->cap - b->len;
                }
                if (avail < 8192) {
                    size_t new_cap = b->cap == 0 ? 16384 : b->cap * 2;
                    while (new_cap < b->len + 8192) new_cap *= 2;
                    uint8_t *nd = realloc(b->data, new_cap);
                    if (!nd) return total > 0 ? total : -1;
                    b->data = nd;
                    b->cap  = new_cap;
                    avail   = b->cap - b->len;  /* b->off == 0 here         */
                }
            }

            /* Read directly into buf — zero extra copy                     */
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
        /* ROOT CAUSE FIX: the plaintext path previously did exactly ONE
         * read() call and returned, unlike the TLS branch above (which
         * correctly loops until EAGAIN/SSL_pending()==0). Under
         * edge-triggered epoll (EPOLLET, used throughout this codebase),
         * a readable edge fires ONCE when data becomes available -- if
         * more data remains in the kernel socket buffer than a single
         * read() drains, epoll will NOT fire again for this fd until NEW
         * data arrives, because from the kernel's perspective nothing
         * "changed" (the fd was already readable and still is). Any
         * message/payload larger than one read() worth (in practice,
         * anything exceeding the buffer's available capacity per call,
         * confirmed at ~16KB in testing) would have its remainder
         * silently stuck in the kernel buffer forever, with the
         * application-level protocol parser (e.g. ws_recv()'s payload
         * accumulation) waiting for bytes that would never be delivered
         * -- observed as a WebSocket binary/text message over 16KB never
         * completing (on_message() never fired), despite the client
         * successfully sending all the bytes and the connection
         * remaining technically alive. This affects every plaintext
         * (non-TLS) connection: HTTP/1.1 request bodies, WebSocket
         * frames, h2c -- not just WS, though WS's per-message framing
         * made the symptom easiest to reproduce and diagnose. */
        /* saw_eof distinguishes "read a real 0-byte EOF from the peer"
         * (connection genuinely closed) from "drained everything
         * available and hit EAGAIN" (connection alive, just no more data
         * right now) -- both end the loop, but callers rely on this
         * function's return value to tell them apart: 0 means "closed,
         * tear down the connection", -1 means "EAGAIN, nothing wrong,
         * just wait for the next readable event". A prior version of
         * this fix conflated the two by returning `total > 0 ? total : 0`
         * on EAGAIN with zero bytes read this call, which callers (e.g.
         * handle_ws_read's caller in event_loop.c) interpreted as EOF and
         * incorrectly tore down perfectly healthy WebSocket connections
         * the moment a read happened to return EAGAIN before any new
         * data had arrived (very reproducible: any message spanning
         * multiple TCP segments would trigger this on the follow-up
         * read()). */
        ssize_t total = 0;
        int saw_eof = 0;
        while (1) {
            size_t avail = b->cap - b->off - b->len;
            if (avail < 8192) {
                /* Compact: move data to front of buffer, reset offset      */
                if (b->off > 0) {
                    memmove(b->data, b->data + b->off, b->len);
                    b->off = 0;
                    avail  = b->cap - b->len;
                }
                if (avail < 8192) {
                    size_t new_cap = b->cap == 0 ? 16384 : b->cap * 2;
                    while (new_cap < b->len + 8192) new_cap *= 2;
                    uint8_t *nd = realloc(b->data, new_cap);
                    if (!nd) return total > 0 ? total : -1;
                    b->data = nd;
                    b->cap  = new_cap;
                    avail   = b->cap - b->len;  /* b->off == 0 here         */
                }
            }
            ssize_t n = read(fd,
                             b->data + b->off + b->len,
                             avail);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                return total > 0 ? total : -1;
            }
            if (n == 0) { saw_eof = 1; break; }
            b->len += (size_t)n;
            total  += n;
            /* A short read (less than requested) on a non-blocking
             * socket usually means the kernel buffer is drained for now
             * -- but isn't a hard guarantee, so we still rely on EAGAIN
             * above to actually stop. This mirrors the TLS branch's
             * SSL_pending() check in spirit: keep pulling until the
             * kernel says there's genuinely nothing left. */
        }
        if (saw_eof) return total;         /* 0 if nothing was read before EOF, else the partial total -- either way, caller sees EOF via a subsequent 0-byte call if total>0 leaves data to process first */
        if (total == 0) return -1;         /* EAGAIN with nothing read this call -- NOT EOF */
        return total;
    }
}

/* ── io_write_from_buf ──────────────────────────────────────────────────────*/
ssize_t io_write_from_buf(int fd, buf_t *b, tls_conn_t *tls) {
    if (!b || b->len == 0) return 0;
    ssize_t total = 0;

    if (tls) {
        while (b->len > 0) {
            ssize_t n = tls_write(tls, buf_data(b), b->len);
            if (n < 0) return total > 0 ? total : 0;
            if (n == 0) break;
            buf_consume(b, (size_t)n);
            total += n;
        }
        return total;
    } else {
        while (b->len > 0) {
            ssize_t n = write(fd, buf_data(b), b->len);
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
                          (const char *)buf_data(hdr_buf) + hdr_off,
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
            iov[iovcnt].iov_base = (char *)buf_data(hdr_buf) + hdr_off;
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
                          (const char *)buf_data(hdr_buf) + off,
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