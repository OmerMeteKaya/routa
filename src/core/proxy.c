#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/proxy.h"
#include "core/conn.h"
#include "core/event_loop.h"
#include "net/poller.h"
#include "http/request.h"
#include "http/response.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* ── Lifecycle ──────────────────────────────────────────────────────────────*/

proxy_ctx_t *proxy_ctx_new(lb_t *lb) {
    proxy_ctx_t *ctx = calloc(1, sizeof(proxy_ctx_t));
    if (!ctx) return NULL;
    ctx->upstream_fd = -1;
    ctx->lb          = lb;
    ctx->pool        = lb_get_pool(lb);
    buf_init(&ctx->req_buf);
    buf_init(&ctx->resp_buf);
    return ctx;
}

/* Drop the upstream connection, closing the fd exactly once.
 * When uconn exists it owns the fd: upstream_conn_release(.., 0) closes it
 * and fixes pool accounting. Only close directly when there is no uconn. */
static void proxy_drop_upstream(proxy_ctx_t *ctx) {
    if (ctx->uconn) {
        upstream_conn_release(ctx->uconn, 0);
        ctx->uconn = NULL;
    } else if (ctx->upstream_fd >= 0) {
        close(ctx->upstream_fd);
    }
    ctx->upstream_fd = -1;
}

void proxy_ctx_free(proxy_ctx_t *ctx) {
    if (!ctx) return;
    proxy_drop_upstream(ctx);
    buf_free(&ctx->req_buf);
    buf_free(&ctx->resp_buf);
    free(ctx);
}

void proxy_conn_cleanup(conn_t *conn) {
    if (!conn || !conn->proxy) return;
    proxy_ctx_free(conn->proxy);
    conn->proxy = NULL;
}

/* ── proxy_begin ────────────────────────────────────────────────────────────*/

int proxy_begin(worker_t *w, conn_t *conn, const http_request_t *req) {
    if (!w || !conn || !req || !w->lb) return -1;

    if (!conn->proxy) {
        conn->proxy = proxy_ctx_new(w->lb);
        if (!conn->proxy) {
            http_response_simple(&conn->write_buf, 503,
                                 "Service Unavailable", "text/plain",
                                 "Service Unavailable\n");
            conn_reset_write_state(conn);
            conn->state = CONN_WRITING;
            return 0;
        }
    } else {
        buf_reset(&conn->proxy->req_buf);
        buf_reset(&conn->proxy->resp_buf);
        conn->proxy->req_sent = 0;
        conn->proxy->attempt  = 0;
        proxy_drop_upstream(conn->proxy);
    }

    proxy_ctx_t *ctx = conn->proxy;

    upstream_node_t *unode = NULL;
    upstream_conn_t *uconn = NULL;
    int ufd = lb_begin_forward(w->lb, req, conn->remote_ip,
                               conn->tls ? "https" : "http",
                               &ctx->req_buf, &unode, &uconn);
    if (ufd < 0) {
        LOG_WARN("proxy: no upstream available for %s", conn->remote_ip);
        http_response_simple(&conn->write_buf, 502,
                             "Bad Gateway", "text/plain",
                             "Bad Gateway\n");
        conn_reset_write_state(conn);
        conn->state = CONN_WRITING;
        return 0;
    }

    ctx->upstream_fd = ufd;
    ctx->node        = unode;
    ctx->uconn       = uconn;
    ctx->req_sent    = 0;

    conn->state = CONN_UPSTREAM_CONNECTING;
    poller_add(w->poller, ufd, POLLER_WRITE | POLLER_ET, conn);
    return 0;
}

/* ── proxy_on_upstream_writable ─────────────────────────────────────────────*/

int proxy_on_upstream_writable(worker_t *w, conn_t *conn) {
    proxy_ctx_t *ctx = conn->proxy;
    if (!ctx) return -1;

    if (conn->state == CONN_UPSTREAM_CONNECTING) {
        if (upstream_conn_check_connected(ctx->upstream_fd) < 0) {
            /* Genuine connect failure (SO_ERROR set) — the only place a
             * connect attempt may count against passive health. */
            LOG_WARN("proxy: upstream connect failed");
            poller_del(w->poller, ctx->upstream_fd);
            if (ctx->node && ctx->pool)
                upstream_node_record_failure(ctx->node, ctx->pool);
            proxy_drop_upstream(ctx);
            http_response_simple(&conn->write_buf, 502,
                                 "Bad Gateway", "text/plain",
                                 "Bad Gateway\n");
            conn_reset_write_state(conn);
            conn->state = CONN_WRITING;
            return 0;
        }
        conn->state = CONN_UPSTREAM_WRITING;
        if (ctx->node && ctx->pool)
            upstream_node_record_success(ctx->node, ctx->pool);
    }

    if (conn->state == CONN_UPSTREAM_WRITING) {
        buf_t  *rb  = &ctx->req_buf;
        size_t  rem = rb->len - ctx->req_sent;

        if (rem > 0) {
            ssize_t n = write(ctx->upstream_fd,
                              buf_data(rb) + ctx->req_sent, rem);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
                LOG_WARN("proxy: upstream write failed: %s", strerror(errno));
                poller_del(w->poller, ctx->upstream_fd);
                proxy_drop_upstream(ctx);
                http_response_simple(&conn->write_buf, 502,
                                     "Bad Gateway", "text/plain",
                                     "Bad Gateway\n");
                conn_reset_write_state(conn);
                conn->state = CONN_WRITING;
                return 0;
            }
            ctx->req_sent += (size_t)n;
        }

        if (ctx->req_sent >= rb->len) {
            ctx->req_sent = 0;
            buf_reset(rb);
            conn->state = CONN_UPSTREAM_READING;
            poller_del(w->poller, ctx->upstream_fd);
            poller_add(w->poller, ctx->upstream_fd,
                       POLLER_READ | POLLER_ET, conn);
        }
    }
    return 0;
}

/* ── proxy_on_upstream_readable ─────────────────────────────────────────────*/

int proxy_on_upstream_readable(worker_t *w, conn_t *conn) {
    proxy_ctx_t *ctx = conn->proxy;
    if (!ctx) return -1;

    char tmp[16384];
    ssize_t n = read(ctx->upstream_fd, tmp, sizeof(tmp));

    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        poller_del(w->poller, ctx->upstream_fd);
        if (ctx->node && ctx->pool)
            upstream_node_record_failure(ctx->node, ctx->pool);
        proxy_drop_upstream(ctx);
        http_response_simple(&conn->write_buf, 502,
                             "Bad Gateway", "text/plain",
                             "Bad Gateway\n");
        conn_reset_write_state(conn);
        conn->state = CONN_WRITING;
        return 0;
    }

    if (n > 0)
        buf_append(&ctx->resp_buf, tmp, (size_t)n);

    if (n == 0) {
        /* EOF — upstream closed connection, parse whatever we have */
        poller_del(w->poller, ctx->upstream_fd);

        if (ctx->resp_buf.len == 0) {
            /* No data at all — upstream closed without response */
            if (ctx->node && ctx->pool)
                upstream_node_record_failure(ctx->node, ctx->pool);
            proxy_drop_upstream(ctx);
            http_response_simple(&conn->write_buf, 502,
                                 "Bad Gateway", "text/plain",
                                 "Bad Gateway\n");
            conn_reset_write_state(conn);
            conn->state = CONN_WRITING;
            return 0;
        }

        /* Parse accumulated response.  healthy=0: the request was sent with
         * "Connection: close" and the upstream already half-closed, so the
         * conn must never go back to the idle pool.  lb_finish_forward owns
         * the fd from here (release closes it) and records success/failure
         * itself — no duplicate record_* calls in this path. */
        http_response_t resp;
        http_response_init(&resp);
        int ok = lb_finish_forward(ctx->lb,
                                   &ctx->resp_buf, &resp,
                                   ctx->node, ctx->uconn, 0);
        ctx->uconn       = NULL;
        ctx->node        = NULL;
        ctx->upstream_fd = -1;
        buf_reset(&ctx->resp_buf);

        if (ok < 0) {
            http_response_destroy(&resp);
            http_response_simple(&conn->write_buf, 502,
                                 "Bad Gateway", "text/plain",
                                 "Bad Gateway\n");
            conn_reset_write_state(conn);
        } else {
            http_response_set_header(&resp, "Connection",
                conn->keep_alive ? "keep-alive" : "close");
            conn_prepare_writev(conn, &resp);
            http_response_destroy(&resp);
        }
        conn->state = CONN_WRITING;
        return 0;
    }

    /* EAGAIN or partial data — more coming, keep waiting */
    return 0;
}