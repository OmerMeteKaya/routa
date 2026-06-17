#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/proxy.h"
#include "core/conn.h"
#include "core/event_loop.h"
#include "net/poller.h"
#include "http/request.h"
#include "http/response.h"
#include "http/h2.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* ── Lifecycle ──────────────────────────────────────────────────────────────*/

proxy_ctx_t *proxy_ctx_new(lb_t *lb, struct conn *conn) {
    proxy_ctx_t *ctx = calloc(1, sizeof(proxy_ctx_t));
    if (!ctx) return NULL;
    ctx->magic               = PROXY_CTX_MAGIC;
    ctx->conn                = conn;
    ctx->upstream_fd         = -1;
    ctx->lb                  = lb;
    ctx->pool                = lb_get_pool(lb);
    ctx->resp_content_length = -1;
    ctx->upstream_state      = PROXY_STATE_CONNECTING;
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
    if (!conn) return;
    if (conn->proxy) {
        proxy_ctx_free(conn->proxy);
        conn->proxy = NULL;
    }
    proxy_stream_map_free(conn);
}

/* ── Stream map (H2 per-stream proxy contexts) ──────────────────────────────*/

proxy_ctx_t *proxy_stream_get(conn_t *conn, uint32_t stream_id, lb_t *lb) {
    if (!conn->proxy_map) {
        conn->proxy_map = calloc(1, sizeof(proxy_stream_map_t));
        if (!conn->proxy_map) return NULL;
    }
    proxy_stream_map_t *m = conn->proxy_map;
    for (int i = 0; i < m->count; i++)
        if (m->stream_ids[i] == stream_id) return m->ctxs[i];
    if (m->count >= PROXY_STREAM_MAP_SIZE) return NULL;
    proxy_ctx_t *ctx = proxy_ctx_new(lb, conn);
    if (!ctx) return NULL;
    m->stream_ids[m->count] = stream_id;
    m->ctxs[m->count]       = ctx;
    m->count++;
    return ctx;
}

void proxy_stream_remove(conn_t *conn, uint32_t stream_id) {
    if (!conn->proxy_map) return;
    proxy_stream_map_t *m = conn->proxy_map;
    for (int i = 0; i < m->count; i++) {
        if (m->stream_ids[i] == stream_id) {
            proxy_ctx_free(m->ctxs[i]);
            m->stream_ids[i] = m->stream_ids[m->count - 1];
            m->ctxs[i]       = m->ctxs[m->count - 1];
            m->count--;
            return;
        }
    }
}

void proxy_stream_map_free(conn_t *conn) {
    if (!conn->proxy_map) return;
    proxy_stream_map_t *m = conn->proxy_map;
    for (int i = 0; i < m->count; i++)
        proxy_ctx_free(m->ctxs[i]);
    free(m);
    conn->proxy_map = NULL;
}

/* ── proxy_begin ────────────────────────────────────────────────────────────*/

int proxy_begin(worker_t *w, conn_t *conn, const http_request_t *req,
                uint32_t stream_id) {
    if (!w || !conn || !req || !w->lb) return -1;

    proxy_ctx_t *ctx;

    if (conn->h2 && stream_id > 0) {
        /* H2 path: each stream gets its own proxy_ctx from the per-conn map */
        ctx = proxy_stream_get(conn, stream_id, w->lb);
        if (!ctx) return -1;
        ctx->front_h2        = conn->h2;
        ctx->front_stream_id = stream_id;
    } else {
        /* H1 path: single proxy_ctx reused across keep-alive requests */
        if (!conn->proxy) {
            conn->proxy = proxy_ctx_new(w->lb, conn);
            if (!conn->proxy) {
                http_response_simple(&conn->write_buf, 503,
                                     "Service Unavailable", "text/plain",
                                     "Service Unavailable\n");
                conn_reset_write_state(conn);
                conn->state = CONN_WRITING;
                return 0;
            }
        } else {
            buf_free(&conn->proxy->req_buf);   buf_init(&conn->proxy->req_buf);
            buf_free(&conn->proxy->resp_buf);  buf_init(&conn->proxy->resp_buf);
            conn->proxy->req_sent            = 0;
            conn->proxy->attempt             = 0;
            conn->proxy->resp_head_done      = 0;
            conn->proxy->resp_content_length = -1;
            conn->proxy->front_h2            = NULL;
            conn->proxy->front_stream_id     = 0;
            proxy_drop_upstream(conn->proxy);
        }
        ctx = conn->proxy;
    }

    upstream_node_t *unode = NULL;
    upstream_conn_t *uconn = NULL;
    int ufd = lb_begin_forward(w->lb, req, conn->remote_ip,
                               conn->tls ? "https" : "http",
                               &ctx->req_buf, &unode, &uconn);
    if (ufd < 0) {
        LOG_WARN("proxy: no upstream available for %s", conn->remote_ip);
        if (conn->h2 && stream_id > 0) {
            proxy_stream_remove(conn, stream_id);
            return -1;
        }
        http_response_simple(&conn->write_buf, 502,
                             "Bad Gateway", "text/plain",
                             "Bad Gateway\n");
        conn_reset_write_state(conn);
        conn->state = CONN_WRITING;
        return 0;
    }

    ctx->upstream_fd    = ufd;
    ctx->node           = unode;
    ctx->uconn          = uconn;
    ctx->req_sent       = 0;
    ctx->upstream_state = PROXY_STATE_CONNECTING;

    if (conn->h2 && stream_id > 0) {
        /* H2: register ctx as the poller ptr so the event loop identifies
         * which per-stream context owns the upstream fd event.              */
        struct worker *h2_worker = (struct worker *)conn->h2->worker;
        if (!h2_worker) {
            proxy_ctx_free(ctx);
            proxy_stream_remove(conn, stream_id);
            return -1;
        }
        poller_add(h2_worker->poller, ufd, POLLER_WRITE | POLLER_ET, ctx);
    } else {
        conn->state = CONN_UPSTREAM_CONNECTING;
        poller_add(w->poller, ufd, POLLER_WRITE | POLLER_ET, conn);
    }
    return 0;
}

/* ── proxy_on_upstream_writable ─────────────────────────────────────────────*/

/* Send a 502 error to the frontend. For H2: encodes via H2 on front_stream_id.
 * For H1: serializes into conn->write_buf and sets CONN_WRITING.             */
static void proxy_send_upstream_error(conn_t *conn, proxy_ctx_t *ctx,
                                      int status, const char *reason,
                                      const char *body) {
    if (conn->h2 && ctx->front_h2) {
        http_response_t err;
        http_response_init(&err);
        http_response_set_status(&err, status, reason);
        http_response_set_body(&err, body, strlen(body));
        h2_proxy_send_response(ctx->front_h2, ctx->front_stream_id, &err);
        http_response_destroy(&err);
    } else if (!conn->h2) {
        http_response_simple(&conn->write_buf, status, reason, "text/plain", body);
        conn_reset_write_state(conn);
        conn->state = CONN_WRITING;
    }
}

int proxy_on_upstream_writable(worker_t *w, conn_t *conn, proxy_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->upstream_state == PROXY_STATE_CONNECTING) {
        if (upstream_conn_check_connected(ctx->upstream_fd) < 0) {
            LOG_WARN("proxy: upstream connect failed");
            poller_del(w->poller, ctx->upstream_fd);
            if (ctx->node && ctx->pool)
                upstream_node_record_failure(ctx->node, ctx->pool);
            proxy_drop_upstream(ctx);
            uint32_t sid = ctx->front_stream_id;
            proxy_send_upstream_error(conn, ctx, 502, "Bad Gateway",
                                      "Bad Gateway\n");
            if (conn->h2 && sid) proxy_stream_remove(conn, sid);
            return 0;
        }
        ctx->upstream_state = PROXY_STATE_WRITING;
        if (!conn->h2) conn->state = CONN_UPSTREAM_WRITING;
        if (ctx->node && ctx->pool)
            upstream_node_record_success(ctx->node, ctx->pool);
    }

    if (ctx->upstream_state == PROXY_STATE_WRITING) {
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
                uint32_t sid = ctx->front_stream_id;
                proxy_send_upstream_error(conn, ctx, 502, "Bad Gateway",
                                          "Bad Gateway\n");
                if (conn->h2 && sid) proxy_stream_remove(conn, sid);
                return 0;
            }
            ctx->req_sent += (size_t)n;
        }

        if (ctx->req_sent >= rb->len) {
            ctx->req_sent = 0;
            buf_reset(rb);
            ctx->upstream_state = PROXY_STATE_READING;
            if (!conn->h2) conn->state = CONN_UPSTREAM_READING;
            poller_del(w->poller, ctx->upstream_fd);
            /* H2: keep ctx as ptr so upstream-READ events stay tagged */
            poller_add(w->poller, ctx->upstream_fd,
                       POLLER_READ | POLLER_ET,
                       conn->h2 ? (void *)ctx : (void *)conn);
        }
    }
    return 0;
}

/* ── proxy_on_upstream_readable ─────────────────────────────────────────────*/

int proxy_on_upstream_readable(worker_t *w, conn_t *conn, proxy_ctx_t *ctx) {
    if (!ctx) return -1;

    char tmp[16384];
    ssize_t n = read(ctx->upstream_fd, tmp, sizeof(tmp));

    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        poller_del(w->poller, ctx->upstream_fd);
        if (ctx->node && ctx->pool)
            upstream_node_record_failure(ctx->node, ctx->pool);
        proxy_drop_upstream(ctx);
        uint32_t sid = ctx->front_stream_id;
        proxy_send_upstream_error(conn, ctx, 502, "Bad Gateway",
                                  "Bad Gateway\n");
        if (conn->h2 && sid) proxy_stream_remove(conn, sid);
        return 0;
    }

    if (n < 0) return 0;  /* EAGAIN — wait for more data */

    if (n > 0)
        buf_append(&ctx->resp_buf, tmp, (size_t)n);

    /* Parse Content-Length from headers once */
    if (!ctx->resp_head_done && ctx->resp_buf.len > 0) {
        const char *raw = (const char *)buf_data(&ctx->resp_buf);
        size_t raw_len  = ctx->resp_buf.len;
        const char *hdr_end = memmem(raw, raw_len, "\r\n\r\n", 4);
        if (hdr_end) {
            ctx->resp_head_done = 1;
            const char *cl = strcasestr(raw, "content-length:");
            if (cl && cl < hdr_end) {
                ctx->resp_content_length = strtoll(cl + 15, NULL, 10);
            }
        }
    }

    /* Check if full response received */
    int response_complete = 0;

    if (n == 0) {
        /* EOF — whatever we have is the response */
        response_complete = 1;
    } else if (ctx->resp_head_done && ctx->resp_content_length >= 0) {
        const char *raw = (const char *)buf_data(&ctx->resp_buf);
        const char *hdr_end = memmem(raw, ctx->resp_buf.len, "\r\n\r\n", 4);
        if (hdr_end) {
            size_t hdr_size = (size_t)(hdr_end - raw) + 4;
            size_t body_received = ctx->resp_buf.len - hdr_size;
            if ((long long)body_received >= ctx->resp_content_length)
                response_complete = 1;
        }
    }

    if (!response_complete) return 0; /* wait for more */

    /* Full response received — parse and forward */
    poller_del(w->poller, ctx->upstream_fd);

    int healthy = (ctx->resp_content_length >= 0 && n != 0);

    http_response_t resp;
    http_response_init(&resp);
    int ok = lb_finish_forward(ctx->lb,
                               &ctx->resp_buf, &resp,
                               ctx->node, ctx->uconn, healthy);
    ctx->uconn               = NULL;
    ctx->node                = NULL;
    ctx->upstream_fd         = -1;
    buf_free(&ctx->resp_buf);
    buf_init(&ctx->resp_buf);
    ctx->resp_head_done      = 0;
    ctx->resp_content_length = -1;

    if (ok < 0) {
        http_response_destroy(&resp);
        uint32_t sid = ctx->front_stream_id;
        proxy_send_upstream_error(conn, ctx, 502, "Bad Gateway",
                                  "Bad Gateway\n");
        if (conn->h2 && sid) proxy_stream_remove(conn, sid);
        return 0;
    }

    if (conn->h2 && ctx->front_h2) {
        /* H2 frontend: relay via H2 HEADERS + DATA, then free per-stream ctx */
        uint32_t sid      = ctx->front_stream_id;
        struct h2_conn *fh2 = ctx->front_h2;
        h2_proxy_send_response(fh2, sid, &resp);
        http_response_destroy(&resp);
        proxy_stream_remove(conn, sid);  /* frees ctx — do not touch ctx after */
        h2_conn_flush(fh2);
        /* conn stays CONN_H2; event loop arms POLLER_WRITE if write_buf > 0 */
    } else {
        http_response_set_header(&resp, "Connection",
            conn->keep_alive ? "keep-alive" : "close");
        conn_prepare_writev(conn, &resp);
        http_response_destroy(&resp);
        conn->state = CONN_WRITING;
    }
    return 0;
}