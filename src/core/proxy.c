#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/proxy.h"
#include "core/conn.h"
#include "core/event_loop.h"
#include "net/poller.h"
#include "net/h2_client.h"
#include "http/request.h"
#include "http/response.h"
#include "http/h2.h"
#include "lb/lb.h"
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
 * For H2 upstream (up_h2up != NULL): just remove the stream slot — the
 * shared h2up conn is owned by the worker, not this ctx.
 * For H1: upstream_conn_release closes via pool accounting, or direct close. */
static void proxy_drop_upstream(proxy_ctx_t *ctx) {
    if (ctx->up_h2up) {
        /* H2 upstream: detach this ctx from its stream slot so the
         * upstream connection's pending I/O never touches a freed ctx. */
        h2up_stream_remove(ctx->up_h2up, ctx->up_stream_id);
        ctx->up_h2up      = NULL;
        ctx->up_stream_id = 0;
    }
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
        conn->proxy_map->cap = 16;
        conn->proxy_map->stream_ids = calloc(16, sizeof(uint32_t));
        conn->proxy_map->ctxs       = calloc(16, sizeof(proxy_ctx_t *));
        if (!conn->proxy_map->stream_ids || !conn->proxy_map->ctxs) {
            free(conn->proxy_map->stream_ids);
            free(conn->proxy_map->ctxs);
            free(conn->proxy_map);
            conn->proxy_map = NULL;
            return NULL;
        }
    }
    proxy_stream_map_t *m = conn->proxy_map;

    /* existing stream */
    for (int i = 0; i < m->count; i++)
        if (m->stream_ids[i] == stream_id) return m->ctxs[i];

    /* grow if needed */
    if (m->count >= m->cap) {
        int new_cap = m->cap * 2;
        uint32_t    *new_ids  = realloc(m->stream_ids,
                                        (size_t)new_cap * sizeof(uint32_t));
        proxy_ctx_t **new_ctxs = realloc(m->ctxs,
                                         (size_t)new_cap * sizeof(proxy_ctx_t *));
        if (!new_ids || !new_ctxs) {
            free(new_ids);
            free(new_ctxs);
            return NULL;
        }
        m->stream_ids = new_ids;
        m->ctxs       = new_ctxs;
        m->cap        = new_cap;
    }

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
    free(m->stream_ids);
    free(m->ctxs);
    free(m);
    conn->proxy_map = NULL;
}

/* ── H2 upstream acquire ────────────────────────────────────────────────────*/

/* Find or create an h2up_conn_t for node on this worker.
 * Searches the per-worker pool first; creates a new (blocking) conn if needed.
 * Returns NULL on failure (node unreachable or H2 not negotiated). */
static h2up_conn_t *h2up_acquire_for_node(worker_t *w, upstream_node_t *node)
{
    for (int i = 0; i < w->h2up_count; i++) {
        h2up_conn_t *h = w->h2up_conns[i];
        if (h->node == node && h2up_has_capacity(h))
            return h;
    }

    h2up_conn_t *h = h2up_conn_create(node);
    if (!h) return NULL;
    h->worker = w;

    if (w->h2up_count >= w->h2up_cap) {
        int nc = w->h2up_cap ? w->h2up_cap * 2 : 4;
        h2up_conn_t **tmp = realloc(w->h2up_conns, (size_t)nc * sizeof(*tmp));
        if (!tmp) { h2up_conn_free(h); return NULL; }
        w->h2up_conns = tmp;
        w->h2up_cap   = nc;
    }
    w->h2up_conns[w->h2up_count++] = h;
    poller_add(w->poller, h->fd, POLLER_READ | POLLER_ET, h);
    return h;
}

/* ── proxy_begin ────────────────────────────────────────────────────────────*/

int proxy_begin(worker_t *w, conn_t *conn, const http_request_t *req,
                uint32_t stream_id) {
    if (!w || !conn || !req || !w->lb) {
        LOG_WARN("proxy_begin: null check failed w=%p conn=%p req=%p lb=%p",
                 (void*)w, (void*)conn, (void*)req, w ? (void*)w->lb : NULL);
        return -1;
    }

    proxy_ctx_t *ctx;

    if (conn->h2 && stream_id > 0) {
        /* H2 path: each stream gets its own proxy_ctx from the per-conn map */
        ctx = proxy_stream_get(conn, stream_id, w->lb);
        if (!ctx) {
            LOG_WARN("proxy_begin: proxy_stream_get failed stream_id=%u map_count=%d",
                    stream_id,
                    conn->proxy_map ? conn->proxy_map->count : -1);
            return -1;
        }
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
            conn->proxy->resp_chunked        = 0;
            conn->proxy->front_h2            = NULL;
            conn->proxy->front_stream_id     = 0;
            proxy_drop_upstream(conn->proxy);
        }
        ctx = conn->proxy;
    }

    /* ── H2 upstream path ────────────────────────────────────────────────── */
    if (w->lb && lb_is_tls_upstream(w->lb)) {
        upstream_node_t *unode = lb_pick_node(w->lb, conn->remote_ip);
        if (!unode) {
            LOG_WARN("proxy: no H2 upstream node for %s", conn->remote_ip);
            goto upstream_error;
        }

        h2up_conn_t *h2up = h2up_acquire_for_node(w, unode);
        if (!h2up) {
            LOG_WARN("proxy: failed to acquire H2 upstream to %s:%d",
                     unode->host, unode->port);
            goto upstream_error;
        }

        const char *proto = conn->tls ? "https" : "http";
        int sid = h2up_begin_stream(h2up, ctx, req, conn->remote_ip, proto);
        if (sid < 0) {
            LOG_WARN("proxy: h2up_begin_stream failed (capacity=%d count=%d)",
                     h2up_has_capacity(h2up), h2up->stream_count);
            goto upstream_error;
        }

        ctx->up_h2up      = h2up;
        ctx->up_stream_id = (uint32_t)sid;
        ctx->node         = unode;
        ctx->upstream_fd  = -1;

        /* Arm h2up fd for write — we just queued frames in write_buf */
        poller_mod(w->poller, h2up->fd,
                   POLLER_READ | POLLER_WRITE | POLLER_ET, h2up);
        return 0;
    }

    /* ── H1 upstream path ────────────────────────────────────────────────── */
    {
    upstream_node_t *unode = NULL;
    upstream_conn_t *uconn = NULL;
    int ufd = lb_begin_forward(w->lb, req, conn->remote_ip,
                               conn->tls ? "https" : "http",
                               &ctx->req_buf, &unode, &uconn);
    if (ufd < 0 && ctx->attempt == 0) {
        ctx->attempt = 1;
        buf_reset(&ctx->req_buf);
        ufd = lb_begin_forward(w->lb, req, conn->remote_ip,
                               conn->tls ? "https" : "http",
                               &ctx->req_buf, &unode, &uconn);
    }
    if (ufd < 0) {
        LOG_WARN("proxy: no upstream available for %s", conn->remote_ip);
        goto upstream_error;
    }

    ctx->upstream_fd    = ufd;
    ctx->node           = unode;
    ctx->uconn          = uconn;
    ctx->req_sent       = 0;
    ctx->upstream_state = (uconn && uconn->requests > 0)
                      ? PROXY_STATE_WRITING
                      : PROXY_STATE_CONNECTING;

    if (conn->h2 && stream_id > 0) {
        /* H2 frontend: register ctx as the poller ptr */
        struct worker *h2_worker = (struct worker *)conn->h2->worker;
        if (!h2_worker) {
            LOG_WARN("proxy_begin: h2_worker is NULL stream_id=%u", stream_id);
            proxy_ctx_free(ctx);
            proxy_stream_remove(conn, stream_id);
            return -1;
        }
        poller_add(h2_worker->poller, ufd, POLLER_WRITE | POLLER_ET, ctx);
        /* Eager write: ONLY for pooled (idle) connections, which are
         * already connected and typically already writable RIGHT NOW.
         * With EPOLLET, adding interest in an fd already in the ready
         * state is not guaranteed to generate a fresh edge. Restricted to
         * PROXY_STATE_WRITING (pooled) — a fresh PROXY_STATE_CONNECTING
         * socket hasn't completed its handshake yet, and calling
         * check_connected()/attempting a write before the real POLLER_WRITE
         * edge for that case is unnecessary (fresh connects reliably
         * deliver their first edge) and risks racing the connect(). */
        if (ctx->upstream_state == PROXY_STATE_WRITING)
            proxy_on_upstream_writable(h2_worker, conn, ctx);
    } else {
        conn->state = CONN_UPSTREAM_CONNECTING;
        poller_add(w->poller, ufd, POLLER_WRITE | POLLER_ET, conn);
        /* Same eager-write rationale as the H2 branch above, for the H1
         * frontend path. */
        if (ctx->upstream_state == PROXY_STATE_WRITING)
            proxy_on_upstream_writable(w, conn, ctx);
    }
    return 0;
    } /* H1 block */

upstream_error:
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

    /* Parse response headers once (bounded within the header section) */
    if (!ctx->resp_head_done && ctx->resp_buf.len > 0) {
        const char *raw = (const char *)buf_data(&ctx->resp_buf);
        size_t raw_len  = ctx->resp_buf.len;
        const char *hdr_end = memmem(raw, raw_len, "\r\n\r\n", 4);
        if (hdr_end) {
            ctx->resp_head_done = 1;
            /* Scan headers line by line without reading past hdr_end */
            const char *p = memchr(raw, '\n', (size_t)(hdr_end - raw));
            if (p) p++;   /* skip status line */
            while (p && p < hdr_end) {
                /* Include the terminator's own \r\n bytes in the search
                 * window — otherwise the last header before the blank line
                 * (its \r\n lives at [hdr_end, hdr_end+2), just outside the
                 * old [p, hdr_end) window) is silently dropped. If that
                 * header happens to be Content-Length, resp_content_length
                 * stays -1 forever and the connection hangs indefinitely
                 * waiting for a "complete" response that already arrived. */
                const char *eol = memmem(p, (size_t)(hdr_end + 2 - p), "\r\n", 2);
                if (!eol || eol == p) break;
                const char *col = memchr(p, ':', (size_t)(eol - p));
                if (col) {
                    size_t klen = (size_t)(col - p);
                    const char *val = col + 1;
                    while (val < eol && *val == ' ') val++;
                    if (klen == 14 && strncasecmp(p, "content-length", 14) == 0)
                        ctx->resp_content_length = strtoll(val, NULL, 10);
                    else if (klen == 17 &&
                             strncasecmp(p, "transfer-encoding", 17) == 0 &&
                             strncasecmp(val, "chunked", 7) == 0)
                        ctx->resp_chunked = 1;
                }
                p = eol + 2;
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
    } else if (ctx->resp_head_done && ctx->resp_chunked) {
        /* Chunked: complete when terminal chunk 0\r\n\r\n is present */
        const char *raw = (const char *)buf_data(&ctx->resp_buf);
        const char *hdr_end = memmem(raw, ctx->resp_buf.len, "\r\n\r\n", 4);
        if (hdr_end) {
            const char *body_start = hdr_end + 4;
            size_t body_len = (size_t)(raw + ctx->resp_buf.len - body_start);
            if (body_len > 0 && memmem(body_start, body_len, "0\r\n\r\n", 5))
                response_complete = 1;
        }
    }

    if (!response_complete) return 0; /* wait for more */

    /* Full response received — parse and forward */
    poller_del(w->poller, ctx->upstream_fd);

    int healthy = ((ctx->resp_content_length >= 0 || ctx->resp_chunked) && n != 0);

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