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
#include "util/metrics.h"
#include "http/cookie.h"
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
    ctx->last_upstream_io_ms = routa_now_ms();
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
    if (ctx->has_retry_req) {
        http_request_free(&ctx->retry_req);
        ctx->has_retry_req = 0;
    }
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
/* BUG FIX (H2/TLS concurrency cold-start): now takes ctx/client_ip/proto
 * so that a request landing on a connection that's already establishing
 * (not READY yet, but not dead either) can be QUEUED as a waiter on
 * that connection instead of being told "no capacity" and either
 * 502ing or spinning up a redundant duplicate connection to the same
 * node. See h2up_conn_t's waiters[] field doc comment in h2_client.h
 * for the full rationale and h2up_flush_waiters()/h2up_fail_waiters()
 * for how queued requests get resolved once establishment finishes one
 * way or another.
 *
 * Return value contract (CHANGED from before):
 *   non-NULL            -- a READY connection, use it immediately
 *                           (same as before)
 *   NULL, *out_queued=1  -- no READY connection exists, but this
 *                           request was successfully queued on one
 *                           that's still establishing; caller must NOT
 *                           502 or retry, the response will be
 *                           produced asynchronously once that
 *                           connection resolves
 *   NULL, *out_queued=0  -- no READY connection, nothing to queue on
 *                           either (pool truly has no live/establishing
 *                           connection to this node, or the queue was
 *                           full) -- caller retries a different node or
 *                           gives up, exactly like the old NULL
 *                           contract
 */
static h2up_conn_t *h2up_acquire_for_node(worker_t *w, upstream_node_t *node)
{
    for (int i = 0; i < w->h2up_count; i++) {
        h2up_conn_t *h = w->h2up_conns[i];
        /* h2up_has_capacity() now also requires async_state == READY
         * (see its updated doc comment in h2_client.c) -- a connection
         * still being established is skipped here, exactly like a full
         * connection would be, rather than made callers wait on it. */
        if (h->node == node && h2up_has_capacity(h))
            return h;
    }
    /* BUG FIX (H2/TLS failover): h2up_conn_create_async(), not the old
     * blocking h2up_conn_create() -- see h2up_async_state_t's doc
     * comment in h2_client.h for the full root-cause writeup of why the
     * old blocking version froze this worker thread (and every other
     * in-flight request on it) whenever the target node was slow or
     * dead. The returned connection is NOT ready to use yet -- it's
     * registered in the pool and driven forward via h2up_conn_advance()
     * on subsequent poller events (see event_loop.c's h2up dispatch),
     * but THIS caller gets NULL here regardless of whether the new
     * connection succeeds or fails, exactly as if no capacity existed
     * (matches nginx's own upstream-H2 behavior of opening a fresh
     * connection per request rather than making callers wait on one
     * still being established -- see nginx/nginx#1066). The request
     * that triggered this new connection attempt falls through to the
     * normal upstream-error/retry path below in proxy_begin(); it's a
     * LATER request to the same node that benefits from this connection
     * once it reaches READY. */
    h2up_conn_t *h = h2up_conn_create_async(node);
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
    /* BUG FIX (H2/TLS failover, async establishment): watch BOTH
     * POLLER_READ and POLLER_WRITE, not just POLLER_WRITE. A
     * non-blocking connect() only ever needs a writable event to detect
     * completion, but TLS_do_handshake() -- the very next state --
     * can request EITHER direction depending on which leg of the TLS
     * handshake it's waiting on (SSL_ERROR_WANT_READ vs WANT_WRITE).
     * Watching only POLLER_WRITE meant a handshake that hit WANT_READ
     * never got a poller event again (the peer's response sat readable
     * on the socket, but nothing told epoll we cared), so the
     * connection stalled forever in H2UP_ASYNC_TLS_HANDSHAKE -- this
     * was the actual root cause of most pre-warmed/newly-acquired H2
     * connections never reaching READY, discovered via instrumentation
     * showing dozens of connections stuck at "entering state=1"
     * (TLS_HANDSHAKE) with no further progress. */
    poller_add(w->poller, h->fd, POLLER_READ | POLLER_WRITE | POLLER_ET, h);
    /* Immediately attempt to advance -- on loopback or an already-
     * writable socket this can complete the ENTIRE connect+handshake+
     * preface+settings sequence right here without waiting for a
     * separate poller event (see h2up_conn_advance()'s doc comment).
     * If it doesn't fully complete, h2up->async_state simply reflects
     * however far it got, and event_loop.c's dispatch picks up from
     * there on the next poller event -- no special-casing needed here
     * for the partial-progress case.
     *
     * Optimization: if THIS call happens to finish establishment
     * synchronously (common on loopback / very fast upstreams -- rc==0
     * means READY), hand the connection back to the caller immediately
     * rather than forcing this request through a needless 502/retry
     * cycle just to have the NEXT request benefit from a connection
     * that's already perfectly usable right now. Whenever advance()
     * doesn't finish synchronously (the common case against real
     * network upstreams), this falls through to returning NULL exactly
     * as before -- this request still doesn't wait, it just doesn't
     * get an unnecessary free ride either. */
    if (h2up_conn_advance(h) == 0) return h;
    return NULL;  /* still establishing (or failed) -- see doc comment
                     above: this caller doesn't wait on it, a later
                     request benefits once it reaches READY */
}

/* ── proxy_begin ────────────────────────────────────────────────────────────*/

int proxy_begin(worker_t *w, conn_t *conn, const http_request_t *req,
                uint32_t stream_id, lb_t *lb) {
    if (!w || !conn || !req || !lb) {
        LOG_WARN("proxy_begin: null check failed w=%p conn=%p req=%p lb=%p",
                 (void*)w, (void*)conn, (void*)req, (void*)lb);
        return -1;
    }

    proxy_ctx_t *ctx;

    if (conn->h2 && stream_id > 0) {
        /* H2 path: each stream gets its own proxy_ctx from the per-conn map */
        ctx = proxy_stream_get(conn, stream_id, lb);
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
            conn->proxy = proxy_ctx_new(lb, conn);
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
            if (conn->proxy->has_retry_req) {
                http_request_free(&conn->proxy->retry_req);
                conn->proxy->has_retry_req = 0;
            }
        }
        ctx = conn->proxy;
    }

    /* Deep-copy the request so a later ASYNC connect-refused failure
     * (discovered in proxy_on_upstream_writable(), after this function has
     * already returned and the caller's req has been freed) can retry
     * against a different node. See proxy_ctx_t.retry_req. Best-effort:
     * if the clone fails (OOM), retry is simply unavailable for this
     * request -- not a fatal error. */
    if (ctx->has_retry_req) {
        http_request_free(&ctx->retry_req);
        ctx->has_retry_req = 0;
    }
    if (http_request_clone(req, &ctx->retry_req) == 0) {
        ctx->has_retry_req = 1;
    }

    /* Pick upstream node ONCE; branch per-node on use_tls, not pool-wide.
     * A mixed pool (some H1, some TLS/H2 nodes) must not force every H1
     * node's traffic through the H2/TLS path just because SOME node in
     * the pool is TLS. */
    /* Sticky session: if enabled, prefer the node named by the client's
     * sticky cookie (if present and still UP) over the normal lb_algo. */
    const char *sticky_val = NULL;
    cookie_jar_t *sticky_jar = NULL;
    if (lb_sticky_enabled(lb)) {
        sticky_jar = cookie_jar_parse(req);
        if (sticky_jar) sticky_val = cookie_jar_get(sticky_jar, lb_sticky_cookie_name(lb));
    }
    upstream_node_t *unode = lb_pick_node_sticky(lb, conn->remote_ip, sticky_val);
    if (sticky_jar) cookie_jar_free(sticky_jar);
    if (!unode) {
        LOG_WARN("proxy: no upstream node for %s", conn->remote_ip);
        goto upstream_error;
    }
    if (lb_sticky_enabled(lb)) {
        ctx->sticky_node_for_cookie = unode;
    }

    if (unode->use_tls) {
        /* proto computed here (rather than further below, where the
         * old code had it) so it's available for this call -- retry
         * loop below also needs it. */
        const char *proto = conn->tls ? "https" : "http";
        h2up_conn_t *h2up = h2up_acquire_for_node(w, unode);
        /* BUG FIX (H2/TLS failover): this was the actual root cause of
         * the failover test's flakiness/failures. h2up_acquire_for_node()
         * returning NULL (dead/refused/non-h2 upstream -- see
         * h2up_conn_advance()'s H2UP_ASYNC_FAILED path) never called
         * upstream_node_record_failure() anywhere in this file, unlike
         * the H1 path (proxy_on_upstream_writable()) and every other
         * upstream-error path in this file, which all do. Concretely:
         * once a TLS node died, every request that landed on it kept
         * failing forever WITHOUT the node's fail_count ever
         * incrementing, so passive_fail_threshold was never reached and
         * the node never tripped to NODE_DOWN -- lb_pick_node() kept
         * offering it up right alongside the healthy nodes,
         * indefinitely. Recording the failure here, before the retry
         * loop runs, means the circuit breaker actually works for H2/TLS
         * nodes the same way it already does for H1. */
        if (!h2up) {
            upstream_pool_t *_p = lb_get_pool(lb);
            if (_p) upstream_node_record_failure(unode, _p);
        }
        if (!h2up && ctx->attempt == 0) {
            /* BUG FIX (H2/TLS failover): retry across the WHOLE pool,
             * not just a single alternate node -- previously this
             * branch had NO retry at all, so a dead/still-connecting
             * TLS node meant an immediate 502 even when healthy sibling
             * nodes existed. A single retry attempt (picking exactly
             * one alternate node) turned out to still be insufficient:
             * during a connect storm (e.g. right after a node dies and
             * many requests arrive at once), the FIRST alternate picked
             * can itself have no READY connection yet (its own
             * h2up_acquire_for_node() call also just started a pending
             * one), so a single retry still 502'd. Looping up to
             * node_count times -- trying a genuinely different node
             * each iteration -- means this only gives up once every
             * node in the pool has been tried and none had a READY
             * connection, rather than giving up after exactly one
             * alternate. h2up_acquire_for_node() never blocks regardless
             * of which node it targets (see its doc comment), so this
             * loop is bounded and cheap even in the worst case. */
            ctx->attempt = 1;
            int _pool_size = lb_get_pool(lb) ? lb_get_pool(lb)->node_count : 1;
            upstream_node_t *_tried[64];
            int _tried_count = 0;
            if (_tried_count < 64) _tried[_tried_count++] = unode;
            for (int _pi = 0; _pi < _pool_size && !h2up; _pi++) {
                upstream_node_t *retry_node = lb_pick_node(lb, conn->remote_ip);
                if (!retry_node) break;
                int _already_tried = 0;
                for (int _ti = 0; _ti < _tried_count; _ti++) {
                    if (_tried[_ti] == retry_node) { _already_tried = 1; break; }
                }
                if (_already_tried) continue;
                if (_tried_count < 64) _tried[_tried_count++] = retry_node;

                if (retry_node->use_tls) {
                    h2up = h2up_acquire_for_node(w, retry_node);
                    if (h2up) unode = retry_node;
                } else {
                    /* Retry landed on an H1 node -- fall through to the
                     * H1 path below by jumping past the rest of this
                     * TLS branch, so it gets identical pooling/keepalive
                     * behavior to a normal H1 request instead of a
                     * duplicated code path here. */
                    unode = retry_node;
                    goto h1_upstream_path;
                }
            }
        }
        if (!h2up) {
            LOG_WARN("proxy: failed to acquire H2 upstream to %s:%d",
                     unode->host, unode->port);
            goto upstream_error;
        }

        /* proto already computed above (moved up for the first h2up_acquire_for_node() call) -- no longer redefined here. */
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
                   POLLER_READ | POLLER_WRITE, h2up);
        /* Eager write: h2up connections are frequently reused/pre-warmed
         * (see worker_run()'s pre_warm block) and are typically already
         * connected and writable at this point. Same ET-mode caveat as
         * the H1 pooled-connection path: re-arming interest via
         * poller_mod() on an fd that's already in the ready state is not
         * guaranteed to produce a fresh edge, which can strand the queued
         * HEADERS/DATA frames until an edge that never comes. Flush once,
         * synchronously, right after arming — h2up_on_writable() already
         * handles the EAGAIN case correctly if the fd isn't ready yet. */
        h2up_on_writable(h2up, w);
        return 0;
    }

    /* ── H1 upstream path ────────────────────────────────────────────────── */
    {
    upstream_conn_t *uconn = NULL;
    h1_upstream_path: ;  /* see the TLS branch's retry-onto-H1 jump above --
                            trailing ';' makes this a valid empty statement
                            so the label can precede a declaration-adjacent
                            statement without violating C's "label must
                            precede a statement, not a declaration" rule */
    int ufd = lb_begin_forward_to_node(lb, unode, req, conn->remote_ip,
                                       conn->tls ? "https" : "http",
                                       &ctx->req_buf, &uconn);
    if (ufd < 0 && ctx->attempt == 0) {
        ctx->attempt = 1;
        buf_reset(&ctx->req_buf);
        /* Re-pick: maybe another node is UP now. If the retry lands on a
         * TLS node, don't cross into the H2 path mid-attempt — just fail
         * this attempt and let the normal error handling below take over
         * (502). Crossing protocols mid-retry is out of scope. */
        upstream_node_t *retry_node = lb_pick_node(lb, conn->remote_ip);
        if (retry_node && !retry_node->use_tls) {
            unode = retry_node;
            ufd = lb_begin_forward_to_node(lb, unode, req, conn->remote_ip,
                                           conn->tls ? "https" : "http",
                                           &ctx->req_buf, &uconn);
        } else {
            ufd = -1;
        }
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

            /* Async connect-refused retry: proxy_begin()'s retry only
             * covers a SYNCHRONOUS lb_begin_forward_to_node() failure.
             * connect() to a dead upstream frequently returns EINPROGRESS
             * and fails asynchronously instead (discovered here, on the
             * first writable event) -- without this branch, that case
             * skipped retry entirely and went straight to a 502, even
             * though ctx->attempt was still 0 and a healthy node might be
             * available. Uses ctx->retry_req (a deep copy taken in
             * proxy_begin(), since the caller's original http_request_t
             * has already been freed by this point). */
            if (ctx->attempt == 0 && ctx->has_retry_req) {
                ctx->attempt = 1;
                buf_reset(&ctx->req_buf);
                upstream_node_t *retry_node = lb_pick_node(ctx->lb, conn->remote_ip);
                if (retry_node && !retry_node->use_tls) {
                    upstream_conn_t *retry_uconn = NULL;
                    int retry_fd = lb_begin_forward_to_node(
                        ctx->lb, retry_node, &ctx->retry_req, conn->remote_ip,
                        conn->tls ? "https" : "http", &ctx->req_buf, &retry_uconn);
                    if (retry_fd >= 0) {
                        ctx->upstream_fd    = retry_fd;
                        ctx->node           = retry_node;
                        ctx->uconn          = retry_uconn;
                        ctx->req_sent       = 0;
                        ctx->upstream_state = (retry_uconn && retry_uconn->requests > 0)
                                            ? PROXY_STATE_WRITING
                                            : PROXY_STATE_CONNECTING;
                        void *poller_ptr = (conn->h2 && ctx->front_stream_id > 0)
                                         ? (void *)ctx : (void *)conn;
                        if (!conn->h2) conn->state = CONN_UPSTREAM_CONNECTING;
                        poller_add(w->poller, retry_fd, POLLER_WRITE | POLLER_ET,
                                  poller_ptr);
                        if (ctx->upstream_state == PROXY_STATE_WRITING)
                            proxy_on_upstream_writable(w, conn, ctx);
                        return 0;
                    }
                }
            }

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
            ctx->last_upstream_io_ms = routa_now_ms();
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

    if (n > 0) {
        ctx->last_upstream_io_ms = routa_now_ms();
        buf_append(&ctx->resp_buf, tmp, (size_t)n);
    }

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

    /* Retry on 5xx (RFC-agnostic operational feature, not spec-mandated):
     * lb_retry_on_5xx / lb_max_retries were previously parsed from config
     * and stored, but nothing ever consulted them -- the only retry path
     * implemented was "upstream connect() refused" (see
     * proxy_on_upstream_writable() above). A pool with
     * lb_retry_on_5xx = true had zero actual effect; confirmed via bench
     * testing against a deliberately flaky (10% error rate) upstream,
     * where the client-visible error rate matched the raw upstream error
     * rate exactly. This mirrors the existing connect-refused retry's
     * pattern: pick a different node, resend the deep-copied request
     * (ctx->retry_req, taken once in proxy_begin() since the caller's
     * original http_request_t is long gone by the time a response
     * arrives), same TLS-crossing restriction (retry_node must not use
     * TLS when the original attempt didn't -- crossing protocols
     * mid-retry stays out of scope, matching the existing connect-retry
     * comment above). Only fires once (attempt 0 -> 1), same bound as
     * the connect-refused path -- lb_get_max_retries() governs how many
     * total attempts are allowed; this implementation caps at a single
     * retry regardless of a larger configured value, which is a
     * reasonable and conservative first cut rather than a full retry
     * budget/backoff loop. */
    if (resp.status >= 500 && resp.status <= 599 &&
        ctx->lb && lb_retry_on_5xx_enabled(ctx->lb) &&
        ctx->attempt < lb_get_max_retries(ctx->lb) &&
        ctx->has_retry_req) {
        upstream_node_t *retry_node = lb_pick_node(ctx->lb, conn->remote_ip);
        int orig_used_tls = (ctx->node && ctx->node->use_tls);
        if (retry_node && retry_node->use_tls == orig_used_tls) {
            ctx->attempt++;
            lb_record_retry(ctx->lb);
            http_response_destroy(&resp);
            buf_reset(&ctx->req_buf);
            upstream_conn_t *retry_uconn = NULL;
            int retry_fd = lb_begin_forward_to_node(
                ctx->lb, retry_node, &ctx->retry_req, conn->remote_ip,
                conn->tls ? "https" : "http", &ctx->req_buf, &retry_uconn);
            if (retry_fd >= 0) {
                ctx->upstream_fd    = retry_fd;
                ctx->node           = retry_node;
                ctx->uconn          = retry_uconn;
                ctx->req_sent       = 0;
                ctx->upstream_state = (retry_uconn && retry_uconn->requests > 0)
                                    ? PROXY_STATE_WRITING
                                    : PROXY_STATE_CONNECTING;
                void *poller_ptr = (conn->h2 && ctx->front_stream_id > 0)
                                 ? (void *)ctx : (void *)conn;
                if (!conn->h2) conn->state = CONN_UPSTREAM_CONNECTING;
                poller_add(w->poller, retry_fd, POLLER_WRITE | POLLER_ET,
                          poller_ptr);
                if (ctx->upstream_state == PROXY_STATE_WRITING)
                    proxy_on_upstream_writable(w, conn, ctx);
                return 0;
            }
            /* retry_fd < 0: no node available to retry against -- fall
             * through and forward the original 5xx response as-is below
             * (resp was already destroyed above, so re-init a minimal
             * one describing the original failure rather than trying to
             * resurrect the freed response). */
            http_response_init(&resp);
            http_response_set_status(&resp, 502, "Bad Gateway");
            http_response_set_body(&resp, "Bad Gateway\n", 12);
        }
    }

    /* Sticky session: set the cookie identifying which node served this
     * request, so subsequent requests from this client stick to it (as
     * long as it stays UP -- see lb_pick_node_sticky()). Set on every
     * response while sticky sessions are enabled, not just the first,
     * so a client's cookie stays fresh/correct even if a prior sticky
     * pin become stale (e.g. it fell back to a different node because
     * the original went DOWN) -- this naturally "re-stickies" them. */
    if (ctx->sticky_node_for_cookie && ctx->lb) {
        char idx_buf[16];
        lb_sticky_cookie_value_for_node(ctx->lb, ctx->sticky_node_for_cookie,
                                        idx_buf, sizeof(idx_buf));
        cookie_opts_t sticky_opts = {
            .name      = lb_sticky_cookie_name(ctx->lb),
            .value     = idx_buf,
            .path      = "/",
            .domain    = NULL,
            .max_age   = -1,
            .http_only = 1,
            .secure    = 0,
            .same_site = "Lax",
        };
        cookie_set(&resp, &sticky_opts);
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
        /* req=NULL: proxy responses don't have a live http_request_t
         * at this call point -- this preserves the exact previous
         * (also-broken, not-yet-fixed) behavior of not stashing
         * observability data for proxy responses. See
         * METRICS_STASH_FIX_PLAN.md Faz 2 for the follow-up fix. */
        conn_prepare_writev(conn, &resp, NULL);
        http_response_destroy(&resp);
        conn->state = CONN_WRITING;
    }
    return 0;
}
/* ── proxy_check_upstream_timeout ────────────────────────────────────────── */
int proxy_check_upstream_timeout(struct worker *w, conn_t *conn, uint64_t now_ms) {
    proxy_ctx_t *ctx = conn ? conn->proxy : NULL;
    if (!ctx || !ctx->lb || ctx->up_h2up) return 0;
    if (ctx->upstream_state != PROXY_STATE_WRITING &&
        ctx->upstream_state != PROXY_STATE_READING) return 0;
    if (ctx->last_upstream_io_ms == 0) return 0;

    int read_to = 30000, write_to = 30000;
    lb_get_upstream_timeouts(ctx->lb, &read_to, &write_to);
    int limit_ms = (ctx->upstream_state == PROXY_STATE_READING) ? read_to : write_to;
    if (limit_ms <= 0) return 0;

    uint64_t elapsed = (now_ms > ctx->last_upstream_io_ms)
                      ? (now_ms - ctx->last_upstream_io_ms) : 0;
    if (elapsed <= (uint64_t)limit_ms) return 0;

    LOG_WARN("upstream_%s_timeout: fd=%d elapsed=%llums (limit=%dms)",
             ctx->upstream_state == PROXY_STATE_READING ? "read" : "write",
             conn->fd, (unsigned long long)elapsed, limit_ms);
    if (ctx->node && ctx->pool)
        upstream_node_record_failure(ctx->node, ctx->pool);
    poller_del(w->poller, ctx->upstream_fd);
    proxy_drop_upstream(ctx);
    proxy_send_upstream_error(conn, ctx, 504, "Gateway Timeout", "Gateway Timeout\n");
    return 1;
}
