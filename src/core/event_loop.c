#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/event_loop.h"
#include "core/numa.h"
#include <sched.h>
#include <stdatomic.h>
#include "core/conn.h"
#include "util/metrics.h"
#include "net/poller.h"
#include "net/socket.h"
#include "net/io.h"
#include "http/request.h"
#include "http/response.h"
#include "http/mw_acl.h"
#include "http/mw_cors.h"
#include "http/mw_auth.h"
#include "http/mw_ratelimit.h"
#include "http/mw_compress.h"
#include "util/logger.h"
#if defined(__linux__)
#include <sys/sendfile.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#if defined(__linux__)
#include <sys/epoll.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include "http/ws.h"
#include "http/ws_registry.h"
#if defined(__linux__)
#include <sys/eventfd.h>
#endif
#include <netinet/tcp.h>

#include "core/config.h"
#include "core/proxy.h"
#include "core/server.h"
#include "http/h2.h"
#include "net/h2_client.h"



#define MAX_EVENTS        1024
#define SEND_BUF_SZ       131072
#define RECV_BUF_SZ       65536
#define URING_POOL_SZ     8192
#define URING_QUEUE_DEPTH 4096

static router_t           *g_router = NULL;
static middleware_chain_t *g_chain  = NULL;

/* Global response header manipulation, set once via
 * event_loop_set_global_response_headers() (called from
 * server_from_config()) and applied to EVERY response in
 * conn_prepare_writev() -- proxy, static file, or custom route handler
 * alike. Mirrors the g_router/g_chain "single server instance" pattern
 * already used in this file. */
typedef struct { char name[128]; char value[256]; } global_hdr_rule_t;
static global_hdr_rule_t g_resp_header_add[ROUTA_MAX_GLOBAL_HEADER_RULES];
static int               g_resp_header_add_count = 0;
static char              g_resp_header_remove[ROUTA_MAX_GLOBAL_HEADER_RULES][128];
static int               g_resp_header_remove_count = 0;

void event_loop_set_global_response_headers(
    const void *add_rules_v, int add_count,
    const char remove_rules[][128], int remove_count)
{
    const struct { char name[128]; char value[256]; } *add_rules = add_rules_v;
    if (add_count > ROUTA_MAX_GLOBAL_HEADER_RULES) add_count = ROUTA_MAX_GLOBAL_HEADER_RULES;
    if (remove_count > ROUTA_MAX_GLOBAL_HEADER_RULES) remove_count = ROUTA_MAX_GLOBAL_HEADER_RULES;
    g_resp_header_add_count = add_count;
    for (int i = 0; i < add_count; i++) memcpy(&g_resp_header_add[i], &add_rules[i], sizeof(global_hdr_rule_t));
    g_resp_header_remove_count = remove_count;
    for (int i = 0; i < remove_count; i++)
        strncpy(g_resp_header_remove[i], remove_rules[i], sizeof(g_resp_header_remove[i]) - 1);
}
static ws_handler_t  *g_ws_handlers      = NULL;
static int            g_ws_handler_count = 0;


struct event_loop {
    int            port;
    int            n_workers;
    int            max_connections;
    int            socket_recv_buf_size;
    int            socket_send_buf_size;
    int            cpu_affinity_enabled;
    int            cpu_affinity_start_core;
    int            numa_aware_enabled;   /* only meaningful when built with
                                          * ROUTA_NUMA and cpu_affinity_enabled
                                          * is also set -- see worker startup */
    int            keepalive_timeout_ms;
    int            request_timeout_ms;
    worker_t      *workers;
    tls_context_t *tls_ctx;
    lb_t          *lb;              /* legacy: == lbs[0] when lb_count > 0 */
    lb_t          *lbs[ROUTA_MAX_LB_POOLS];
    int            lb_count;
    int            should_stop;
    routa_h2_config_t h2_cfg;
    ws_config_t       ws_cfg;

    /* Graceful shutdown */
    int            draining;
    int            shutdown_timeout_ms;  /* default: 30000                  */

    /* Hot reload (SIGHUP) — set via event_loop_set_config_reload()         */
    volatile sig_atomic_t *reload_flag;
    char           config_path[512];

    /* Chain indices of config-driven middlewares, for hot reload -- see
     * event_loop_set_middleware_reload_indices()'s doc comment. -1 = not
     * enabled for this server. */
    int            reload_acl_idx;
    int            reload_cors_idx;
    int            reload_basic_auth_idx;
    int            reload_jwt_auth_idx;
    int            reload_rate_limit_idx;
    int            reload_compress_idx;

    /* Protects tls_ctx pointer during hot reload: readers (accept path)
     * hold rdlock; reloader (worker 0) holds wrlock while swapping.        */
    pthread_rwlock_t tls_reload_lock;

    /* ── Process-wide memory limits (0 = disabled) ──────────────────────
     * Checked periodically by a single worker (see worker 0's sweep-loop
     * branch); memory_reject_new_conns is then read by every worker's
     * accept path, which is why it's a plain atomic int rather than
     * anything requiring the tls_reload_lock-style rwlock -- it's a
     * simple boolean gate, not a pointer swap. */
    int          memory_soft_limit_mb;
    int          memory_hard_limit_mb;
    volatile int memory_reject_new_conns; /* 1 = soft limit currently tripped, read/written via __atomic_* like `draining` above */
    uint64_t     last_memory_check_ms;    /* routa_now_ms() of last RSS read  */
};
static inline void conn_poller_mod(worker_t *w, conn_t *conn, uint32_t mask) {
    if ((uint32_t)conn->poller_mask == mask) return;
    conn->poller_mask = (uint8_t)mask;
    poller_mod(w->poller, conn->fd, mask, conn);
}
static int ws_route_placeholder(const http_request_t *req,
                                 http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 426, "Upgrade Required");
    http_response_set_header(resp, "Upgrade", "websocket");
    http_response_set_body(resp, "WebSocket upgrade required\n", 27);
    return 0;
}

void event_loop_set_h2_config(event_loop_t *loop,
                               const routa_h2_config_t *cfg) {
    if (loop && cfg) loop->h2_cfg = *cfg;
}

void event_loop_set_ws_config(event_loop_t *loop, const ws_config_t *cfg) {
    if (loop && cfg) loop->ws_cfg = *cfg;
}

void event_loop_add_ws_route(event_loop_t *loop, const char *path,
                              const ws_handler_t *handler) {

    (void)loop;
    if (!path || !handler) return;

    /* Ensure the path is also registered in the HTTP router so the epoll
     * read path can match it before handing off to ws_handshake.          */
    if (!g_router) {
        g_router = router_new();
        if (!g_router) { LOG_ERROR("Failed to create router"); return; }
    }
    /* Register with HTTP_GET — browsers always upgrade via GET             */
    router_add(g_router, path, 1 << HTTP_GET, ws_route_placeholder, NULL);

    /* Grow handler table */
    ws_handler_t *tmp = realloc(g_ws_handlers,
                                (size_t)(g_ws_handler_count + 1)
                                * sizeof(ws_handler_t));
    if (!tmp) { LOG_ERROR("ws: failed to grow handler table"); return; }
    g_ws_handlers = tmp;
    g_ws_handlers[g_ws_handler_count] = *handler;
    strncpy(g_ws_handlers[g_ws_handler_count].path, path,
        sizeof(g_ws_handlers[0].path) - 1);
    g_ws_handler_count++;

    LOG_INFO("ws: registered handler for path '%s'", path);
}

/* Lookup a WS handler by path.  Linear scan — handler count is small.    */
/* Made non-static so h2.c's RFC 8441 (WebSocket-over-HTTP/2) Extended
 * CONNECT handling can look up the same WS route table the H1 upgrade
 * path uses -- see dispatch_stream()'s CONNECT+:protocol=websocket
 * handling in h2.c. */
ws_handler_t *ws_handler_find(const char *path) {
    for (int i = 0; i < g_ws_handler_count; i++) {
        if (strcmp(g_ws_handlers[i].path, path) == 0)
            return &g_ws_handlers[i];
    }
    return NULL;
}
int event_loop_broadcast(event_loop_t *loop,
                         const uint8_t *data, size_t len,
                         ws_opcode_t opcode) {
    if (!loop) return -1;
    worker_t *ptrs[loop->n_workers];
    for (int i = 0; i < loop->n_workers; i++)
        ptrs[i] = &loop->workers[i];
    return ws_broadcast(ptrs, loop->n_workers, data, len, opcode);
}

/* ── Helpers ────────────────────────────────────────────────────────────────*/


static void conn_remove(worker_t *w, conn_t *conn) {
    for (int j = 0; j < w->active_conn_count; j++) {
        if (w->active_conns[j] == conn) {
            w->active_conns[j] = w->active_conns[--w->active_conn_count];
            return;
        }
    }
}
/* Process a readable CONN_WEBSOCKET connection.
 * Returns -1 if the connection should be closed.                          */
static int handle_ws_read(worker_t *w, conn_t *conn) {
    ws_handler_t *handler = conn->ws_handler;
    if (!handler) {
        ws_close(conn, WS_CLOSE_ERROR, "no handler");
        return -1;
    }

    /* Use the per-route config if set, otherwise fall back to the
     * worker's configured defaults (from routa_config_t.ws, see
     * event_loop_set_ws_config) -- previously this fell back to a
     * hardcoded ws_config_init() default regardless of what the config
     * file specified, silently ignoring every ws_* setting. */
    const ws_config_t *cfg = (handler->cfg.max_frame_size > 0)
                             ? &handler->cfg : &w->ws_cfg;

    int rc = ws_recv(conn, handler, cfg);
    if (rc < 0) {
        ws_registry_remove(&w->ws_registry, conn);
        ROUTA_METRIC_INC(ws_disconnects_total);
        return -1;
    }
    return 0;
}

tls_context_t *event_loop_get_tls_ctx(event_loop_t *loop) {
    return loop ? loop->tls_ctx : NULL;
}

/* Reset per-response writev state and free owned body */
void conn_reset_write_state(conn_t *conn) {
    free((void *)conn->resp_body_ptr);
    conn->resp_body_ptr  = NULL;
    conn->resp_body_len  = 0;
    conn->writev_written = 0;
    buf_reset(&conn->hdr_buf);
}

/* Flush a frontend conn after an h2up response delivery.
 * Called from h2_client.c deliver_response / proc_rst_stream. */
void worker_conn_flush(worker_t *w, conn_t *conn)
{
    if (!conn) return;
    if (conn->h2 && conn->h2->write_buf.len > 0) {
        h2_conn_flush(conn->h2);
        if (conn->h2->write_buf.len > 0) {
            conn_poller_mod(w, conn, POLLER_READ | POLLER_WRITE | POLLER_ET);
        } else {
            /* Flush fully drained write_buf -- make sure the connection
             * is still watched for POLLER_READ. Without this, a
             * connection whose poller registration happened to be
             * POLLER_WRITE-only at the moment this function was called
             * (e.g. mid-flow-control-stall, waiting only to finish
             * draining write_buf) would be left with NO active epoll
             * interest at all once write_buf hit zero here -- the worker
             * would never see another readable event for this fd again,
             * silently orphaning the connection (confirmed via strace:
             * the fd received zero read/write/epoll_ctl syscalls for the
             * remainder of the connection's life after this exact call
             * pattern, until the peer eventually gave up and closed).
             * This was a strong suspect -- possibly the actual root cause
             * -- for the intermittent H2-over-TLS large-file stalls
             * investigated earlier this session. */
            conn_poller_mod(w, conn, POLLER_READ | POLLER_ET);
        }
        return;
    }
    if (conn->h2) return;

    /* H1 frontend response, queued via conn_prepare_writev() (the path used
     * by deliver_response() for H2-upstream responses, and by most normal
     * H1 responses): attempt an immediate flush using the SAME mechanism
     * as the CONN_WRITING case in handle_events_worker() (io_writev_response
     * for hdr_buf/resp_body_ptr, or io_write_from_buf for the legacy
     * write_buf error-response path) before relying on the next epoll
     * WRITE event. In ET mode, re-arming the poller via conn_poller_mod()
     * when the client fd is already writable (very likely on loopback / a
     * fast client) is not guaranteed to produce a fresh edge — without an
     * eager flush here, a response queued by deliver_response() can sit in
     * hdr_buf/resp_body_ptr forever and the client sees a bare connection
     * hang/close instead of the response. */
    if (conn->hdr_buf.len > 0 || conn->resp_body_ptr != NULL) {
        http_response_t view;
        memset(&view, 0, sizeof(view));
        view.body_fd  = -1;
        view.body     = (char *)conn->resp_body_ptr;
        view.body_len = conn->resp_body_len;

        ssize_t n = io_writev_response(conn->fd, conn->tls, &view,
                                       &conn->hdr_buf, &conn->writev_written);
        if (n < 0) {
            conn->state = CONN_CLOSING;
            return;
        }
        size_t total = conn->hdr_buf.len + conn->resp_body_len;
        if (total > 0 && conn->writev_written < total)
            conn_poller_mod(w, conn, POLLER_WRITE | POLLER_ET);
    } else if (conn->write_buf.len > 0) {
        ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf, conn->tls);
        if (n < 0) {
            conn->state = CONN_CLOSING;
            return;
        }
        if (conn->write_buf.len > 0)
            conn_poller_mod(w, conn, POLLER_WRITE | POLLER_ET);
    }
}

/* TLS sendfile fallback: read file → tls_write, blocking-emulation loop.
 *
 * conn->fd is non-blocking (edge-triggered epoll), so tls_write() can:
 *   (a) return a SHORT count (n > 0 but n < requested) -- SSL_write does
 *       not guarantee writing the whole buffer in one call, unlike a
 *       blocking write() to a regular file.
 *   (b) return -1 for SSL_ERROR_WANT_WRITE/WANT_READ, meaning "try again,
 *       nothing was written" -- NOT a fatal error. The previous version
 *       treated this identically to a real error and aborted immediately,
 *       which is exactly what silently truncated every response whose
 *       body exceeded the socket's TLS write buffer capacity (observed:
 *       2MB file truncated to exactly 512KB = 8 * 64KB chunks, i.e. it
 *       died on the first WANT_WRITE, which on a fast loopback with a
 *       large file arrives quickly once the kernel socket buffer fills).
 * Both must be retried, not treated as fatal, for this "blocking" fallback
 * to actually behave as advertised. A short retry-sleep avoids a tight
 * spin loop while the kernel socket buffer drains. */
static int send_file_tls(worker_t *w, conn_t *conn,
                         int fd, off_t off, size_t len) {
    (void)w;
    char tmp[65536];
    lseek(fd, off, SEEK_SET);
    size_t rem = len;
    while (rem > 0) {
        size_t  to_read = rem < sizeof(tmp) ? rem : sizeof(tmp);
        ssize_t n       = read(fd, tmp, to_read);
        if (n <= 0) break;

        size_t written = 0;
        while (written < (size_t)n) {
            ssize_t wn = tls_write(conn->tls, tmp + written, (size_t)n - written);
            if (wn > 0) {
                written += (size_t)wn;
                continue;
            }
            if (wn == -1) {
                /* WANT_READ/WANT_WRITE: not fatal, just not ready yet */
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 }; /* 1ms */
                nanosleep(&ts, NULL);
                continue;
            }
            /* wn == 0 (ZERO_RETURN, clean TLS close) or -2 (real error) */
            close(fd);
            return -1;
        }
        rem -= (size_t)n;
    }
    close(fd);
    return 0;
}
static void conn_close_and_free(worker_t *w, conn_t *conn) {
    poller_del(w->poller, conn->fd);
    conn_remove(w, conn);

    if (conn->proxy && conn->proxy->upstream_fd >= 0)
        poller_del(w->poller, conn->proxy->upstream_fd);
    if (conn->proxy_map) {
        proxy_stream_map_t *pm = conn->proxy_map;
        for (int i = 0; i < pm->count; i++) {
            if (pm->ctxs[i]->upstream_fd >= 0)
                poller_del(w->poller, pm->ctxs[i]->upstream_fd);
            /* H2-upstream-backed streams don't own a poller fd themselves
             * (the shared h2up->fd is separate) — detach so deliver_response
             * or proc_rst_stream never touches this ctx after it's freed.  */
            if (pm->ctxs[i]->up_h2up) {
                h2up_stream_remove(pm->ctxs[i]->up_h2up, pm->ctxs[i]->up_stream_id);
                pm->ctxs[i]->up_h2up      = NULL;
                pm->ctxs[i]->up_stream_id = 0;
            }
        }
    }

    if (conn->h2 && conn->h2->write_buf.len > 0)
        h2_conn_flush(conn->h2);
    if (conn->h2)  { h2_conn_free(conn->h2);  conn->h2  = NULL; }
    if (conn->tls) { tls_shutdown(conn->tls); tls_conn_free(conn->tls); conn->tls = NULL; }
    if (conn->sendfile_fd >= 0) { close(conn->sendfile_fd); conn->sendfile_fd = -1; }
    proxy_conn_cleanup(conn);

    shutdown(conn->fd, SHUT_WR);
    net_close(conn->fd);
    conn->fd = -1;

    conn_reset_write_state(conn);
    buf_free(&conn->read_buf);
    buf_free(&conn->write_buf);
    buf_free(&conn->hdr_buf);

    routa_metrics_conn_close();
    if (conn->from_slab && w->slab) {
        conn->recv_buf = NULL;
        conn->send_buf = NULL;
        conn_slab_release(w->slab, conn);
    } else {
        free(conn->recv_buf);
        conn->recv_buf = NULL;
        free(conn->send_buf);
        conn->send_buf = NULL;
        free(conn);
    }
}
/* ── Build and stash response on conn for writev path ───────────────────────
 *
 * Serializes headers into conn->hdr_buf immediately (not lazily) so that
 * the view passed to io_writev_response doesn't need status/headers.
 * Body is stolen from resp (zero extra malloc).
 */
void conn_prepare_writev(conn_t *conn, http_response_t *resp) {
    conn_reset_write_state(conn);

    /* Global response header manipulation, applied to every response
     * before serialization -- see event_loop_set_global_response_headers(). */
    for (int i = 0; i < g_resp_header_remove_count; i++) {
        http_response_remove_header(resp, g_resp_header_remove[i]);
    }
    for (int i = 0; i < g_resp_header_add_count; i++) {
        http_response_set_header(resp, g_resp_header_add[i].name, g_resp_header_add[i].value);
    }

    /* Serialize headers now, while resp is still fully populated */
    /* We reuse the existing serialize path via http_response_serialize
     * but only want headers — so we temporarily null the body */
    char  *saved_body     = resp->body;
    size_t saved_body_len = resp->body_len;
    int    saved_body_fd  = resp->body_fd;

    resp->body     = NULL;
    resp->body_len = 0;
    resp->body_fd  = -1;   /* prevent serialize from thinking sendfile */

    http_response_serialize(resp, &conn->hdr_buf);

    /* Restore and steal body */
    resp->body     = saved_body;
    resp->body_len = saved_body_len;
    resp->body_fd  = saved_body_fd;

    if (resp->body && resp->body_len > 0) {
        conn->resp_body_ptr = resp->body;
        conn->resp_body_len = resp->body_len;
        resp->body          = NULL;
        resp->body_len      = 0;
    }
}
static const char *req_method_str(http_method_t m) {
    switch (m) {
        case HTTP_GET:     return "GET";
        case HTTP_POST:    return "POST";
        case HTTP_PUT:     return "PUT";
        case HTTP_DELETE:  return "DELETE";
        case HTTP_HEAD:    return "HEAD";
        case HTTP_PATCH:   return "PATCH";
        case HTTP_OPTIONS: return "OPTIONS";
        default:           return "UNKNOWN";
    }
}
/* ── 400/404/405 fast-path: serialize into write_buf (no body steal) ────────
 * These simple error responses go through the legacy write_buf path because
 * http_response_simple() writes into a buf_t directly.
 * We keep them on write_buf and handle them in CONN_WRITING via
 * io_write_from_buf — acceptable since errors are not on the hot path.     */

/* ── epoll worker ───────────────────────────────────────────────────────────*/

static void handle_events_worker(worker_t *w) {
    poller_event_t events[MAX_EVENTS];

    int nfds = poller_wait(w->poller, events, MAX_EVENTS, 100);
    if (nfds < 0) {
        if (!w->should_stop) LOG_ERROR("Poller wait failed");
        return;
    }

    int i;
    for (i = 0; i < nfds; i++) {
        // Broadcast notification from ws_broadcast()
        if (events[i].ptr == (void *)(uintptr_t)w->ws_notify_fd) {
            ws_notify_fd_drain(w->ws_notify_fd);
            ws_registry_dispatch_broadcast(&w->ws_registry,
                                           &w->ws_broadcast_queue);
            continue;
        }

        /* ── Accept ── */
        if (events[i].ptr == NULL) {
            if (__atomic_load_n(&w->draining, __ATOMIC_RELAXED)) continue;
            /* Soft memory limit tripped: decline new connections (existing
             * ones are untouched) until RSS drops back down -- see the
             * periodic check in worker 0's sweep-loop branch below, which
             * is what sets/clears this flag for every worker to read. */
            if (w->loop && __atomic_load_n(&w->loop->memory_reject_new_conns, __ATOMIC_RELAXED))
                continue;
            for (;;) {
                struct sockaddr_in client_addr = {0};
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(w->server_fd,
                                       (struct sockaddr *)&client_addr, &client_len);
                if (client_fd < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        LOG_ERROR("Accept failed: %s", strerror(errno));
                    break;
                }
                if (net_set_nonblocking(client_fd) < 0) { net_close(client_fd); continue; }

                /* TCP_NODELAY */
                int flag = 1;
                setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#ifdef TCP_QUICKACK
                int qa = 1;
                setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &qa, sizeof(qa));
#endif
                if (w->socket_recv_buf_size > 0)
                    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF,
                              &w->socket_recv_buf_size, sizeof(w->socket_recv_buf_size));
                if (w->socket_send_buf_size > 0)
                    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF,
                              &w->socket_send_buf_size, sizeof(w->socket_send_buf_size));
                char client_ip[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                conn_t *conn;
                if (w->slab) {
                    conn = conn_slab_acquire(w->slab);
                    if (conn) {
                        conn_init(conn, client_fd, client_ip, ntohs(client_addr.sin_port));
                        conn->from_slab = 1;
                    }
                } else {
                    conn = conn_new(client_fd, client_ip, ntohs(client_addr.sin_port));
                }
                if (!conn) { net_close(client_fd); continue; }
                routa_metrics_conn_open();

                if (w->active_conn_count < w->max_connections) {
                    w->active_conns[w->active_conn_count++] = conn;
                } else {
                    LOG_WARN("Max connections reached, dropping");
                    conn_free(conn); net_close(client_fd); continue;
                }

                pthread_rwlock_rdlock(&w->loop->tls_reload_lock);
                tls_context_t *cur_tls = w->loop->tls_ctx;
                if (cur_tls) {
                    conn->tls = tls_conn_new(cur_tls, client_fd);
                }
                pthread_rwlock_unlock(&w->loop->tls_reload_lock);

                if (cur_tls && !conn->tls) {
                    LOG_ERROR("Failed to create TLS connection");
                    conn_remove(w, conn); conn_free(conn); net_close(client_fd); continue;
                }
                if (conn->tls) conn->state = CONN_TLS_HANDSHAKE;

                if (poller_add(w->poller, client_fd, POLLER_READ | POLLER_ET, conn) < 0) {
                    LOG_ERROR("Failed to add client to poller");
                    conn_remove(w, conn); conn_free(conn); net_close(client_fd); continue;
                }
            }
            continue;
        }

        /* ── H2 upstream fd event ──────────────────────────────────────── */
        if (((uint32_t *)events[i].ptr)[0] == H2UP_MAGIC) {
            h2up_conn_t *h2up = (h2up_conn_t *)events[i].ptr;
            /* Drain both directions in a flat loop on this single
             * epoll_wait turn, instead of nesting h2up_on_readable() and
             * h2up_on_writable() inside each other (as used to happen via
             * calls buried inside those two functions). Nested calls
             * created an ET-mode edge-timing hazard: a response could
             * arrive from the upstream in the microsecond window *between*
             * a nested call re-arming poller interest and control returning
             * to the outer function, and that edge would never be observed
             * again until the connection was force-closed. Looping here,
             * at the top level, right after epoll_wait, closes that window:
             * we keep alternating write/read until BOTH report no more
             * progress (write_buf empty and no more frames parsed from
             * read_buf), all before this epoll_wait turn ends. Capped
             * iteration count is a defensive bound, not expected to bite in
             * practice (a handful of queued control frames at most). */
            for (int _drain = 0; _drain < 8 && !h2up->closed; _drain++) {
                size_t wb_before = h2up->write_buf.len;
                size_t rb_before = h2up->read_buf.len;

                if (!h2up->closed && h2up->write_buf.len > 0)
                    h2up_on_writable(h2up, w);
                if (!h2up->closed)
                    h2up_on_readable(h2up, w);

                if (h2up->closed) break;
                /* Stop once neither buffer changed size this round. */
                if (h2up->write_buf.len == wb_before &&
                    h2up->read_buf.len  == rb_before)
                    break;
            }
            if (h2up->closed) {
                /* Remove from per-worker pool */
                poller_del(w->poller, h2up->fd);
                for (int j = 0; j < w->h2up_count; j++) {
                    if (w->h2up_conns[j] == h2up) {
                        w->h2up_conns[j] =
                            w->h2up_conns[--w->h2up_count];
                        break;
                    }
                }
                h2up_conn_free(h2up);
            }
            continue;
        }

        /* ── Upstream proxy fd event (H1 path, H2 frontend) ─────────── */
        /* proxy_begin sets ctx as the poller ptr; detect by magic tag.    */
        if (((proxy_ctx_t *)events[i].ptr)->magic == PROXY_CTX_MAGIC) {
            proxy_ctx_t *pctx  = (proxy_ctx_t *)events[i].ptr;
            conn_t      *pconn = pctx->conn;
            if (pconn->h2 && pconn->h2->worker != w) {
                /* BUG: cross-worker dispatch detected, skip silently.
                 * This upstream fd will be re-registered on the correct worker. */
                continue;
            }
            if (events[i].events & POLLER_WRITE)
                proxy_on_upstream_writable(w, pconn, pctx);
            else if (events[i].events & POLLER_READ)
                proxy_on_upstream_readable(w, pconn, pctx);
            /* Flush any H2 response data written into the frontend's write_buf */
            if (pconn->h2 && pconn->h2->write_buf.len > 0) {
                h2_conn_flush(pconn->h2);
                if (pconn->h2->write_buf.len > 0)
                    conn_poller_mod(w, pconn,
                                    POLLER_READ | POLLER_WRITE | POLLER_ET);
            }
            continue;
        }

        /* ── Client event ── */
        conn_t *conn = (conn_t *)events[i].ptr;

        /* HUP / ERR */
        if (events[i].events & (POLLER_HUP | POLLER_ERR)) {
            /* The H1 async-proxy upstream fd shares the same poller tag
             * (data.ptr == conn) as the client fd — see proxy_begin()'s
             * poller_add(w->poller, ufd, POLLER_WRITE | POLLER_ET, conn).
             * When connect() to a dead/refusing upstream fails fast, the
             * kernel reports EPOLLERR|EPOLLHUP on THAT fd, but since it
             * carries the same conn pointer, without this check it would
             * fall straight into the generic "tear down the client" path
             * below — closing the client connection with no response at
             * all (curl sees "Empty reply from server") instead of giving
             * proxy_on_upstream_writable()/readable() a chance to inspect
             * SO_ERROR and send a proper 502 Bad Gateway. Route to the
             * matching proxy handler first; it already knows how to detect
             * and report the failure. */
            if (conn->state == CONN_UPSTREAM_CONNECTING ||
                conn->state == CONN_UPSTREAM_WRITING) {
                proxy_on_upstream_writable(w, conn, conn->proxy);
                goto handle_state;
            }
            if (conn->state == CONN_UPSTREAM_READING) {
                proxy_on_upstream_readable(w, conn, conn->proxy);
                goto handle_state;
            }
            if (conn->state == CONN_TLS_HANDSHAKE) {
                poller_del(w->poller, conn->fd);
                conn_remove(w, conn);
                if (conn->tls) { tls_shutdown(conn->tls); tls_conn_free(conn->tls); conn->tls = NULL; }
                net_close(conn->fd);
                conn_free(conn);
                if (conn->from_slab && w->slab) conn_slab_release(w->slab, conn);
                continue;
            }
            conn->state = CONN_CLOSING;
            goto handle_state;
        }

        /* ── POLLER_READ ── */
        if (events[i].events & POLLER_READ) {
            h2_read:
            if (conn->state == CONN_H2) {
                int rc = h2_conn_flush(conn->h2);
                if (rc < 0) {
                    conn->state = CONN_CLOSING;
                    goto handle_state;
                }
                while (1) {
                    ssize_t n = io_read_into_buf(conn->fd, &conn->read_buf,
                                                 conn->tls);
                    if (n < 0) break;    /* EAGAIN                                  */
                    if (n == 0) {        /* EOF                                     */
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    int rrc = h2_conn_recv(conn->h2, w->router, w->chain);
                    if (conn->h2->write_buf.len > 0) {
                        h2_conn_flush(conn->h2);
                    }
                    if (conn->h2->write_buf.len > 0) {
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET);
                    } else {
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_ET);
                    }
                    if (rrc < 0) {
                        if (conn->h2->write_buf.len > 0) {
                            conn_poller_mod(w, conn,
                                       POLLER_READ | POLLER_WRITE | POLLER_ET);
                        } else {
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                        continue;
                    }
                }

                if (conn->h2->write_buf.len > 0) {
                    conn_poller_mod(w, conn,
                               POLLER_READ | POLLER_WRITE | POLLER_ET);
                } else {
                    conn_poller_mod(w, conn,
                               POLLER_READ | POLLER_ET);
                }
                continue;
            }
            // WebSocket data
            if (conn->state == CONN_WEBSOCKET) {
                ssize_t n = io_read_into_buf(conn->fd, &conn->read_buf, conn->tls);
                if (n == 0) {
                    ws_registry_remove(&w->ws_registry, conn);
                    ROUTA_METRIC_INC(ws_disconnects_total);
                    ws_frame_state_free(&conn->ws_fs);
                    conn->state = CONN_CLOSING;
                    goto handle_state;
                }
                if (n < 0) continue;   /* EAGAIN */
                if (handle_ws_read(w, conn) < 0) {
                    if (conn->write_buf.len > 0) {
                        conn->keep_alive = 0;
                        conn->state = CONN_WEBSOCKET;
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET);
                    } else {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    continue;
                }
                // Flush any responses (pong, close echo, or an
                // application on_message handler's own ws_send/echo) that
                // ws_recv wrote to conn->write_buf. Bug fix: this used to
                // only call conn_poller_mod() to re-arm POLLER_WRITE,
                // never attempting an actual write() first -- in ET mode,
                // re-arming when the client fd is already writable (very
                // likely on loopback / a fast client) does not reliably
                // produce a fresh edge, so the response could sit in
                // write_buf forever with the client seeing no reply at
                // all. worker_conn_flush() does the same eager-flush-then-
                // re-arm-only-if-needed dance already used for H1/H2
                // responses (see its own doc comment) -- it correctly
                // falls into the plain write_buf branch here since WS
                // connections have conn->h2 == NULL and no hdr_buf/
                // resp_body_ptr in play.
                if (conn->write_buf.len > 0) {
                    worker_conn_flush(w, conn);
                }
                continue;
            }

            /* ── Upstream response reading ── */
            if (conn->state == CONN_UPSTREAM_READING) {
                proxy_on_upstream_readable(w, conn, conn->proxy);
                goto handle_state;
            }

            /* TLS handshake */
            if (conn->state == CONN_TLS_HANDSHAKE) {
                int hs = tls_handshake(conn->tls);
                if (hs == 0) {
                    ROUTA_METRIC_INC(tls_handshakes_total);
                    if (tls_session_resumed(conn->tls))
                        ROUTA_METRIC_INC(tls_resumptions_total);
                    const char *proto = tls_negotiated_protocol(conn->tls);
                    if (proto && strcmp(proto, "h2") == 0) {
                        conn->h2 = h2_conn_new(conn, &w->h2_cfg);
                        if (!conn->h2) {
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                        conn->h2->worker = w;
                        conn->h2->lb     = w->lb;
                        conn->state = CONN_H2;
                        h2_conn_flush(conn->h2);
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET);
                        /* The client preface may already sit in the TLS
                         * buffer (read together with Finished).  With ET no
                         * further event fires for it — process it now. */
                        goto h2_read;
                    }
                    conn->state = CONN_READING;
                    conn_poller_mod(w, conn,
                               POLLER_READ | POLLER_ET);
                    /* Only fall through to the read below when the TLS
                     * buffer holds data — the read path treats EAGAIN as
                     * fatal for h1 connections */
                    if (!tls_has_pending(conn->tls)) continue;
                } else if (hs == 1 || hs == -1) {
                    /* Always watch both during handshake — TLS 1.3 needs it         */
                    conn_poller_mod(w, conn,
                               POLLER_READ | POLLER_WRITE | POLLER_ET);
                    continue;
                } else {
                    poller_del(w->poller, conn->fd);
                    conn_remove(w, conn);
                    ROUTA_METRIC_INC(tls_errors_total);
                    if (conn->tls) { tls_shutdown(conn->tls); tls_conn_free(conn->tls); conn->tls = NULL; }
                    net_close(conn->fd);
                    conn_free(conn);
                    if (conn->from_slab && w->slab) conn_slab_release(w->slab, conn);
                    continue;
                }
            }

            /* Read data */
            h1_read: ;
            ssize_t n = io_read_into_buf(conn->fd, &conn->read_buf, conn->tls);
            if (n < 0 || n == 0) { conn->state = CONN_CLOSING; goto handle_state; }
            if (conn->read_buf.len == 0) continue;

            /* Parse */
            http_request_t req;
            size_t consumed = 0;
            int pr = http_request_parse(&req, &conn->read_buf, &consumed);

            if (pr == 1) continue;   /* incomplete */
            /* h2c — cleartext HTTP/2 direct connection (RFC 7540 §3.4)   */
            if (pr == -1 ) {
                /* Peek: is this the H2 client preface?                   */
                static const uint8_t H2_PREFACE[] =
                    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if (conn->read_buf.len >= 24 &&
                    memcmp(buf_data(&conn->read_buf), H2_PREFACE, 24) == 0) {
                    conn->h2 = h2_conn_new(conn, &w->h2_cfg);
                    if (!conn->h2) {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    conn->h2->worker = w;
                    conn->h2->lb     = w->lb;
                    conn->state = CONN_H2;
                    h2_conn_flush(conn->h2);
                    conn_poller_mod(w, conn,
                               POLLER_READ | POLLER_WRITE | POLLER_ET);
                    continue;
                    }
            }

            if (pr == -1) {
                /* 400 — legacy write_buf path */
                buf_reset(&conn->write_buf);
                http_response_simple(&conn->write_buf, 400, "Bad Request",
                                     "text/plain", "Bad Request\n");
                ROUTA_METRIC_INC(parse_errors_total);
                conn->keep_alive = 0;
                conn_reset_write_state(conn);   /* ensure writev state clear */
                conn->state = CONN_WRITING;
                goto handle_state;
            }

            conn->consumed  = consumed;
            conn->keep_alive = req.keep_alive;

            /* ── h2c Upgrade (RFC 7540 §3.2) ────────────────────────── */
            {
                const char *upgrade = http_request_get_header(&req, "Upgrade");
                if (upgrade && strcasecmp(upgrade, "h2c") == 0) {
                    conn->h2 = h2_conn_new(conn, &w->h2_cfg);
                    if (!conn->h2) {
                        buf_reset(&conn->write_buf);
                        http_response_simple(&conn->write_buf, 500,
                                            "Internal Server Error",
                                            "text/plain",
                                            "Internal Server Error\n");
                        conn->keep_alive = 0;
                        conn_reset_write_state(conn);
                        http_request_free(&req);
                        conn->state = CONN_WRITING;
                        goto handle_state;
                    }
                    conn->h2->worker = w;
                    conn->h2->lb     = w->lb;
                    if (h2_upgrade_from_h1(conn->h2, &req,
                                           w->router, w->chain) < 0) {
                        h2_conn_free(conn->h2);
                        conn->h2 = NULL;
                        buf_reset(&conn->write_buf);
                        http_response_simple(&conn->write_buf, 500,
                                            "Internal Server Error",
                                            "text/plain",
                                            "Internal Server Error\n");
                        conn->keep_alive = 0;
                        conn_reset_write_state(conn);
                        http_request_free(&req);
                        conn->state = CONN_WRITING;
                        goto handle_state;
                    }
                    /* Switch connection to H2 mode                       */
                    h2_conn_flush(conn->h2);
                    buf_consume(&conn->read_buf, consumed);
                    conn->consumed = 0;
                    conn->state    = CONN_H2;
                    http_request_free(&req);
                    h2_conn_flush(conn->h2);
                    conn_poller_mod(w, conn,
                               POLLER_READ | POLLER_WRITE | POLLER_ET);
                    continue;
                }
            }

            /* Copy client IP for LB algo */
            strncpy(req.remote_ip, conn->remote_ip, sizeof(req.remote_ip) - 1);
            http_response_t resp;
            http_response_init(&resp);

            int allowed_methods = 0;
            route_t *matched_route = router_match(w->router, &req, &allowed_methods);
            if (matched_route == NULL && allowed_methods == 0) {
                /* 404 — legacy write_buf */
                buf_reset(&conn->write_buf);
                http_response_simple(&conn->write_buf, 404, "Not Found",
                                     "text/plain", "Not Found\n");
                conn_reset_write_state(conn);
                http_response_destroy(&resp);
                http_request_free(&req);
                conn->state = CONN_WRITING;
                goto handle_state;

            } else if (matched_route == NULL && allowed_methods != 0) {
                /* 405 — check OPTIONS preflight first */
                if (w->chain && req.method == HTTP_OPTIONS) {
                    middleware_chain_set_handler(w->chain, NULL, NULL);
                    middleware_chain_execute(w->chain, &req, &resp);
                    if (resp.status != 0) {
                        http_response_set_header(&resp, "Connection",
                                                 conn->keep_alive ? "keep-alive" : "close");
                        conn_prepare_writev(conn, &resp);
                        http_response_destroy(&resp);
                        http_request_free(&req);
                        conn->state = CONN_WRITING;
                        goto handle_state;
                    }
                }

                http_response_destroy(&resp);
                http_response_init(&resp);
                http_response_set_status(&resp, 405, "Method Not Allowed");
                http_response_set_header(&resp, "Connection",
                                         conn->keep_alive ? "keep-alive" : "close");

                /* Build Allow header */
                char allow_hdr[256] = {0};
                int  first = 1;
                static const char *mnames[] = {
                    "GET","POST","PUT","DELETE","HEAD",
                    "PATCH","OPTIONS","TRACE","CONNECT"
                };
                for (int m = 0; m < HTTP_METHOD_UNKNOWN; m++) {
                    if (!(allowed_methods & (1 << m))) continue;
                    if (!first) strncat(allow_hdr, ", ", sizeof(allow_hdr)-strlen(allow_hdr)-1);
                    strncat(allow_hdr, mnames[m], sizeof(allow_hdr)-strlen(allow_hdr)-1);
                    first = 0;
                }
                http_response_set_header(&resp, "Allow", allow_hdr);
                http_response_set_body(&resp, "Method Not Allowed\n", 20);
                conn_prepare_writev(conn, &resp);
                /* ── Observability stash ── */
                strncpy(conn->last_trace_id,
                        req.trace_id[0] ? req.trace_id : "0000000000000000",
                        sizeof(conn->last_trace_id) - 1);
                strncpy(conn->last_method_str,
                        req_method_str(req.method),
                        sizeof(conn->last_method_str) - 1);
                strncpy(conn->last_path,
                        req.path ? req.path : "/",
                        sizeof(conn->last_path) - 1);
                conn->last_status   = resp.status;
                conn->last_start_us = req.start_us;

                http_response_destroy(&resp);
                http_request_free(&req);
                conn->state = CONN_WRITING;
                goto handle_state;

            } else {        // ── WebSocket upgrade check ──────────────────────────────────────
                if (ws_is_upgrade_request(&req)) {
                    ws_handler_t *wsh = ws_handler_find(req.path);
                    if (!wsh) {
                        buf_reset(&conn->write_buf);
                        http_response_simple(&conn->write_buf, 404, "Not Found",
                                             "text/plain", "Not Found\n");
                        conn_reset_write_state(conn);
                        http_request_free(&req);
                        conn->state = CONN_WRITING;
                        goto handle_state;
                    }

                    /* See the comment on the identical fallback above --
                     * this is the H1-upgrade-path counterpart of the same
                     * fix (fall back to the worker's real configured
                     * defaults, not a hardcoded ws_config_init()). */
                    const ws_config_t *wscfg = (wsh->cfg.max_frame_size > 0)
                                               ? &wsh->cfg : &w->ws_cfg;

                    if (ws_handshake(conn, &req, &conn->write_buf, wscfg) < 0) {
                        buf_reset(&conn->write_buf);
                        http_response_simple(&conn->write_buf, 400, "Bad Request",
                                             "text/plain", "WebSocket handshake failed\n");
                        conn_reset_write_state(conn);
                        http_request_free(&req);
                        conn->keep_alive = 0;
                        conn->state = CONN_WRITING;
                        goto handle_state;
                    }

                    // Handshake response is in write_buf — flush it first, then
                    conn->ws_handler = wsh;
                    // transition to CONN_WEBSOCKET after the write completes.
                    conn->state = CONN_WRITING;
                    // Mark the connection so write completion switches to WS mode.
                    conn->ws_state = WS_STATE_HANDSHAKING;

                    http_request_free(&req);
                    goto handle_state;
                }

                /* ── Normal response ── */

                if (w->chain && matched_route != NULL) {
                    middleware_chain_set_handler(w->chain,
                                                matched_route->handler,
                                                matched_route->ctx);
                    middleware_chain_execute(w->chain, &req, &resp);
                } else if (matched_route != NULL) {
                    matched_route->handler(&req, &resp, matched_route->ctx);
                }

                /* ── Async upstream: if handler set upstream_fd via lb ──
                 * Resolve the lb_t for THIS route from matched_route->ctx
                 * (an lb_handler_ctx_t*), not from a single server-wide
                 * w->lb -- a server may have multiple independently
                 * configured pools bound to different path patterns. */
                {
                    lb_t *route_lb = NULL;
                    if (matched_route != NULL && matched_route->ctx != NULL) {
                        route_lb = ((lb_handler_ctx_t *)matched_route->ctx)->lb;
                    }
                    if (route_lb && resp.status == 0) {
                        http_response_destroy(&resp);
                        proxy_begin(w, conn, &req, 0, route_lb);  /* stream_id=0 for H1 */
                        http_request_free(&req);
                        goto handle_state;
                    }
                }
                if (0) {
                    http_request_free(&req);
                    goto handle_state;
                }

                http_response_set_header(&resp, "Connection",
                                         conn->keep_alive ? "keep-alive" : "close");

                /* sendfile path */
                if (resp.body_fd >= 0) {
                    if (conn->tls == NULL) {
                        conn->sendfile_fd  = resp.body_fd;
                        conn->sendfile_off = resp.body_fd_off;
                        conn->sendfile_rem = resp.body_fd_len;
                        resp.body_fd = -1;
                        io_cork(conn->fd);
                        /* Headers via writev, then CONN_SENDFILE */
                        conn_prepare_writev(conn, &resp);
                    } else {
                        /* TLS: no async sendfile() equivalent, so this path
                         * is blocking -- but headers MUST reach the peer
                         * before the body. conn_prepare_writev() only
                         * serializes headers into conn->hdr_buf; it does
                         * NOT write them to the socket (that normally
                         * happens later via the writev/POLLER_WRITE path).
                         * send_file_tls() used to be called immediately
                         * after, writing raw file bytes straight to the
                         * TLS session while the headers were still sitting
                         * unsent in conn->hdr_buf -- the peer received body
                         * bytes before (or instead of) headers, corrupting
                         * the response (observed as connection resets /
                         * empty bodies under wrk for any body_fd response
                         * over TLS, e.g. large static files, range
                         * requests). Fix: flush conn->hdr_buf to the TLS
                         * session synchronously first, THEN send the file
                         * body. */
                        conn_prepare_writev(conn, &resp);
                        if (conn->hdr_buf.len > 0) {
                            if (tls_write(conn->tls, buf_data(&conn->hdr_buf),
                                         buf_len(&conn->hdr_buf)) < 0) {
                                conn->state = CONN_CLOSING;
                                http_response_destroy(&resp);
                                http_request_free(&req);
                                goto handle_state;
                            }
                            buf_consume(&conn->hdr_buf, conn->hdr_buf.len);
                        }
                        send_file_tls(w, conn, resp.body_fd,
                                      resp.body_fd_off, resp.body_fd_len);
                        resp.body_fd = -1;
                    }
                } else {
                    /* In-memory body: writev (header + body, zero extra copy) */
                    conn_prepare_writev(conn, &resp);
                }

                http_response_destroy(&resp);
                http_request_free(&req);
                conn->state = CONN_WRITING;
                goto handle_state;
            }
        }

        /* ── POLLER_WRITE ── */
        if (events[i].events & POLLER_WRITE) {
            if (conn->state == CONN_H2) {
                int rc = h2_conn_flush(conn->h2);
                if (rc < 0) {
                    conn->state = CONN_CLOSING;
                    goto handle_state;
                }
                if (conn->h2->write_buf.len > 0) {
                    /* Partial flush — keep watching for write             */
                    conn_poller_mod(w, conn,
                               POLLER_READ | POLLER_WRITE | POLLER_ET);
                } else {
                    /* All flushed */
                    if (conn->h2->error) {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    h2_conn_flush_pending(conn->h2);
                    if (conn->h2->write_buf.len > 0) {
                        /* h2_conn_flush_pending() (e.g. resuming a
                         * body_fd-backed response after a WINDOW_UPDATE,
                         * see h2.c's flush_pending()) can refill write_buf
                         * here. Previously this just re-armed POLLER_WRITE
                         * and continued without attempting a real write --
                         * on a loopback socket that's already writable,
                         * edge-triggered epoll may never deliver a fresh
                         * writable edge to justify a "later" flush, so
                         * this data could sit unsent indefinitely. This
                         * was the root cause of H2-over-TLS large file/
                         * video downloads hanging partway through even
                         * though flow control and the body_fd resume
                         * logic were both working correctly (confirmed by
                         * the same request completing successfully over
                         * plaintext h2c, where the socket's own EAGAIN
                         * behavior happened to mask this gap). Flush
                         * eagerly here instead of only hoping for a later
                         * event. */
                        h2_conn_flush(conn->h2);
                        conn_poller_mod(w, conn, POLLER_READ | POLLER_WRITE | POLLER_ET);
                        continue;
                    }
                    /* Drain any pending input */
                    while (1) {
                        ssize_t n = io_read_into_buf(conn->fd,
                                                     &conn->read_buf,
                                                     conn->tls);
                        if (n < 0) break;
                        if (n == 0) {
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                        int rrc = h2_conn_recv(conn->h2, w->router, w->chain);
                        if (rrc < 0) {
                            if (conn->h2->write_buf.len > 0) {
                                conn_poller_mod(w, conn,
                                           POLLER_READ | POLLER_WRITE | POLLER_ET);
                            } else {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            goto h2_write_done;
                        }
                    }
                    /* The "drain pending input" loop above can process
                     * WINDOW_UPDATE frames whose handler (handle_window_update
                     * -> flush_pending(), see h2.c) refills write_buf with
                     * resumed body_fd data -- but nothing in this loop or
                     * its exit path ever called h2_conn_flush() to actually
                     * put that data on the wire. On a loopback socket
                     * already writable under edge-triggered epoll, just
                     * re-arming POLLER_WRITE and hoping for a future edge
                     * is not guaranteed to produce one, so this data could
                     * sit in write_buf indefinitely. This was the actual
                     * root cause of H2-over-TLS large file/video downloads
                     * hanging partway through -- confirmed by the
                     * identical request completing successfully over
                     * plaintext h2c, where the socket's own write-side
                     * retry behavior happened to paper over this gap by
                     * forcing a flush elsewhere. Flush eagerly here. */
                    if (conn->h2->write_buf.len > 0) {
                        h2_conn_flush(conn->h2);
                    }
                    if (conn->h2->write_buf.len > 0) {
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET);
                    } else {
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_ET);
                    }
                    h2_write_done:
                    continue;
                }

                continue;
            }
                // WebSocket outbound flush
                if (conn->state == CONN_WEBSOCKET) {
                    ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf, conn->tls);
                    if (n < 0) {
                        ws_registry_remove(&w->ws_registry, conn);
                        ROUTA_METRIC_INC(ws_disconnects_total);
                        ws_frame_state_free(&conn->ws_fs);
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    if (conn->write_buf.len == 0) {
                        // All flushed — back to read-only watch
                        if (conn->ws_state == WS_STATE_CLOSED) {
                            ws_registry_remove(&w->ws_registry, conn);
                            ROUTA_METRIC_INC(ws_disconnects_total);
                            ws_frame_state_free(&conn->ws_fs);
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_ET);
                    }
                    continue;
                }

                /* ── Upstream connecting ── */
                if (conn->state == CONN_UPSTREAM_CONNECTING ||
                                conn->state == CONN_UPSTREAM_WRITING) {
                                proxy_on_upstream_writable(w, conn, conn->proxy);
                                /* If proxy_on_upstream_writable() buffered an error response
                                 * (e.g. 502 after an upstream connect failure) and moved us
                                 * to CONN_WRITING, attempt to flush it immediately instead
                                 * of relying solely on the next epoll WRITE event. In ET
                                 * mode, re-arming the poller via conn_poller_mod() when the
                                 * fd is already writable is not guaranteed to generate a
                                 * fresh edge, which can strand the buffered response and
                                 * leave the client with a bare connection close (curl 000)
                                 * instead of the intended 502. */
                                if (conn->state == CONN_WRITING && conn->write_buf.len > 0 &&
                                    conn->hdr_buf.len == 0 && conn->resp_body_ptr == NULL) {
                                    ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf,
                                                                  conn->tls);
                                    if (n < 0) { conn->state = CONN_CLOSING; goto handle_state; }
                                }
                                goto handle_state;
                                }
                /* TLS handshake */
                if (conn->state == CONN_TLS_HANDSHAKE) {
                    int hs = tls_handshake(conn->tls);
                    if (hs == 0) {
                        ROUTA_METRIC_INC(tls_handshakes_total);
                        if (tls_session_resumed(conn->tls))
                            ROUTA_METRIC_INC(tls_resumptions_total);
                        const char *proto = tls_negotiated_protocol(conn->tls);
                        if (proto && strcmp(proto, "h2") == 0) {
                            conn->h2 = h2_conn_new(conn, &w->h2_cfg);
                            if (!conn->h2) {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            conn->h2->worker = w;
                            conn->h2->lb     = w->lb;
                            conn->state = CONN_H2;
                            h2_conn_flush(conn->h2);
                            conn_poller_mod(w, conn,
                                       POLLER_READ | POLLER_WRITE | POLLER_ET);
                            /* Drain any preface bytes OpenSSL buffered
                             * during the handshake (see READ branch) */
                            goto h2_read;
                        } else {
                            conn->state = CONN_READING;
                            conn_poller_mod(w, conn,
                                       POLLER_READ | POLLER_ET);
                            if (tls_has_pending(conn->tls)) goto h1_read;
                        }
                    } else if (hs == 1 || hs == -1) {
                        /* Always watch both during handshake — TLS 1.3 needs it         */
                        conn_poller_mod(w, conn,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET);
                    } else {
                        poller_del(w->poller, conn->fd);
                        conn_remove(w, conn);
                        ROUTA_METRIC_INC(tls_errors_total);
                        if (conn->tls) { tls_shutdown(conn->tls); tls_conn_free(conn->tls); conn->tls = NULL; }
                        net_close(conn->fd);
                        conn_free(conn);
                        if (conn->from_slab && w->slab) conn_slab_release(w->slab, conn);
                        continue;
                    }
                    continue;
                }

                /* sendfile body */
                if (conn->state == CONN_SENDFILE) {
#if defined(__linux__)
                    ssize_t n = sendfile(conn->fd, conn->sendfile_fd,
                                         &conn->sendfile_off, conn->sendfile_rem);
#else
                    /* macOS/BSD: fall back to read+write */
                    char _sf_buf[65536];
                    lseek(conn->sendfile_fd, conn->sendfile_off, SEEK_SET);
                    ssize_t _sf_r = read(conn->sendfile_fd, _sf_buf,
                        conn->sendfile_rem < sizeof(_sf_buf)
                        ? conn->sendfile_rem : sizeof(_sf_buf));
                    ssize_t n = (_sf_r > 0)
                        ? write(conn->fd, _sf_buf, (size_t)_sf_r) : _sf_r;
                    if (n > 0) conn->sendfile_off += n;
#endif
                    if (n > 0) {
                        conn->sendfile_rem -= (size_t)n;
                        if (conn->sendfile_rem == 0) {
                            io_uncork(conn->fd);
                            close(conn->sendfile_fd);
                            conn->sendfile_fd = -1;
                            if (conn->keep_alive) {
                                buf_consume(&conn->read_buf, conn->consumed);
                                conn->consumed = 0;
                                conn_reset_write_state(conn);
                                conn->state = CONN_READING;
                                conn->keepalive_deadline = time(NULL) + (w->keepalive_timeout_ms / 1000);
                                conn_poller_mod(w, conn, POLLER_READ|POLLER_ET);
                            } else {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                        }
                    } else if (n < 0 && errno != EAGAIN) {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    continue;
                }

                /* ── Write path ── */
                int write_complete = 0;

                /* Legacy write_buf (400/404 simple error responses) */
                if (conn->write_buf.len > 0 && conn->hdr_buf.len == 0
                        && conn->resp_body_ptr == NULL) {
                    ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf, conn->tls);
                    if (n < 0) { conn->state = CONN_CLOSING; goto handle_state; }
                    if (conn->write_buf.len == 0) write_complete = 1;

                        } else {
                            /* writev path (normal responses) */
                            http_response_t view;
                            memset(&view, 0, sizeof(view));
                            view.body_fd  = -1;
                            view.body     = (char *)conn->resp_body_ptr;
                            view.body_len = conn->resp_body_len;

                            ssize_t n = io_writev_response(conn->fd, conn->tls,
                                                           &view, &conn->hdr_buf,
                                                           &conn->writev_written);
                            if (n < 0) { conn->state = CONN_CLOSING; goto handle_state; }

                            /* hdr_buf is populated by io_writev_response on first call */
                            size_t total = conn->hdr_buf.len + conn->resp_body_len;
                            if (total == 0 || conn->writev_written >= total)
                                write_complete = 1;
                        }

                if (write_complete) {
                    // WebSocket handshake write complete — transition to WS mode
                    if (conn->ws_state == WS_STATE_HANDSHAKING) {
                        conn->ws_state = WS_STATE_OPEN;
                        conn->state    = CONN_WEBSOCKET;
                        buf_reset(&conn->write_buf);
                        conn_reset_write_state(conn);

                        buf_consume(&conn->read_buf, conn->consumed);
                        conn->consumed = 0;

                        if (ws_registry_add(&w->ws_registry, conn) < 0) {
                            LOG_ERROR("ws: failed to add to registry fd=%d", conn->fd);
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }

                        // Call on_open callback
                        //ws_handler_t *wsh = ws_handler_find(NULL);
                        if (conn->ws_handler && conn->ws_handler->on_open)
                            conn->ws_handler->on_open(conn, conn->ws_handler->ctx);

                        conn_poller_mod(w, conn, POLLER_READ | POLLER_ET);
                        /* Bug fix: previously only checked conn->read_buf
                         * for data the H1 parser might have over-read
                         * during the handshake request itself. But a
                         * client that pipelines its first WS frame right
                         * after the handshake request (i.e. doesn't wait
                         * for the 101 before sending) can have that frame
                         * sitting in the kernel's socket receive buffer
                         * BEFORE this epoll_ctl(MOD) call runs -- and in
                         * ET mode, arming POLLER_READ via MOD on an fd
                         * that was already readable before the call does
                         * not reliably produce a fresh edge (the "became
                         * readable" transition already happened in the
                         * past, from the kernel's point of view, while we
                         * were still in POLLER_WRITE-only mode watching
                         * for the handshake response to flush). Without an
                         * eager read attempt here, that frame can sit
                         * unread in the kernel buffer indefinitely, and
                         * the client sees no response to it at all -- this
                         * was the root cause of test_ws's echo/ping/close/
                         * fragmented test failures (all "no response"),
                         * every one of which sends its first frame
                         * immediately after receiving the 101, before
                         * waiting for any further server event. */
                        {
                            ssize_t rn = io_read_into_buf(conn->fd, &conn->read_buf, conn->tls);
                            if (rn == 0) {
                                ws_registry_remove(&w->ws_registry, conn);
                                ROUTA_METRIC_INC(ws_disconnects_total);
                                ws_frame_state_free(&conn->ws_fs);
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            /* rn < 0 (EAGAIN, nothing pending yet) is fine
                             * -- just fall through to the existing
                             * read_buf.len check below, which will find
                             * nothing new and skip handle_ws_read(), same
                             * as before this fix. */
                        }
                        if (conn->read_buf.len > 0) {
                            if (handle_ws_read(w, conn) < 0) {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            /* Same eager-flush bug fix as the main WS read
                             * loop above -- see the comment there. */
                            if (conn->write_buf.len > 0) {
                                worker_conn_flush(w, conn);
                            }
                        }
                        continue;
                    }
                    /* ── Access log + metrics ── */
                    if (conn->last_status > 0) {
                        log_access_json(
                            conn->last_trace_id,
                            conn->last_method_str,
                            conn->last_path,
                            conn->last_status,
                            routa_now_us() - conn->last_start_us,
                            conn->remote_ip,
                            w->worker_id,
                            conn->resp_body_len);
                        routa_metrics_record(
                            conn->last_method_str,
                            conn->last_status,
                            conn->last_start_us,
                            conn->resp_body_len);
                        conn->last_status = 0;
                    }
                    if (conn->sendfile_fd >= 0) {
                        conn->state = CONN_SENDFILE;
                        conn_poller_mod(w, conn, POLLER_WRITE|POLLER_ET);
                    } else if (conn->keep_alive) {
                        buf_consume(&conn->read_buf, conn->consumed);
                        conn->consumed = 0;
                        conn_reset_write_state(conn);
                        buf_reset(&conn->write_buf);
                        conn->state = CONN_READING;
                        conn->keepalive_deadline = time(NULL) + (w->keepalive_timeout_ms / 1000);
                        conn_poller_mod(w, conn, POLLER_READ|POLLER_ET);
                    } else {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                }
            } /* POLLER_WRITE */

            handle_state:
                switch (conn->state) {
            case CONN_H2:
            case CONN_WEBSOCKET:
                        conn_poller_mod(w, conn, POLLER_READ | POLLER_ET);
                        break;
            case CONN_WRITING:
                        /* A response can already be FULLY complete by the
                         * time we land in this case -- specifically, the
                         * TLS body_fd path (see the POLLER_READ handling
                         * above: "TLS: no async sendfile() equivalent")
                         * flushes headers AND the entire file body
                         * synchronously before ever reaching
                         * `conn->state = CONN_WRITING; goto handle_state;`.
                         * In that situation, write_buf/hdr_buf/resp_body_ptr
                         * are all already empty/NULL here, so there is
                         * nothing left to write -- but the code below
                         * unconditionally re-arms POLLER_WRITE and waits,
                         * which (on a connection that's already fully
                         * drained) never fires again since nothing will
                         * ever make the socket "become" writable in a new
                         * way. The connection was permanently stuck in
                         * CONN_WRITING, silently discarding every
                         * subsequent request sent on the same keep-alive
                         * connection (confirmed: second-and-later large
                         * file requests over TLS on a reused connection
                         * came back with an empty body). Detect the
                         * fully-drained case up front and go straight back
                         * to reading the next request instead. */
                        if (conn->write_buf.len == 0 && conn->hdr_buf.len == 0 &&
                            conn->resp_body_ptr == NULL &&
                            conn->ws_state != WS_STATE_HANDSHAKING) {
                            conn_reset_write_state(conn);
                            buf_consume(&conn->read_buf, conn->consumed);
                            conn->consumed = 0;
                            if (!conn->keep_alive) {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            conn->state = CONN_READING;
                            conn_poller_mod(w, conn, POLLER_READ | POLLER_ET);
                            /* Eagerly try to read a pipelined next request,
                             * same reasoning as the WS-transition copy below
                             * -- a client that already sent it won't
                             * generate a fresh epoll edge to prompt us. */
                            ssize_t rn = io_read_into_buf(conn->fd, &conn->read_buf, conn->tls);
                            if (rn == 0) {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            if (conn->read_buf.len > 0) {
                                conn->state = CONN_READING;
                                goto handle_state;
                            }
                            break;
                        }
                        /* Attempt an immediate flush of any buffered response
                         * (e.g. a 502 from proxy_begin()'s synchronous upstream_error
                         * path, or from proxy_on_upstream_writable()) before relying
                         * on the next epoll WRITE event. In ET mode, re-arming the
                         * poller via conn_poller_mod() when the fd is already
                         * writable is not guaranteed to generate a fresh edge, which
                         * can strand the buffered response and leave the client with
                         * a bare connection close (curl 000) instead of the intended
                         * HTTP response. Guarded to the plain write_buf path only —
                         * CONN_SENDFILE and writev/hdr_buf responses use a different
                         * write mechanism and must not be touched here. */
                        if (conn->write_buf.len > 0 && conn->hdr_buf.len == 0 &&
                            conn->resp_body_ptr == NULL) {
                            ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf,
                                                          conn->tls);
                            if (n < 0) {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                        }
                        /* Bug fix: a WebSocket handshake response reaches
                         * CONN_WRITING via `conn->state = CONN_WRITING;
                         * goto handle_state;` (see the WS upgrade branch
                         * in the POLLER_READ handling above), NOT via a
                         * real epoll POLLER_WRITE event -- so it lands
                         * HERE, in this switch case, not in the
                         * `if (events[i].events & POLLER_WRITE)` block
                         * above (which has its own, separate copy of the
                         * write-complete-triggers-WS-transition logic).
                         * If the 101 response is small enough to write in
                         * full on this very first attempt (the overwhelmingly
                         * common case -- it's ~127 bytes), write_buf.len
                         * drops to 0 right here and this case used to just
                         * re-arm POLLER_WRITE and return, NEVER transitioning
                         * the connection to CONN_WEBSOCKET. Since write_buf
                         * was already empty, no further POLLER_WRITE event
                         * would ever fire to reach the other copy of this
                         * logic either -- the connection was stuck in
                         * CONN_WRITING forever, and any WS frame the client
                         * sent afterward just sat unread until some
                         * unrelated timeout/teardown closed the socket.
                         * This was the root cause of every "no response"
                         * failure in test_ws (echo/ping/close/fragmented) --
                         * all of them send their first frame immediately
                         * after the 101, and none of them ever got a
                         * genuine POLLER_WRITE epoll event because the
                         * handshake response had already fully drained on
                         * this first synchronous attempt. */
                        if (conn->write_buf.len == 0 &&
                            conn->ws_state == WS_STATE_HANDSHAKING) {
                            conn->ws_state = WS_STATE_OPEN;
                            conn->state    = CONN_WEBSOCKET;
                            conn_reset_write_state(conn);

                            buf_consume(&conn->read_buf, conn->consumed);
                            conn->consumed = 0;

                            if (ws_registry_add(&w->ws_registry, conn) < 0) {
                                LOG_ERROR("ws: failed to add to registry fd=%d", conn->fd);
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }

                            if (conn->ws_handler && conn->ws_handler->on_open)
                                conn->ws_handler->on_open(conn, conn->ws_handler->ctx);

                            conn_poller_mod(w, conn, POLLER_READ | POLLER_ET);

                            /* Same "data pipelined right after the
                             * handshake request" eager-read handling as
                             * the other WS-transition copy above. */
                            ssize_t rn = io_read_into_buf(conn->fd, &conn->read_buf, conn->tls);
                            if (rn == 0) {
                                ws_registry_remove(&w->ws_registry, conn);
                                ROUTA_METRIC_INC(ws_disconnects_total);
                                ws_frame_state_free(&conn->ws_fs);
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            if (conn->read_buf.len > 0) {
                                if (handle_ws_read(w, conn) < 0) {
                                    conn->state = CONN_CLOSING;
                                    goto handle_state;
                                }
                                if (conn->write_buf.len > 0) {
                                    worker_conn_flush(w, conn);
                                }
                            }
                            break;
                        }
                        conn_poller_mod(w, conn, POLLER_WRITE | POLLER_ET);
                        break;
            case CONN_SENDFILE:
                        conn_poller_mod(w, conn, POLLER_WRITE | POLLER_ET);
                        break;
            case CONN_CLOSING:
                        conn_close_and_free(w, conn);
                        break;
            default:
                        break;
                }
        }
    }
/* ── Hot-reload helper (runs only on worker 0) ─────────────────────────────*/
static void worker_apply_reload(worker_t *w) {
    if (!w->loop || !w->loop->config_path[0]) {
        LOG_WARN("hot reload: no config path stored, skipping");
        return;
    }

    routa_config_t new_cfg;
    /* current has port/workers preserved by routa_config_reload() */
    routa_config_t current;
    routa_config_init(&current);
    current.port      = w->loop->port;
    current.n_workers = w->loop->n_workers;

    if (routa_config_reload(w->loop->config_path, &current, &new_cfg) < 0) {
        LOG_ERROR("hot reload: config load/validate failed, ignoring SIGHUP");
        return;
    }

    /* Apply log level — global, safe to call from any thread */
    log_set_level((log_level_t)new_cfg.log_level);
    LOG_INFO("hot reload: log_level -> %d", new_cfg.log_level);

    /* Reload TLS cert/key if TLS is active and paths are provided */
    if (w->loop->tls_ctx && new_cfg.tls_enabled &&
        new_cfg.tls_cert[0] && new_cfg.tls_key[0]) {
        pthread_rwlock_wrlock(&w->loop->tls_reload_lock);
        int rc = tls_context_reload(w->loop->tls_ctx,
                                    new_cfg.tls_cert, new_cfg.tls_key);
        pthread_rwlock_unlock(&w->loop->tls_reload_lock);
        if (rc < 0)
            LOG_ERROR("hot reload: TLS reload failed, keeping old certificates");
    }

    /* Process-wide memory limits — plain ints on event_loop_t, safe to
     * write directly (no lock: worker 0 is the only writer, readers in
     * the sweep loop read them at most once per ~2s tick, a torn read of
     * an int-sized value isn't a real hazard here). */
    w->loop->memory_soft_limit_mb = new_cfg.memory_soft_limit_mb;
    w->loop->memory_hard_limit_mb = new_cfg.memory_hard_limit_mb;
    LOG_INFO("hot reload: memory limits -> soft=%d hard=%d",
             new_cfg.memory_soft_limit_mb, new_cfg.memory_hard_limit_mb);

    /* WebSocket config — affects newly-handshaking connections only;
     * connections already in CONN_WEBSOCKET keep whatever w->ws_cfg
     * snapshot they captured (in the per-route cfg lookup at handshake
     * time), unaffected by this later change. */
    w->ws_cfg = new_cfg.ws;
    LOG_INFO("hot reload: ws config updated");

    /* Global response header rules — read directly off event_loop_t by
     * the response path (see event_loop_set_global_response_headers()'s
     * existing callers); safe to just re-call it here. */
    event_loop_set_global_response_headers(
        new_cfg.response_header_add, new_cfg.response_header_add_count,
        new_cfg.response_header_remove, new_cfg.response_header_remove_count);
    LOG_INFO("hot reload: global response headers updated");

    /* ── Middleware ctx hot-swap ──────────────────────────────────────────
     * For each middleware type that was enabled at startup (idx >= 0),
     * build a brand-new ctx from the reloaded config and atomically swap
     * it into the chain slot via middleware_chain_update_ctx() -- see
     * that function's doc comment for why this is a pointer swap rather
     * than an in-place mutation (no lock needed, in-flight requests see
     * either the complete old or complete new config, never a torn
     * state). The old ctx struct is intentionally leaked (see the same
     * doc comment) -- an accepted tradeoff given this whole layer is
     * slated for a Rust rewrite rather than adding refcounting here.
     * A middleware type that was NOT enabled at startup (idx == -1) is
     * skipped entirely: newly enabling a middleware via reload would
     * require restructuring the chain itself, which stays restart-only. */
    if (w->loop->reload_acl_idx >= 0 && new_cfg.acl_enabled) {
        acl_config_t *new_acl = acl_config_new(new_cfg.acl_default_allow);
        if (new_acl) {
            for (int i = 0; i < new_cfg.acl_rule_count; i++) {
                acl_config_add_rule(new_acl, new_cfg.acl_rules[i].rule,
                    new_cfg.acl_rules[i].action == 0 ? ACL_ACTION_ALLOW : ACL_ACTION_DENY);
            }
            middleware_chain_update_ctx(w->chain, w->loop->reload_acl_idx, new_acl);
            LOG_INFO("hot reload: ACL rules updated (%d rule(s))", new_cfg.acl_rule_count);
        }
    }

    if (w->loop->reload_cors_idx >= 0 && new_cfg.cors_enabled) {
        cors_config_t *new_cors = mw_cors_config_new(
            new_cfg.cors_origin, new_cfg.cors_methods, new_cfg.cors_headers);
        if (new_cors) {
            middleware_chain_update_ctx(w->chain, w->loop->reload_cors_idx, new_cors);
            LOG_INFO("hot reload: CORS config updated");
        }
    }

    if (w->loop->reload_basic_auth_idx >= 0 && new_cfg.auth_basic_enabled) {
        basic_auth_config_t *new_auth = basic_auth_config_new(new_cfg.auth_basic_realm);
        if (new_auth) {
            for (int i = 0; i < new_cfg.auth_basic_user_count; i++) {
                basic_auth_config_add_user(new_auth,
                    new_cfg.auth_basic_users[i].username,
                    new_cfg.auth_basic_users[i].password);
            }
            middleware_chain_update_ctx(w->chain, w->loop->reload_basic_auth_idx, new_auth);
            LOG_INFO("hot reload: basic auth config updated (%d user(s))",
                     new_cfg.auth_basic_user_count);
        }
    }

    if (w->loop->reload_jwt_auth_idx >= 0 && new_cfg.auth_jwt_enabled) {
        jwt_config_t *new_jwt = NULL;
        if (new_cfg.auth_jwt_secret[0]) {
            new_jwt = jwt_config_new_hs256(new_cfg.auth_jwt_secret);
        } else if (new_cfg.auth_jwt_pubkey_path[0]) {
            FILE *pkf = fopen(new_cfg.auth_jwt_pubkey_path, "r");
            if (pkf) {
                char pembuf[8192];
                size_t n = fread(pembuf, 1, sizeof(pembuf) - 1, pkf);
                pembuf[n] = '\0';
                fclose(pkf);
                new_jwt = jwt_config_new_rs256(pembuf);
            } else {
                LOG_ERROR("hot reload: cannot open auth_jwt_pubkey_path '%s', keeping old JWT config",
                          new_cfg.auth_jwt_pubkey_path);
            }
        }
        if (new_jwt) {
            new_jwt->verify_exp = new_cfg.auth_jwt_verify_exp;
            if (new_cfg.auth_jwt_issuer[0])
                strncpy(new_jwt->issuer, new_cfg.auth_jwt_issuer, sizeof(new_jwt->issuer) - 1);
            if (new_cfg.auth_jwt_audience[0])
                strncpy(new_jwt->audience, new_cfg.auth_jwt_audience, sizeof(new_jwt->audience) - 1);
            middleware_chain_update_ctx(w->chain, w->loop->reload_jwt_auth_idx, new_jwt);
            LOG_INFO("hot reload: JWT auth config updated");
        }
    }

    if (w->loop->reload_rate_limit_idx >= 0 && new_cfg.rate_limit_enabled) {
        rate_limit_config_t *new_rl = mw_rate_limit_config_new(
            new_cfg.rate_limit_requests_per_second, new_cfg.rate_limit_burst);
        if (new_rl) {
            middleware_chain_update_ctx(w->chain, w->loop->reload_rate_limit_idx, new_rl);
            LOG_INFO("hot reload: rate limit updated (%d req/s, burst %d)",
                     new_cfg.rate_limit_requests_per_second, new_cfg.rate_limit_burst);
        }
    }

    if (w->loop->reload_compress_idx >= 0 && new_cfg.compress_enabled) {
        compress_config_t *new_cc = calloc(1, sizeof(compress_config_t));
        if (new_cc) {
            new_cc->min_size = new_cfg.compress_min_size;
            new_cc->level    = new_cfg.compress_level;
            new_cc->prefer   = COMPRESS_PREFER_GZIP;
            middleware_chain_update_ctx(w->chain, w->loop->reload_compress_idx, new_cc);
            LOG_INFO("hot reload: compress config updated (level %d, min_size %zu)",
                     new_cfg.compress_level, new_cfg.compress_min_size);
        }
    }

    LOG_INFO("hot reload complete");
}

/* ── epoll worker thread ────────────────────────────────────────────────────*/
static void *worker_run(void *arg) {
    worker_t *w = (worker_t *)arg;
    w->server_fd = net_server_socket(w->port, 4096);
    if (w->server_fd < 0) { LOG_ERROR("Worker: server socket failed"); return NULL; }
    int slab_sz = w->max_connections / w->loop->n_workers;
    if (slab_sz < 100) slab_sz = 100;
    w->slab = conn_slab_new(slab_sz);
    if (!w->slab) {
        LOG_WARN("Worker %d: conn slab alloc failed, falling back to heap",
                 w->worker_id);
    }
    w->active_conns = (conn_t **)calloc((size_t)w->max_connections, sizeof(conn_t *));
    if (!w->active_conns) { net_close(w->server_fd); return NULL; }

    w->poller = poller_new();
    if (!w->poller) { net_close(w->server_fd); free((void *)w->active_conns); return NULL; }

    if (poller_add(w->poller, w->server_fd, POLLER_READ, NULL) < 0) {
        net_close(w->server_fd); poller_free(w->poller); free((void *)w->active_conns); return NULL;
    }

    ws_registry_init(&w->ws_registry);
    ws_msg_queue_init(&w->ws_broadcast_queue);
    w->ws_notify_fd = ws_notify_fd_create(&w->ws_notify_write_fd);
    if (w->ws_notify_fd >= 0) {
        poller_add(w->poller, w->ws_notify_fd, POLLER_READ,
                   (void *)(uintptr_t)w->ws_notify_fd);
    }

    /* Pre-warm H2 upstream connections so the first request burst doesn't
     * block the event loop creating TLS connections one at a time.           */
    if (w->lb && lb_is_tls_upstream(w->lb)) {
        upstream_pool_t *_p = lb_get_pool(w->lb);
        /* pre_warm: enough conns to cover peak concurrency = pool_max / n_workers
         * / peer_max_concurrent_streams (250).  Clamp to [2, 16].           */
        int n_workers = w->loop ? w->loop->n_workers : 1;
        int pool_max  = _p && _p->node_count > 0
                      ? _p->nodes[0]->pool_max : 64;
        /* pre_warm: conns per worker = (pool_max / n_workers) / 250,
         * so total capacity = pool_max upstream streams. Clamp [2, 32]. */
        int pre_warm  = 2; //(pool_max / n_workers + 249) / 250; // DÜZENLENECEK — temporarily lowered from 16 for debugging (CPU-safety, was causing system slowdown at 48 workers)
        if (pre_warm < 2)  pre_warm = 2;
        if (pre_warm > 32) pre_warm = 32;
        if (_p) {
            for (int _ni = 0; _ni < _p->node_count; _ni++) {
                upstream_node_t *_nd = _p->nodes[_ni];
                if (!_nd->use_tls) continue;
                for (int _k = 0; _k < pre_warm; _k++) {
                    h2up_conn_t *_h = h2up_conn_create(_nd);
                    if (!_h) break;
                    _h->worker = w;
                    if (w->h2up_count >= w->h2up_cap) {
                        int _nc = w->h2up_cap ? w->h2up_cap * 2 : 32;
                        h2up_conn_t **_tmp = realloc(w->h2up_conns,
                                                     (size_t)_nc * sizeof(*_tmp));
                        if (!_tmp) { h2up_conn_free(_h); break; }
                        w->h2up_conns = _tmp;
                        w->h2up_cap   = _nc;
                    }
                    w->h2up_conns[w->h2up_count++] = _h;
                    poller_add(w->poller, _h->fd, POLLER_READ, _h);
                }
            }
        }
        LOG_INFO("worker %d: pre-warmed %d H2 upstream connections (peer_max_streams~%u)",
         w->worker_id, w->h2up_count,
         w->h2up_count > 0 ? w->h2up_conns[0]->peer_max_concurrent_streams : 0);
    }

    uint64_t last_ping_sweep_ms = 0;
    uint64_t last_idle_reap_ms  = 0;
    int      drain_init_done    = 0;
    uint64_t drain_start_ms     = 0;

    while (!w->should_stop) {
        handle_events_worker(w);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ms = (uint64_t)ts.tv_sec * 1000
                        + (uint64_t)ts.tv_nsec / 1000000;

        /* ── Graceful drain ── */
        if (__atomic_load_n(&w->draining, __ATOMIC_RELAXED) && !drain_init_done) {
            drain_init_done = 1;
            drain_start_ms  = now_ms;
            LOG_INFO("Worker %d: graceful drain started", w->worker_id);

            /* Stop accepting new connections */
            if (w->server_fd >= 0) {
                poller_del(w->poller, w->server_fd);
                net_close(w->server_fd);
                w->server_fd = -1;
            }

            /* Close connections that are idle (not mid-request) */
            int ci = 0;
            while (ci < w->active_conn_count) {
                conn_t *c = w->active_conns[ci];
                if (c->state == CONN_READING ||
                    c->state == CONN_TLS_HANDSHAKE) {
                    poller_del(w->poller, c->fd);
                    /* swap-remove to avoid shifting the entire array */
                    w->active_conns[ci] =
                        w->active_conns[--w->active_conn_count];
                    if (c->tls) { tls_shutdown(c->tls); tls_conn_free(c->tls); c->tls = NULL; }
                    net_close(c->fd);
                    conn_reset_write_state(c);
                    conn_free(c);
                    if (c->from_slab && w->slab) conn_slab_release(w->slab, c);
                    /* do not increment ci — check swapped-in element  */
                } else {
                    ci++;
                }
            }
        }

        if (__atomic_load_n(&w->draining, __ATOMIC_RELAXED) && drain_init_done) {
            if (w->active_conn_count == 0) {
                LOG_INFO("Worker %d: all connections drained, stopping",
                         w->worker_id);
                w->should_stop = 1;
            } else if (now_ms - drain_start_ms >=
                       (uint64_t)w->shutdown_timeout_ms) {
                LOG_WARN("Worker %d: drain timeout (%d ms), "
                         "force-closing %d connection(s)",
                         w->worker_id, w->shutdown_timeout_ms,
                         w->active_conn_count);
                w->should_stop = 1;
            }
        }

        /* ── Graceful drain trigger from signal handler ── */
        if (!__atomic_load_n(&w->draining, __ATOMIC_RELAXED) && w->loop) {
            int expected = 1;
            /* Only one worker does the drain_start, others pick up via w->draining */
            extern atomic_int g_drain_flag;
            if (atomic_compare_exchange_strong(&g_drain_flag, &expected, 0)) {
                event_loop_drain_start(w->loop);
            }
        }

        /* ── Hot reload (worker 0 only, skip during drain) ── */
        if (!__atomic_load_n(&w->draining, __ATOMIC_RELAXED) && w->worker_id == 0 && w->loop &&
            w->loop->reload_flag && *w->loop->reload_flag) {
            *w->loop->reload_flag = 0;
            worker_apply_reload(w);
            }

        /* ── Process memory limits (~2 s, worker 0 only) ──────────────────
         * Reads RSS from /proc/self/status (cheap, but still not something
         * every worker needs to do every tick), updates the metrics gauge,
         * and:
         *   - soft limit exceeded: sets memory_reject_new_conns so every
         *     worker's accept path (not just worker 0's) starts declining
         *     new connections. Cleared again once RSS drops back below the
         *     soft limit -- this is a level-triggered gate, not a one-shot.
         *   - hard limit exceeded: triggers the same graceful-drain path
         *     as SIGTERM/SIGINT (g_drain_flag), expecting a process
         *     supervisor to restart routa afterward. Only fires once per
         *     process lifetime in practice, since drain leads to exit. */
        if (w->worker_id == 0 && w->loop &&
            (w->loop->memory_soft_limit_mb > 0 || w->loop->memory_hard_limit_mb > 0) &&
            now_ms - w->loop->last_memory_check_ms >= 2000) {
            w->loop->last_memory_check_ms = now_ms;
            routa_metrics_update_rss();
            uint64_t rss_mb = ROUTA_METRIC_GET(process_rss_bytes) / (1024ULL * 1024ULL);

            if (w->loop->memory_hard_limit_mb > 0 &&
                rss_mb >= (uint64_t)w->loop->memory_hard_limit_mb) {
                LOG_WARN("Memory hard limit exceeded (%llu MB >= %d MB), "
                         "triggering graceful shutdown",
                         (unsigned long long)rss_mb, w->loop->memory_hard_limit_mb);
                ROUTA_METRIC_INC(memory_hard_limit_exceeded_total);
                extern atomic_int g_drain_flag;
                atomic_store_explicit(&g_drain_flag, 1, memory_order_relaxed);
            } else if (w->loop->memory_soft_limit_mb > 0) {
                int was_rejecting = __atomic_load_n(&w->loop->memory_reject_new_conns, __ATOMIC_RELAXED);
                int should_reject = rss_mb >= (uint64_t)w->loop->memory_soft_limit_mb;
                if (should_reject && !was_rejecting) {
                    LOG_WARN("Memory soft limit exceeded (%llu MB >= %d MB), "
                             "rejecting new connections until it clears",
                             (unsigned long long)rss_mb, w->loop->memory_soft_limit_mb);
                    ROUTA_METRIC_INC(memory_soft_limit_exceeded_total);
                } else if (!should_reject && was_rejecting) {
                    LOG_INFO("Memory back under soft limit (%llu MB < %d MB), "
                             "accepting new connections again",
                             (unsigned long long)rss_mb, w->loop->memory_soft_limit_mb);
                }
                __atomic_store_n(&w->loop->memory_reject_new_conns, should_reject, __ATOMIC_RELAXED);
            }
        }

        /* ── Upstream idle connection reaper (~30 s, worker 0 only) ── */
        if (w->worker_id == 0 && w->lb &&
            now_ms - last_idle_reap_ms >= 30000) {
            upstream_pool_t *_pool = lb_get_pool(w->lb);
            if (_pool) {
                for (int _pi = 0; _pi < _pool->node_count; _pi++)
                    upstream_node_reap_idle(_pool->nodes[_pi], 60);
            }
            last_idle_reap_ms = now_ms;
        }

        /* ── Periodic ping + H2 timeout sweep (~1 s) ── */
        if (now_ms - last_ping_sweep_ms >= 1000) {
            /* Previously used a hardcoded ws_config_init() default here
             * (fixed 30s ping interval, 10s timeout, 3 max misses)
             * regardless of ws_ping_interval_ms/ws_ping_timeout_ms/
             * ws_max_ping_misses in the config file. */
            ws_registry_ping_sweep(&w->ws_registry, &w->ws_cfg, now_ms);
            for (int _i = 0; _i < w->active_conn_count; ) {
                conn_t *_c = w->active_conns[_i];
                if (_c->state == CONN_H2 && _c->h2 &&
                    h2_conn_check_timeouts(_c->h2, now_ms) < 0) {
                    h2_conn_flush(_c->h2);
                    conn_close_and_free(w, _c);
                    continue;
                    }
                _i++;
            }

            /* H1 keepalive idle sweep */
            time_t now_sec = (time_t)(now_ms / 1000);
            int ci = 0;
            while (ci < w->active_conn_count) {
                conn_t *_c = w->active_conns[ci];
                if (_c->state == CONN_READING &&
                    _c->keepalive_deadline > 0 &&
                    now_sec > _c->keepalive_deadline) {
                    LOG_DEBUG("h1: keepalive timeout fd=%d", _c->fd);
                    conn_close_and_free(w, _c);
                    continue;
                }
                ci++;
            }

            /* H1 request_timeout_ms sweep: caps how long a request may
             * take from the moment its headers finished parsing
             * (conn->last_start_us) until a response is fully sent. Only
             * applies while actively processing a request -- CONN_READING
             * (idle, waiting for the next request on a keep-alive conn)
             * is governed by keepalive_deadline above, not this. Without
             * this, a handler or upstream that never completes (e.g. a
             * hung proxy_ctx) can hold a connection/slot open forever. */
            if (w->request_timeout_ms > 0) {
                int ri = 0;
                while (ri < w->active_conn_count) {
                    conn_t *_c = w->active_conns[ri];
                    int in_flight = (_c->state == CONN_WRITING ||
                                     _c->state == CONN_SENDFILE ||
                                     _c->state == CONN_UPSTREAM_CONNECTING ||
                                     _c->state == CONN_UPSTREAM_WRITING);
                    if (in_flight && _c->last_start_us > 0) {
                        uint64_t elapsed_ms = (now_ms > _c->last_start_us / 1000)
                            ? (now_ms - _c->last_start_us / 1000) : 0;
                        if (elapsed_ms > (uint64_t)w->request_timeout_ms) {
                            LOG_WARN("request_timeout: fd=%d elapsed=%lums (limit=%dms)",
                                     _c->fd, (unsigned long)elapsed_ms, w->request_timeout_ms);
                            conn_close_and_free(w, _c);
                            continue;
                        }
                    }
                    ri++;
                }
            }

            /* Upstream (H1) read/write timeout sweep -- see
             * proxy_check_upstream_timeouts() in proxy.c for the full
             * rationale. H2 upstream connections (shared h2up_conn_t, not
             * per-request) are not covered here yet -- see roadmap. */
            {
                int wi = 0;
                while (wi < w->active_conn_count) {
                    conn_t *_c = w->active_conns[wi];
                    if (proxy_check_upstream_timeout(w, _c, now_ms)) {
                        continue;   /* _c was closed; don't advance wi */
                    }
                    wi++;
                }
            }

            last_ping_sweep_ms = now_ms;
        }
    }

    /* Force-close any remaining connections */
    for (int i = 0; i < w->active_conn_count; i++) {
        conn_t *c = w->active_conns[i];
        poller_del(w->poller, c->fd);
        if (c->sendfile_fd >= 0) { close(c->sendfile_fd); c->sendfile_fd = -1; }
        if (c->proxy && c->proxy->upstream_fd >= 0)
            poller_del(w->poller, c->proxy->upstream_fd);
        if (c->proxy_map) {
            proxy_stream_map_t *pm = c->proxy_map;
            for (int pi = 0; pi < pm->count; pi++)
                if (pm->ctxs[pi]->upstream_fd >= 0)
                    poller_del(w->poller, pm->ctxs[pi]->upstream_fd);
        }
        /* upstream fds are closed by conn_free → proxy_conn_cleanup */
        if (c->tls) tls_shutdown(c->tls);
        if (c->h2 && c->h2->write_buf.len > 0) h2_conn_flush(c->h2);
        shutdown(c->fd, SHUT_WR);
        net_close(c->fd);
        conn_reset_write_state(c);
        if (c->h2)  { h2_conn_free(c->h2);  c->h2  = NULL; }
        if (c->tls) { tls_conn_free(c->tls); c->tls = NULL; }
        proxy_conn_cleanup(c);
        buf_free(&c->read_buf);
        buf_free(&c->write_buf);
        buf_free(&c->hdr_buf);
        routa_metrics_conn_close();
        if (c->from_slab && w->slab) {
            c->recv_buf = NULL;
            c->send_buf = NULL;
            conn_slab_release(w->slab, c);
        } else {
            free(c->recv_buf);
            free(c->send_buf);
            free(c);
        }
    }
    /* Close all H2 upstream connections owned by this worker */
    for (int i = 0; i < w->h2up_count; i++) {
        h2up_conn_t *h2up = w->h2up_conns[i];
        if (!h2up) continue;
        poller_del(w->poller, h2up->fd);
        h2up_conn_close(h2up, w);
        h2up_conn_free(h2up);
    }
    free(w->h2up_conns);
    w->h2up_conns = NULL;
    w->h2up_count = 0;
    w->h2up_cap   = 0;

    if (w->server_fd >= 0) net_close(w->server_fd);
    poller_free(w->poller);
    free((void *)w->active_conns);
    if (w->slab) { conn_slab_free(w->slab); w->slab = NULL; }
    return NULL;
}


/* ── Public API ─────────────────────────────────────────────────────────────*/

void event_loop_run(event_loop_t *loop) {
    if (!loop) return;
    signal(SIGPIPE, SIG_IGN);
    LOG_INFO("\nEvent loop started\n");
    for (int i = 0; i < loop->n_workers; i++) {
        worker_t *w           = &loop->workers[i];
        w->port               = loop->port;
        w->max_connections    = loop->max_connections;
        w->keepalive_timeout_ms = loop->keepalive_timeout_ms > 0 ? loop->keepalive_timeout_ms : 30000;
        w->request_timeout_ms   = loop->request_timeout_ms   > 0 ? loop->request_timeout_ms   : 10000;
        w->socket_recv_buf_size  = loop->socket_recv_buf_size;
        w->socket_send_buf_size  = loop->socket_send_buf_size;
        w->tls_ctx            = loop->tls_ctx;
        w->router             = g_router;
        w->chain              = g_chain;
        w->lb                 = loop->lb;   /* legacy mirror, last pool added */
        w->lb_count           = loop->lb_count;
        for (int _li = 0; _li < loop->lb_count; _li++) w->lbs[_li] = loop->lbs[_li];
        w->should_stop        = 0;
        w->draining           = 0;
        w->worker_id          = i;
        w->loop               = loop;
        w->shutdown_timeout_ms = loop->shutdown_timeout_ms;
        w->h2_cfg             = loop->h2_cfg;
        w->ws_cfg             = loop->ws_cfg;
pthread_create(&w->thread, NULL, worker_run, w);

#ifdef __linux__
        /* CPU affinity: pin worker i to core (start_core + i), wrapping
         * around the number of online CPUs if there are more workers
         * than cores. Improves cache locality and reduces cross-core
         * migration jitter on multi-core machines; on single-core or
         * low-core-count machines this is a no-op in practice (every
         * worker ends up sharing the same small set of cores anyway). */
        if (loop->cpu_affinity_enabled) {
            int target_core = -1;
#ifdef ROUTA_NUMA
            if (loop->numa_aware_enabled && numa_is_available()) {
                target_core = numa_pick_core_for_worker(i, loop->n_workers,
                                                        loop->cpu_affinity_start_core);
            }
#endif
            if (target_core < 0) {
                /* Plain round-robin fallback: NUMA disabled, unavailable
                 * (single-node system, or not built with ROUTA_NUMA), or
                 * numa_pick_core_for_worker() itself declined (returned
                 * -1). Same behavior as before NUMA support existed. */
                long n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
                if (n_cpus > 0)
                    target_core = (loop->cpu_affinity_start_core + i) % (int)n_cpus;
            }
            if (target_core >= 0) {
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(target_core, &cpuset);
                int rc = pthread_setaffinity_np(w->thread, sizeof(cpu_set_t), &cpuset);
                if (rc != 0) {
                    LOG_WARN("worker %d: pthread_setaffinity_np failed (core %d): %s",
                             i, target_core, strerror(rc));
                }
            }
        }
#endif
    }
    for (int i = 0; i < loop->n_workers; i++)
        pthread_join(loop->workers[i].thread, NULL);
    LOG_INFO("Event loop stopped");
}

event_loop_t *event_loop_new(int port, int n_threads) {
    event_loop_t *loop = calloc(1, sizeof(event_loop_t));
    if (!loop) { LOG_ERROR("Failed to allocate event loop"); return NULL; }
    loop->port                = port;
    loop->n_workers           = n_threads;
    loop->max_connections     = 10000;
    loop->shutdown_timeout_ms = 30000;
    loop->workers             = calloc((size_t)n_threads, sizeof(worker_t));
    if (!loop->workers)       { free(loop); return NULL; }
    for (int i = 0; i < n_threads; i++) {
        loop->workers[i].ws_notify_fd = -1;
        loop->workers[i].ws_notify_write_fd = -1;
    }
    pthread_rwlock_init(&loop->tls_reload_lock, NULL);
    return loop;
}

void event_loop_add_route(event_loop_t *loop, const char *path,
                          int methods, route_handler_t handler, void *ctx) {
    (void)loop;
    if (!g_router) {
        g_router = router_new();
        if (!g_router) { LOG_ERROR("Failed to create router"); return; }
    }
    router_add(g_router, path, methods, handler, ctx);
}

void event_loop_set_tls(event_loop_t *loop,
                        const char *cert_file, const char *key_file) {
    if (!loop || !cert_file || !key_file) return;
    loop->tls_ctx = tls_context_new(cert_file, key_file);
}

void event_loop_set_lb(event_loop_t *loop, lb_t *lb) {
    if (!loop || !lb) return;
    /* Legacy mirror: always the most recently added pool. */
    loop->lb = lb;
    /* Avoid adding the same lb_t twice (server_lb_route() may be called
     * once per pool, but guard anyway in case of a duplicate call). */
    for (int i = 0; i < loop->lb_count; i++) {
        if (loop->lbs[i] == lb) return;
    }
    if (loop->lb_count < ROUTA_MAX_LB_POOLS) {
        loop->lbs[loop->lb_count++] = lb;
    } else {
        LOG_ERROR("event_loop_set_lb: max %d LB pools exceeded", ROUTA_MAX_LB_POOLS);
    }
}

void event_loop_set_chain(event_loop_t *loop, middleware_chain_t *chain) {
    (void)loop; g_chain = chain;
}

void event_loop_set_max_connections(event_loop_t *loop, int max_connections) {
    if (loop) loop->max_connections = max_connections;
}

void event_loop_set_timeouts(event_loop_t *loop, int keepalive_timeout_ms,
                             int request_timeout_ms) {
    if (!loop) return;
    loop->keepalive_timeout_ms = keepalive_timeout_ms > 0 ? keepalive_timeout_ms : 30000;
    loop->request_timeout_ms   = request_timeout_ms   > 0 ? request_timeout_ms   : 10000;
}

void event_loop_set_socket_buffers(event_loop_t *loop, int recv_buf_size, int send_buf_size) {
    if (!loop) return;
    loop->socket_recv_buf_size = recv_buf_size;
    loop->socket_send_buf_size = send_buf_size;
}

void event_loop_set_cpu_affinity(event_loop_t *loop, int enabled, int start_core) {
    if (!loop) return;
    loop->cpu_affinity_enabled   = enabled;
    loop->cpu_affinity_start_core = start_core;
}

void event_loop_set_numa_aware(event_loop_t *loop, int enabled) {
    if (!loop) return;
    loop->numa_aware_enabled = enabled;
}

void event_loop_set_memory_limits(event_loop_t *loop, int soft_limit_mb, int hard_limit_mb) {
    if (!loop) return;
    loop->memory_soft_limit_mb = soft_limit_mb;
    loop->memory_hard_limit_mb = hard_limit_mb;
}

void event_loop_free(event_loop_t *loop) {
    if (!loop) return;
    if (g_router)     { router_free(g_router); g_router = NULL; }
    g_chain = NULL;
    if (loop->tls_ctx){ tls_context_free(loop->tls_ctx); loop->tls_ctx = NULL; }
    if (g_ws_handlers) {
        free(g_ws_handlers);
        g_ws_handlers      = NULL;
        g_ws_handler_count = 0;
    }
    pthread_rwlock_destroy(&loop->tls_reload_lock);
    free(loop->workers);
    free(loop);
}

void event_loop_stop(event_loop_t *loop) {
    if (!loop) return;
    loop->should_stop = 1;
    for (int i = 0; i < loop->n_workers; i++)
        loop->workers[i].should_stop = 1;
}

void event_loop_drain_start(event_loop_t *loop) {
    if (!loop) return;
    /* Atomic gate: only the first caller proceeds; others return immediately */
    int expected = 0;
    if (!__atomic_compare_exchange_n(&loop->draining, &expected, 1, 0,
                                     __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        return;
    for (int i = 0; i < loop->n_workers; i++)
        __atomic_store_n(&loop->workers[i].draining, 1, __ATOMIC_RELAXED);
    LOG_INFO("Graceful shutdown initiated (timeout %d ms)",
             loop->shutdown_timeout_ms);
}

void event_loop_set_config_reload(event_loop_t *loop,
                                  volatile sig_atomic_t *flag,
                                  const char *path) {
    if (!loop) return;
    loop->reload_flag = flag;
    if (path)
        strncpy(loop->config_path, path, sizeof(loop->config_path) - 1);
}

void event_loop_set_middleware_reload_indices(
        event_loop_t *loop,
        int acl_idx, int cors_idx, int basic_auth_idx,
        int jwt_auth_idx, int rate_limit_idx, int compress_idx) {
    if (!loop) return;
    loop->reload_acl_idx        = acl_idx;
    loop->reload_cors_idx       = cors_idx;
    loop->reload_basic_auth_idx = basic_auth_idx;
    loop->reload_jwt_auth_idx   = jwt_auth_idx;
    loop->reload_rate_limit_idx = rate_limit_idx;
    loop->reload_compress_idx   = compress_idx;
}

void event_loop_set_shutdown_timeout(event_loop_t *loop, int ms) {
    if (!loop || ms <= 0) return;
    loop->shutdown_timeout_ms = ms;
}
