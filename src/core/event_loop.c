#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/event_loop.h"
#include "core/conn.h"
#include "net/poller.h"
#include "net/socket.h"
#include "net/io.h"
#include "http/request.h"
#include "http/response.h"
#include "util/logger.h"
#include <sys/sendfile.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include "net/uring.h"
#include "http/ws.h"
#include "http/ws_registry.h"
#include <sys/eventfd.h>
#include "core/config.h"
#include "http/h2.h"


#if defined(__linux__) && defined(ROUTA_IO_URING)
#include "net/uring.h"
#endif

#define MAX_EVENTS        1024
#define SEND_BUF_SZ       131072
#define RECV_BUF_SZ       65536
#define URING_POOL_SZ     8192
#define URING_QUEUE_DEPTH 4096

static router_t           *g_router = NULL;
static middleware_chain_t *g_chain  = NULL;
static ws_handler_t  *g_ws_handlers      = NULL;
static int            g_ws_handler_count = 0;


struct event_loop {
    int            port;
    int            n_workers;
    int            max_connections;
    worker_t      *workers;
    tls_context_t *tls_ctx;
    lb_t          *lb;
    int            should_stop;
    routa_h2_config_t h2_cfg;

    /* Graceful shutdown */
    int            draining;
    int            shutdown_timeout_ms;  /* default: 30000                  */

    /* Hot reload (SIGHUP) — set via event_loop_set_config_reload()         */
    volatile sig_atomic_t *reload_flag;
    char           config_path[512];

    /* Protects tls_ctx pointer during hot reload: readers (accept path)
     * hold rdlock; reloader (worker 0) holds wrlock while swapping.        */
    pthread_rwlock_t tls_reload_lock;
};
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
static ws_handler_t *ws_handler_find(const char *path) {
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

    /* Use the per-route config if set, otherwise fall back to defaults    */
    ws_config_t default_cfg;
    ws_config_init(&default_cfg);
    const ws_config_t *cfg = (handler->cfg.max_frame_size > 0)
                             ? &handler->cfg : &default_cfg;

    int rc = ws_recv(conn, handler, cfg);
    if (rc < 0) {
        ws_registry_remove(&w->ws_registry, conn);
        return -1;
    }
    return 0;
}

tls_context_t *event_loop_get_tls_ctx(event_loop_t *loop) {
    return loop ? loop->tls_ctx : NULL;
}

/* Reset per-response writev state and free owned body */
static void conn_reset_write_state(conn_t *conn) {
    free((void *)conn->resp_body_ptr);
    conn->resp_body_ptr  = NULL;
    conn->resp_body_len  = 0;
    conn->writev_written = 0;
    buf_reset(&conn->hdr_buf);
}

/* TLS sendfile fallback: read file → tls_write */
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
        if (tls_write(conn->tls, tmp, (size_t)n) < 0) { close(fd); return -1; }
        rem -= (size_t)n;
    }
    close(fd);
    return 0;
}

/* ── Build and stash response on conn for writev path ───────────────────────
 *
 * Serializes headers into conn->hdr_buf immediately (not lazily) so that
 * the view passed to io_writev_response doesn't need status/headers.
 * Body is stolen from resp (zero extra malloc).
 */
static void conn_prepare_writev(conn_t *conn, http_response_t *resp) {
    conn_reset_write_state(conn);

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
            /* Refuse new connections during graceful drain */
            if (w->draining) continue;

            struct sockaddr_in client_addr = {0};
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(w->server_fd,
                                   (struct sockaddr *)&client_addr, &client_len);
            if (client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    LOG_ERROR("Accept failed: %s", strerror(errno));
                continue;
            }

            if (net_set_nonblocking(client_fd) < 0) { net_close(client_fd); continue; }

            char client_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

            conn_t *conn = conn_new(client_fd, client_ip, ntohs(client_addr.sin_port));
            if (!conn) { net_close(client_fd); continue; }

            if (w->active_conn_count < w->max_connections) {
                w->active_conns[w->active_conn_count++] = conn;
            } else {
                LOG_WARN("Max connections reached, dropping");
                conn_free(conn); net_close(client_fd); continue;
            }

            /* Use loop->tls_ctx under read-lock so hot-reload can safely
             * swap the SSL_CTX pointer while workers are accepting.         */
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
            continue;
        }

        /* ── Client event ── */
        conn_t *conn = (conn_t *)events[i].ptr;

        /* HUP / ERR */
        if (events[i].events & (POLLER_HUP | POLLER_ERR)) {
            if (conn->state == CONN_TLS_HANDSHAKE) {
                poller_del(w->poller, conn->fd);
                conn_remove(w, conn);
                if (conn->tls) tls_shutdown(conn->tls);
                net_close(conn->fd);
                conn_free(conn);
                continue;
            }
            conn->state = CONN_CLOSING;
            goto handle_state;
        }

        /* ── POLLER_READ ── */
        if (events[i].events & POLLER_READ) {
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
                    if (rrc < 0) {
                        if (conn->h2->write_buf.len > 0) {
                            poller_mod(w->poller, conn->fd,
                                       POLLER_READ | POLLER_WRITE | POLLER_ET,
                                       conn);
                        } else {
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                        continue;
                    }
                }

                if (conn->h2->write_buf.len > 0) {
                    poller_mod(w->poller, conn->fd,
                               POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                } else {
                    poller_mod(w->poller, conn->fd,
                               POLLER_READ | POLLER_ET, conn);
                }
                continue;
            }
            // WebSocket data
            if (conn->state == CONN_WEBSOCKET) {
                ssize_t n = io_read_into_buf(conn->fd, &conn->read_buf, conn->tls);
                if (n == 0) {
                    ws_registry_remove(&w->ws_registry, conn);
                    ws_frame_state_free(&conn->ws_fs);
                    conn->state = CONN_CLOSING;
                    goto handle_state;
                }
                if (n < 0) continue;   /* EAGAIN */
                if (handle_ws_read(w, conn) < 0) {
                    if (conn->write_buf.len > 0) {
                        conn->keep_alive = 0;
                        conn->state = CONN_WEBSOCKET;
                        poller_mod(w->poller, conn->fd,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                    } else {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    continue;
                }
                // Flush any responses (pong, close echo) that ws_recv wrote
                if (conn->write_buf.len > 0) {
                    poller_mod(w->poller, conn->fd,
                               POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                }
                continue;
            }

            /* ── Upstream response reading ── */
            if (conn->state == CONN_UPSTREAM_READING) {
                char tmp[16384];
                ssize_t n = read(conn->upstream_fd, tmp, sizeof(tmp));
                if (n < 0 && errno != EAGAIN) {
                    /* upstream error */
                    poller_del(w->poller, conn->upstream_fd);
                    close(conn->upstream_fd);
                    conn->upstream_fd = -1;
                    if (w->lb)
                        lb_finish_forward(w->lb, &conn->upstream_resp_buf,
                                         NULL,
                                         (upstream_node_t *)conn->upstream_node,
                                         (upstream_conn_t *)conn->upstream_conn,
                                         0);
                    conn->upstream_node = conn->upstream_conn = NULL;
                    buf_reset(&conn->upstream_resp_buf);
                    /* Send 502 */
                    buf_reset(&conn->write_buf);
                    http_response_simple(&conn->write_buf, 502, "Bad Gateway",
                                        "text/plain", "Bad Gateway\n");
                    conn_reset_write_state(conn);
                    conn->state = CONN_WRITING;
                    goto handle_state;
                }
                if (n > 0) {
                    buf_append(&conn->upstream_resp_buf, tmp, (size_t)n);
                }
                if (n == 0 || (n < 0 && errno == EAGAIN)) {
                    /* EOF or no more data — try to parse what we have */
                    if (conn->upstream_resp_buf.len > 0) {
                        /* Remove upstream fd from poller */
                        poller_del(w->poller, conn->upstream_fd);
                        close(conn->upstream_fd);
                        conn->upstream_fd = -1;

                        http_response_t resp;
                        http_response_init(&resp);
                        int ok = (w->lb)
                            ? lb_finish_forward(w->lb,
                                               &conn->upstream_resp_buf,
                                               &resp,
                                               (upstream_node_t *)conn->upstream_node,
                                               (upstream_conn_t *)conn->upstream_conn,
                                               1)
                            : -1;
                        conn->upstream_node = conn->upstream_conn = NULL;
                        buf_reset(&conn->upstream_resp_buf);

                        if (ok < 0) {
                            http_response_destroy(&resp);
                            buf_reset(&conn->write_buf);
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
                        goto handle_state;
                    }
                }
                continue;
            }

            /* TLS handshake */
            if (conn->state == CONN_TLS_HANDSHAKE) {
                int hs = tls_handshake(conn->tls);
                if (hs == 0) {
                    const char *proto = tls_negotiated_protocol(conn->tls);
                    if (proto && strcmp(proto, "h2") == 0) {
                        conn->h2 = h2_conn_new(conn, &w->h2_cfg);
                        if (!conn->h2) {
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                        conn->state = CONN_H2;
                        h2_conn_flush(conn->h2);
                        poller_mod(w->poller, conn->fd,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                    } else {
                        conn->state = CONN_READING;
                        poller_mod(w->poller, conn->fd,
                                   POLLER_READ | POLLER_ET, conn);
                    }
                } else if (hs == 1 || hs == -1) {
                    /* Always watch both during handshake — TLS 1.3 needs it         */
                    poller_mod(w->poller, conn->fd,
                               POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                } else {
                    poller_del(w->poller, conn->fd);
                    conn_remove(w, conn);
                    if (conn->tls) tls_shutdown(conn->tls);
                    net_close(conn->fd); conn_free(conn); continue;
                }
                continue;
            }

            /* Read data */
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
                    memcmp(conn->read_buf.data, H2_PREFACE, 24) == 0) {
                    conn->h2 = h2_conn_new(conn, &w->h2_cfg);
                    if (!conn->h2) {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    conn->state = CONN_H2;
                    h2_conn_flush(conn->h2);
                    poller_mod(w->poller, conn->fd,
                               POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                    continue;
                    }
            }
            
            if (pr == -1) {
                /* 400 — legacy write_buf path */
                buf_reset(&conn->write_buf);
                http_response_simple(&conn->write_buf, 400, "Bad Request",
                                     "text/plain", "Bad Request\n");
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
                    poller_mod(w->poller, conn->fd,
                               POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
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

                    ws_config_t default_cfg;
                    ws_config_init(&default_cfg);
                    const ws_config_t *wscfg = (wsh->cfg.max_frame_size > 0)
                                               ? &wsh->cfg : &default_cfg;

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

                /* ── Async upstream: if handler set upstream_fd via lb ── */
                if (w->lb && resp.status == 0) {
                    /* Handler didn't fill resp — treat as LB proxy request */
                    http_request_free(&req);
                    http_response_destroy(&resp);

                    upstream_node_t *unode = NULL;
                    upstream_conn_t *uconn = NULL;
                    int ufd = lb_begin_forward(w->lb, &req, conn->remote_ip,
                                               &conn->upstream_req_buf,
                                               &unode, &uconn);
                    if (ufd < 0) {
                        buf_reset(&conn->write_buf);
                        http_response_simple(&conn->write_buf, 502,
                                            "Bad Gateway", "text/plain",
                                            "Bad Gateway\n");
                        conn_reset_write_state(conn);
                        conn->state = CONN_WRITING;
                        goto handle_state;
                    }

                    conn->upstream_fd   = ufd;
                    conn->upstream_node = unode;
                    conn->upstream_conn = uconn;
                    conn->upstream_req_sent = 0;
                    buf_reset(&conn->upstream_resp_buf);

                    /* Connect may already be done (loopback) or in progress */
                    conn->state = CONN_UPSTREAM_CONNECTING;
                    poller_add(w->poller, ufd, POLLER_WRITE | POLLER_ET, conn);
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
                        /* TLS: blocking file send, then headers via writev */
                        conn_prepare_writev(conn, &resp);
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
                    poller_mod(w->poller, conn->fd,
                               POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                } else {
                    /* All flushed */
                    if (conn->h2->error) {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
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
                                poller_mod(w->poller, conn->fd,
                                           POLLER_READ | POLLER_WRITE | POLLER_ET,
                                           conn);
                            } else {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            break;
                        }
                    }
                    if (conn->h2->write_buf.len > 0) {
                        poller_mod(w->poller, conn->fd,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                    } else {
                        poller_mod(w->poller, conn->fd,
                                   POLLER_READ | POLLER_ET, conn);
                    }
                }
                continue;
            }
                // WebSocket outbound flush
                if (conn->state == CONN_WEBSOCKET) {
                    ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf, conn->tls);
                    if (n < 0) {
                        ws_registry_remove(&w->ws_registry, conn);
                        ws_frame_state_free(&conn->ws_fs);
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    if (conn->write_buf.len == 0) {
                        // All flushed — back to read-only watch
                        if (conn->ws_state == WS_STATE_CLOSED) {
                            ws_registry_remove(&w->ws_registry, conn);
                            ws_frame_state_free(&conn->ws_fs);
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                        poller_mod(w->poller, conn->fd,
                                   POLLER_READ | POLLER_ET, conn);
                    }
                    continue;
                }

                /* ── Upstream connecting ── */
                if (conn->state == CONN_UPSTREAM_CONNECTING) {
                    if (upstream_conn_check_connected(conn->upstream_fd) < 0) {
                        poller_del(w->poller, conn->upstream_fd);
                        close(conn->upstream_fd);
                        conn->upstream_fd = -1;
                        if (w->lb && conn->upstream_conn)
                            upstream_conn_release(
                                (upstream_conn_t *)conn->upstream_conn, 0);
                        conn->upstream_node = conn->upstream_conn = NULL;
                        buf_reset(&conn->upstream_req_buf);
                        buf_reset(&conn->upstream_resp_buf);
                        buf_reset(&conn->write_buf);
                        http_response_simple(&conn->write_buf, 502, "Bad Gateway",
                                            "text/plain", "Bad Gateway\n");
                        conn_reset_write_state(conn);
                        conn->state = CONN_WRITING;
                        goto handle_state;
                    }
                    /* Connected — transition to writing */
                    conn->state = CONN_UPSTREAM_WRITING;
                    /* fall through to UPSTREAM_WRITING immediately */
                }

                /* ── Upstream writing ── */
                if (conn->state == CONN_UPSTREAM_WRITING) {
                    buf_t *rb = &conn->upstream_req_buf;
                    if (rb->len > 0) {
                        ssize_t n = write(conn->upstream_fd,
                                          rb->data + conn->upstream_req_sent,
                                          rb->len - conn->upstream_req_sent);
                        if (n < 0 && errno != EAGAIN) {
                            poller_del(w->poller, conn->upstream_fd);
                            close(conn->upstream_fd);
                            conn->upstream_fd = -1;
                            buf_reset(&conn->write_buf);
                            http_response_simple(&conn->write_buf, 502, "Bad Gateway",
                                                "text/plain", "Bad Gateway\n");
                            conn_reset_write_state(conn);
                            conn->state = CONN_WRITING;
                            goto handle_state;
                        }
                        if (n > 0) conn->upstream_req_sent += (size_t)n;
                    }

                    if (conn->upstream_req_sent >= rb->len) {
                        /* All sent — wait for response */
                        conn->upstream_req_sent = 0;
                        buf_reset(&conn->upstream_req_buf);
                        conn->state = CONN_UPSTREAM_READING;
                        poller_mod(w->poller, conn->upstream_fd,
                                   POLLER_READ | POLLER_ET, conn);
                    }
                    continue;
                }

                /* TLS handshake */
                if (conn->state == CONN_TLS_HANDSHAKE) {
                    int hs = tls_handshake(conn->tls);
                    if (hs == 0) {
                        const char *proto = tls_negotiated_protocol(conn->tls);
                        if (proto && strcmp(proto, "h2") == 0) {
                            conn->h2 = h2_conn_new(conn, &w->h2_cfg);
                            if (!conn->h2) {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            conn->state = CONN_H2;
                            h2_conn_flush(conn->h2);
                            poller_mod(w->poller, conn->fd,
                                       POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                        } else {
                            conn->state = CONN_READING;
                            poller_mod(w->poller, conn->fd,
                                       POLLER_READ | POLLER_ET, conn);
                        }
                    } else if (hs == 1 || hs == -1) {
                        /* Always watch both during handshake — TLS 1.3 needs it         */
                        poller_mod(w->poller, conn->fd,
                                   POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                    } else {
                        poller_del(w->poller, conn->fd);
                        conn_remove(w, conn);
                        if (conn->tls) tls_shutdown(conn->tls);
                        net_close(conn->fd); conn_free(conn); continue;
                    }
                    continue;
                }

                /* sendfile body */
                if (conn->state == CONN_SENDFILE) {
                    ssize_t n = sendfile(conn->fd, conn->sendfile_fd,
                                         &conn->sendfile_off, conn->sendfile_rem);
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
                                conn->keepalive_deadline = time(NULL) + 30;
                                poller_mod(w->poller, conn->fd, POLLER_READ|POLLER_ET, conn);
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

                        poller_mod(w->poller, conn->fd, POLLER_READ | POLLER_ET, conn);
                        if (conn->read_buf.len > 0) {
                            if (handle_ws_read(w, conn) < 0) {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                            if (conn->write_buf.len > 0) {
                                poller_mod(w->poller, conn->fd,
                                           POLLER_READ | POLLER_WRITE | POLLER_ET, conn);
                            }
                        }
                        continue;
                    }
                    if (conn->sendfile_fd >= 0) {
                        conn->state = CONN_SENDFILE;
                        poller_mod(w->poller, conn->fd, POLLER_WRITE|POLLER_ET, conn);
                    } else if (conn->keep_alive) {
                        buf_consume(&conn->read_buf, conn->consumed);
                        conn->consumed = 0;
                        conn_reset_write_state(conn);
                        buf_reset(&conn->write_buf);
                        conn->state = CONN_READING;
                        conn->keepalive_deadline = time(NULL) + 30;
                        poller_mod(w->poller, conn->fd, POLLER_READ|POLLER_ET, conn);
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
                        poller_mod(w->poller, conn->fd, POLLER_READ | POLLER_ET, conn);
                        break;
            case CONN_WRITING:
            case CONN_SENDFILE:
                        poller_mod(w->poller, conn->fd, POLLER_WRITE | POLLER_ET, conn);
                        break;
            case CONN_CLOSING:
                        poller_del(w->poller, conn->fd);
                        conn_remove(w, conn);
                        if (conn->tls) tls_shutdown(conn->tls);
                        shutdown(conn->fd, SHUT_WR);
                        net_close(conn->fd);
                        conn_reset_write_state(conn);
                        conn_free(conn);
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

    LOG_INFO("hot reload complete");
}

/* ── epoll worker thread ────────────────────────────────────────────────────*/
static void *worker_run(void *arg) {
    worker_t *w = (worker_t *)arg;

    w->server_fd = net_server_socket(w->port, 128);
    if (w->server_fd < 0) { LOG_ERROR("Worker: server socket failed"); return NULL; }

    w->active_conns = (conn_t **)calloc((size_t)w->max_connections, sizeof(conn_t *));
    if (!w->active_conns) { net_close(w->server_fd); return NULL; }

    w->poller = poller_new();
    if (!w->poller) { net_close(w->server_fd); free((void *)w->active_conns); return NULL; }

    if (poller_add(w->poller, w->server_fd, POLLER_READ, NULL) < 0) {
        net_close(w->server_fd); poller_free(w->poller); free((void *)w->active_conns); return NULL;
    }

    ws_registry_init(&w->ws_registry);
    ws_msg_queue_init(&w->ws_broadcast_queue);
    w->ws_notify_fd = ws_notify_fd_create();
    if (w->ws_notify_fd >= 0) {
        poller_add(w->poller, w->ws_notify_fd, POLLER_READ,
                   (void *)(uintptr_t)w->ws_notify_fd);
    }

    uint64_t last_ping_sweep_ms = 0;
    int      drain_init_done    = 0;
    uint64_t drain_start_ms     = 0;

    while (!w->should_stop) {
        handle_events_worker(w);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ms = (uint64_t)ts.tv_sec * 1000
                        + (uint64_t)ts.tv_nsec / 1000000;

        /* ── Graceful drain ── */
        if (w->draining && !drain_init_done) {
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
                if (c->state == CONN_READING    ||
                    c->state == CONN_KEEPALIVE  ||
                    c->state == CONN_TLS_HANDSHAKE) {
                    poller_del(w->poller, c->fd);
                    /* swap-remove to avoid shifting the entire array */
                    w->active_conns[ci] =
                        w->active_conns[--w->active_conn_count];
                    if (c->tls) tls_shutdown(c->tls);
                    net_close(c->fd);
                    conn_reset_write_state(c);
                    conn_free(c);
                    /* do not increment ci — check swapped-in element  */
                } else {
                    ci++;
                }
            }
        }

        if (w->draining && drain_init_done) {
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

        /* ── Hot reload (worker 0 only) ── */
        if (w->worker_id == 0 && w->loop &&
            w->loop->reload_flag && *w->loop->reload_flag) {
            *w->loop->reload_flag = 0;
            worker_apply_reload(w);
        }

        /* ── Periodic ping + H2 timeout sweep (~1 s) ── */
        if (now_ms - last_ping_sweep_ms >= 1000) {
            ws_config_t default_cfg;
            ws_config_init(&default_cfg);
            ws_registry_ping_sweep(&w->ws_registry, &default_cfg, now_ms);
            for (int _i = 0; _i < w->active_conn_count; _i++) {
                conn_t *_c = w->active_conns[_i];
                if (_c->state != CONN_H2 || !_c->h2) continue;
                if (h2_conn_check_timeouts(_c->h2, now_ms) < 0) {
                    h2_conn_flush(_c->h2);
                    _c->state = CONN_CLOSING;
                }
            }
            last_ping_sweep_ms = now_ms;
        }
    }

    /* Force-close any remaining connections */
    for (int i = 0; i < w->active_conn_count; i++) {
        conn_t *c = w->active_conns[i];
        poller_del(w->poller, c->fd);
        if (c->sendfile_fd >= 0) close(c->sendfile_fd);
        if (c->tls) tls_shutdown(c->tls);
        conn_reset_write_state(c);
        net_close(c->fd);
        conn_free(c);
    }
    if (w->server_fd >= 0) net_close(w->server_fd);
    poller_free(w->poller);
    free((void *)w->active_conns);
    return NULL;
}


/* ── io_uring worker ────────────────────────────────────────────────────────*/
#if defined(__linux__) && defined(ROUTA_IO_URING)

static void conn_close_uring(worker_t *w, conn_t *conn) {
    if (conn->closing) return;
    conn->closing = 1;
    if (conn->tls) tls_shutdown(conn->tls);
    if (conn->sendfile_fd >= 0) { close(conn->sendfile_fd); conn->sendfile_fd = -1; }
    if (conn->fd >= 0) { shutdown(conn->fd, SHUT_WR); close(conn->fd); conn->fd = -1; }
    if (conn->pending_io <= 0) { conn_remove(w, conn); conn_free(conn); }
}

static void handle_request_parsing(worker_t *w, conn_t *conn) {
    http_request_t req;
    size_t consumed = 0;
    int pr = http_request_parse(&req, &conn->read_buf, &consumed);

    if (pr == 1) {
        if (!conn->recv_pending) {
            conn->recv_pending = 1;
            if (uring_submit_recv(w->uring, conn, conn->fd,
                                  conn->recv_buf, RECV_BUF_SZ) < 0)
                conn_close_uring(w, conn);
        }
        return;
    }
    if (pr == -1) {
        buf_reset(&conn->write_buf);
        http_response_simple(&conn->write_buf, 400, "Bad Request",
                             "text/plain", "Bad Request\n");
        conn->keep_alive   = 0;
        conn->send_buf_len = conn->write_buf.len;
        memcpy(conn->send_buf, conn->write_buf.data, conn->send_buf_len);
        if (uring_submit_send(w->uring, conn, conn->fd,
                              conn->send_buf, conn->send_buf_len) < 0)
            conn_close_uring(w, conn);
        return;
    }

    conn->consumed   = consumed;
    conn->keep_alive = req.keep_alive;

    http_response_t resp;
    http_response_init(&resp);
    int allowed = 0;
    route_t *route = router_match(w->router, &req, &allowed);

    if (!route && allowed == 0) {
        http_response_simple(&conn->write_buf, 404, "Not Found", "text/plain", "Not Found\n");
    } else if (!route) {
        http_response_set_status(&resp, 405, "Method Not Allowed");
        http_response_set_body(&resp, "Method Not Allowed\n", 20);
        buf_reset(&conn->write_buf);
        http_response_serialize(&resp, &conn->write_buf);
    } else {
        if (w->chain) {
            w->chain->current = 0;
            middleware_chain_set_handler(w->chain, route->handler, route->ctx);
            middleware_chain_execute(w->chain, &req, &resp);
        } else {
            route->handler(&req, &resp, route->ctx);
        }
        http_response_set_header(&resp, "Connection",
                                 conn->keep_alive ? "keep-alive" : "close");
        buf_reset(&conn->write_buf);
        http_response_serialize(&resp, &conn->write_buf);
        if (resp.body_fd >= 0 && !conn->tls) {
            conn->sendfile_fd  = resp.body_fd;
            conn->sendfile_off = resp.body_fd_off;
            conn->sendfile_rem = resp.body_fd_len;
            resp.body_fd = -1;
        }
    }

    http_response_destroy(&resp);
    http_request_free(&req);

    conn->send_buf_len = conn->write_buf.len;
    if (conn->send_buf_len > SEND_BUF_SZ) conn->send_buf_len = SEND_BUF_SZ;
    memcpy(conn->send_buf, conn->write_buf.data, conn->send_buf_len);
    if (uring_submit_send(w->uring, conn, conn->fd,
                          conn->send_buf, conn->send_buf_len) < 0)
        conn_close_uring(w, conn);
}

static void uring_cqe_handler(uring_udata_t *ud, int res,
                               uint32_t flags, void *arg) {
    worker_t *w = (worker_t *)arg;

    if (ud->op == URING_OP_ACCEPT) {
        if (!(flags & IORING_CQE_F_MORE)) uring_submit_accept(w->uring);
        if (res < 0) return;
        conn_t *c = conn_new(res, "unknown", 0);
        if (!c) { close(res); return; }
        c->active = 1;
        w->active_conns[w->active_conn_count++] = c;
        c->recv_pending = 1;
        if (uring_submit_recv(w->uring, c, res, c->recv_buf, RECV_BUF_SZ) < 0)
            conn_close_uring(w, c);
        return;
    }

    conn_t *conn = (conn_t *)ud->conn;
    if (!conn || conn->id != ud->conn_id || !conn->active) {
        uring_udata_put(w->uring, ud); return;
    }
    conn->pending_io--;

    if (res == -EAGAIN || res == -EINTR) {
        if (ud->op == URING_OP_RECV) {
            conn->recv_pending = 1;
            uring_submit_recv(w->uring, conn, conn->fd, conn->recv_buf, RECV_BUF_SZ);
        }
        uring_udata_put(w->uring, ud); return;
    }
    if (conn->closing) {
        if (conn->pending_io <= 0) { conn_remove(w, conn); conn_free(conn); }
        uring_udata_put(w->uring, ud); return;
    }
    switch (ud->op) {
        case URING_OP_RECV:
            if (res <= 0) { conn_close_uring(w, conn); break; }
            buf_append(&conn->read_buf, conn->recv_buf, (size_t)res);
            handle_request_parsing(w, conn);
            break;
        case URING_OP_SEND:
            if (res < 0) { conn_close_uring(w, conn); break; }
            if ((size_t)res < conn->send_buf_len) {
                conn->send_buf_len -= (size_t)res;
                memmove(conn->send_buf, conn->send_buf + res, conn->send_buf_len);
                uring_submit_send(w->uring, conn, conn->fd,
                                  conn->send_buf, conn->send_buf_len);
                break;
            }
            conn->send_buf_len = 0;
            buf_reset(&conn->write_buf);
            if (conn->consumed > 0) { buf_consume(&conn->read_buf, conn->consumed); conn->consumed = 0; }
            if (conn->keep_alive) {
                if (conn->read_buf.len > 0) handle_request_parsing(w, conn);
                else {
                    conn->recv_pending = 1;
                    uring_submit_recv(w->uring, conn, conn->fd, conn->recv_buf, RECV_BUF_SZ);
                }
            } else conn_close_uring(w, conn);
            break;
        case URING_OP_SPLICE:
            if (res < 0) { conn_close_uring(w, conn); break; }
            if (ud->splice_phase == 0) { if (ud->fd >= 0) { close(ud->fd); ud->fd = -1; } break; }
            conn->sendfile_rem -= (size_t)res;
            if (conn->sendfile_rem > 0)
                uring_submit_splice(w->uring, conn, conn->sendfile_fd,
                                    conn->fd, conn->sendfile_rem);
            else {
                close(conn->sendfile_fd); conn->sendfile_fd = -1;
                if (conn->keep_alive) {
                    conn->recv_pending = 1;
                    uring_submit_recv(w->uring, conn, conn->fd, conn->recv_buf, RECV_BUF_SZ);
                } else conn_close_uring(w, conn);
            }
            break;
    }
    uring_udata_put(w->uring, ud);
}

static void *worker_run_uring(void *arg) {
    worker_t *w = (worker_t *)arg;
    w->server_fd = net_server_socket(w->port, 128);
    if (w->server_fd < 0) return NULL;

    w->active_conns = calloc((size_t)w->max_connections, sizeof(conn_t *));
    if (!w->active_conns) { net_close(w->server_fd); return NULL; }

    w->uring = uring_new(w->server_fd, URING_QUEUE_DEPTH, URING_POOL_SZ);
    if (!w->uring) { free(w->active_conns); net_close(w->server_fd); return NULL; }

    while (!w->should_stop) {
        int n = uring_wait(w->uring, uring_cqe_handler, w);
        if (n < 0 && !w->should_stop) LOG_ERROR("uring_wait failed");
    }

    for (int i = 0; i < w->active_conn_count; i++) {
        conn_t *c = w->active_conns[i];
        if (c->tls) tls_shutdown(c->tls);
        if (c->sendfile_fd >= 0) close(c->sendfile_fd);
        net_close(c->fd);
        conn_free(c);
    }
    uring_free(w->uring);
    free(w->active_conns);
    net_close(w->server_fd);
    return NULL;
}

#endif /* ROUTA_IO_URING */

/* ── Public API ─────────────────────────────────────────────────────────────*/

void event_loop_run(event_loop_t *loop) {
    if (!loop) return;
    LOG_INFO("\nEvent loop started\n");
    for (int i = 0; i < loop->n_workers; i++) {
        worker_t *w           = &loop->workers[i];
        w->port               = loop->port;
        w->max_connections    = loop->max_connections;
        w->tls_ctx            = loop->tls_ctx;
        w->router             = g_router;
        w->chain              = g_chain;
        w->lb                 = loop->lb;
        w->should_stop        = 0;
        w->draining           = 0;
        w->worker_id          = i;
        w->loop               = loop;
        w->shutdown_timeout_ms = loop->shutdown_timeout_ms;
        w->h2_cfg             = loop->h2_cfg;
#if defined(__linux__) && defined(ROUTA_IO_URING)
        pthread_create(&w->thread, NULL, worker_run_uring, w);
#else
        pthread_create(&w->thread, NULL, worker_run, w);
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
    for (int i = 0; i < n_threads; i++)
        loop->workers[i].ws_notify_fd = -1;
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
    if (loop) loop->lb = lb;
}

void event_loop_set_chain(event_loop_t *loop, middleware_chain_t *chain) {
    (void)loop; g_chain = chain;
}

void event_loop_set_max_connections(event_loop_t *loop, int max_connections) {
    if (loop) loop->max_connections = max_connections;
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
    loop->draining = 1;
    for (int i = 0; i < loop->n_workers; i++)
        loop->workers[i].draining = 1;
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

void event_loop_set_shutdown_timeout(event_loop_t *loop, int ms) {
    if (!loop || ms <= 0) return;
    loop->shutdown_timeout_ms = ms;
}

