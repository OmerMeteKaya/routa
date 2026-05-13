#define _GNU_SOURCE
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
#include "net/uring.h"

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

struct event_loop {
    int            port;
    int            n_workers;
    int            max_connections;
    worker_t      *workers;
    tls_context_t *tls_ctx;
    int            should_stop;
};

/* ── Helpers ────────────────────────────────────────────────────────────────*/

static void conn_remove(worker_t *w, conn_t *conn) {
    for (int j = 0; j < w->active_conn_count; j++) {
        if (w->active_conns[j] == conn) {
            w->active_conns[j] = w->active_conns[--w->active_conn_count];
            return;
        }
    }
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

        /* ── Accept ── */
        if (events[i].ptr == NULL) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(w->server_fd,
                                   (struct sockaddr *)&client_addr, &client_len);
            if (client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    LOG_ERROR("Accept failed: %s", strerror(errno));
                continue;
            }

            if (net_set_nonblocking(client_fd) < 0) { net_close(client_fd); continue; }

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

            conn_t *conn = conn_new(client_fd, client_ip, ntohs(client_addr.sin_port));
            if (!conn) { net_close(client_fd); continue; }

            if (w->active_conn_count < w->max_connections) {
                w->active_conns[w->active_conn_count++] = conn;
            } else {
                LOG_WARN("Max connections reached, dropping");
                conn_free(conn); net_close(client_fd); continue;
            }

            if (w->tls_ctx) {
                conn->tls = tls_conn_new(w->tls_ctx, client_fd);
                if (!conn->tls) {
                    LOG_ERROR("Failed to create TLS connection");
                    conn_remove(w, conn); conn_free(conn); net_close(client_fd); continue;
                }
                conn->state = CONN_TLS_HANDSHAKE;
            }

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

            /* TLS handshake */
            if (conn->state == CONN_TLS_HANDSHAKE) {
                int hs = tls_handshake(conn->tls);
                if      (hs ==  0) { conn->state = CONN_READING;
                                     poller_mod(w->poller, conn->fd, POLLER_READ|POLLER_ET, conn); }
                else if (hs ==  1)   poller_mod(w->poller, conn->fd, POLLER_READ|POLLER_ET, conn);
                else if (hs == -1)   poller_mod(w->poller, conn->fd, POLLER_WRITE|POLLER_ET, conn);
                else { /* -2 fatal */
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
                    w->chain->current = 0;
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

            } else {
                /* ── Normal response ── */
                if (w->chain) {
                    w->chain->current = 0;
                    middleware_chain_set_handler(w->chain,
                                                matched_route->handler,
                                                matched_route->ctx);
                    middleware_chain_execute(w->chain, &req, &resp);
                } else {
                    matched_route->handler(&req, &resp, matched_route->ctx);
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

            /* TLS handshake */
            if (conn->state == CONN_TLS_HANDSHAKE) {
                int hs = tls_handshake(conn->tls);
                if      (hs ==  0) { conn->state = CONN_READING;
                                     poller_mod(w->poller, conn->fd, POLLER_READ|POLLER_ET, conn); }
                else if (hs ==  1)   poller_mod(w->poller, conn->fd, POLLER_READ|POLLER_ET, conn);
                else if (hs == -1)   poller_mod(w->poller, conn->fd, POLLER_WRITE|POLLER_ET, conn);
                else {
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
                if (total > 0 && conn->writev_written >= total)
                    write_complete = 1;
                else if (total == 0)
                    write_complete = 1;  /* empty response edge case */
            }

            if (write_complete) {
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
            case CONN_WRITING:
                poller_mod(w->poller, conn->fd, POLLER_WRITE|POLLER_ET, conn);
                break;
            case CONN_SENDFILE:
                poller_mod(w->poller, conn->fd, POLLER_WRITE|POLLER_ET, conn);
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

/* ── epoll worker thread ────────────────────────────────────────────────────*/
static void *worker_run(void *arg) {
    worker_t *w = (worker_t *)arg;

    w->server_fd = net_server_socket(w->port, 128);
    if (w->server_fd < 0) { LOG_ERROR("Worker: server socket failed"); return NULL; }

    w->active_conns = calloc((size_t)w->max_connections, sizeof(conn_t *));
    if (!w->active_conns) { net_close(w->server_fd); return NULL; }

    w->poller = poller_new();
    if (!w->poller) { net_close(w->server_fd); free(w->active_conns); return NULL; }

    if (poller_add(w->poller, w->server_fd, POLLER_READ, NULL) < 0) {
        net_close(w->server_fd); poller_free(w->poller); free(w->active_conns); return NULL;
    }

    while (!w->should_stop) handle_events_worker(w);

    for (int i = 0; i < w->active_conn_count; i++) {
        conn_t *c = w->active_conns[i];
        poller_del(w->poller, c->fd);
        if (c->sendfile_fd >= 0) close(c->sendfile_fd);
        if (c->tls) tls_shutdown(c->tls);
        conn_reset_write_state(c);
        net_close(c->fd);
        conn_free(c);
    }
    net_close(w->server_fd);
    poller_free(w->poller);
    free(w->active_conns);
    return NULL;
}

/* ── io_uring worker (unchanged from original) ──────────────────────────────*/
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

/* ── Public API ─────────────────────────────────────────────────────────────*/

void event_loop_run(event_loop_t *loop) {
    if (!loop) return;
    LOG_INFO("Event loop started");
    for (int i = 0; i < loop->n_workers; i++) {
        worker_t *w    = &loop->workers[i];
        w->port        = loop->port;
        w->max_connections = loop->max_connections;
        w->tls_ctx     = loop->tls_ctx;
        w->router      = g_router;
        w->chain       = g_chain;
        w->should_stop = 0;
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
    loop->port           = port;
    loop->n_workers      = n_threads;
    loop->max_connections = 10000;
    loop->workers        = calloc((size_t)n_threads, sizeof(worker_t));
    if (!loop->workers)  { free(loop); return NULL; }
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
    free(loop->workers);
    free(loop);
}

void event_loop_stop(event_loop_t *loop) {
    if (!loop) return;
    loop->should_stop = 1;
    for (int i = 0; i < loop->n_workers; i++)
        loop->workers[i].should_stop = 1;
}