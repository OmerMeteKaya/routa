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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define MAX_EVENTS 1024

static router_t *g_router = NULL;

struct event_loop {
    int            port;
    int            n_workers;
    worker_t      *workers;   /* array of n_workers */
    tls_context_t *tls_ctx;
    int            should_stop;
};

static int send_file_tls(worker_t *w, conn_t *conn,
                         int fd, off_t off, size_t len) {
    (void)w;
    char tmp[65536];
    lseek(fd, off, SEEK_SET);
    size_t rem = len;
    while (rem > 0) {
        size_t to_read = rem < sizeof(tmp) ? rem : sizeof(tmp);
        ssize_t n = read(fd, tmp, to_read);
        if (n <= 0) break;
        ssize_t written = tls_write(conn->tls, tmp, (size_t)n);
        if (written < 0) return -1;
        rem -= (size_t)n;
    }
    close(fd);
    return 0;
}

static void handle_events_worker(worker_t *w) {
    poller_event_t events[MAX_EVENTS];
    
    int nfds = poller_wait(w->poller, events, MAX_EVENTS, 100);
    if (nfds < 0) {
        if (!w->should_stop) {
            LOG_ERROR("Poller wait failed");
        }
        return;
    }
    int i;
    for (i = 0; i < nfds; i++) {
        if (events[i].data.ptr == NULL) {
            // Server socket - accept new connection
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(w->server_fd, (struct sockaddr *)&client_addr, &client_len);
            if (client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_ERROR("Accept failed: %s", strerror(errno));
                }
                continue;
            }
            
            // Set non-blocking
            if (net_set_nonblocking(client_fd) < 0) {
                net_close(client_fd);
                continue;
            }
            
            // Get client IP
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            
            // Create connection object
            conn_t *conn = conn_new(client_fd, client_ip, ntohs(client_addr.sin_port));
            if (!conn) {
                net_close(client_fd);
                continue;
            }
            
            // Add to active connections list
            if (w->active_conn_count < 10000) {
                w->active_conns[w->active_conn_count++] = conn;
            } else {
                LOG_WARN("Active connections limit reached, dropping connection");
                conn_free(conn);
                net_close(client_fd);
                continue;
            }
                
            // Set up TLS if enabled
            if (w->tls_ctx) {
                conn->tls = tls_conn_new(w->tls_ctx, client_fd);
                if (!conn->tls) {
                    LOG_ERROR("Failed to create TLS connection");
                    for (int j = 0; j < w->active_conn_count; j++) {
                        if (w->active_conns[j] == conn) {
                            w->active_conns[j] = w->active_conns[--w->active_conn_count];
                            break;
                        }
                    }
                    conn_free(conn);
                    net_close(client_fd);
                    continue;
                }
                conn->state = CONN_TLS_HANDSHAKE;
                // Add to poller for TLS handshake
                if (poller_add(w->poller, client_fd, POLLER_READ | POLLER_ET, conn) < 0) {
                    LOG_ERROR("Failed to add TLS client to poller");
                    for (int j = 0; j < w->active_conn_count; j++) {
                        if (w->active_conns[j] == conn) {
                            w->active_conns[j] = w->active_conns[--w->active_conn_count];
                            break;
                        }
                    }
                    conn_free(conn);
                    net_close(client_fd);
                    continue;
                }
            } else {
                // Add to poller for plain HTTP
                if (poller_add(w->poller, client_fd, POLLER_READ | POLLER_ET, conn) < 0) {
                    LOG_ERROR("Failed to add client to poller");
                    for (int j = 0; j < w->active_conn_count; j++) {
                        if (w->active_conns[j] == conn) {
                            w->active_conns[j] = w->active_conns[--w->active_conn_count];
                            break;
                        }
                    }
                    conn_free(conn);
                    net_close(client_fd);
                    continue;
                }
            }
        } else {
            // Client socket
            conn_t *conn = (conn_t *)events[i].ptr;
            
            if (events[i].events & (POLLER_HUP | POLLER_ERR)) {
                if (conn->state == CONN_TLS_HANDSHAKE) {
                    // Clean up TLS connection
                    epoll_del(&w->ep, conn->fd);
                    // Remove from active connections list
                    for (int j = 0; j < w->active_conn_count; j++) {
                        if (w->active_conns[j] == conn) {
                            w->active_conns[j] =
                                w->active_conns[--w->active_conn_count];
                            break;
                        }
                    }
                    if (conn->tls) {
                        tls_shutdown(conn->tls);
                    }
                    net_close(conn->fd);
                    conn_free(conn);
                    continue;
                } else {
                    conn->state = CONN_CLOSING;
                }
            } else if (events[i].events & EPOLLIN) {
                if (conn->state == CONN_TLS_HANDSHAKE) {
                    // Handle TLS handshake
                    int hs = tls_handshake(conn->tls);
                    switch (hs) {
                        case 0:  // Handshake complete
                            conn->state = CONN_READING;
                            epoll_mod(&w->ep, conn->fd, EPOLLIN | EPOLLET, conn);
                            break;
                        case 1:  // Want read
                            epoll_mod(&w->ep, conn->fd, EPOLLIN | EPOLLET, conn);
                            break;
                        case -1: // Want write
                            epoll_mod(&w->ep, conn->fd, EPOLLOUT | EPOLLET, conn);
                            break;
                        case -2: // Fatal error
                            // Clean up TLS connection
                            epoll_del(&w->ep, conn->fd);
                            // Remove from active connections list
                            for (int j = 0; j < w->active_conn_count; j++) {
                                if (w->active_conns[j] == conn) {
                                    w->active_conns[j] =
                                        w->active_conns[--w->active_conn_count];
                                    break;
                                }
                            }
                            if (conn->tls) {
                                tls_shutdown(conn->tls);
                            }
                            net_close(conn->fd);
                            conn_free(conn);
                            continue;
                    }
                } else {
                    // Read data into buffer
                    ssize_t n = io_read_into_buf(conn->fd, &conn->read_buf, conn->tls);
                    if (n < 0) {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    if (n == 0) {
                        /* client closed connection */
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                    if (conn->read_buf.len == 0) {
                        continue;
                    }
                
                    // Parse HTTP request
                    http_request_t req;
                    size_t consumed = 0;
                    int parse_result = http_request_parse(&req, &conn->read_buf, &consumed);

                    if (parse_result == 1) {
                        // Incomplete request, wait for more data
                        continue;
                    } else if (parse_result == -1) {
                        // Malformed request, send 400
                        buf_reset(&conn->write_buf);
                        http_response_simple(&conn->write_buf, 400, "Bad Request",
                                            "text/plain", "Bad Request\n");
                        conn->keep_alive = 0; // Close connection after error
                        goto handle_state;
                    }

                    // Save consumed bytes for keep-alive
                    conn->consumed = consumed;

                    // Valid request, process it
                    http_response_t resp;
                    http_response_init(&resp);

                    // Set keep-alive based on request
                    conn->keep_alive = req.keep_alive;

                    int allowed_methods = 0;
                    int dispatch_result = router_dispatch(w->router, &req, &resp, &allowed_methods);

                    if (dispatch_result == -1) {
                        // 404 Not Found
                        http_response_destroy(&resp);
                        http_response_init(&resp);
                        http_response_simple(&conn->write_buf, 404, "Not Found",
                                            "text/plain", "Not Found\n");
                    } else if (dispatch_result == -2) {
                        // 405 Method Not Allowed
                        http_response_destroy(&resp);
                        http_response_init(&resp);
                        http_response_set_status(&resp, 405, "Method Not Allowed");
                        http_response_set_header(&resp, "Connection",
                                               conn->keep_alive ? "keep-alive" : "close");

                        // Build Allow header
                        char allow_header[256] = {0};
                        int first = 1;
                        for (i = 0; i < HTTP_METHOD_UNKNOWN; i++) {
                            if (allowed_methods & (1 << i)) {
                                if (!first) {
                                    strncat(allow_header, ", ", sizeof(allow_header) - strlen(allow_header) - 1);
                                }
                                switch (i) {
                                    case HTTP_GET:
                                        strncat(allow_header, "GET", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_POST:
                                        strncat(allow_header, "POST", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_PUT:
                                        strncat(allow_header, "PUT", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_DELETE:
                                        strncat(allow_header, "DELETE", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_HEAD:
                                        strncat(allow_header, "HEAD", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_PATCH:
                                        strncat(allow_header, "PATCH", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_OPTIONS:
                                        strncat(allow_header, "OPTIONS", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_TRACE:
                                        strncat(allow_header, "TRACE", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                    case HTTP_CONNECT:
                                        strncat(allow_header, "CONNECT", sizeof(allow_header) - strlen(allow_header) - 1);
                                        break;
                                }
                                first = 0;
                            }
                        }

                        http_response_set_header(&resp, "Allow", allow_header);
                        http_response_set_body(&resp, "Method Not Allowed\n", 20);
                        buf_reset(&conn->write_buf);
                        http_response_serialize(&resp, &conn->write_buf);
                    } else {
                        // Success, set connection header and serialize response
                        http_response_set_header(&resp, "Connection",
                                               conn->keep_alive ? "keep-alive" : "close");
                        
                        buf_reset(&conn->write_buf);
                        http_response_serialize(&resp, &conn->write_buf);

                        /* Check if response has a file body for sendfile */
                        if (resp.body_fd >= 0) {
                            if (conn->tls == NULL) {
                                /* Transfer fd ownership to conn */
                                conn->sendfile_fd  = resp.body_fd;
                                conn->sendfile_off = resp.body_fd_off;
                                conn->sendfile_rem = resp.body_fd_len;
                                resp.body_fd = -1;  /* prevent destroy from closing it */
                                io_cork(conn->fd);  /* headers + file in one burst */
                            } else {
                                /* For TLS, we need to send the file through the TLS layer */
                                /* This blocks but TLS file serving is inherently slower */
                                send_file_tls(w, conn, resp.body_fd, resp.body_fd_off, resp.body_fd_len);
                                resp.body_fd = -1;  /* prevent destroy from closing it */
                            }
                        }
                    }

                    http_response_destroy(&resp);
                    http_request_free(&req);
                    conn->state = CONN_WRITING;
                    goto handle_state;
                }
            } else if (events[i].events & EPOLLOUT) {
                if (conn->state == CONN_TLS_HANDSHAKE) {
                    // Handle TLS handshake
                    int hs = tls_handshake(conn->tls);
                    switch (hs) {
                        case 0:  // Handshake complete
                            conn->state = CONN_READING;
                            epoll_mod(&w->ep, conn->fd, EPOLLIN | EPOLLET, conn);
                            break;
                        case 1:  // Want read
                            epoll_mod(&w->ep, conn->fd, EPOLLIN | EPOLLET, conn);
                            break;
                        case -1: // Want write
                            epoll_mod(&w->ep, conn->fd, EPOLLOUT | EPOLLET, conn);
                            break;
                        case -2: // Fatal error
                            // Clean up TLS connection
                            epoll_del(&w->ep, conn->fd);
                            // Remove from active connections list
                            for (int j = 0; j < w->active_conn_count; j++) {
                                if (w->active_conns[j] == conn) {
                                    w->active_conns[j] =
                                        w->active_conns[--w->active_conn_count];
                                    break;
                                }
                            }
                            if (conn->tls) {
                                tls_shutdown(conn->tls);
                            }
                            net_close(conn->fd);
                            conn_free(conn);
                            continue;
                    }
                } else if (conn->state == CONN_SENDFILE) {
                    // Send file data
                    ssize_t n = sendfile(conn->fd, conn->sendfile_fd,
                                         &conn->sendfile_off, conn->sendfile_rem);
                    if (n > 0) {
                        conn->sendfile_rem -= (size_t)n;
                        if (conn->sendfile_rem == 0) {
                            io_uncork(conn->fd);
                            close(conn->sendfile_fd);
                            conn->sendfile_fd = -1;
                            
                            // Transition to keep-alive or closing
                            if (conn->keep_alive) {
                                // Keep connection alive - consume processed request from buffer
                                buf_consume(&conn->read_buf, conn->consumed);
                                conn->consumed = 0;
                                conn->state = CONN_READING;
                                conn->keepalive_deadline = time(NULL) + 30; // Reset timeout
                                epoll_mod(&w->ep, conn->fd, EPOLLIN | EPOLLET, conn);
                            } else {
                                conn->state = CONN_CLOSING;
                                goto handle_state;
                            }
                        }
                    } else if (n < 0 && errno != EAGAIN) {
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                } else {
                    // Write data to client
                    ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf, conn->tls);
                    if (n < 0) {
                        conn->state = CONN_CLOSING;
                    } else if (conn->write_buf.len == 0) {
                        // All data written
                        if (conn->sendfile_fd >= 0) {
                            /* Headers sent, now send file body */
                            conn->state = CONN_SENDFILE;
                            /* stay armed for EPOLLOUT — already set */
                        } else if (conn->keep_alive) {
                            // Keep connection alive - consume processed request from buffer
                            buf_consume(&conn->read_buf, conn->consumed);
                            conn->consumed = 0;
                            conn->state = CONN_READING;
                            conn->keepalive_deadline = time(NULL) + 30; // Reset timeout
                            epoll_mod(&w->ep, conn->fd, EPOLLIN | EPOLLET, conn);
                        } else {
                            // Close connection
                            conn->state = CONN_CLOSING;
                            goto handle_state;
                        }
                    }
                }
            }

            handle_state:
                    // Handle connection state
                    switch (conn->state) {
                case CONN_WRITING: {
                    epoll_mod(&w->ep, conn->fd, EPOLLOUT | EPOLLET, conn);
                    break;
                }

                case CONN_SENDFILE:
                    /* Already armed for EPOLLOUT from previous iteration */
                    epoll_mod(&w->ep, conn->fd, EPOLLOUT | EPOLLET, conn);
                    break;

                case CONN_CLOSING:
                    epoll_del(&w->ep, conn->fd);
                    // Remove from active connections list
                    for (int j = 0; j < w->active_conn_count; j++) {
                        if (w->active_conns[j] == conn) {
                            w->active_conns[j] = 
                                w->active_conns[--w->active_conn_count];
                            break;
                        }
                    }
                    if (conn->tls) {
                        tls_shutdown(conn->tls);
                    }
                    shutdown(conn->fd, SHUT_WR);
                    net_close(conn->fd);
                    conn_free(conn);
                    break;

                default:
                            break;
                    }
        }
    }
}



static void *worker_run(void *arg) {
    worker_t *w = (worker_t *)arg;
    
    /* Each worker creates its own server socket on the same port */
    w->server_fd = net_server_socket(w->port, 128);
    if (w->server_fd < 0) {
        LOG_ERROR("Worker failed to create server socket");
        return NULL;
    }
    
    if (epoll_init(&w->ep) < 0) {
        LOG_ERROR("Worker failed to initialize epoll");
        net_close(w->server_fd);
        return NULL;
    }
    
    if (epoll_add(&w->ep, w->server_fd, EPOLLIN, NULL) < 0) {
        LOG_ERROR("Worker failed to add server socket to epoll");
        net_close(w->server_fd);
        return NULL;
    }
    
    while (!w->should_stop) {
        handle_events_worker(w);
    }
    
    /* cleanup active conns */
    for (int i = 0; i < w->active_conn_count; i++) {
        conn_t *c = w->active_conns[i];
        epoll_del(&w->ep, c->fd);
        if (c->sendfile_fd >= 0) {
            close(c->sendfile_fd);
            c->sendfile_fd = -1;
        }
        if (c->tls) {
            tls_shutdown(c->tls);
        }
        net_close(c->fd);
        conn_free(c);
    }
    w->active_conn_count = 0;
    net_close(w->server_fd);
    
    return NULL;
}

void event_loop_run(event_loop_t *loop) {
    if (!loop) return;

    LOG_INFO("Event loop started");

    for (int i = 0; i < loop->n_workers; i++) {
        worker_t *w = &loop->workers[i];
        w->port      = loop->port;
        w->tls_ctx   = loop->tls_ctx;
        w->router    = g_router;
        w->should_stop = 0;
        pthread_create(&w->thread, NULL, worker_run, w);
    }
    
    /* Wait for all workers */
    for (int i = 0; i < loop->n_workers; i++) {
        pthread_join(loop->workers[i].thread, NULL);
    }

    LOG_INFO("Event loop stopped");
}



event_loop_t *event_loop_new(int port, int n_threads) {
    event_loop_t *loop = calloc(1, sizeof(event_loop_t));
    if (!loop) {
        LOG_ERROR("Failed to allocate event loop");
        return NULL;
    }
    
    loop->port = port;
    loop->n_workers = n_threads;
    loop->workers = calloc((size_t)n_threads, sizeof(worker_t));
    if (!loop->workers) {
        LOG_ERROR("Failed to allocate workers");
        free(loop);
        return NULL;
    }
    
    return loop;
}

void event_loop_add_route(event_loop_t *loop, const char *path,
                          int methods, route_handler_t handler, void *ctx) {
    if (!g_router) {
        g_router = router_new();
        if (!g_router) {
            LOG_ERROR("Failed to create router");
            return;
        }
    }
    
    router_add(g_router, path, methods, handler, ctx);
}

void event_loop_set_tls(event_loop_t *loop,
                        const char *cert_file, const char *key_file) {
    if (!loop || !cert_file || !key_file) {
        return;
    }
    
    loop->tls_ctx = tls_context_new(cert_file, key_file);
}






void event_loop_free(event_loop_t *loop) {
    if (!loop) return;
    
    // Free router
    if (g_router) {
        router_free(g_router);
        g_router = NULL;
    }
    
    // Free TLS context
    if (loop->tls_ctx) {
        tls_context_free(loop->tls_ctx);
    }
    
    // Free workers
    if (loop->workers) {
        free(loop->workers);
    }
    
    free(loop);
}

void event_loop_stop(event_loop_t *loop) {
    if (loop) {
        loop->should_stop = 1;
        for (int i = 0; i < loop->n_workers; i++) {
            loop->workers[i].should_stop = 1;
        }
    }
}
