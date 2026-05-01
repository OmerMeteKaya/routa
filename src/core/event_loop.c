#define _GNU_SOURCE
#include "core/event_loop.h"
#include "core/conn.h"
#include "core/threadpool.h"
#include "net/epoll.h"
#include "net/socket.h"
#include "net/io.h"
#include "http/request.h"
#include "http/response.h"
#include "util/logger.h"
#include <sys/epoll.h>
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
    int server_fd;
    epoll_t ep;
    threadpool_t *tp;
    int should_stop;
};

event_loop_t *event_loop_new(int port, int n_threads) {
    event_loop_t *loop = calloc(1, sizeof(event_loop_t));
    if (!loop) {
        LOG_ERROR("Failed to allocate event loop");
        return NULL;
    }
    
    // Create server socket
    loop->server_fd = net_server_socket(port, 128);
    if (loop->server_fd < 0) {
        LOG_ERROR("Failed to create server socket");
        free(loop);
        return NULL;
    }
    
    // Initialize epoll
    if (epoll_init(&loop->ep) < 0) {
        LOG_ERROR("Failed to initialize epoll");
        net_close(loop->server_fd);
        free(loop);
        return NULL;
    }
    
    // Add server socket to epoll
    if (epoll_add(&loop->ep, loop->server_fd, EPOLLIN, NULL) < 0) {
        LOG_ERROR("Failed to add server socket to epoll");
        net_close(loop->server_fd);
        free(loop);
        return NULL;
    }
    
    // Create thread pool
    loop->tp = threadpool_new(n_threads);
    if (!loop->tp) {
        LOG_ERROR("Failed to create thread pool");
        net_close(loop->server_fd);
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




static void handle_events(event_loop_t *loop) {
    struct epoll_event events[MAX_EVENTS];
    
    int nfds = epoll_wait_events(&loop->ep, events, MAX_EVENTS, -1);
    if (nfds < 0) {
        if (!loop->should_stop) {
            LOG_ERROR("Epoll wait failed");
        }
        return;
    }
    int i;
    for (i = 0; i < nfds; i++) {
        if (events[i].data.ptr == NULL) {
            // Server socket - accept new connection
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(loop->server_fd, (struct sockaddr *)&client_addr, &client_len);
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
            
            // Add to epoll
            if (epoll_add(&loop->ep, client_fd, EPOLLIN | EPOLLET, conn) < 0) {
                LOG_ERROR("Failed to add client to epoll");
                conn_free(conn);
                net_close(client_fd);
                continue;
            }
        } else {
            // Client socket
            conn_t *conn = (conn_t *)events[i].data.ptr;
            
            if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                conn->state = CONN_CLOSING;
            } else if (events[i].events & EPOLLIN) {
                // Read data into buffer
                ssize_t n = io_read_into_buf(conn->fd, &conn->read_buf);
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
                int dispatch_result = router_dispatch(g_router, &req, &resp, &allowed_methods);
                
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
                }
                
                http_response_destroy(&resp);
                http_request_free(&req);
                
                conn->state = CONN_WRITING;
            } else if (events[i].events & EPOLLOUT) {
                // Write data to client
                ssize_t n = io_write_from_buf(conn->fd, &conn->write_buf);
                if (n < 0) {
                    conn->state = CONN_CLOSING;
                } else if (conn->write_buf.len == 0) {
                    // All data written
                    if (conn->keep_alive) {
                        // Keep connection alive - consume processed request from buffer
                        buf_consume(&conn->read_buf, conn->consumed);
                        conn->consumed = 0;
                        conn->state = CONN_READING;
                        conn->keepalive_deadline = time(NULL) + 30; // Reset timeout
                        epoll_mod(&loop->ep, conn->fd, EPOLLIN | EPOLLET, conn);
                    } else {
                        // Close connection
                        conn->state = CONN_CLOSING;
                        goto handle_state;
                    }
                }
            }
            
handle_state:
            // Handle connection state
            switch (conn->state) {
                case CONN_WRITING:
                    epoll_mod(&loop->ep, conn->fd, EPOLLOUT | EPOLLET, conn);
                    break;
                    
                case CONN_CLOSING:
                    epoll_del(&loop->ep, conn->fd);
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

void event_loop_run(event_loop_t *loop) {
    if (!loop) return;
    
    LOG_INFO("Event loop started");
    
    while (!loop->should_stop) {
        handle_events(loop);
    }
    
    LOG_INFO("Event loop stopped");
}

void event_loop_free(event_loop_t *loop) {
    if (!loop) return;
    
    // Free thread pool
    if (loop->tp) {
        threadpool_destroy(loop->tp);
    }
    
    // Free router
    if (g_router) {
        router_free(g_router);
        g_router = NULL;
    }
    
    // Close epoll
    // Note: epoll fd is closed when epoll_t is freed
    // Close server socket
    if (loop->server_fd >= 0) {
        net_close(loop->server_fd);
    }
    
    free(loop);
}

void event_loop_stop(event_loop_t *loop) {
    if (loop) {
        loop->should_stop = 1;
    }
}
