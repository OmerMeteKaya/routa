#ifndef ROUTA_CORE_EVENT_LOOP_H
#define ROUTA_CORE_EVENT_LOOP_H

#include <pthread.h>
#include "core/conn.h"
#include "http/router.h"
#include "net/poller.h"
#include "net/tls.h"
#include "http/middleware.h"
#include "http/ws.h"
#include "lb/lb.h"
#include "net/uring.h"
#include "core/config.h"

#if defined(__linux__) && defined(ROUTA_IO_URING)
#include "net/uring.h"
#endif

typedef struct event_loop event_loop_t;
typedef struct worker     worker_t;

struct worker {
    int             server_fd;
    poller_t       *poller;
    conn_t        **active_conns;
    int             active_conn_count;
    int             max_connections;
    int             should_stop;
    int             port;
    tls_context_t  *tls_ctx;
    router_t       *router;
    middleware_chain_t *chain;
    pthread_t       thread;

    /* Load balancer — shared across workers, thread-safe internally */
    lb_t           *lb;

    /* io_uring (optional) */
   // uring_t        *uring;
    uint8_t        *recv_bufs;
    uint8_t        *send_bufs;

    /* ── WebSocket ──────────────────────────────────────────────────────
     *
     * ws_registry   — owned exclusively by this worker thread, no lock.
     * ws_notify_fd  — eventfd written by ws_broadcast from any thread;
     *                 this worker watches it in epoll/kqueue.
     * ws_broadcast_queue — mutex-protected; producer is any caller of
     *                 ws_broadcast, consumer is this worker thread.
     * ----------------------------------------------------------------- */
    ws_registry_t    ws_registry;
    int              ws_notify_fd;       /* eventfd fd, -1 if disabled     */
    ws_msg_queue_t   ws_broadcast_queue;

    /* Per-route WebSocket handler table (mirrors router, WS paths only) */
    ws_handler_t   **ws_handlers;        /* indexed same as router routes  */
    int              ws_handler_count;

    /* h2 */
    routa_h2_config_t h2_cfg;
};

event_loop_t *event_loop_new(int port, int n_threads);
void          event_loop_run(event_loop_t *loop);
void          event_loop_stop(event_loop_t *loop);
void          event_loop_free(event_loop_t *loop);
int event_loop_broadcast(event_loop_t *loop,
                         const uint8_t *data, size_t len,
                         ws_opcode_t opcode);
void          event_loop_add_route(event_loop_t *loop, const char *path,
                                   int methods, route_handler_t handler,
                                   void *ctx);

/* Register a WebSocket handler for a path.
 * The handler is copied — caller may free the original after this call.  */
void          event_loop_add_ws_route(event_loop_t *loop, const char *path,
                                      const ws_handler_t *handler);

void          event_loop_set_tls(event_loop_t *loop,
                                 const char *cert_file, const char *key_file);
void          event_loop_set_chain(event_loop_t *loop,
                                   middleware_chain_t *chain);
void          event_loop_set_max_connections(event_loop_t *loop,
                                             int max_connections);
void          event_loop_set_lb(event_loop_t *loop, lb_t *lb);
tls_context_t *event_loop_get_tls_ctx(event_loop_t *loop);

void event_loop_set_h2_config(event_loop_t *loop,
                               const routa_h2_config_t *cfg);

#endif /* ROUTA_CORE_EVENT_LOOP_H */