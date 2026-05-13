#ifndef ROUTA_CORE_EVENT_LOOP_H
#define ROUTA_CORE_EVENT_LOOP_H

#include <pthread.h>
#include "core/conn.h"
#include "http/router.h"
#include "net/poller.h"
#include "net/tls.h"
#include "http/middleware.h"
#include "net/uring.h"

#if defined(__linux__) && defined(ROUTA_IO_URING)
#include "net/uring.h"
#endif

typedef struct event_loop event_loop_t;
typedef struct worker     worker_t;

struct worker {
    int            server_fd;
    poller_t      *poller;
    conn_t       **active_conns;   /* heap allocated, size = max_connections */
    int            active_conn_count;
    int            max_connections;
    int            should_stop;
    int            port;
    tls_context_t *tls_ctx;
    router_t      *router;
    middleware_chain_t *chain;
    pthread_t      thread;
    uint8_t *send_bufs;
//#if defined(__linux__) && defined(ROUTA_IO_URING)
    uring_t   *uring;
    uint8_t   *recv_bufs;   /* pre-allocated recv buffers: pool_sz * RECV_BUF_SZ */
//#endif
};

event_loop_t *event_loop_new(int port, int n_threads);
void          event_loop_run(event_loop_t *loop);
void          event_loop_stop(event_loop_t *loop);
void          event_loop_free(event_loop_t *loop);
void          event_loop_add_route(event_loop_t *loop, const char *path,
                                   int methods, route_handler_t handler,
                                   void *ctx);
void          event_loop_set_tls(event_loop_t *loop,
                                 const char *cert_file, const char *key_file);
void          event_loop_set_chain(event_loop_t *loop, middleware_chain_t *chain);
void          event_loop_set_max_connections(event_loop_t *loop, int max_connections);
tls_context_t *event_loop_get_tls_ctx(event_loop_t *loop);

#endif /* ROUTA_CORE_EVENT_LOOP_H */
