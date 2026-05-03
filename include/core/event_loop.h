#ifndef ROUTA_CORE_EVENT_LOOP_H
#define ROUTA_CORE_EVENT_LOOP_H

#include <pthread.h>
#include "core/conn.h"
#include "http/router.h"
#include "net/poller.h"
#include "net/tls.h"

typedef struct event_loop event_loop_t;
typedef struct worker     worker_t;

struct worker {
    int            server_fd;
    poller_t      *poller;
    conn_t        *active_conns[10000];
    int            active_conn_count;
    int            should_stop;
    int            port;
    tls_context_t *tls_ctx;
    router_t      *router;
    pthread_t      thread;
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

#endif /* ROUTA_CORE_EVENT_LOOP_H */
