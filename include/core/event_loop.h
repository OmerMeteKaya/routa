#ifndef ROUTA_CORE_EVENT_LOOP_H
#define ROUTA_CORE_EVENT_LOOP_H

#include "conn.h"
#include "http/router.h"
#include "net/epoll.h"
#include "net/tls.h"

typedef struct event_loop event_loop_t;
typedef struct worker worker_t;

/* Each worker has its own epoll + server socket + conn tracking */
struct worker {
    int            server_fd;
    epoll_t        ep;
    conn_t        *active_conns[10000];
    int            active_conn_count;
    int            should_stop;
    int            port;
    tls_context_t *tls_ctx;   /* shared, not owned */
    router_t      *router;    /* shared, not owned */
    pthread_t      thread;
};

event_loop_t *event_loop_new(int port, int n_threads);
void          event_loop_run(event_loop_t *loop);
void          event_loop_stop(event_loop_t *loop);
void          event_loop_add_route(event_loop_t *loop, const char *path,
                                   int methods, route_handler_t handler, void *ctx);
void          event_loop_free(event_loop_t *loop);
void          event_loop_set_tls(event_loop_t *loop,
                                 const char *cert_file, const char *key_file);

#endif // ROUTA_CORE_EVENT_LOOP_H
