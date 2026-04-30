#ifndef ROUTA_CORE_EVENT_LOOP_H
#define ROUTA_CORE_EVENT_LOOP_H

#include "http/router.h"

typedef struct event_loop event_loop_t;

event_loop_t *event_loop_new(int port, int n_threads);
void          event_loop_run(event_loop_t *loop);
void          event_loop_stop(event_loop_t *loop);
void          event_loop_add_route(event_loop_t *loop, const char *path,
                                   int methods, route_handler_t handler, void *ctx);
void          event_loop_free(event_loop_t *loop);

#endif // ROUTA_CORE_EVENT_LOOP_H
