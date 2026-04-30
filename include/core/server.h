#ifndef ROUTA_CORE_SERVER_H
#define ROUTA_CORE_SERVER_H

#include "http/router.h"

struct event_loop;

typedef struct {
    struct event_loop *loop;
} server_t;

server_t *server_new(int port, int n_threads);
void      server_run(server_t *s);
void      server_free(server_t *s);
void      server_route(server_t *s, const char *path, int methods,
                       route_handler_t handler, void *ctx);

// convenience macros:
#define HTTP_GET_M     (1 << HTTP_GET)
#define HTTP_POST_M    (1 << HTTP_POST)
#define HTTP_PUT_M     (1 << HTTP_PUT)
#define HTTP_DELETE_M  (1 << HTTP_DELETE)
#define HTTP_HEAD_M    (1 << HTTP_HEAD)

#endif // ROUTA_CORE_SERVER_H
