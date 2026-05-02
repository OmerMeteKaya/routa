#ifndef ROUTA_CORE_SERVER_H
#define ROUTA_CORE_SERVER_H

#include "http/router.h"
#include "http/static.h"

struct event_loop;

typedef struct {
    struct event_loop *loop;
    void  *static_configs[16];
    int    static_config_count;
} server_t;

server_t *server_new(int port, int n_threads);
void      server_run(server_t *s);
void      server_free(server_t *s);
void      server_route(server_t *s, const char *path, int methods,
                       route_handler_t handler, void *ctx);
int       server_static(server_t *s, const char *url_prefix,
                        const char *doc_root, int enable_index);
int       server_enable_tls(server_t *s,
                            const char *cert_file, const char *key_file);

// convenience macros:
#define HTTP_GET_M     (1 << HTTP_GET)
#define HTTP_POST_M    (1 << HTTP_POST)
#define HTTP_PUT_M     (1 << HTTP_PUT)
#define HTTP_DELETE_M  (1 << HTTP_DELETE)
#define HTTP_HEAD_M    (1 << HTTP_HEAD)

#endif // ROUTA_CORE_SERVER_H
