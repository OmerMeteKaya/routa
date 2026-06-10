#ifndef ROUTA_CORE_PROXY_H
#define ROUTA_CORE_PROXY_H

#include "util/buf.h"
#include "lb/lb.h"
#include "lb/upstream.h"
#include <stdint.h>
#include <stddef.h>
#include "http/request.h"

struct conn;
struct worker;
struct h2_conn;

typedef struct proxy_ctx {
    int               upstream_fd;
    upstream_node_t  *node;
    upstream_conn_t  *uconn;
    upstream_pool_t  *pool;
    lb_t             *lb;

    buf_t             req_buf;
    size_t            req_sent;
    buf_t             resp_buf;

    struct h2_conn   *front_h2;
    uint32_t          front_stream_id;

    int               attempt;
} proxy_ctx_t;

proxy_ctx_t *proxy_ctx_new(lb_t *lb);
void         proxy_ctx_free(proxy_ctx_t *ctx);
void         proxy_conn_cleanup(struct conn *conn);


int proxy_begin(struct worker *w, struct conn *conn,
                const http_request_t *req);
int proxy_on_upstream_writable(struct worker *w, struct conn *conn);
int proxy_on_upstream_readable(struct worker *w, struct conn *conn);

#endif /* ROUTA_CORE_PROXY_H */