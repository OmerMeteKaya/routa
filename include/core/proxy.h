#ifndef ROUTA_CORE_PROXY_H
#define ROUTA_CORE_PROXY_H

#include "util/buf.h"
#include "lb/lb.h"
#include "lb/upstream.h"
#include <stdint.h>
#include <stddef.h>
#include "http/request.h"
#include <string.h>

struct conn;
struct worker;
struct h2_conn;

/* Magic value at the start of proxy_ctx_t so the event loop can distinguish
 * upstream-fd events (ptr = proxy_ctx_t*) from client-fd events (ptr = conn_t*). */
#define PROXY_CTX_MAGIC  0x50524F58u   /* 'PROX' */

/* Explicit upstream state — used instead of conn->state for H2 connections so
 * the frontend H2 state (CONN_H2) is never overwritten by the proxy machine. */
typedef enum {
    PROXY_STATE_CONNECTING = 0,
    PROXY_STATE_WRITING,
    PROXY_STATE_READING,
} proxy_state_t;

typedef struct proxy_ctx {
    /* MUST be the first field — the event loop reads magic to tag the ptr  */
    uint32_t          magic;           /* PROXY_CTX_MAGIC                   */
    struct conn      *conn;            /* owning connection (back-pointer)   */

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
    int               resp_head_done;       /* headers fully received        */
    long long         resp_content_length;  /* -1 = unknown/chunked          */
    size_t            resp_body_received;   /* bytes received so far         */

    proxy_state_t     upstream_state;       /* connecting / writing / reading */
} proxy_ctx_t;

/* Per-stream proxy context map for H2 — one ctx per concurrent stream.
 * H1 connections use the single conn->proxy pointer instead.                */
#define PROXY_STREAM_MAP_SIZE 64  /* covers h2load -m50 and typical production concurrency */

typedef struct proxy_stream_map {
    uint32_t      stream_ids[PROXY_STREAM_MAP_SIZE];
    proxy_ctx_t  *ctxs[PROXY_STREAM_MAP_SIZE];
    int           count;
} proxy_stream_map_t;

proxy_ctx_t *proxy_ctx_new(lb_t *lb, struct conn *conn);
void         proxy_ctx_free(proxy_ctx_t *ctx);
void         proxy_conn_cleanup(struct conn *conn);

/* H2 stream map API */
proxy_ctx_t *proxy_stream_get(struct conn *conn, uint32_t stream_id, lb_t *lb);
void         proxy_stream_remove(struct conn *conn, uint32_t stream_id);
void         proxy_stream_map_free(struct conn *conn);

/* stream_id: 0 for H1, non-zero for H2 per-stream dispatch */
int proxy_begin(struct worker *w, struct conn *conn,
                const http_request_t *req, uint32_t stream_id);

/* ctx: the specific proxy_ctx_t whose upstream fd fired */
int proxy_on_upstream_writable(struct worker *w, struct conn *conn,
                               proxy_ctx_t *ctx);
int proxy_on_upstream_readable(struct worker *w, struct conn *conn,
                               proxy_ctx_t *ctx);

#endif /* ROUTA_CORE_PROXY_H */