#ifndef ROUTA_NET_H2_CLIENT_H
#define ROUTA_NET_H2_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include "util/buf.h"
#include "net/tls.h"
#include "http/h2_hpack.h"
#include "http/request.h"
#include "http/response.h"

struct worker;
struct upstream_node;
struct proxy_ctx;

/* Magic tag — first field of h2up_conn_t, used by event_loop to distinguish
 * H2-upstream fd events from client-conn and proxy_ctx events.              */
#define H2UP_MAGIC       0x48325550u   /* 'H2UP' */

/* Max simultaneous streams on one upstream H2 connection.
 * Go's default SETTINGS_MAX_CONCURRENT_STREAMS is 250.                      */
#define H2UP_MAX_STREAMS 256

/* ── Per-stream state ────────────────────────────────────────────────────── */
typedef struct {
    uint32_t          stream_id;   /* 0 = free slot                         */
    struct proxy_ctx *ctx;         /* owning frontend proxy context          */

    http_response_t   resp;        /* assembled from H2 HEADERS + DATA      */
    buf_t             hdr_block;   /* fragment accumulator (CONTINUATION)   */
    buf_t             body_buf;    /* DATA accumulator                      */

    int32_t           send_window; /* per-stream send flow-control window   */
    int               hdr_done;
    int               end_stream;
} h2up_stream_t;

/* ── H2 upstream connection ──────────────────────────────────────────────── */
typedef struct h2up_conn {
    /* MUST be first — event_loop reads magic to tag the ptr */
    uint32_t          magic;       /* H2UP_MAGIC                            */

    int               fd;
    tls_conn_t       *tls;
    struct upstream_node *node;

    /* H2 state */
    uint32_t          next_stream_id;           /* 1, 3, 5, … (client-side) */
    int32_t           conn_send_window;         /* connection-level window   */
    int32_t           stream_init_window;       /* initial stream window     */
    uint32_t          peer_max_concurrent_streams;
    uint32_t          peer_max_frame_size;

    /* Active streams */
    h2up_stream_t     streams[H2UP_MAX_STREAMS];
    int               stream_count;

    /* I/O buffers */
    buf_t             write_buf;
    buf_t             read_buf;

    /* HPACK encode/decode contexts */
    hpack_ctx_t       hpack_tx;
    hpack_ctx_t       hpack_rx;

    /* State flags */
    int               goaway_received;
    int               closed;

    /* Worker that owns this fd in the poller */
    struct worker    *worker;

    /* Intrusive linked list for worker's h2up pool */
    struct h2up_conn *next;
} h2up_conn_t;

/* ── API ─────────────────────────────────────────────────────────────────── */

/* Blocking: TCP connect + TLS handshake + H2 client-preface exchange.
 * Returns h2up_conn_t if ALPN negotiated "h2", NULL on error or no H2.      */
h2up_conn_t *h2up_conn_create(struct upstream_node *node);

void         h2up_conn_free(h2up_conn_t *h2up);

/* Close h2up, sending 502 to every in-flight frontend stream.               */
void         h2up_conn_close(h2up_conn_t *h2up, struct worker *w);

/* Open a new H2 stream for ctx, encode request as HEADERS (+DATA) frames
 * queued in h2up->write_buf.
 * Returns the upstream stream_id (> 0) on success, -1 on error.            */
int  h2up_begin_stream(h2up_conn_t *h2up, struct proxy_ctx *ctx,
                       const http_request_t *req,
                       const char *client_ip, const char *proto);

/* Called on POLLER_READ: read upstream data, parse H2 frames, deliver.     */
int  h2up_on_readable(h2up_conn_t *h2up, struct worker *w);

/* Called on POLLER_WRITE: flush h2up->write_buf to upstream.               */
int  h2up_on_writable(h2up_conn_t *h2up, struct worker *w);

/* Free a stream slot (call via proxy_drop_upstream → proxy_ctx_free).      */
void h2up_stream_remove(h2up_conn_t *h2up, uint32_t stream_id);

/* Returns 1 if there is room for another stream.                            */
int  h2up_has_capacity(const h2up_conn_t *h2up);

#endif /* ROUTA_NET_H2_CLIENT_H */
