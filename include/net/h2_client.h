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

/* -- Async connection-establishment state machine ------------------------
 * BUG FIX (H2/TLS failover): h2up_conn_create() used to do TCP connect,
 * TLS handshake, H2 preface send, and initial SETTINGS read all
 * SYNCHRONOUSLY on the calling worker thread. If the upstream node was
 * unreachable or slow to respond (e.g. killed mid-connection, as in the
 * "kill one node out of three" failover test), this blocked the ENTIRE
 * worker thread for up to several seconds -- since routa is thread-per-
 * worker (not process-per-worker), this froze every OTHER request that
 * worker was handling too, not just requests to the dead node. This is
 * why the failover test saw ~59/60 failures instead of the expected
 * ~20/60 (only the dead node's own share): a single blocked worker
 * thread starved all its other in-flight requests until the timeout.
 *
 * This enum tracks progress through the same phases h2up_conn_create()
 * used to do blockingly, now driven one poller event at a time -- the
 * same pattern already used for frontend TLS handshakes (see
 * event_loop.c's CONN_TLS_HANDSHAKE) and H1 upstream connects (see
 * proxy.h's PROXY_STATE_CONNECTING). */
typedef enum {
    H2UP_ASYNC_CONNECTING       = 0,  /* non-blocking connect() in flight */
    H2UP_ASYNC_TLS_HANDSHAKE    = 1,  /* SSL_do_handshake() in progress */
    H2UP_ASYNC_SENDING_PREFACE  = 2,  /* writing preface+SETTINGS+WINDOW_UPDATE */
    H2UP_ASYNC_READING_SETTINGS = 3,  /* reading frames until peer SETTINGS seen */
    H2UP_ASYNC_READY            = 4,  /* fully negotiated, can open streams */
    H2UP_ASYNC_FAILED           = 5   /* terminal error state */
} h2up_async_state_t;

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

    /* -- Async establishment state (see h2up_async_state_t doc comment) -- */
    h2up_async_state_t async_state;
    struct upstream_node *pending_node;  /* target, valid from CONNECTING
                                             through READY; ->node itself is
                                             only set once fully established,
                                             preserving old code's invariant
                                             that a non-NULL ->node means a
                                             usable connection */
    void             *client_ssl_ctx;    /* SSL_CTX*, kept until handshake
                                             completes then freed -- void* so
                                             this header doesn't need to
                                             pull in openssl/ssl.h */

    /* Preface + initial SETTINGS + WINDOW_UPDATE, built once and flushed
     * incrementally across possibly-multiple POLLER_WRITE events. */
    buf_t             preface_buf;
    size_t            preface_sent;

    /* Upstream's initial SETTINGS frame, accumulated incrementally across
     * possibly-multiple POLLER_READ events (mirrors ssl_read_exactly()'s
     * old blocking behavior, but now resumable). Any non-SETTINGS frames
     * seen first (e.g. a stray WINDOW_UPDATE) are read and discarded the
     * same way the old blocking code skipped them, just one frame at a
     * time instead of in a tight loop. */
    uint8_t           settings_hdr_buf[9];  /* H2_FRAME_HDR_SZ, defined in .c */
    size_t            settings_hdr_got;
    uint8_t          *settings_payload_buf;   /* allocated once header is known */
    size_t            settings_payload_got;
    uint32_t          settings_payload_len;
    int               settings_frames_skipped; /* mirrors old "attempts < 20" bound */

} h2up_conn_t;

/* ── API ─────────────────────────────────────────────────────────────────── */

/* Blocking: TCP connect + TLS handshake + H2 client-preface exchange.
 * Returns h2up_conn_t if ALPN negotiated "h2", NULL on error or no H2.      */
h2up_conn_t *h2up_conn_create(struct upstream_node *node);

/* Non-blocking: starts a TCP connect() and returns immediately with a
 * h2up_conn_t in H2UP_ASYNC_CONNECTING state (or NULL if the initial
 * socket()/connect() call fails synchronously, e.g. bad address).
 * Caller must poller_add() the returned conn's fd with POLLER_WRITE and
 * call h2up_conn_advance() on every subsequent poller event for that fd
 * until it returns a definitive result (see h2up_conn_advance's doc
 * comment). The returned h2up_conn_t is NOT yet usable for
 * h2up_begin_stream() -- check ->async_state == H2UP_ASYNC_READY (or
 * rely on h2up_conn_advance()'s return value) first. */
h2up_conn_t *h2up_conn_create_async(struct upstream_node *node);

/* Advances the async connection-establishment state machine by one
 * step in response to a poller event (POLLER_READ and/or POLLER_WRITE
 * -- pass whatever the poller reported, this function checks internally
 * which one(s) it actually needs for the current state).
 *
 * Returns:
 *    1  if still in progress (caller should keep waiting for more
 *       poller events; may need poller_mod() to flip between
 *       POLLER_READ/POLLER_WRITE interest depending on the new state --
 *       see the implementation's per-state comments for exactly when)
 *    0  if the connection just became fully ready (H2UP_ASYNC_READY) --
 *       caller can now call h2up_begin_stream() on it
 *   -1  if the connection failed (h2up->async_state is now
 *       H2UP_ASYNC_FAILED) -- caller should treat this exactly like the
 *       old h2up_conn_create() returning NULL: h2up_conn_free() this
 *       conn and fail/retry the request(s) waiting on it. */
int h2up_conn_advance(h2up_conn_t *h2up);

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
