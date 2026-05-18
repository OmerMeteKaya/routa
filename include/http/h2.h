#ifndef ROUTA_HTTP_H2_H
#define ROUTA_HTTP_H2_H

#include <stdint.h>
#include <stddef.h>
#include "http/h2_hpack.h"
#include "util/buf.h"
#include "core/config.h"

/* ── Frame types (RFC 7540 §6) ───────────────────────────────────────────── */
typedef enum {
    H2_FRAME_DATA          = 0x0,
    H2_FRAME_HEADERS       = 0x1,
    H2_FRAME_PRIORITY      = 0x2,
    H2_FRAME_RST_STREAM    = 0x3,
    H2_FRAME_SETTINGS      = 0x4,
    H2_FRAME_PUSH_PROMISE  = 0x5,
    H2_FRAME_PING          = 0x6,
    H2_FRAME_GOAWAY        = 0x7,
    H2_FRAME_WINDOW_UPDATE = 0x8,
    H2_FRAME_CONTINUATION  = 0x9,
} h2_frame_type_t;

/* ── Frame flags ─────────────────────────────────────────────────────────── */
#define H2_FLAG_END_STREAM  0x1
#define H2_FLAG_END_HEADERS 0x4
#define H2_FLAG_PADDED      0x8
#define H2_FLAG_PRIORITY    0x20
#define H2_FLAG_ACK         0x1

/* ── Error codes (RFC 7540 §7) ───────────────────────────────────────────── */
typedef enum {
    H2_ERR_NO_ERROR            = 0x0,
    H2_ERR_PROTOCOL_ERROR      = 0x1,
    H2_ERR_INTERNAL_ERROR      = 0x2,
    H2_ERR_FLOW_CONTROL_ERROR  = 0x3,
    H2_ERR_SETTINGS_TIMEOUT    = 0x4,
    H2_ERR_STREAM_CLOSED       = 0x5,
    H2_ERR_FRAME_SIZE_ERROR    = 0x6,
    H2_ERR_REFUSED_STREAM      = 0x7,
    H2_ERR_CANCEL              = 0x8,
    H2_ERR_COMPRESSION_ERROR   = 0x9,
    H2_ERR_CONNECT_ERROR       = 0xa,
    H2_ERR_ENHANCE_YOUR_CALM   = 0xb,
    H2_ERR_INADEQUATE_SECURITY = 0xc,
    H2_ERR_HTTP_1_1_REQUIRED   = 0xd,
} h2_error_code_t;

/* ── SETTINGS parameter IDs (RFC 7540 §6.5.2) ────────────────────────────── */
#define H2_SETTINGS_HEADER_TABLE_SIZE      0x1
#define H2_SETTINGS_ENABLE_PUSH            0x2
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define H2_SETTINGS_INITIAL_WINDOW_SIZE    0x4
#define H2_SETTINGS_MAX_FRAME_SIZE         0x5
#define H2_SETTINGS_MAX_HEADER_LIST_SIZE   0x6

/* ── Stream states (RFC 7540 §5.1) ──────────────────────────────────────── */
typedef enum {
    H2_STREAM_IDLE,
    H2_STREAM_OPEN,
    H2_STREAM_HALF_CLOSED_REMOTE,
    H2_STREAM_HALF_CLOSED_LOCAL,
    H2_STREAM_CLOSED,
} h2_stream_state_t;

/* ── Stream ──────────────────────────────────────────────────────────────── */
#define H2_MAX_STREAMS 256

typedef struct h2_stream {
    uint32_t          id;
    h2_stream_state_t state;

    /* Received request headers */
    hpack_header_t   *headers;
    int               header_count;

    /* Request body */
    buf_t             body;

    /* Flow control */
    int32_t           send_window;

    /* HEADERS continuation accumulation */
    buf_t             header_block;
    int               expect_continuation;

    /* Priority (RFC 7540 §5.3) — extended later */
    uint32_t          dependency;
    uint8_t           weight;
    int               exclusive;
    buf_t    pending_data;      /* buffered DATA frames waiting for window    */
    size_t   pending_offset;    /* bytes already sent from pending_data       */
} h2_stream_t;

/* ── Stream storage backends ─────────────────────────────────────────────── */

typedef struct {
    h2_stream_t slots[H2_MAX_STREAMS];
    int         count;
} h2_stream_pool_t;

typedef struct {
    h2_stream_t **buckets;   /* open addressing, power-of-2              */
    uint32_t     *keys;      /* parallel key array, 0 = empty            */
    int           capacity;
    int           count;
} h2_stream_map_t;

/* ── Connection ──────────────────────────────────────────────────────────── */
typedef struct h2_conn {
    struct conn      *conn;          /* back-pointer, not owned            */

    /* HPACK — separate contexts per direction                             */
    hpack_ctx_t       hpack_rx;
    hpack_ctx_t       hpack_tx;

    /* Stream storage */
    h2_stream_lookup_t lookup_mode;
    union {
        h2_stream_pool_t pool;
        h2_stream_map_t  map;
    } streams;

    /* Connection-level flow control */
    int32_t           send_window;
    int32_t           recv_window;
    uint32_t          initial_send_window;

    /* Peer SETTINGS */
    uint32_t          peer_header_table_size;
    uint32_t          peer_max_concurrent_streams;
    uint32_t          peer_max_frame_size;
    uint32_t          peer_initial_window_size;

    /* Our SETTINGS ACK tracking */
    int               settings_ack_pending;

    /* GOAWAY */
    uint32_t          last_stream_id;
    int               goaway_sent;
    int               goaway_received;

    /* CONTINUATION tracking */
    uint32_t          continuation_stream_id;

    /* Outbound buffer */
    buf_t             write_buf;

} h2_conn_t;

/* Forward declarations */
struct conn;
struct router;
struct middleware_chain;

/* ── Public API ──────────────────────────────────────────────────────────── */

h2_conn_t *h2_conn_new(struct conn        *conn,
                        const routa_h2_config_t *cfg);

void h2_conn_free(h2_conn_t *hc);

int h2_conn_recv(h2_conn_t               *hc,
                 struct router           *router,
                 struct middleware_chain *chain);

int h2_conn_flush(h2_conn_t *hc);

#endif /* ROUTA_HTTP_H2_H */