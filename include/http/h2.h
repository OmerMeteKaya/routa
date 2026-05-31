#ifndef ROUTA_HTTP_H2_H
#define ROUTA_HTTP_H2_H

#include <stdint.h>
#include <stddef.h>
#include "http/h2_hpack.h"
#include "util/buf.h"
#include "core/config.h"
#include "http/request.h"
#include "http/response.h"

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

    /* HEADERS / CONTINUATION accumulation */
    buf_t             header_block;
    int               expect_continuation;

    /* Priority — struct retained, RFC 7540 PRIORITY logic not implemented.
     * RFC 9113 deprecated the dependency-tree model; RFC 9218 Extensible
     * Priorities will be added at the HTTP/3 milestone.                   */
    uint32_t          dependency;
    uint8_t           weight;
    int               exclusive;

    /* Outbound data buffered while send window is exhausted              */
    buf_t             pending_data;
    size_t            pending_offset;
    uint64_t start_us;
} h2_stream_t;

/* ── Stream storage backends ─────────────────────────────────────────────── */

typedef struct {
    h2_stream_t slots[H2_MAX_STREAMS];
    int         count;
} h2_stream_pool_t;

typedef struct {
    h2_stream_t **buckets;
    uint32_t     *keys;
    int           capacity;
    int           count;
} h2_stream_map_t;

/* ── Connection ──────────────────────────────────────────────────────────── */
typedef struct h2_conn {
    struct conn      *conn;

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

    /* Peer SETTINGS (updated on each SETTINGS frame from client)         */
    uint32_t          peer_header_table_size;
    uint32_t          peer_max_concurrent_streams;
    uint32_t          peer_max_frame_size;
    uint32_t          peer_initial_window_size;

    /* Our SETTINGS ACK tracking */
    int               settings_ack_pending;

    /* SETTINGS flood protection counter                                  */
    uint32_t          settings_recv_count;

    /* GOAWAY */
    uint32_t          last_stream_id;
    int               goaway_sent;
    int               goaway_received;

    /* CONTINUATION tracking */
    uint32_t          continuation_stream_id;

    /* Server Push (RFC 7540 §8.2)
     * push_enabled:          set from config, cleared if client sends
     *                        SETTINGS ENABLE_PUSH=0
     * next_push_stream_id:   next even stream ID for server-initiated streams */
    int               push_enabled;
    uint32_t          next_push_stream_id;

    /* Outbound buffer */
    buf_t             write_buf;

    /* State flags */
    int               error;
    int               preface_done;

    /* Idle timeout tracking                                              */
    uint64_t          last_stream_ts;    /* monotonic ms, last stream activity */
    uint64_t          last_recv_ts;      /* monotonic ms, last frame received  */
    uint32_t          cfg_stream_timeout_ms;
    uint32_t          cfg_keepalive_timeout_ms;

    uint32_t          frame_count;
    uint32_t recv_pending_update;
} h2_conn_t;

/* Forward declarations */
struct conn;
struct router;
struct middleware_chain;
struct http_request;
struct http_response;

/* ── Core API ────────────────────────────────────────────────────────────── */

h2_conn_t *h2_conn_new(struct conn             *conn,
                        const routa_h2_config_t *cfg);

void       h2_conn_free(h2_conn_t *hc);

int h2_conn_check_timeouts(h2_conn_t *hc, uint64_t now_ms);

int        h2_conn_recv(h2_conn_t               *hc,
                        struct router           *router,
                        struct middleware_chain *chain);

int        h2_conn_flush(h2_conn_t *hc);


/* ── h2c Upgrade (RFC 7540 §3.2) ────────────────────────────────────────── */

/* Called by the HTTP/1.1 layer when it sees "Upgrade: h2c".
 * Sends 101, synthesizes stream 1, dispatches the request.
 * After return, the connection is in H2 mode.                              */
int        h2_upgrade_from_h1(h2_conn_t               *hc,
                                http_request_t     *req,
                               struct router           *router,
                               struct middleware_chain *chain);

/* ── Server Push (RFC 7540 §8.2) ────────────────────────────────────────── */

/* Send a PUSH_PROMISE for push_path on behalf of stream_id.
 * Returns the promised stream ID (> 0) on success, -1 if push is disabled
 * or an error occurs.  The caller MUST call h2_push_response() immediately
 * after to send the actual resource.
 *
 * Typical usage inside a route handler:
 *
 *   int pid = h2_push_promise(hc, stream_id,
 *                             "/style.css", "GET", "https", host);
 *   if (pid > 0) {
 *       http_response_t push_resp;
 *       http_response_init(&push_resp);
 *       // ... populate push_resp ...
 *       h2_push_response(hc, (uint32_t)pid, &push_resp);
 *       http_response_destroy(&push_resp);
 *   }                                                                       */
int        h2_push_promise(h2_conn_t  *hc,
                            uint32_t    stream_id,
                            const char *push_path,
                            const char *push_method,
                            const char *scheme,
                            const char *authority);

int        h2_push_response(h2_conn_t        *hc,
                             uint32_t          promised_stream_id,
                              http_response_t *resp);

/* ── 103 Early Hints (RFC 8297) ─────────────────────────────────────────── */

/* Send a 103 Early Hints informational response on stream_id.
 * hints: NULL-terminated array of Link header values.
 *
 * Must be called before h2_conn_recv dispatches the final response.
 * Safe to call multiple times; each call emits one 103 frame.
 *
 * Example:
 *   const char *hints[] = {
 *       "</style.css>; rel=preload; as=style",
 *       "</app.js>; rel=preload; as=script",
 *       NULL
 *   };
 *   h2_early_hints(hc, stream_id, hints);                                   */
int        h2_early_hints(h2_conn_t   *hc,
                           uint32_t     stream_id,
                           const char **hints);

#endif /* ROUTA_HTTP_H2_H */