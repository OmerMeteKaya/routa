#ifndef ROUTA_HTTP_WS_H
#define ROUTA_HTTP_WS_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "util/buf.h"
#include "http/request.h"
#include "core/config.h"

/* ── Forward declarations ───────────────────────────────────────────────── */
typedef struct conn      conn_t;
typedef struct ws_conn   ws_conn_t;
typedef struct worker    worker_t;
typedef http_request_t http_request;

/* ═══════════════════════════════════════════════════════════════════════════
 * Enums
 * ═══════════════════════════════════════════════════════════════════════════*/

/* RFC 6455 opcodes */
typedef enum {
    WS_OP_CONTINUATION = 0x0,
    WS_OP_TEXT         = 0x1,
    WS_OP_BINARY       = 0x2,
    WS_OP_CLOSE        = 0x8,
    WS_OP_PING         = 0x9,
    WS_OP_PONG         = 0xA,
} ws_opcode_t;

/* RFC 6455 close codes */
typedef enum {
    WS_CLOSE_NORMAL      = 1000,
    WS_CLOSE_GOING_AWAY  = 1001,
    WS_CLOSE_PROTOCOL    = 1002,
    WS_CLOSE_UNSUPPORTED = 1003,
    WS_CLOSE_INVALID     = 1007,
    WS_CLOSE_POLICY      = 1008,
    WS_CLOSE_TOO_LARGE   = 1009,
    WS_CLOSE_ERROR       = 1011,
} ws_close_code_t;

/* Per-connection WebSocket state */
typedef enum {
    WS_STATE_INIT,
    WS_STATE_HANDSHAKING,
    WS_STATE_OPEN,
    WS_STATE_CLOSING,
    WS_STATE_CLOSED,
} ws_conn_state_t;

/* Frame parse */
typedef enum {
    WS_PARSE_HEADER,            /* First 2 byte — FIN/opcode/mask/len        */
    WS_PARSE_LENGTH_EXT,        /* 16 or 64-bit length                */
    WS_PARSE_MASK,              /* 4-byte masking key                      */
    WS_PARSE_PAYLOAD,           /* payload bytes                           */
} ws_parse_phase_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Frame parser state
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef struct {
    ws_parse_phase_t phase;


    int          fin;
    int          rsv1;

    /* permessage-deflate (RFC 7692) */
    int          pmd_enabled;       /* negotiated per-connection           */
    int          pmd_server_no_context_takeover;
    int          pmd_client_no_context_takeover;

    ws_opcode_t  opcode;
    int          masked;
    uint8_t      mask[4];


    uint64_t     payload_len;
    uint64_t     payload_read;


    uint8_t      hdr_buf[14];
    int          hdr_buf_len;
    int          hdr_needed;


    ws_opcode_t  frag_opcode;
    buf_t        frag_buf;
    int          in_fragment;
} ws_frame_state_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Broadcast message
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef struct ws_msg {
    uint8_t        *data;
    size_t          len;
    ws_opcode_t     opcode;
    struct ws_msg  *next;
} ws_msg_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-worker broadcast queue
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef struct {
    ws_msg_t   *head;
    ws_msg_t   *tail;
    int         count;
    pthread_mutex_t lock;
} ws_msg_queue_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-worker WebSocket connection registry
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef struct ws_registry_node {
    conn_t                  *conn;
    struct ws_registry_node *next;
} ws_registry_node_t;

typedef struct {
    ws_registry_node_t *head;
    int                 count;
} ws_registry_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Callback types
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef void (*ws_on_open_fn)   (conn_t *conn, void *ctx);
typedef void (*ws_on_message_fn)(conn_t *conn, const uint8_t *data,
                                 size_t len, ws_opcode_t opcode, void *ctx);
typedef void (*ws_on_close_fn)  (conn_t *conn, ws_close_code_t code,
                                 const char *reason, void *ctx);
typedef void (*ws_on_error_fn)  (conn_t *conn, const char *msg, void *ctx);

/* ═══════════════════════════════════════════════════════════════════════════
 * Route-level WebSocket handler config
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef struct {
    char             path[256];
    ws_on_open_fn    on_open;
    ws_on_message_fn on_message;
    ws_on_close_fn   on_close;
    ws_on_error_fn   on_error;
    void            *ctx;
    ws_config_t      cfg;
    /* permessage-deflate negotiated state (set during handshake)         */
    int          pmd_negotiated;
} ws_handler_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Config defaults */
void ws_config_init(ws_config_t *cfg);


int  ws_handshake(conn_t *conn, const http_request *req,
                  buf_t *out, const ws_config_t *cfg);


int  ws_recv(conn_t *conn, const ws_handler_t *handler,
             const ws_config_t *cfg);

int  ws_send(conn_t *conn, const uint8_t *data, size_t len,
             ws_opcode_t opcode);

/* Close handshake  */
int  ws_close(conn_t *conn, ws_close_code_t code, const char *reason);

/* Ping  */
int  ws_ping(conn_t *conn, const uint8_t *payload, size_t len);

/* Pong   */
int  ws_pong(conn_t *conn, const uint8_t *payload, size_t len);

int  ws_broadcast(worker_t **workers, int worker_count,
                  const uint8_t *data, size_t len, ws_opcode_t opcode);

/* Frame state init/free */
void ws_frame_state_init(ws_frame_state_t *fs);
void ws_frame_state_free(ws_frame_state_t *fs);

int  ws_is_upgrade_request(const http_request *req);

int  ws_send_pmd(conn_t *conn, const uint8_t *data, size_t len,
                 ws_opcode_t opcode, const ws_config_t *cfg);

#endif /* ROUTA_HTTP_WS_H */