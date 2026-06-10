#ifndef ROUTA_CORE_CONN_H
#define ROUTA_CORE_CONN_H

#include "util/buf.h"
#include "net/tls.h"
#include "http/response.h"
#include "http/ws.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct h2_conn;

typedef enum {
    CONN_READING,
    CONN_PARSING,
    CONN_PROCESSING,
    CONN_WRITING,
    CONN_CLOSING,
    CONN_TLS_HANDSHAKE,
    CONN_SENDFILE,
    /* Async upstream (reverse proxy / LB) */
    CONN_UPSTREAM_CONNECTING,
    CONN_UPSTREAM_WRITING,
    CONN_UPSTREAM_READING,
    CONN_UPSTREAM_DONE,
    /* WebSocket */
    CONN_WEBSOCKET,             /* connection has been upgraded to WS      */
    CONN_H2,   /* HTTP/2 connection — h2_conn_t manages               */
} conn_state_t;

/* ── conn_t — cache-line aware layout ──────────────────────────────────────
 *
 * CL0 (0–63):   HOT  — fd, state, keep_alive, tls, read_buf, sendfile_fd
 * CL1 (64–127): WARM — write_buf, hdr_buf, writev state
 * CL2 (128–191): WARM — body/sendfile/consumed + uring bufs
 * CL3 (192+):   COLD — upstream, websocket, id, timestamps, remote_ip
 * -------------------------------------------------------------------------*/
typedef struct conn {

    /* ── CL0: HOT ────────────────────────────────────────────────────────*/
    int          fd;                    /*  4 */
    conn_state_t state;                 /*  4 */
    int          keep_alive;            /*  4 */
    int          sendfile_fd;           /*  4 */
    tls_conn_t  *tls;                   /*  8 */
    buf_t        read_buf;              /* 24 */
    char         _pad0[16];             /* 16 — pad to 64 */

    /* ── CL1: WARM write path ───────────────────────────────────────────*/
    buf_t        write_buf;             /* 24 */
    buf_t        hdr_buf;               /* 24 */
    size_t       writev_written;        /*  8 */
    const char  *resp_body_ptr;         /*  8 */
    /* 64 bytes — line full */

    /* ── CL2: WARM sendfile + uring ────────────────────────────────────*/
    size_t       resp_body_len;         /*  8 */
    off_t        sendfile_off;          /*  8 */
    size_t       sendfile_rem;          /*  8 */
    size_t       consumed;              /*  8 */
    uint8_t     *recv_buf;              /*  8 */
    uint8_t     *send_buf;              /*  8 */
    size_t       send_buf_len;          /*  8 */
    int          recv_pending;          /*  4 */
    int          pending_io;            /*  4 */

    /* ── CL3: COLD — upstream fields ───────────────────────────────────*/
    struct proxy_ctx *proxy;

    /* ── WebSocket fields ───────────────────────────────────────────────
     *
     * ws_frame_state_t is embedded (no heap alloc) to avoid an extra
     * pointer chase on every ws_recv call.  frag_buf inside ws_fs is
     * the only heap allocation and is initialised lazily on upgrade.
     * -------------------------------------------------------------------*/
    ws_conn_state_t  ws_state;          /* WS_STATE_INIT until upgraded    */
    ws_frame_state_t ws_fs;             /* frame parser state machine       */
    uint64_t         ws_last_ping_ms;   /* monotonic ms of last ping sent   */
    int              ws_ping_misses;    /* consecutive unanswered pings     */
    int              ws_write_queued;   /* frames waiting in write_buf      */
    int              ws_pmd_enabled;    /* permessage-deflate active       */
    ws_handler_t     *ws_handler;

    /* ── Cold metadata ──────────────────────────────────────────────────*/
    int          closing;
    int          active;
    int          remote_port;
    int          _pad3;
    uint64_t     id;
    uint64_t     last_active_ms;
    time_t       keepalive_deadline;
    char         remote_ip[46];
    char         _pad4[2];
    struct h2_conn *h2;   /* NULL if HTTP/1.1                         */

    /* Observability — stash for access log at write completion */
    char     last_trace_id[17];
    char     last_method_str[16];
    char     last_path[256];
    int      last_status;
    uint64_t last_start_us;

    uint8_t poller_mask;
    uint8_t from_slab; /* 1 = slab allocated, don't heap-free */
} conn_t;

/* ── Slab pool ──────────────────────────────────────────────────────────────
 *
 * Per-worker, single-threaded — no locks needed.
 * Pre-allocates `capacity` conn_t + recv/send buffers upfront.
 * O(1) acquire/release via freelist.
 * -------------------------------------------------------------------------*/
#define CONN_RECV_BUF_SZ  65536
#define CONN_SEND_BUF_SZ  131072
#define CONN_SLAB_ALIGN   64

typedef struct conn_slab conn_slab_t;

conn_slab_t *conn_slab_new(int capacity);
void         conn_slab_free(conn_slab_t *slab);

/* Returns a zeroed conn_t with recv_buf/send_buf already set.
 * Returns NULL if slab is exhausted (fall back to conn_new).              */
conn_t *conn_slab_acquire(conn_slab_t *slab);

/* Return conn to slab freelist.
 * Caller must have already closed fd, freed tls, reset bufs.             */
void conn_slab_release(conn_slab_t *slab, conn_t *conn);

int conn_slab_available(const conn_slab_t *slab);

/* Per-connection init/reset (used by both heap and slab paths) */
void conn_init(conn_t *c, int fd, const char *ip, int port);

/* Legacy heap API */
conn_t *conn_new(int fd, const char *ip, int port);
void    conn_free(conn_t *c);

#endif /* ROUTA_CORE_CONN_H */