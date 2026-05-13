#ifndef ROUTA_CORE_CONN_H
#define ROUTA_CORE_CONN_H

#include "util/buf.h"
#include "net/tls.h"
#include "http/response.h"

typedef enum {
    CONN_READING,
    CONN_PARSING,
    CONN_PROCESSING,
    CONN_WRITING,
    CONN_KEEPALIVE,
    CONN_CLOSING,
    CONN_TLS_HANDSHAKE,
    CONN_SENDFILE
} conn_state_t;

typedef struct conn {
    int          fd;
    size_t       consumed;
    conn_state_t state;
    buf_t        read_buf;
    buf_t        write_buf;     /* legacy: used by old io_write_from_buf path  */
    char         remote_ip[46];
    int          remote_port;
    int          keep_alive;
    uint64_t     last_active_ms;
    time_t       keepalive_deadline;
    tls_conn_t  *tls;
    int          sendfile_fd;
    off_t        sendfile_off;
    size_t       sendfile_rem;
    int          closing;
    int          pending_io;
    uint8_t     *recv_buf;
    int          recv_pending;
    uint8_t     *send_buf;
    size_t       send_buf_len;
    uint64_t     id;
    int          active;

    /* ── writev path ──────────────────────────────────────────────────────
     * hdr_buf holds the serialized HTTP headers (built once per response).
     * writev_written tracks total bytes sent so far (headers + body).
     * resp_body_{ptr,len} are a non-owning view into the response body so
     * that io_writev_response can reference it across partial writes.
     * ------------------------------------------------------------------- */
    buf_t        hdr_buf;          /* serialized headers, reset after send  */
    size_t       writev_written;   /* bytes sent this response              */
    const char  *resp_body_ptr;    /* non-owning pointer into resp->body    */
    size_t       resp_body_len;
} conn_t;

conn_t *conn_new(int fd, const char *ip, int port);
void    conn_free(conn_t *c);

#endif /* ROUTA_CORE_CONN_H */