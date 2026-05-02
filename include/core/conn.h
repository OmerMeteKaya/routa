#ifndef ROUTA_CORE_CONN_H
#define ROUTA_CORE_CONN_H

#include "util/buf.h"
#include "net/tls.h"

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
    buf_t        write_buf;
    char         remote_ip[46];
    int          remote_port;
    int          keep_alive;
    uint64_t     last_active_ms;
    time_t       keepalive_deadline;
    tls_conn_t  *tls;
    int          sendfile_fd;
    off_t        sendfile_off;
    size_t       sendfile_rem;
} conn_t;

conn_t *conn_new(int fd, const char *ip, int port);
void    conn_free(conn_t *c);

#endif // ROUTA_CORE_CONN_H
