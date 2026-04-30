#ifndef ROUTA_CORE_CONN_H
#define ROUTA_CORE_CONN_H

#include "util/buf.h"

typedef enum {
    CONN_READING,
    CONN_PARSING,
    CONN_PROCESSING,
    CONN_WRITING,
    CONN_KEEPALIVE,
    CONN_CLOSING
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
} conn_t;

conn_t *conn_new(int fd, const char *ip, int port);
void    conn_free(conn_t *c);

#endif // ROUTA_CORE_CONN_H
