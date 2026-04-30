#define _GNU_SOURCE
#include "core/conn.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>

conn_t *conn_new(int fd, const char *ip, int port) {
    conn_t *c = calloc(1, sizeof(conn_t));
    if (!c) {
        LOG_ERROR("Failed to allocate connection");
        return NULL;
    }
    
    c->fd = fd;
    c->state = CONN_READING;
    c->keep_alive = 1;
    
    if (ip) {
        strncpy(c->remote_ip, ip, sizeof(c->remote_ip) - 1);
        c->remote_ip[sizeof(c->remote_ip) - 1] = '\0';
    }
    
    c->remote_port = port;
    
    buf_init(&c->read_buf);
    buf_init(&c->write_buf);
    
    return c;
}

void conn_free(conn_t *c) {
    if (c) {
        buf_free(&c->read_buf);
        buf_free(&c->write_buf);
        free(c);
    }
}
