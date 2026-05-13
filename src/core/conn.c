#define _GNU_SOURCE
#include "core/conn.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

#define SEND_BUF_SZ 131072
#define RECV_BUF_SZ  65536

conn_t *conn_new(int fd, const char *ip, int port) {
    conn_t *c = calloc(1, sizeof(conn_t));
    if (!c) { LOG_ERROR("conn_new: calloc failed"); return NULL; }

    c->fd          = fd;
    c->state       = CONN_READING;
    c->keep_alive  = 1;
    c->sendfile_fd = -1;

    c->recv_buf = malloc(RECV_BUF_SZ);
    c->send_buf = malloc(SEND_BUF_SZ);
    if (!c->recv_buf || !c->send_buf) {
        free(c->recv_buf);
        free(c->send_buf);
        free(c);
        return NULL;
    }

    c->keepalive_deadline = time(NULL) + 30;

    static uint_fast64_t g_conn_id = 0;
    c->id = __atomic_fetch_add(&g_conn_id, 1, __ATOMIC_SEQ_CST);

    if (ip) {
        strncpy(c->remote_ip, ip, sizeof(c->remote_ip) - 1);
        c->remote_ip[sizeof(c->remote_ip) - 1] = '\0';
    }
    c->remote_port = port;

    buf_init(&c->read_buf);
    buf_init(&c->write_buf);
    buf_init(&c->hdr_buf);    /* writev header scratch buffer */

    return c;
}

void conn_free(conn_t *c) {
    if (!c) return;
    if (c->tls)    tls_conn_free(c->tls);
    buf_free(&c->read_buf);
    buf_free(&c->write_buf);
    buf_free(&c->hdr_buf);
    free(c->recv_buf);
    free(c->send_buf);
    free(c);
}