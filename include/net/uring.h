#ifndef ROUTA_NET_URING_H
#define ROUTA_NET_URING_H

#pragma once
#if defined(ROUTA_IO_URING) && defined(__linux__)
#include <liburing.h>

typedef enum {
    URING_OP_ACCEPT,
    URING_OP_RECV,
    URING_OP_SEND,
    URING_OP_SPLICE,
    URING_OP_CLOSE,
} uring_op_t;

typedef struct {
    uring_op_t  op;
    void       *conn;
    int         fd;
    uint64_t    conn_id;
    int         splice_phase;
    uint8_t    *in_use;
    socklen_t               accept_addrlen;
    struct sockaddr_storage accept_addr;
} uring_udata_t;

typedef struct {
    struct io_uring ring;
    uring_udata_t  *pool;
    int            *free_stack;
    int             free_top;
    int             pool_sz;
    int             server_fd;
    struct sockaddr_storage accept_addr;
    uint8_t    *in_use;
    socklen_t   accept_addrlen;
} uring_t;

uring_t *uring_new(int server_fd, int queue_depth, int pool_sz);
void     uring_free(uring_t *u);
int      uring_submit_accept(uring_t *u);
int      uring_submit_recv(uring_t *u, void *conn, int fd, void *buf, size_t len);
int      uring_submit_send(uring_t *u, void *conn, int fd, const void *buf, size_t len);
int      uring_submit_splice(uring_t *u, void *conn, int src_fd, int dst_fd, size_t len);

typedef void (*uring_cqe_cb_t)(uring_udata_t *ud, int res, uint32_t flags, void *arg);
int uring_wait(uring_t *u, uring_cqe_cb_t cb, void *arg);

uring_udata_t *uring_udata_get(uring_t *u);
void           uring_udata_put(uring_t *u, uring_udata_t *ud);

//#endif /* ROUTA_IO_URING */
#endif
#endif /* ROUTA_NET_URING_H */