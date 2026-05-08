#ifndef ROUTA_NET_URING_H
#define ROUTA_NET_URING_H

#if defined(__linux__)
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
    void       *conn;   /* conn_t * — NULL for ACCEPT */
    int         fd;     /* pipe read-end for SPLICE, -1 otherwise */
} uring_udata_t;

typedef struct {
    struct io_uring ring;
    uring_udata_t  *pool;    /* pre-allocated udata pool */
    int            *free_stack;   /* indices of free slots */
    int             free_top;     /* stack pointer */
    int             pool_sz;
    int             server_fd;
    /* for multishot accept */
    struct sockaddr_storage accept_addr;
    socklen_t               accept_addrlen;
} uring_t;

/* Init ring with given queue depth and pre-allocate udata pool.
   Returns NULL on error. */
uring_t *uring_new(int server_fd, int queue_depth, int pool_sz);
void     uring_free(uring_t *u);

/* Submit one ACCEPT SQE — multishot if kernel >= 5.19 */
int uring_submit_accept(uring_t *u);

/* Submit RECV SQE for conn. len = max bytes to read. */
int uring_submit_recv(uring_t *u, void *conn, int fd, void *buf, size_t len);

/* Submit SEND SQE for conn. */
int uring_submit_send(uring_t *u, void *conn, int fd,
                      const void *buf, size_t len);

/* Submit SPLICE SQE for sendfile replacement.
   src_fd = file fd, dst_fd = socket fd, len = bytes to splice. */
int uring_submit_splice(uring_t *u, void *conn,
                        int src_fd, int dst_fd, size_t len);

/* Wait for completions. Returns number of CQEs processed.
   Calls cb(udata, res) for each. */
typedef void (*uring_cqe_cb_t)(uring_udata_t *ud, int res, void *arg);
int uring_wait(uring_t *u, uring_cqe_cb_t cb, void *arg);

/* Acquire/release udata from pool — O(1) */
uring_udata_t *uring_udata_get(uring_t *u);
void           uring_udata_put(uring_t *u, uring_udata_t *ud);

#endif /* __linux__ */
#endif /* ROUTA_NET_URING_H */
