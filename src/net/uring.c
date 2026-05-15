#define _GNU_SOURCE
#if defined(__linux__)
#include "net/uring.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/logger.h"
#include <errno.h>
#include <sys/socket.h>
#include <liburing.h>

#include "core/conn.h"

uring_t *uring_new(int server_fd, int queue_depth, int pool_sz) {
    if (pool_sz <= 0 || queue_depth <= 0) return NULL;
    
    uring_t *u = calloc(1, sizeof(uring_t));

    if (!u) return NULL;

    if (io_uring_queue_init(queue_depth, &u->ring, 0) < 0) {
        free(u);
        return NULL;
    }
    
    u->pool = calloc(pool_sz, sizeof(uring_udata_t));
    if (!u->pool) {
        io_uring_queue_exit(&u->ring);
        free(u);
        return NULL;
    }
    
    u->free_stack = malloc(pool_sz * sizeof(int));
    u->in_use = calloc((size_t)pool_sz, sizeof(uint8_t));
    if (!u->in_use) { free(u->free_stack); free(u->pool); io_uring_queue_exit(&u->ring); free(u); return NULL; }
    if (!u->free_stack) {
        free(u->pool);
        io_uring_queue_exit(&u->ring);
        free(u);
        return NULL;
    }
    
    // Initialize free stack (slot 0 reserved for accept)
    for (int i = 0; i < pool_sz - 1; i++) {
        u->free_stack[i] = i + 1;
    }
    u->free_top = pool_sz - 1;
    
    u->pool_sz = pool_sz;
    u->server_fd = server_fd;
    u->accept_addrlen = sizeof(u->accept_addr);
    
    if (uring_submit_accept(u) < 0) {
        uring_free(u);
        return NULL;
    }
    
    io_uring_submit(&u->ring);
    return u;
}

void uring_free(uring_t *u) {
    if (!u) return;
    
    io_uring_queue_exit(&u->ring);
    free(u->pool);
    free(u->free_stack);
    free(u->in_use);
    free(u);
}

uring_udata_t *uring_udata_get(uring_t *u) {
    if (!u || u->free_top == 0) return NULL;
    int idx = u->free_stack[--u->free_top];
    u->in_use[idx] = 1;
    return &u->pool[idx];
}

void uring_udata_put(uring_t *u, uring_udata_t *ud) {
    if (!u || !ud) return;
    int index = (int)(ud - u->pool);
    if (index < 1 || index >= u->pool_sz) return;
    if (!u->in_use[index]) return;  
    u->in_use[index] = 0;
    memset(ud, 0, sizeof(uring_udata_t));
    u->free_stack[u->free_top++] = index;
}

int uring_submit_accept(uring_t *u) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&u->ring);
    if (!sqe) return -1;
    
    io_uring_prep_multishot_accept(sqe, u->server_fd,
        (struct sockaddr *)&u->accept_addr,
        &u->accept_addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    
    /* slot 0 is reserved for accept udata */
    u->pool[0].op   = URING_OP_ACCEPT;
    u->pool[0].conn = NULL;
    u->pool[0].fd   = -1;
    io_uring_sqe_set_data(sqe, &u->pool[0]);
    return 0;
}

int uring_submit_recv(uring_t *u, void *conn, int fd, void *buf, size_t len) {
    conn_t *c = (conn_t *) conn;
    uring_udata_t *ud = uring_udata_get(u);
    if (!ud) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&u->ring);
    if (!sqe) {
        io_uring_submit(&u->ring);
        sqe = io_uring_get_sqe(&u->ring);
        if (!sqe) { uring_udata_put(u, ud); return -1; }
    }

    c->pending_io++;
    ud->op = URING_OP_RECV;
    ud->conn = conn;
    ud->fd = -1;
    ud->conn_id = c->id;
    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, ud);
    return 0;
}
int uring_submit_send(uring_t *u, void *conn, int fd, const void *buf, size_t len) {
    conn_t *c = (conn_t *)conn;
    uring_udata_t *ud = uring_udata_get(u);
    if (!ud) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&u->ring);
    if (!sqe) {
        io_uring_submit(&u->ring);
        sqe = io_uring_get_sqe(&u->ring);
        if (!sqe) { uring_udata_put(u, ud); return -1; }
    }

    c->pending_io++;
    ud->op = URING_OP_SEND;
    ud->conn = conn;
    ud->fd = -1;
    ud->conn_id = c->id;
    io_uring_prep_send(sqe, fd, buf, len, MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, ud);
    return 0;
}
int uring_submit_splice(uring_t *u, void *conn, int src_fd, int dst_fd, size_t len) {
    conn_t *c = (conn_t *)conn;
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC) < 0) return -1;

    struct io_uring_sqe *sqe1 = io_uring_get_sqe(&u->ring);
    if (!sqe1) {
        io_uring_submit(&u->ring);
        sqe1 = io_uring_get_sqe(&u->ring);
        if (!sqe1) { close(pipe_fds[0]); close(pipe_fds[1]); return -1; }
    }
    uring_udata_t *ud1 = uring_udata_get(u);
    if (!ud1) { close(pipe_fds[0]); close(pipe_fds[1]); return -1; }

    struct io_uring_sqe *sqe2 = io_uring_get_sqe(&u->ring);
    if (!sqe2) {
       io_uring_submit(&u->ring);
        sqe2 = io_uring_get_sqe(&u->ring);
        if (!sqe2) {
            uring_udata_put(u, ud1); close(pipe_fds[0]); close(pipe_fds[1]); return -1;
        }
    }
    uring_udata_t *ud2 = uring_udata_get(u);
    if (!ud2) {
        uring_udata_put(u, ud1); close(pipe_fds[0]); close(pipe_fds[1]); return -1;
    }

    c->pending_io += 2;
    ud1->splice_phase = 0;
    ud2->splice_phase = 1;

    ud1->op = URING_OP_SPLICE;
    ud1->conn = conn;
    ud1->fd = pipe_fds[0];
    ud1->conn_id = c->id;
    io_uring_prep_splice(sqe1, src_fd, -1, pipe_fds[1], -1, (unsigned int)len, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    io_uring_sqe_set_data(sqe1, ud1);
    sqe1->flags |= IOSQE_IO_LINK;

    ud2->op = URING_OP_SPLICE;
    ud2->conn = conn;
    ud2->fd = -1;
    ud2->conn_id = c->id;

    io_uring_prep_splice(sqe2, pipe_fds[0], -1, dst_fd, -1, (unsigned int)len, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    io_uring_sqe_set_data(sqe2, ud2);

    io_uring_submit(&u->ring);
    close(pipe_fds[1]);
    return 0;
}

int uring_wait(uring_t *u, uring_cqe_cb_t cb, void *arg) {
    struct io_uring_cqe *cqe;

    io_uring_submit(&u->ring);

    int r = io_uring_wait_cqe(&u->ring, &cqe);
    if (r < 0) return (r == -EINTR) ? 0 : -1;

    unsigned head;
    int count = 0;
    io_uring_for_each_cqe(&u->ring, head, cqe) {
        uring_udata_t *ud = io_uring_cqe_get_data(cqe);
        if (ud) {
            cb(ud, cqe->res, cqe->flags, arg);
        }
        count++;
    }
    io_uring_cqe_seen(&u->ring, cqe);

    return count;
}

#endif /* __linux__ */
