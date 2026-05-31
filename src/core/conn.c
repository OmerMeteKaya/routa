#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/conn.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <unistd.h>

#include "http/h2.h"

/* ── ID counter (worker-local in practice, atomic for safety) ───────────── */
static uint_fast64_t g_conn_id = 0;

static uint64_t next_id(void) {
    return __atomic_fetch_add(&g_conn_id, 1, __ATOMIC_RELAXED);
}

/* ── conn_init: fill a zeroed conn_t (heap or slab) ────────────────────── */
void conn_init(conn_t *c, int fd, const char *ip, int port) {
    c->fd           = fd;
    c->state        = CONN_READING;
    c->keep_alive   = 1;
    c->sendfile_fd  = -1;
    c->upstream_fd  = -1;
    c->id           = next_id();
    c->keepalive_deadline = time(NULL) + 30;

    if (ip) {
        strncpy(c->remote_ip, ip, sizeof(c->remote_ip) - 1);
        c->remote_ip[sizeof(c->remote_ip) - 1] = '\0';
    }
    c->remote_port = port;

    buf_init(&c->read_buf);
    buf_init(&c->write_buf);
    buf_init(&c->hdr_buf);
    buf_init(&c->upstream_req_buf);
    buf_init(&c->upstream_resp_buf);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Slab allocator
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Layout in memory:
 *   [ conn_t[0] aligned to 64B ][ conn_t[1] ]...[ conn_t[N-1] ]
 *   [ recv_buf[0] 64KB ][ recv_buf[1] ]...
 *   [ send_buf[0] 128KB ][ send_buf[1] ]...
 *
 * Freelist: singly-linked through conn_t->_pad0 (first 8 bytes of padding).
 * _pad0 is never read by hot path code so this is safe.
 * -------------------------------------------------------------------------*/

/* We reuse the _pad0 field (16 bytes, first 8 used for next pointer).     */
#define SLAB_NEXT(c) (*(conn_t **)((c)->_pad0))

struct conn_slab {
    conn_t   *slots;          /* aligned conn_t array              */
    uint8_t  *recv_pool;      /* CONN_RECV_BUF_SZ * capacity       */
    uint8_t  *send_pool;      /* CONN_SEND_BUF_SZ * capacity       */
    conn_t   *freelist;       /* head of free conn_t chain         */
    int       capacity;
    int       available;
};

conn_slab_t *conn_slab_new(int capacity) {
    if (capacity <= 0) return NULL;

    conn_slab_t *slab = calloc(1, sizeof(conn_slab_t));
    if (!slab) return NULL;

    /* conn_t array: aligned to cache line */
    if (posix_memalign((void **)&slab->slots,
                       CONN_SLAB_ALIGN,
                       (size_t)capacity * sizeof(conn_t)) != 0) {
        free(slab);
        return NULL;
    }
    memset(slab->slots, 0, (size_t)capacity * sizeof(conn_t));

    /* recv pool */
    slab->recv_pool = malloc((size_t)capacity * CONN_RECV_BUF_SZ);
    if (!slab->recv_pool) {
        free(slab->slots); free(slab); return NULL;
    }

    /* send pool */
    slab->send_pool = malloc((size_t)capacity * CONN_SEND_BUF_SZ);
    if (!slab->send_pool) {
        free(slab->recv_pool); free(slab->slots); free(slab); return NULL;
    }

    slab->capacity  = capacity;
    slab->available = capacity;

    /* Build freelist — last slot points to NULL */
    for (int i = 0; i < capacity; i++) {
        conn_t *c = &slab->slots[i];
        c->recv_buf = slab->recv_pool + (size_t)i * CONN_RECV_BUF_SZ;
        c->send_buf = slab->send_pool + (size_t)i * CONN_SEND_BUF_SZ;
        SLAB_NEXT(c) = (i + 1 < capacity) ? &slab->slots[i + 1] : NULL;
    }
    slab->freelist = &slab->slots[0];

    LOG_INFO("conn_slab: allocated %d slots (%.1f MB)",
             capacity,
             (double)((size_t)capacity *
                 (sizeof(conn_t) + CONN_RECV_BUF_SZ + CONN_SEND_BUF_SZ))
             / (1024.0 * 1024.0));

    return slab;
}

void conn_slab_free(conn_slab_t *slab) {
    if (!slab) return;
    free(slab->send_pool);
    free(slab->recv_pool);
    free(slab->slots);
    free(slab);
}

conn_t *conn_slab_acquire(conn_slab_t *slab) {
    if (!slab || !slab->freelist) return NULL;

    conn_t *c      = slab->freelist;
    slab->freelist = SLAB_NEXT(c);
    slab->available--;

    /* Zero everything except pre-allocated buffers */
    uint8_t *recv = c->recv_buf;
    uint8_t *send = c->send_buf;
    memset(c, 0, sizeof(conn_t));
    c->recv_buf = recv;
    c->send_buf = send;

    return c;
}

void conn_slab_release(conn_slab_t *slab, conn_t *conn) {
    if (!slab || !conn) return;

    /* Preserve buffer pointers, zero everything else */
    uint8_t *recv = conn->recv_buf;
    uint8_t *send = conn->send_buf;
    memset(conn, 0, sizeof(conn_t));
    conn->recv_buf = recv;
    conn->send_buf = send;

    SLAB_NEXT(conn)= slab->freelist;
    slab->freelist = conn;
    slab->available++;
}

int conn_slab_available(const conn_slab_t *slab) {
    return slab ? slab->available : 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Legacy heap API — used when no slab is configured
 * ═══════════════════════════════════════════════════════════════════════════*/

conn_t *conn_new(int fd, const char *ip, int port) {
    conn_t *c = calloc(1, sizeof(conn_t));
    if (!c) { LOG_ERROR("conn_new: calloc failed"); return NULL; }

    c->recv_buf = malloc(CONN_RECV_BUF_SZ);
    c->send_buf = malloc(CONN_SEND_BUF_SZ);
    if (!c->recv_buf || !c->send_buf) {
        free(c->recv_buf);
        free(c->send_buf);
        free(c);
        return NULL;
    }

    conn_init(c, fd, ip, port);
    return c;
}

void conn_free(conn_t *c) {
    if (!c) return;
    if (c->tls) tls_conn_free(c->tls);
    if (c->upstream_fd >= 0) close(c->upstream_fd);
    if (c->h2) { h2_conn_free(c->h2); c->h2 = NULL; }
    buf_free(&c->read_buf);
    buf_free(&c->write_buf);
    buf_free(&c->hdr_buf);
    buf_free(&c->upstream_req_buf);
    buf_free(&c->upstream_resp_buf);
    if (!c->from_slab) {
        free(c->recv_buf);
        free(c->send_buf);
        free(c);
    }
}