#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/ws_registry.h"
#include "http/ws.h"
#include "core/conn.h"
#include "util/logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <errno.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * ws_msg_queue — producer/consumer queue for broadcast messages
 *
 * Producer: any thread calling ws_broadcast()
 * Consumer: the owner worker thread, woken via eventfd
 * ═══════════════════════════════════════════════════════════════════════════*/

int ws_msg_queue_init(ws_msg_queue_t *q) {
    if (!q) return -1;
    memset(q, 0, sizeof(*q));
    if (pthread_mutex_init(&q->lock, NULL) != 0) return -1;
    return 0;
}

void ws_msg_queue_destroy(ws_msg_queue_t *q) {
    if (!q) return;
    pthread_mutex_lock(&q->lock);
    ws_msg_t *msg = q->head;
    while (msg) {
        ws_msg_t *next = msg->next;
        free(msg->data);
        free(msg);
        msg = next;
    }
    q->head  = NULL;
    q->tail  = NULL;
    q->count = 0;
    pthread_mutex_unlock(&q->lock);
    pthread_mutex_destroy(&q->lock);
}

/* Drain the queue and return a detached list (caller owns it, no lock held). */
static ws_msg_t *ws_msg_queue_drain(ws_msg_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    ws_msg_t *list = q->head;
    q->head  = NULL;
    q->tail  = NULL;
    q->count = 0;
    pthread_mutex_unlock(&q->lock);
    return list;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ws_registry — per-worker open WebSocket connection list
 *
 * Only the owner worker thread reads/writes this struct — no locking needed.
 * ═══════════════════════════════════════════════════════════════════════════*/

void ws_registry_init(ws_registry_t *r) {
    if (!r) return;
    r->head  = NULL;
    r->count = 0;
}

void ws_registry_destroy(ws_registry_t *r) {
    if (!r) return;
    ws_registry_node_t *n = r->head;
    while (n) {
        ws_registry_node_t *next = n->next;
        free(n);
        n = next;
    }
    r->head  = NULL;
    r->count = 0;
}

/* Add a connection to the registry.
 * Called by the worker when a WS upgrade completes.                       */
int ws_registry_add(ws_registry_t *r, conn_t *conn) {
    if (!r || !conn) return -1;

    ws_registry_node_t *node = malloc(sizeof(ws_registry_node_t));
    if (!node) return -1;

    node->conn = conn;
    node->next = r->head;
    r->head    = node;
    r->count++;

    LOG_DEBUG("ws_registry: added conn fd=%d (total=%d)", conn->fd, r->count);
    return 0;
}

/* Remove a connection from the registry.
 * Called by the worker when a WS connection closes.                       */
void ws_registry_remove(ws_registry_t *r, conn_t *conn) {
    if (!r || !conn) return;

    ws_registry_node_t **pp = &r->head;
    while (*pp) {
        if ((*pp)->conn == conn) {
            ws_registry_node_t *dead = *pp;
            *pp = dead->next;
            free(dead);
            r->count--;
            LOG_DEBUG("ws_registry: removed conn fd=%d (total=%d)",
                      conn->fd, r->count);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Broadcast dispatch — called by the worker thread after eventfd fires
 *
 * Drains the broadcast queue, then sends each message to every open WS
 * connection registered with this worker.
 * ═══════════════════════════════════════════════════════════════════════════*/

void ws_registry_dispatch_broadcast(ws_registry_t *r, ws_msg_queue_t *q) {
    if (!r || !q) return;

    /* Drain the eventfd counter so epoll re-arms correctly */
    /* (caller is responsible for reading eventfd before calling here)     */

    ws_msg_t *msgs = ws_msg_queue_drain(q);
    if (!msgs) return;

    /* For each pending broadcast message, send to all registered conns */
    ws_msg_t *msg = msgs;
    while (msg) {
        ws_registry_node_t *node = r->head;
        while (node) {
            conn_t *conn = node->conn;
            /* Skip connections that are not fully open */
            if (conn->ws_state == WS_STATE_OPEN) {
                if (ws_send(conn, msg->data, msg->len, msg->opcode) < 0) {
                    LOG_WARN("ws_registry: send failed on fd=%d", conn->fd);
                }
            }
            node = node->next;
        }

        ws_msg_t *next = msg->next;
        free(msg->data);
        free(msg);
        msg = next;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Ping sweep — called periodically by the worker (e.g. every second)
 *
 * Sends a ping to connections that have been idle longer than
 * ping_interval_ms.  Closes connections that have exceeded max_ping_misses.
 * ═══════════════════════════════════════════════════════════════════════════*/

void ws_registry_ping_sweep(ws_registry_t *r, const ws_config_t *cfg,
                             uint64_t now_ms) {
    if (!r || !cfg) return;
    if (cfg->ping_interval_ms <= 0) return;

    ws_registry_node_t **pp = &r->head;
    while (*pp) {
        conn_t *conn = (*pp)->conn;

        if (conn->ws_state != WS_STATE_OPEN) {
            pp = &(*pp)->next;
            continue;
        }

        uint64_t elapsed = now_ms - conn->ws_last_ping_ms;

        if (elapsed >= (uint64_t)cfg->ping_interval_ms) {
            if (conn->ws_ping_misses >= cfg->max_ping_misses) {
                /* Too many missed pings — close the connection */
                LOG_INFO("ws_registry: closing fd=%d after %d missed pings",
                         conn->fd, conn->ws_ping_misses);
                ws_close(conn, WS_CLOSE_GOING_AWAY, "ping timeout");
                pp = &(*pp)->next;
                continue;
            }

            /* Send ping — empty payload is valid per RFC 6455 §5.5.2 */
            ws_ping(conn, NULL, 0);
            conn->ws_ping_misses++;
            conn->ws_last_ping_ms = now_ms;
        }

        pp = &(*pp)->next;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * eventfd helpers
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Create an eventfd for this worker's broadcast notification.
 * Returns fd on success, -1 on error.                                     */
int ws_notify_fd_create(void) {
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0)
        LOG_ERROR("ws: eventfd creation failed: %s", strerror(errno));
    return fd;
}

/* Read and discard the eventfd counter.
 * Must be called before ws_registry_dispatch_broadcast to re-arm epoll.  */
void ws_notify_fd_drain(int fd) {
    if (fd < 0) return;
    uint64_t val;
    if (read(fd, &val, sizeof(val)) < 0 && errno != EAGAIN)
        LOG_WARN("ws: eventfd drain failed: %s", strerror(errno));
}
