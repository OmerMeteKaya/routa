#ifndef ROUTA_HTTP_WS_REGISTRY_H
#define ROUTA_HTTP_WS_REGISTRY_H

#include "http/ws.h"
#include <stdint.h>

/* Forward declaration */
typedef struct conn conn_t;

/* ── ws_msg_queue ───────────────────────────────────────────────────────── */
int  ws_msg_queue_init(ws_msg_queue_t *q);
void ws_msg_queue_destroy(ws_msg_queue_t *q);

/* ── ws_registry ────────────────────────────────────────────────────────── */
void ws_registry_init(ws_registry_t *r);
void ws_registry_destroy(ws_registry_t *r);

int  ws_registry_add(ws_registry_t *r, conn_t *conn);
void ws_registry_remove(ws_registry_t *r, conn_t *conn);

/* Drain the broadcast queue and deliver messages to all open connections.
 * Must be called from the owner worker thread only.                       */
void ws_registry_dispatch_broadcast(ws_registry_t *r, ws_msg_queue_t *q);

/* Send pings / enforce ping timeout.  now_ms = monotonic milliseconds.   */
void ws_registry_ping_sweep(ws_registry_t *r, const ws_config_t *cfg,
                             uint64_t now_ms);

/* ── eventfd helpers ────────────────────────────────────────────────────── */
int  ws_notify_fd_create(void);
void ws_notify_fd_drain(int fd);

#endif /* ROUTA_HTTP_WS_REGISTRY_H */