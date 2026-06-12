#ifndef ROUTA_LB_LB_H
#define ROUTA_LB_LB_H

#include "lb/upstream.h"
#include "http/request.h"
#include "http/response.h"
#include <stdint.h>

/* ── Algorithms ────────────────────────────────────────────────────────────*/
typedef enum {
    LB_ROUND_ROBIN        = 0,
    LB_WEIGHTED_RR        = 1,
    LB_LEAST_CONN         = 2,
    LB_IP_HASH            = 3,
    LB_RANDOM             = 4,
    LB_P2C                = 5,   /* Power of Two Choices (least-conn variant)*/
    LB_CONSISTENT_HASH    = 6,   /* ketama-style, for cache affinity         */
} lb_algo_t;

/* ── Config ────────────────────────────────────────────────────────────────*/
typedef struct {
    lb_algo_t algo;

    /* Connection pool per node */
    int pool_max_per_node;      /* default: 64                              */
    int pool_connect_timeout_ms;/* default: 2000                            */
    int pool_idle_timeout_s;    /* close idle conns after N seconds, def 60 */

    /* Passive health */
    int passive_fail_threshold;    /* default: 3                            */
    int passive_recover_threshold; /* default: 2                            */

    /* Active health check (applies to all nodes unless overridden) */
    health_check_config_t hc;

    /* Consistent hash virtual nodes */
    int consistent_hash_vnodes;    /* default: 150                          */

    /* Retry */
    int max_retries;            /* 0 = no retry, default: 1                 */
    int retry_on_connect_fail;  /* default: 1                               */
    int retry_on_5xx;           /* default: 0                               */
} lb_config_t;

/* ── Load balancer instance ────────────────────────────────────────────────*/
typedef struct lb lb_t;
/* Returns the upstream pool for direct node state recording.
 * Used by proxy.c to call upstream_node_record_failure/success. */
upstream_pool_t *lb_get_pool(lb_t *lb);
/* Create / destroy */
lb_t *lb_new(const lb_config_t *cfg);
void  lb_free(lb_t *lb);

/* Add an upstream node.  weight ignored for non-weighted algorithms.       */
int lb_add_upstream(lb_t *lb,
                    const char *host, uint16_t port, int weight);

/* Start background threads (health check, idle conn reaper).
 * Call after all upstreams are added, before first request.                */
int lb_start(lb_t *lb);
void lb_stop(lb_t *lb);

/* ── Request forwarding ────────────────────────────────────────────────────
 *
 * lb_forward() picks an upstream, borrows a pooled connection, forwards the
 * serialized request, reads the response, and fills *resp.
 *
 * client_ip  — used by IP_HASH and CONSISTENT_HASH algorithms.
 * Returns  0  on success (resp filled).
 *         -1  on failure (all upstreams down, pool exhausted, timeout).
 * -------------------------------------------------------------------------*/
int lb_forward(lb_t *lb,
               const http_request_t *req,
               http_response_t      *resp,
               const char           *client_ip);

/* ── Node selection (exposed for testing / custom wrappers) ────────────────*/
upstream_node_t *lb_pick_node(lb_t *lb, const char *client_ip);

/* ── Async forwarding API ───────────────────────────────────────────────────
 *
 * Instead of blocking, these functions integrate with the worker's epoll loop.
 *
 * lb_begin_forward():
 *   - Picks an upstream node
 *   - Acquires a pooled connection (or opens a new non-blocking one)
 *   - Serializes the HTTP request into req_buf
 *   - Returns the upstream fd to add to poller (POLLER_WRITE for connect/send)
 *   - out_node / out_uconn: set for later pool return
 *   Returns fd >= 0 on success, -1 on failure (all nodes down).
 *
 * lb_finish_forward():
 *   - Parses the raw upstream response bytes into resp
 *   - Returns connection to pool (healthy flag)
 *   Returns 0 ok, -1 parse error.
 * -------------------------------------------------------------------------*/
int lb_begin_forward(lb_t *lb,
                     const http_request_t *req,
                     const char           *client_ip,
                     const char           *proto,          /* "https"/"http"/NULL */
                     buf_t                *req_buf,        /* out: serialized req */
                     upstream_node_t     **out_node,       /* out: for record_* */
                     upstream_conn_t     **out_uconn);     /* out: for release   */

int lb_finish_forward(lb_t            *lb,
                      buf_t           *resp_buf,           /* raw upstream bytes */
                      http_response_t *resp,               /* out: parsed resp   */
                      upstream_node_t *node,
                      upstream_conn_t *uconn,
                      int              healthy);
typedef struct {
    uint64_t requests_total;
    uint64_t requests_failed;
    uint64_t retries;
    /* per-node stats are in upstream_node_t */
} lb_stats_t;

lb_stats_t lb_get_stats(const lb_t *lb);

/* ── Defaults helper ───────────────────────────────────────────────────────*/
void lb_config_init(lb_config_t *cfg);   /* fills sensible defaults         */

#endif /* ROUTA_LB_LB_H */