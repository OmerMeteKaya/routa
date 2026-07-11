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
    int upstream_read_timeout_ms;  /* max time between reads on an active upstream conn, default: 30000 */
    int upstream_write_timeout_ms; /* max time between writes on an active upstream conn, default: 30000 */
    int pool_idle_timeout_s;    /* close idle conns after N seconds, def 60 */

    /* Passive health */
    int passive_fail_threshold;    /* default: 3                            */
    int passive_recover_threshold; /* default: 2                            */

    /* Circuit-breaker half-open: how long (ms) a DOWN node with no active
     * health check (hc.type == HC_NONE) waits before the next request is
     * let through as a recovery trial. 0 disables half-open -- such a
     * node then stays DOWN forever once tripped. default: 30000 (30s). */
    int half_open_retry_after_ms;

    /* Active health check (applies to all nodes unless overridden) */
    health_check_config_t hc;

    /* Consistent hash virtual nodes */
    int consistent_hash_vnodes;    /* default: 150                          */

    /* Retry */
    int max_retries;            /* 0 = no retry, default: 1                 */
    int retry_on_connect_fail;  /* default: 1                               */
    int retry_on_5xx;           /* default: 0                               */

    /* Cookie-based sticky sessions (override on top of the configured
     * algo, checked first). When enabled, routa sets a cookie identifying
     * which node served a request; subsequent requests carrying that
     * cookie are pinned to the same node as long as it's still UP. */
    int  sticky_session_enabled;   /* default: 0 */
    char sticky_cookie_name[128];  /* default: "routa_sticky" */

    /* ── Header manipulation ──────────────────────────────────────────────
     * Applied on top of routa's own automatic headers (X-Forwarded-For,
     * X-Forwarded-Proto, Via, Host, Content-Length, Connection) -- these
     * are always added/removed in addition to that base behavior, never
     * instead of it. request_header_* affects what's sent to the
     * upstream; response_header_* affects what's sent back to the
     * client. "Remove" is checked case-insensitively and happens before
     * "add" for the same header name, so an add of a header also present
     * in the remove list still ends up present exactly once. */
#define LB_MAX_HEADER_RULES 16
    struct { char name[128]; char value[256]; } request_header_add[LB_MAX_HEADER_RULES];
    int      request_header_add_count;
    char     request_header_remove[LB_MAX_HEADER_RULES][128];
    int      request_header_remove_count;

    struct { char name[128]; char value[256]; } response_header_add[LB_MAX_HEADER_RULES];
    int      response_header_add_count;
    char     response_header_remove[LB_MAX_HEADER_RULES][128];
    int      response_header_remove_count;
} lb_config_t;

#define ROUTA_MAX_LB_POOLS 16

/* ── Load balancer instance ────────────────────────────────────────────────*/
typedef struct lb lb_t;
/* Returns the upstream pool for direct node state recording.
 * Used by proxy.c to call upstream_node_record_failure/success. */
upstream_pool_t *lb_get_pool(lb_t *lb);
void lb_get_upstream_timeouts(const lb_t *lb, int *read_timeout_ms, int *write_timeout_ms);
int  lb_sticky_enabled(const lb_t *lb);
const char *lb_sticky_cookie_name(const lb_t *lb);
/* Retry policy accessors -- see lb.c's lb_retry_on_5xx_enabled() doc
 * comment for why these were added (lb_retry_on_5xx / lb_max_retries
 * were parsed from config but never actually consulted anywhere). */
int  lb_retry_on_5xx_enabled(const lb_t *lb);
int  lb_get_max_retries(const lb_t *lb);
void lb_record_retry(lb_t *lb);
/* Create / destroy */
lb_t *lb_new(const lb_config_t *cfg);
void  lb_free(lb_t *lb);

/* Add an upstream node.  weight ignored for non-weighted algorithms.       */
int lb_add_upstream(lb_t *lb,
                    const char *host, uint16_t port, int weight);

/* Add a TLS upstream node (H2 via ALPN when supported).                    */
int lb_add_upstream_tls(lb_t *lb,
                        const char *host, uint16_t port, int weight);

/* Returns 1 if any upstream node uses TLS (potential H2 path).             */
int lb_is_tls_upstream(lb_t *lb);

/* Start background threads (health check, idle conn reaper).
 * Call after all upstreams are added, before first request.                */
int lb_start(lb_t *lb);
void lb_stop(lb_t *lb);

/* ── Node selection (exposed for testing / custom wrappers) ────────────────*/
upstream_node_t *lb_pick_node(lb_t *lb, const char *client_ip);
upstream_node_t *lb_pick_node_sticky(lb_t *lb, const char *client_ip,
                                     const char *sticky_cookie_value);
void lb_sticky_cookie_value_for_node(lb_t *lb, const upstream_node_t *node,
                                     char *out_buf, size_t out_buf_len);

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

/* Like lb_begin_forward() but uses a node the caller has already selected
 * via lb_pick_node(), instead of picking internally. Used by proxy_begin()
 * so node selection happens exactly once per request. */
int lb_begin_forward_to_node(lb_t *lb,
                             upstream_node_t      *node,
                             const http_request_t *req,
                             const char            *client_ip,
                             const char            *proto,
                             buf_t                 *req_buf,
                             upstream_conn_t      **out_uconn);

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