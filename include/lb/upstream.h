#ifndef ROUTA_LB_UPSTREAM_H
#define ROUTA_LB_UPSTREAM_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>

/* ── Forward declarations ──────────────────────────────────────────────────*/
typedef struct upstream_node    upstream_node_t;
typedef struct upstream_pool    upstream_pool_t;
typedef struct upstream_conn    upstream_conn_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * upstream_conn_t — one physical TCP connection to an upstream
 *
 * HTTP/2 note: when multiplexing is added, upstream_conn_t will carry a
 * stream table and max_streams.  The pool interface (acquire/release) stays
 * identical — callers are already stream-ID agnostic.
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef enum {
    UPSTREAM_CONN_IDLE    = 0,
    UPSTREAM_CONN_IN_USE  = 1,
    UPSTREAM_CONN_CLOSING = 2,
} upstream_conn_state_t;

struct upstream_conn {
    int                    fd;
    upstream_conn_state_t  state;
    upstream_node_t       *node;       /* back-pointer                      */
    time_t                 created_at;
    time_t                 last_used;
    uint32_t               requests;   /* total requests served on this fd  */

    /* HTTP/2 future slots — zero for HTTP/1.1 */
    uint32_t               max_streams;    /* 0 = HTTP/1.1 (1 stream/conn)  */
    uint32_t               active_streams; /* concurrent streams in flight   */

    upstream_conn_t       *next;       /* intrusive freelist                */
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Health check config
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef enum {
    HC_NONE   = 0,   /* passive only                                        */
    HC_TCP    = 1,   /* active: TCP connect probe                           */
    HC_HTTP   = 2,   /* active: HTTP GET, expect 2xx                        */
    HC_CUSTOM = 3,   /* active: HTTP GET, parse JSON {"status":"ok"}        */
} health_check_type_t;

typedef struct {
    health_check_type_t type;
    char                path[256];     /* HTTP probe path, default "/health" */
    int                 interval_ms;   /* probe interval, default 5000       */
    int                 timeout_ms;    /* probe timeout,  default 2000       */
    int                 threshold_up;  /* consecutive successes → UP         */
    int                 threshold_down;/* consecutive failures  → DOWN       */
} health_check_config_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * upstream_node_t — one backend server
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef enum {
    NODE_UP   = 0,
    NODE_DOWN = 1,
    NODE_DRAINING = 2,   /* graceful removal: no new conns, finish existing */
} node_state_t;

struct upstream_node {
    char     host[256];
    uint16_t port;
    int      weight;          /* for Weighted RR and P2C                    */

    node_state_t       state;
    pthread_spinlock_t state_lock;

    /* Passive health tracking */
    uint32_t  fail_count;         /* consecutive failures                   */
    uint32_t  success_count;      /* consecutive successes (for recovery)   */
    uint32_t  total_requests;
    uint32_t  total_errors;
    time_t    last_fail_time;

    /* Active health check */
    health_check_config_t hc;
    int                   hc_consec_ok;   /* consecutive probe successes    */
    int                   hc_consec_fail; /* consecutive probe failures     */

    /* Connection pool — guarded by pool_lock */
    pthread_mutex_t  pool_lock;
    upstream_conn_t *idle_conns;    /* freelist of idle connections         */
    int              idle_count;
    int              active_count;  /* connections currently in use         */
    int              pool_max;      /* max total connections to this node   */

    /* Least-connections counter — updated atomically */
    volatile uint32_t inflight;

    /* Resolved address (cached) */
    struct sockaddr_in addr;
    int                addr_resolved;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection pool API
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Acquire an idle connection or open a new one.
 * Returns NULL if node is DOWN or pool exhausted.
 * timeout_ms: how long to wait for a slot (0 = non-blocking).             */
upstream_conn_t *upstream_conn_acquire(upstream_node_t *node, int timeout_ms);

/* Return a connection to the pool.
 * healthy=0 → connection is broken, will be closed instead of recycled.   */
void upstream_conn_release(upstream_conn_t *conn, int healthy);

/* Force-close all idle connections on a node (e.g. after health failure).  */
void upstream_node_drain_idle(upstream_node_t *node);

/* ═══════════════════════════════════════════════════════════════════════════
 * Health check thread API (internal — called by lb.c)
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef struct upstream_pool upstream_pool_t;

/* Start/stop the background health-check thread for a pool.                */
int  upstream_pool_hc_start(upstream_pool_t *pool);
void upstream_pool_hc_stop(upstream_pool_t *pool);

/* ═══════════════════════════════════════════════════════════════════════════
 * upstream_pool_t — collection of nodes + shared config
 * ═══════════════════════════════════════════════════════════════════════════*/
struct upstream_pool {
    upstream_node_t **nodes;
    int               node_count;

    /* Passive health thresholds (shared defaults, overridden per-node) */
    int passive_fail_threshold;    /* failures before marking DOWN, default 3 */
    int passive_recover_threshold; /* successes before marking UP,   default 2 */

    /* Health check thread */
    pthread_t  hc_thread;
    int        hc_running;
    int        hc_stop;

    /* Round-robin counter — updated atomically */
    volatile uint32_t rr_counter;

    /* Consistent hash ring — populated lazily */
    void *hash_ring;   /* opaque, allocated by lb.c when algo=CONSISTENT_HASH */
};

upstream_pool_t *upstream_pool_new(void);
void             upstream_pool_free(upstream_pool_t *pool);
int              upstream_pool_add_node(upstream_pool_t *pool,
                                        upstream_node_t *node);

/* Mark a node UP/DOWN (thread-safe).                                       */
void upstream_node_set_state(upstream_node_t *node, node_state_t state);

/* Record a request outcome — drives passive health logic.                  */
void upstream_node_record_success(upstream_node_t *node,
                                  upstream_pool_t *pool);
void upstream_node_record_failure(upstream_node_t *node,
                                  upstream_pool_t *pool);

#endif /* ROUTA_LB_UPSTREAM_H */