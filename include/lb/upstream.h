#ifndef ROUTA_LB_UPSTREAM_H
#define ROUTA_LB_UPSTREAM_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
/* pthread_spinlock_t is Linux-only; fall back to mutex on other platforms */
#if !defined(__linux__)
#  define pthread_spinlock_t        pthread_mutex_t
#  define pthread_spin_init(l,s)    pthread_mutex_init((l), NULL)
#  define pthread_spin_destroy(l)   pthread_mutex_destroy(l)
#  define pthread_spin_lock(l)      pthread_mutex_lock(l)
#  define pthread_spin_unlock(l)    pthread_mutex_unlock(l)
#endif
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
    NODE_UP        = 0,
    NODE_DOWN      = 1,
    NODE_DRAINING  = 2,   /* graceful removal: no new conns, finish existing */
    NODE_HALF_OPEN = 3,   /* DOWN node currently allowing one trial request to
                           * test recovery -- see upstream_node_is_selectable().
                           * Only reachable/used when hc.type == HC_NONE; nodes
                           * with active health checks recover via the probe
                           * thread instead and never enter this state. */
} node_state_t;

struct upstream_node {
    char     host[256];
    uint16_t port;
    int      weight;          /* for Weighted RR and P2C                    */
    int      current_weight;  /* Smooth WRR dynamic state, guarded by the
                                * owning lb_t's wrr_lock (see pick_wrr() in
                                * lb.c) -- nginx-style: incremented by weight
                                * each pick, winner decremented by total
                                * weight, so bursts of the same high-weight
                                * node get spread out rather than clustered. */

    node_state_t       state;
    pthread_spinlock_t state_lock;

    /* Passive health tracking */
    uint32_t  fail_count;         /* consecutive failures                   */
    uint32_t  success_count;      /* consecutive successes (for recovery)   */
    uint32_t  total_requests;
    uint32_t  total_errors;
    time_t    last_fail_time;

    /* Circuit-breaker half-open state (only used when hc.type == HC_NONE --
     * nodes with an active health check recover via the probe thread
     * instead). down_since is set when the node transitions to NODE_DOWN;
     * once half_open_retry_after_ms has elapsed, the NEXT request routed to
     * this node is allowed through as a trial (state flips to
     * NODE_HALF_OPEN for the duration of that one request) instead of being
     * skipped like a normal DOWN node. half_open_probe_in_flight guards
     * against multiple concurrent requests all trying to be "the" trial at
     * once -- only the request that wins the compare-and-swap gets routed;
     * everyone else still sees the node as DOWN. */
    /* BUG FIX (circuit breaker half-open recovery never triggering with
     * sub-second half_open_retry_after_ms values): time_t has only
     * SECOND resolution. The half-open elapsed-time check
     * (upstream_node_is_selectable()) computed
     * difftime(now, down_since) * 1000 to compare against
     * half_open_retry_after_ms (a MILLISECOND config value) -- for any
     * retry window under ~1 full second, down_since and "now" landing
     * in the same wall-clock second (extremely likely for a sub-second
     * window) made elapsed_ms read as 0, permanently failing the
     * "enough time has passed" check and leaving the node stuck in
     * NODE_DOWN forever (confirmed live: a 500ms half_open_retry_after_ms
     * with the node's replacement upstream demonstrably healthy and
     * reachable never received a single request even 700ms+ after
     * coming back up). Switched to a CLOCK_MONOTONIC-based millisecond
     * timestamp -- same class of fix as this session's H2 last_stream_ts
     * timing bug, and immune to wall-clock adjustments besides. */
    uint64_t            down_since_ms;
    volatile uint32_t   half_open_probe_in_flight; /* 0 or 1, CAS-guarded */

    /* Circuit-breaker observability counters (Faz D). Incremented in
     * upstream_node_set_state() / upstream_node_is_selectable() --
     * distinct from fail_count/success_count (consecutive-run counters
     * used for the UP/DOWN decision itself) and from total_requests/
     * total_errors (per-request outcome tallies): these two specifically
     * count STATE-TRANSITION events, i.e. "how many times did this node
     * actually trip the breaker" / "how many half-open recovery trials
     * were attempted", which total_errors alone can't answer (a node
     * could accumulate many total_errors while only tripping the
     * breaker once, if passive_fail_threshold hasn't been reached). */
    volatile uint32_t   circuit_breaker_trips_total;
    volatile uint32_t   half_open_trials_total;

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

    /* Resolved address (cached). sockaddr_storage holds either an IPv4
     * (sockaddr_in) or IPv6 (sockaddr_in6) address -- addr_family says
     * which, and callers doing raw connect()/socket() calls must use it
     * instead of assuming AF_INET. */
    struct sockaddr_storage addr;
    socklen_t               addr_len;    /* actual size to pass to connect() */
    int                     addr_family; /* AF_INET or AF_INET6 */
    int                     addr_resolved;

    /* TLS upstream: 1 = connect with TLS, try ALPN h2 */
    int                use_tls;

    /* Back-reference to the pool this node belongs to. Set once by
     * upstream_pool_add_node() at pool construction time. Lets any code
     * holding just an upstream_node_t* (e.g. event_loop.c's H2/TLS
     * async-establishment dispatch, which only has h2up->pending_node,
     * not the lb_t/pool the request came from) call
     * upstream_node_record_failure()/record_success() without needing
     * the caller to separately thread a pool pointer through -- see the
     * H2/TLS failover circuit-breaker fix this was added for. */
    struct upstream_pool *pool;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection pool API
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Return a connection to the pool.
 * healthy=0 → connection is broken, will be closed instead of recycled.   */
void upstream_conn_release(upstream_conn_t *conn, int healthy);

/* Force-close all idle connections on a node (e.g. after health failure).  */
void upstream_node_drain_idle(upstream_node_t *node);

/* Close idle connections whose last_used timestamp is older than max_age_s. */
void upstream_node_reap_idle(upstream_node_t *node, time_t max_age_s);

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

    /* Circuit-breaker half-open: how long a DOWN node (with no active
     * health check) sits before the next request is let through as a
     * trial. 0 disables half-open entirely (DOWN nodes with hc.type ==
     * HC_NONE then stay DOWN forever, the pre-existing behavior).
     * default: 30000 (30s). */
    int half_open_retry_after_ms;

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

/* ── Async connect API ─────────────────────────────────────────────────────
 *
 * upstream_conn_connect_async() opens a non-blocking TCP socket and calls
 * connect().  Returns:
 *   fd >= 0  connect in progress (EINPROGRESS) or done — caller adds fd
 *            to its poller with POLLER_WRITE to wait for completion.
 *   -1       fatal error (node marked failed).
 *
 * After POLLOUT fires, call upstream_conn_check_connected(fd):
 *   0   connected OK
 *  -1   connect failed
 * -------------------------------------------------------------------------*/
int upstream_conn_connect_async(upstream_node_t *node);
int upstream_conn_check_connected(int fd);

/* Record a request outcome — drives passive health logic.                  */
void upstream_node_record_success(upstream_node_t *node,
                                  upstream_pool_t *pool);
void upstream_node_record_failure(upstream_node_t *node,
                                  upstream_pool_t *pool);

/* Returns 1 if this node should be considered for selection right now:
* - NODE_UP                                   -> always 1
* - NODE_DRAINING                              -> always 0
* - NODE_DOWN, hc.type != HC_NONE              -> 0 (health-check thread
*                                                 owns recovery for this node)
* - NODE_DOWN, hc.type == HC_NONE:
*     - half_open_retry_after_ms <= 0          -> 0 (half-open disabled)
*     - not enough time elapsed since down_since -> 0
*     - enough time elapsed, but another request already won the trial
*       slot (CAS)                              -> 0
*     - enough time elapsed AND this call wins the CAS -> 1 (caller is now
*       responsible for routing exactly one request to this node and
*       calling upstream_node_half_open_release() when it completes)
* NODE_HALF_OPEN is a transient state only ever seen briefly by the winning
* caller between this check and the request outcome being recorded; it is
* not itself checked here.                                                */
int upstream_node_is_selectable(upstream_node_t *node, upstream_pool_t *pool);

/* Called after a half-open trial request completes (success or failure) to
* release the in-flight guard so a future trial can be attempted. Safe to
* call unconditionally -- a no-op if this node wasn't in a half-open trial
* (e.g. it's a normal NODE_UP node). record_success/record_failure call
* this internally, so callers going through those don't need to call it
* themselves; it's exposed for callers that need to bail out before
* reaching record_success/record_failure (e.g. connect() itself failed). */
void upstream_node_half_open_release(upstream_node_t *node);

#endif /* ROUTA_LB_UPSTREAM_H */