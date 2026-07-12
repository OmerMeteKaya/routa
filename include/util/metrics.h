#ifndef ROUTA_UTIL_METRICS_H
#define ROUTA_UTIL_METRICS_H

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Histogram bucket upper bounds (milliseconds).
 * Log-scale — matches real-world network latency distribution.
 * Last entry is UINT32_MAX → +Inf bucket.
 * ═══════════════════════════════════════════════════════════════════════════*/
#define ROUTA_HIST_BUCKET_COUNT 10
extern const uint32_t routa_hist_bounds_ms[ROUTA_HIST_BUCKET_COUNT];
/* { 1, 5, 10, 25, 50, 100, 250, 500, 1000, UINT32_MAX } */

/* ═══════════════════════════════════════════════════════════════════════════
 * Method index — compact enum for array indexing
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef enum {
    ROUTA_MIDX_GET     = 0,
    ROUTA_MIDX_POST    = 1,
    ROUTA_MIDX_PUT     = 2,
    ROUTA_MIDX_DELETE  = 3,
    ROUTA_MIDX_HEAD    = 4,
    ROUTA_MIDX_PATCH   = 5,
    ROUTA_MIDX_OPTIONS = 6,
    ROUTA_MIDX_OTHER   = 7,
    ROUTA_MIDX_COUNT   = 8,
} routa_method_idx_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Status class index
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef enum {
    ROUTA_SC_1XX   = 0,
    ROUTA_SC_2XX   = 1,
    ROUTA_SC_3XX   = 2,
    ROUTA_SC_4XX   = 3,
    ROUTA_SC_5XX   = 4,
    ROUTA_SC_OTHER = 5,
    ROUTA_SC_COUNT = 6,
} routa_status_class_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Core metrics struct — all fields are lock-free atomics.
 *
 * Workers write directly; /metrics handler reads with relaxed ordering.
 * Slight inconsistency on a single scrape is acceptable for Prometheus.
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef struct {
    /* ── Request counters [method][status_class] ───────────────────────── */
    _Atomic uint64_t requests_total[ROUTA_MIDX_COUNT][ROUTA_SC_COUNT];

    /* ── Latency histogram ─────────────────────────────────────────────── */
    _Atomic uint64_t latency_buckets[ROUTA_HIST_BUCKET_COUNT];
    _Atomic uint64_t latency_sum_us;   /* microseconds, compute ms on read */
    _Atomic uint64_t latency_count;

    /* ── Connection gauges ─────────────────────────────────────────────── */
    _Atomic int64_t  active_connections;   /* signed: dec can race */
    _Atomic uint64_t peak_connections;
    _Atomic uint64_t connections_total;

    /* ── Error counters ────────────────────────────────────────────────── */
    _Atomic uint64_t parse_errors_total;
    _Atomic uint64_t tls_errors_total;
    _Atomic uint64_t ws_disconnects_total;
    _Atomic uint64_t upstream_failures_total;

    _Atomic uint64_t tls_handshakes_total;
    _Atomic uint64_t tls_resumptions_total;

    _Atomic uint64_t h2_streams_opened_total;
    _Atomic uint64_t h2_streams_closed_total;
    _Atomic uint64_t h2_rst_streams_total;
    _Atomic uint64_t h2_goaway_sent_total;
    _Atomic uint64_t h2_flow_control_stalls_total;
    _Atomic int64_t  h2_active_streams;

    /* ── Process memory (updated periodically, see routa_metrics_update_rss) ── */
    _Atomic uint64_t process_rss_bytes;
    _Atomic uint64_t memory_soft_limit_exceeded_total; /* count of times we tripped into reject-new-conns */
    _Atomic uint64_t memory_hard_limit_exceeded_total; /* count of times we triggered a graceful shutdown */

    /* ── Traffic volume ─────────────────────────────────────────────────
     * bytes_sent was previously accepted by routa_metrics_record() but
     * silently discarded ((void)bytes_sent -- "reserved for future");
     * this is that future. bytes_received covers request bodies, tracked
     * separately since read()/write() volume can be very asymmetric
     * (e.g. large file downloads vs small API POSTs). */
    _Atomic uint64_t bytes_sent_total;
    _Atomic uint64_t bytes_received_total;

    /* ── Middleware rejection counters ────────────────────────────────
     * Each of these counts a request that was turned away by a specific
     * middleware BEFORE reaching the route handler -- distinct from the
     * generic requests_total[method][4xx] bucket, which conflates rate
     * limiting, ACL denial, auth failure, and ordinary application-level
     * 4xx responses into one number. An operator paging on a spike in
     * 4xx traffic needs to know WHICH of these it is. */
    _Atomic uint64_t rate_limit_rejected_total;
    _Atomic uint64_t acl_denied_total;
    _Atomic uint64_t auth_basic_failures_total;
    _Atomic uint64_t auth_jwt_failures_total;

    /* ── File cache (src/http/file_cache.c) ───────────────────────────── */
    _Atomic uint64_t file_cache_hits_total;
    _Atomic uint64_t file_cache_misses_total;

    /* ── Config hot-reload (SIGHUP) ───────────────────────────────────── */
    _Atomic uint64_t config_reload_total;
    _Atomic uint64_t config_reload_failures_total;

} routa_metrics_t;

/* Single global instance — defined in metrics.c */
extern routa_metrics_t g_metrics;

/* ═══════════════════════════════════════════════════════════════════════════
 * Abstraction macros — never put backend-specific code in hot path.
 * Swap the backend by redefining these macros only.
 * ═══════════════════════════════════════════════════════════════════════════*/
#define ROUTA_METRIC_INC(field) \
    atomic_fetch_add_explicit(&g_metrics.field, 1, memory_order_relaxed)

#define ROUTA_METRIC_DEC(field) \
    atomic_fetch_sub_explicit(&g_metrics.field, 1, memory_order_relaxed)

#define ROUTA_METRIC_ADD(field, val) \
    atomic_fetch_add_explicit(&g_metrics.field, (val), memory_order_relaxed)

#define ROUTA_METRIC_GET(field) \
((uint64_t)(g_metrics.field))

/* ═══════════════════════════════════════════════════════════════════════════
 * Clock abstraction — portable monotonic microsecond timestamp.
 * Use this everywhere instead of raw clock_gettime.
 * ═══════════════════════════════════════════════════════════════════════════*/
static inline uint64_t routa_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL +
           (uint64_t)ts.tv_nsec / 1000ULL;
}

static inline uint64_t routa_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL +
           (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Call once at startup */
void routa_metrics_init(void);

/* Record a completed request.
 * method_str : "GET", "POST", etc.  (or NULL → OTHER)
 * status     : HTTP status code
 * start_us   : routa_now_us() captured at request start
 * bytes_sent : response body bytes (0 if unknown)                          */
void routa_metrics_record(const char *method_str,
                          int         status,
                          uint64_t    start_us,
                          size_t      bytes_sent);

/* Connection lifecycle helpers */
void routa_metrics_conn_open(void);
void routa_metrics_conn_close(void);

/* Request body bytes received -- see metrics.c for why this is separate
 * from routa_metrics_record()'s bytes_sent parameter. */
void routa_metrics_record_bytes_received(size_t bytes);

/* Reads current process RSS (Linux: /proc/self/status VmRSS; falls back to
 * getrusage(RUSAGE_SELF) ru_maxrss on other platforms, which is peak
 * rather than current RSS -- close enough for a soft/hard limit trigger,
 * and the only portable option without platform-specific APIs) and
 * stores it in g_metrics.process_rss_bytes. Cheap enough to call every
 * couple of seconds from a single worker's sweep loop; not needed (and
 * not safe to assume free of contention) from a hot request path. */
void routa_metrics_update_rss(void);

/* Render Prometheus text format into buf (NUL-terminated).
 * Returns bytes written (excluding NUL), -1 if buf too small.             */
int routa_metrics_prometheus(char *buf, size_t buf_sz);

/* Render per-pool / per-upstream Prometheus metrics (request/error counts,
 * health state, in-flight connections) by walking a server_t's configured
 * LB pools. Appends to buf starting at the position implied by
 * strlen(buf) so callers can render routa_metrics_prometheus() first and
 * this second into the same buffer.
 *
 * srv_ptr is passed as void* (rather than server_t*) deliberately: server_t
 * is an anonymous-struct typedef (`typedef struct { ... } server_t;` in
 * core/server.h, no separate tag to forward-declare), so there is no way
 * to forward-declare it from this header without pulling in core/server.h
 * here -- which metrics.h otherwise has no dependency on. metrics.c casts
 * srv_ptr back to server_t* internally, after including core/server.h
 * itself. Callers should just pass their server_t* directly; the void*
 * here is a header-boundary technicality, not an invitation to pass
 * anything else.
 *
 * Returns bytes appended (excluding NUL), -1 on overflow. srv_ptr may be
 * NULL (e.g. a server built with server_new() directly, with no LB pools
 * configured via server_from_config()) -- in that case this is a no-op
 * that returns 0. */
int routa_metrics_prometheus_lb(char *buf, size_t buf_sz, void *srv_ptr);

#endif /* ROUTA_UTIL_METRICS_H */