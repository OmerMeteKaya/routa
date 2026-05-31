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

/* Render Prometheus text format into buf (NUL-terminated).
 * Returns bytes written (excluding NUL), -1 if buf too small.             */
int routa_metrics_prometheus(char *buf, size_t buf_sz);

#endif /* ROUTA_UTIL_METRICS_H */