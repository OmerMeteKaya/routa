#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "util/metrics.h"
#include "core/server.h"
#include "lb/lb.h"
#include "lb/upstream.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

/* ── Global instance ────────────────────────────────────────────────────── */
routa_metrics_t g_metrics;

/* ── Histogram bounds (ms) ──────────────────────────────────────────────── */
const uint32_t routa_hist_bounds_ms[ROUTA_HIST_BUCKET_COUNT] = {
    1, 5, 10, 25, 50, 100, 250, 500, 1000, UINT32_MAX
};

/* ── Init ───────────────────────────────────────────────────────────────── */
void routa_metrics_init(void) {
    memset(&g_metrics, 0, sizeof(g_metrics));
}

/* ── Process RSS ────────────────────────────────────────────────────────────────────────── */
#ifdef __linux__
void routa_metrics_update_rss(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;

    char line[256];
    uint64_t rss_kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            /* Format: "VmRSS:      12345 kB" */
            (void)sscanf(line + 6, "%" SCNu64, &rss_kb);
            break;
        }
    }
    (void)fclose(f);

    if (rss_kb > 0) {
        atomic_store_explicit(&g_metrics.process_rss_bytes,
                              rss_kb * 1024ULL, memory_order_relaxed);
    }
}
#else
#include <sys/resource.h>
void routa_metrics_update_rss(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return;
    /* ru_maxrss is peak, not current, and its unit is platform-specific
     * (bytes on Darwin historically; POSIX doesn't standardize it) -- a
     * best-effort fallback. Linux (the primary target platform) uses the
     * precise /proc/self/status path above instead. */
    atomic_store_explicit(&g_metrics.process_rss_bytes,
                          (uint64_t)ru.ru_maxrss, memory_order_relaxed);
}
#endif

/* ── Method string → index ──────────────────────────────────────────────── */
static routa_method_idx_t method_to_idx(const char *m) {
    if (!m)                        return ROUTA_MIDX_OTHER;
    if (strcmp(m, "GET")     == 0) return ROUTA_MIDX_GET;
    if (strcmp(m, "POST")    == 0) return ROUTA_MIDX_POST;
    if (strcmp(m, "PUT")     == 0) return ROUTA_MIDX_PUT;
    if (strcmp(m, "DELETE")  == 0) return ROUTA_MIDX_DELETE;
    if (strcmp(m, "HEAD")    == 0) return ROUTA_MIDX_HEAD;
    if (strcmp(m, "PATCH")   == 0) return ROUTA_MIDX_PATCH;
    if (strcmp(m, "OPTIONS") == 0) return ROUTA_MIDX_OPTIONS;
    return ROUTA_MIDX_OTHER;
}

/* ── Status → class index ───────────────────────────────────────────────── */
static routa_status_class_t status_to_class(int s) {
    if (s >= 100 && s < 200) return ROUTA_SC_1XX;
    if (s >= 200 && s < 300) return ROUTA_SC_2XX;
    if (s >= 300 && s < 400) return ROUTA_SC_3XX;
    if (s >= 400 && s < 500) return ROUTA_SC_4XX;
    if (s >= 500 && s < 600) return ROUTA_SC_5XX;
    return ROUTA_SC_OTHER;
}

/* ── Record a completed request ─────────────────────────────────────────── */
void routa_metrics_record(const char *method_str,
                          int         status,
                          uint64_t    start_us,
                          size_t      bytes_sent) {
    if (bytes_sent > 0)
        ROUTA_METRIC_ADD(bytes_sent_total, (uint64_t)bytes_sent);

    /* Request counter */
    routa_method_idx_t  mi = method_to_idx(method_str);
    routa_status_class_t sc = status_to_class(status);
    ROUTA_METRIC_INC(requests_total[mi][sc]);

    /* Latency */
    uint64_t now   = routa_now_us();
    uint64_t delta = (now > start_us) ? (now - start_us) : 0;
    uint32_t delta_ms = (uint32_t)(delta / 1000);

    ROUTA_METRIC_ADD(latency_sum_us, delta);
    ROUTA_METRIC_INC(latency_count);

    /* Update histogram buckets — all buckets where le >= delta_ms */
    for (int i = 0; i < ROUTA_HIST_BUCKET_COUNT; i++) {
        if (delta_ms <= routa_hist_bounds_ms[i])
            ROUTA_METRIC_INC(latency_buckets[i]);
    }
}

/* ── Connection lifecycle ───────────────────────────────────────────────── */
void routa_metrics_conn_open(void) {
    ROUTA_METRIC_INC(connections_total);
    int64_t cur = atomic_fetch_add_explicit(
        &g_metrics.active_connections, 1, memory_order_relaxed) + 1;

    /* Update peak — CAS loop, non-blocking */
    uint64_t peak = ROUTA_METRIC_GET(peak_connections);
    while ((uint64_t)cur > peak) {
        uint64_t old = peak;
        if ((uint64_t)cur > old) {
            atomic_store_explicit(&g_metrics.peak_connections,
                                  (uint64_t)cur,
                                  memory_order_relaxed);
        }
        break;
    }
}

void routa_metrics_conn_close(void) {
    ROUTA_METRIC_DEC(active_connections);
}

/* ── Request body bytes received ────────────────────────────────────────
 * Separate from routa_metrics_record() because body bytes are known as
 * they're read (potentially streamed), not only once at request
 * completion -- callers (H1 body read loop, H2 DATA frame handling, proxy
 * request-body relay) call this incrementally or once with the final
 * total, whichever fits their code path; either way the counter is a
 * simple running total either way. */
void routa_metrics_record_bytes_received(size_t bytes) {
    if (bytes > 0)
        ROUTA_METRIC_ADD(bytes_received_total, (uint64_t)bytes);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Prometheus text format renderer
 * ═══════════════════════════════════════════════════════════════════════════*/

static const char *method_names[ROUTA_MIDX_COUNT] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "OTHER"
};

static const char *status_class_names[ROUTA_SC_COUNT] = {
    "1xx", "2xx", "3xx", "4xx", "5xx", "other"
};

/* Safe append helper — returns 0 on overflow */
#define PROM_APPEND(fmt, ...) \
    do { \
        int _n = snprintf(p, (size_t)(end - p), fmt, ##__VA_ARGS__); \
        if (_n < 0 || _n >= (int)(end - p)) return -1; \
        p += _n; \
    } while (0)

int routa_metrics_prometheus(char *buf, size_t buf_sz) {
    if (!buf || buf_sz == 0) return -1;
    char *p   = buf;
    char *end = buf + buf_sz;

    /* ── requests_total ─────────────────────────────────────────────────── */
    PROM_APPEND(
        "# HELP routa_requests_total Total HTTP requests handled\n"
        "# TYPE routa_requests_total counter\n"
    );
    for (int m = 0; m < ROUTA_MIDX_COUNT; m++) {
        for (int s = 0; s < ROUTA_SC_COUNT; s++) {
            uint64_t v = ROUTA_METRIC_GET(requests_total[m][s]);
            if (v == 0) continue;   /* omit zero-value series */
            PROM_APPEND(
                "routa_requests_total{method=\"%s\",status_class=\"%s\"} %llu\n",
                method_names[m], status_class_names[s],
                (unsigned long long)v
            );
        }
    }

    /* ── latency histogram ──────────────────────────────────────────────── */
    PROM_APPEND(
        "# HELP routa_request_duration_ms Request latency histogram (ms)\n"
        "# TYPE routa_request_duration_ms histogram\n"
    );
    for (int i = 0; i < ROUTA_HIST_BUCKET_COUNT; i++) {
        uint64_t v = ROUTA_METRIC_GET(latency_buckets[i]);
        if (routa_hist_bounds_ms[i] == UINT32_MAX) {
            PROM_APPEND(
                "routa_request_duration_ms_bucket{le=\"+Inf\"} %llu\n",
                (unsigned long long)v
            );
        } else {
            PROM_APPEND(
                "routa_request_duration_ms_bucket{le=\"%u\"} %llu\n",
                routa_hist_bounds_ms[i], (unsigned long long)v
            );
        }
    }
    {
        uint64_t sum_us = ROUTA_METRIC_GET(latency_sum_us);
        uint64_t count  = ROUTA_METRIC_GET(latency_count);
        /* Prometheus expects sum in same unit as buckets (ms) */
        PROM_APPEND(
            "routa_request_duration_ms_sum %.3f\n"
            "routa_request_duration_ms_count %llu\n",
            (double)sum_us / 1000.0,
            (unsigned long long)count
        );
    }


    /* ── connection metrics ─────────────────────────────────────────────── */
    PROM_APPEND(
        "# HELP routa_active_connections Currently open connections\n"
        "# TYPE routa_active_connections gauge\n"
        "routa_active_connections %lld\n"
        "# HELP routa_peak_connections Peak concurrent connections\n"
        "# TYPE routa_peak_connections gauge\n"
        "routa_peak_connections %llu\n"
        "# HELP routa_connections_total Total connections accepted\n"
        "# TYPE routa_connections_total counter\n"
        "routa_connections_total %llu\n",
        (long long)ROUTA_METRIC_GET(active_connections),
        (unsigned long long)ROUTA_METRIC_GET(peak_connections),
        (unsigned long long)ROUTA_METRIC_GET(connections_total)
    );

    /* ── error counters ─────────────────────────────────────────────────── */
    PROM_APPEND(
        "# HELP routa_parse_errors_total HTTP parse errors\n"
        "# TYPE routa_parse_errors_total counter\n"
        "routa_parse_errors_total %llu\n"
        "# HELP routa_tls_errors_total TLS handshake/read/write errors\n"
        "# TYPE routa_tls_errors_total counter\n"
        "routa_tls_errors_total %llu\n"
        "# HELP routa_ws_disconnects_total WebSocket abnormal disconnects\n"
        "# TYPE routa_ws_disconnects_total counter\n"
        "routa_ws_disconnects_total %llu\n"
        "# HELP routa_upstream_failures_total Upstream proxy failures\n"
        "# TYPE routa_upstream_failures_total counter\n"
        "routa_upstream_failures_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(parse_errors_total),
        (unsigned long long)ROUTA_METRIC_GET(tls_errors_total),
        (unsigned long long)ROUTA_METRIC_GET(ws_disconnects_total),
        (unsigned long long)ROUTA_METRIC_GET(upstream_failures_total)
    );
    /* ── TLS counters ── */
    PROM_APPEND(
        "# HELP routa_tls_handshakes_total Total TLS handshakes completed\n"
        "# TYPE routa_tls_handshakes_total counter\n"
        "routa_tls_handshakes_total %llu\n"
        "# HELP routa_tls_resumptions_total TLS session resumptions\n"
        "# TYPE routa_tls_resumptions_total counter\n"
        "routa_tls_resumptions_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(tls_handshakes_total),
        (unsigned long long)ROUTA_METRIC_GET(tls_resumptions_total)
    );

    /* ── H2 protocol counters ── */
    PROM_APPEND(
        "# HELP routa_h2_streams_opened_total H2 streams opened\n"
        "# TYPE routa_h2_streams_opened_total counter\n"
        "routa_h2_streams_opened_total %llu\n"
        "# HELP routa_h2_streams_closed_total H2 streams closed\n"
        "# TYPE routa_h2_streams_closed_total counter\n"
        "routa_h2_streams_closed_total %llu\n"
        "# HELP routa_h2_active_streams Current active H2 streams\n"
        "# TYPE routa_h2_active_streams gauge\n"
        "routa_h2_active_streams %lld\n"
        "# HELP routa_h2_rst_streams_total H2 RST_STREAM frames received\n"
        "# TYPE routa_h2_rst_streams_total counter\n"
        "routa_h2_rst_streams_total %llu\n"
        "# HELP routa_h2_goaway_sent_total H2 GOAWAY frames sent\n"
        "# TYPE routa_h2_goaway_sent_total counter\n"
        "routa_h2_goaway_sent_total %llu\n"
        "# HELP routa_h2_flow_control_stalls_total H2 flow control stalls\n"
        "# TYPE routa_h2_flow_control_stalls_total counter\n"
        "routa_h2_flow_control_stalls_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(h2_streams_opened_total),
        (unsigned long long)ROUTA_METRIC_GET(h2_streams_closed_total),
        (long long)ROUTA_METRIC_GET(h2_active_streams),
        (unsigned long long)ROUTA_METRIC_GET(h2_rst_streams_total),
        (unsigned long long)ROUTA_METRIC_GET(h2_goaway_sent_total),
        (unsigned long long)ROUTA_METRIC_GET(h2_flow_control_stalls_total)
    );

    /* ── Process memory ── */
    PROM_APPEND(
        "# HELP routa_process_rss_bytes Current process resident set size\n"
        "# TYPE routa_process_rss_bytes gauge\n"
        "routa_process_rss_bytes %llu\n"
        "# HELP routa_memory_soft_limit_exceeded_total Times new connections were rejected due to the soft memory limit\n"
        "# TYPE routa_memory_soft_limit_exceeded_total counter\n"
        "routa_memory_soft_limit_exceeded_total %llu\n"
        "# HELP routa_memory_hard_limit_exceeded_total Times a graceful shutdown was triggered by the hard memory limit\n"
        "# TYPE routa_memory_hard_limit_exceeded_total counter\n"
        "routa_memory_hard_limit_exceeded_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(process_rss_bytes),
        (unsigned long long)ROUTA_METRIC_GET(memory_soft_limit_exceeded_total),
        (unsigned long long)ROUTA_METRIC_GET(memory_hard_limit_exceeded_total)
    );

    /* ── Traffic volume ── */
    PROM_APPEND(
        "# HELP routa_bytes_sent_total Total response body bytes sent\n"
        "# TYPE routa_bytes_sent_total counter\n"
        "routa_bytes_sent_total %llu\n"
        "# HELP routa_bytes_received_total Total request body bytes received\n"
        "# TYPE routa_bytes_received_total counter\n"
        "routa_bytes_received_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(bytes_sent_total),
        (unsigned long long)ROUTA_METRIC_GET(bytes_received_total)
    );

    /* ── Middleware rejection counters ── */
    PROM_APPEND(
        "# HELP routa_rate_limit_rejected_total Requests rejected by rate limiting (429)\n"
        "# TYPE routa_rate_limit_rejected_total counter\n"
        "routa_rate_limit_rejected_total %llu\n"
        "# HELP routa_acl_denied_total Requests denied by ACL rules (403)\n"
        "# TYPE routa_acl_denied_total counter\n"
        "routa_acl_denied_total %llu\n"
        "# HELP routa_auth_basic_failures_total Basic Auth failures (401)\n"
        "# TYPE routa_auth_basic_failures_total counter\n"
        "routa_auth_basic_failures_total %llu\n"
        "# HELP routa_auth_jwt_failures_total JWT Auth failures (401)\n"
        "# TYPE routa_auth_jwt_failures_total counter\n"
        "routa_auth_jwt_failures_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(rate_limit_rejected_total),
        (unsigned long long)ROUTA_METRIC_GET(acl_denied_total),
        (unsigned long long)ROUTA_METRIC_GET(auth_basic_failures_total),
        (unsigned long long)ROUTA_METRIC_GET(auth_jwt_failures_total)
    );

    /* ── File cache ── */
    PROM_APPEND(
        "# HELP routa_file_cache_hits_total File stat/content cache hits\n"
        "# TYPE routa_file_cache_hits_total counter\n"
        "routa_file_cache_hits_total %llu\n"
        "# HELP routa_file_cache_misses_total File stat/content cache misses\n"
        "# TYPE routa_file_cache_misses_total counter\n"
        "routa_file_cache_misses_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(file_cache_hits_total),
        (unsigned long long)ROUTA_METRIC_GET(file_cache_misses_total)
    );

    /* ── Config hot-reload ── */
    PROM_APPEND(
        "# HELP routa_config_reload_total Config hot-reloads triggered (SIGHUP)\n"
        "# TYPE routa_config_reload_total counter\n"
        "routa_config_reload_total %llu\n"
        "# HELP routa_config_reload_failures_total Config hot-reloads that failed validation/load\n"
        "# TYPE routa_config_reload_failures_total counter\n"
        "routa_config_reload_failures_total %llu\n",
        (unsigned long long)ROUTA_METRIC_GET(config_reload_total),
        (unsigned long long)ROUTA_METRIC_GET(config_reload_failures_total)
    );

    return (int)(p - buf);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-pool / per-upstream Prometheus metrics
 * ═══════════════════════════════════════════════════════════════════════════*/

static const char *node_state_name(node_state_t st) {
    switch (st) {
        case NODE_UP:        return "up";
        case NODE_DOWN:      return "down";
        case NODE_HALF_OPEN: return "half_open";
        default:             return "unknown";
    }
}

int routa_metrics_prometheus_lb(char *buf, size_t buf_sz, void *srv_ptr) {
    if (!buf || buf_sz == 0) return -1;
    server_t *s = (server_t *)srv_ptr;
    if (!s) return 0;

    size_t used = strlen(buf);
    char  *p    = buf + used;
    char  *end  = buf + buf_sz;

    if (s->lb_pool_count <= 0) return 0;

    PROM_APPEND(
        "# HELP routa_upstream_requests_total Requests sent to this upstream node\n"
        "# TYPE routa_upstream_requests_total counter\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_requests_total{pool=\"%s\",upstream=\"%s:%u\"} %u\n",
                pool_name, node->host, (unsigned)node->port, node->total_requests
            );
        }
    }

    PROM_APPEND(
        "# HELP routa_upstream_errors_total Failed requests to this upstream node\n"
        "# TYPE routa_upstream_errors_total counter\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_errors_total{pool=\"%s\",upstream=\"%s:%u\"} %u\n",
                pool_name, node->host, (unsigned)node->port, node->total_errors
            );
        }
    }

    PROM_APPEND(
        "# HELP routa_upstream_up Whether this upstream node is currently considered healthy (1) or not (0)\n"
        "# TYPE routa_upstream_up gauge\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            /* NODE_HALF_OPEN is a brief transient state for the one
             * request currently on trial -- report it as "not yet up"
             * (0) for the gauge, since it isn't confirmed healthy until
             * that trial succeeds; the routa_upstream_state series below
             * (state name as a label) is where half_open is visible. */
            int up_val = (node->state == NODE_UP) ? 1 : 0;
            PROM_APPEND(
                "routa_upstream_up{pool=\"%s\",upstream=\"%s:%u\"} %d\n",
                pool_name, node->host, (unsigned)node->port, up_val
            );
        }
    }

    PROM_APPEND(
        "# HELP routa_upstream_state Current health-state of this upstream node, as a label (state=\"up\"|\"down\"|\"half_open\"); value is always 1, this is a label-only info series\n"
        "# TYPE routa_upstream_state gauge\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_state{pool=\"%s\",upstream=\"%s:%u\",state=\"%s\"} 1\n",
                pool_name, node->host, (unsigned)node->port, node_state_name(node->state)
            );
        }
    }

    PROM_APPEND(
        "# HELP routa_upstream_inflight Requests currently in flight to this upstream node\n"
        "# TYPE routa_upstream_inflight gauge\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_inflight{pool=\"%s\",upstream=\"%s:%u\"} %u\n",
                pool_name, node->host, (unsigned)node->port, node->inflight
            );
        }
    }

    /* ── Faz 3a: pool-level request/failure/retry counters ──────────────
     * lb_t.stat_requests/stat_failed/stat_retries were already being
     * incremented internally (stat_retries via lb_record_retry(), called
     * from proxy.c's retry path) but were never exposed on /metrics --
     * this is pool-level, not per-upstream, since that's how the
     * underlying counters are actually kept (on lb_t, not per-node). */
    PROM_APPEND(
        "# HELP routa_lb_pool_requests_total Total requests dispatched through this pool\n"
        "# TYPE routa_lb_pool_requests_total counter\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        PROM_APPEND(
            "routa_lb_pool_requests_total{pool=\"%s\"} %llu\n",
            pool_name, (unsigned long long)lb_get_stat_requests(lb)
        );
    }

    PROM_APPEND(
        "# HELP routa_lb_pool_failed_total Total requests that ultimately failed through this pool\n"
        "# TYPE routa_lb_pool_failed_total counter\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        PROM_APPEND(
            "routa_lb_pool_failed_total{pool=\"%s\"} %llu\n",
            pool_name, (unsigned long long)lb_get_stat_failed(lb)
        );
    }

    PROM_APPEND(
        "# HELP routa_lb_pool_retries_total Total retry attempts issued by this pool (lb_max_retries/lb_retry_on_5xx/retry_on_connect_fail)\n"
        "# TYPE routa_lb_pool_retries_total counter\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        PROM_APPEND(
            "routa_lb_pool_retries_total{pool=\"%s\"} %llu\n",
            pool_name, (unsigned long long)lb_get_stat_retries(lb)
        );
    }

    /* ── Faz 3b: connection-pool occupancy (per upstream node) ──────────
     * idle_count/active_count/pool_max already tracked on upstream_node_t
     * (guarded by node->pool_lock for mutation) but never rendered.
     * Read here without taking pool_lock -- same best-effort-snapshot
     * approach already used for node->state/node->inflight above (a
     * gauge that's briefly stale by a request or two is an acceptable
     * tradeoff for a metrics scrape, consistent with the rest of this
     * file's g_metrics fields all being read with relaxed ordering). */
    PROM_APPEND(
        "# HELP routa_upstream_pool_idle Idle pooled connections to this upstream node\n"
        "# TYPE routa_upstream_pool_idle gauge\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_pool_idle{pool=\"%s\",upstream=\"%s:%u\"} %d\n",
                pool_name, node->host, (unsigned)node->port, node->idle_count
            );
        }
    }

    PROM_APPEND(
        "# HELP routa_upstream_pool_active Active (in-use) pooled connections to this upstream node\n"
        "# TYPE routa_upstream_pool_active gauge\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_pool_active{pool=\"%s\",upstream=\"%s:%u\"} %d\n",
                pool_name, node->host, (unsigned)node->port, node->active_count
            );
        }
    }

    PROM_APPEND(
        "# HELP routa_upstream_pool_max Configured max pooled connections to this upstream node\n"
        "# TYPE routa_upstream_pool_max gauge\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_pool_max{pool=\"%s\",upstream=\"%s:%u\"} %d\n",
                pool_name, node->host, (unsigned)node->port, node->pool_max
            );
        }
    }

    /* ── Circuit-breaker observability ──────────────────────────────────
     * circuit_breaker_trips_total: how many times this node transitioned
     * INTO NODE_DOWN (a fresh trip, not re-counted while it stays down).
     * half_open_trials_total: how many times a half-open recovery trial
     * was attempted for this node. Both incremented in
     * upstream_node_set_state()/upstream_node_is_selectable() -- see
     * upstream.h's doc comment on these fields for why they're distinct
     * from fail_count/total_errors. */
    PROM_APPEND(
        "# HELP routa_upstream_circuit_breaker_trips_total Times this upstream node's circuit breaker tripped (transitioned to DOWN)\n"
        "# TYPE routa_upstream_circuit_breaker_trips_total counter\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_circuit_breaker_trips_total{pool=\"%s\",upstream=\"%s:%u\"} %u\n",
                pool_name, node->host, (unsigned)node->port, node->circuit_breaker_trips_total
            );
        }
    }

    PROM_APPEND(
        "# HELP routa_upstream_half_open_trials_total Half-open recovery trials attempted for this upstream node\n"
        "# TYPE routa_upstream_half_open_trials_total counter\n"
    );
    for (int pi = 0; pi < s->lb_pool_count; pi++) {
        lb_t *lb = s->lb_pools[pi].lb;
        if (!lb) continue;
        const char *pool_name = s->lb_pools[pi].name[0] ? s->lb_pools[pi].name : "default";
        upstream_pool_t *up = lb_get_pool(lb);
        if (!up) continue;
        for (int ni = 0; ni < up->node_count; ni++) {
            upstream_node_t *node = up->nodes[ni];
            if (!node) continue;
            PROM_APPEND(
                "routa_upstream_half_open_trials_total{pool=\"%s\",upstream=\"%s:%u\"} %u\n",
                pool_name, node->host, (unsigned)node->port, node->half_open_trials_total
            );
        }
    }

    return (int)(p - buf);
}