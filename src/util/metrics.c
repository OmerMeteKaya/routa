#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "util/metrics.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

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
    (void)bytes_sent;   /* reserved for future bytes_sent histogram */

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
    return (int)(p - buf);
}