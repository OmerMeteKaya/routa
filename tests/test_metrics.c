#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>

#include "util/metrics.h"

/* ── Test harness ────────────────────────────────────────────────────────── */
static int g_pass = 0;
static int g_fail = 0;

#define OK(label)   do { printf("[OK] %s\n",   label); g_pass++; } while(0)
#define FAIL(label, ...) do { \
    printf("[FAIL] %s: ", label); printf(__VA_ARGS__); printf("\n"); \
    g_fail++; \
} while(0)

/* ─────────────────────────────────────────────────────────────────────────*/

static void test_init(void) {
    routa_metrics_init();
    if (ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_2XX]) == 0 &&
        ROUTA_METRIC_GET(active_connections) == 0)
        OK("init — all zeros after init");
    else
        FAIL("init", "non-zero after init");
}

static void test_record_request(void) {
    routa_metrics_init();
    uint64_t start = routa_now_us() - 5000;   /* simulate 5ms ago */
    routa_metrics_record("GET", 200, start, 1024);

    uint64_t cnt = ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_2XX]);
    if (cnt == 1)
        OK("record GET 200 — counter incremented");
    else
        FAIL("record GET 200", "expected 1 got %llu", (unsigned long long)cnt);

    uint64_t lcount = ROUTA_METRIC_GET(latency_count);
    if (lcount == 1)
        OK("record — latency_count = 1");
    else
        FAIL("record — latency_count", "expected 1 got %llu", (unsigned long long)lcount);

    /* 5ms → should hit bucket index 2 (le=10) and above */
    uint64_t b1 = ROUTA_METRIC_GET(latency_buckets[1]);   /* le=5  */
    uint64_t b2 = ROUTA_METRIC_GET(latency_buckets[2]);   /* le=10 */
    /* 5ms may be ≤5 or ≤10 depending on timing; at minimum le=10 must be hit */
    if (b2 == 1)
        OK("record — latency bucket le=10 hit");
    else if (b1 == 1)
        OK("record — latency bucket le=5 hit (fast machine)");
    else
        FAIL("record — latency bucket", "b1=%llu b2=%llu",
             (unsigned long long)b1, (unsigned long long)b2);
}

static void test_method_mapping(void) {
    routa_metrics_init();
    uint64_t t = routa_now_us();
    routa_metrics_record("POST",    201, t, 0);
    routa_metrics_record("PUT",     204, t, 0);
    routa_metrics_record("DELETE",  204, t, 0);
    routa_metrics_record("OPTIONS", 200, t, 0);
    routa_metrics_record("UNKNOWN", 200, t, 0);

    if (ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_POST][ROUTA_SC_2XX])    == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_PUT][ROUTA_SC_2XX])     == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_DELETE][ROUTA_SC_2XX])  == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_OPTIONS][ROUTA_SC_2XX]) == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_OTHER][ROUTA_SC_2XX])   == 1)
        OK("method mapping — POST/PUT/DELETE/OPTIONS/OTHER all correct");
    else
        FAIL("method mapping", "unexpected counter values");
}

static void test_status_classes(void) {
    routa_metrics_init();
    uint64_t t = routa_now_us();
    routa_metrics_record("GET", 101, t, 0);
    routa_metrics_record("GET", 200, t, 0);
    routa_metrics_record("GET", 301, t, 0);
    routa_metrics_record("GET", 404, t, 0);
    routa_metrics_record("GET", 500, t, 0);
    routa_metrics_record("GET", 999, t, 0);

    if (ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_1XX]) == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_2XX]) == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_3XX]) == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_4XX]) == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_5XX]) == 1 &&
        ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_OTHER]) == 1)
        OK("status classes — 1xx/2xx/3xx/4xx/5xx/other all correct");
    else
        FAIL("status classes", "unexpected counter values");
}

static void test_conn_lifecycle(void) {
    routa_metrics_init();
    routa_metrics_conn_open();
    routa_metrics_conn_open();
    routa_metrics_conn_open();

    int64_t  active = ROUTA_METRIC_GET(active_connections);
    uint64_t total  = ROUTA_METRIC_GET(connections_total);
    uint64_t peak   = ROUTA_METRIC_GET(peak_connections);

    if (active == 3 && total == 3 && peak == 3)
        OK("conn_open x3 — active=3 total=3 peak=3");
    else
        FAIL("conn_open", "active=%lld total=%llu peak=%llu",
             (long long)active, (unsigned long long)total,
             (unsigned long long)peak);

    routa_metrics_conn_close();
    routa_metrics_conn_close();
    active = ROUTA_METRIC_GET(active_connections);
    peak   = ROUTA_METRIC_GET(peak_connections);

    if (active == 1 && peak == 3)
        OK("conn_close x2 — active=1, peak preserved at 3");
    else
        FAIL("conn_close", "active=%lld peak=%llu",
             (long long)active, (unsigned long long)peak);
}

static void test_error_counters(void) {
    routa_metrics_init();
    ROUTA_METRIC_INC(parse_errors_total);
    ROUTA_METRIC_INC(parse_errors_total);
    ROUTA_METRIC_INC(tls_errors_total);
    ROUTA_METRIC_INC(ws_disconnects_total);
    ROUTA_METRIC_INC(upstream_failures_total);

    if (ROUTA_METRIC_GET(parse_errors_total)      == 2 &&
        ROUTA_METRIC_GET(tls_errors_total)         == 1 &&
        ROUTA_METRIC_GET(ws_disconnects_total)     == 1 &&
        ROUTA_METRIC_GET(upstream_failures_total)  == 1)
        OK("error counters — all incremented correctly");
    else
        FAIL("error counters", "unexpected values");
}

static void test_prometheus_render(void) {
    routa_metrics_init();
    uint64_t t = routa_now_us() - 2000;   /* 2ms ago */
    routa_metrics_record("GET", 200, t, 512);
    routa_metrics_record("POST", 201, t, 0);
    routa_metrics_conn_open();
    ROUTA_METRIC_INC(parse_errors_total);

    char buf[32768];
    int n = routa_metrics_prometheus(buf, sizeof(buf));

    if (n <= 0) {
        FAIL("prometheus render", "returned %d", n); return;
    }

    /* Check required fields present */
    int ok = 1;
    if (!strstr(buf, "routa_requests_total"))      { ok = 0; puts("  missing: requests_total"); }
    if (!strstr(buf, "routa_request_duration_ms")) { ok = 0; puts("  missing: duration"); }
    if (!strstr(buf, "routa_active_connections"))  { ok = 0; puts("  missing: active_conns"); }
    if (!strstr(buf, "routa_parse_errors_total"))  { ok = 0; puts("  missing: parse_errors"); }
    if (!strstr(buf, "method=\"GET\""))            { ok = 0; puts("  missing: GET label"); }
    if (!strstr(buf, "status_class=\"2xx\""))      { ok = 0; puts("  missing: 2xx label"); }
    if (!strstr(buf, "+Inf"))                      { ok = 0; puts("  missing: +Inf bucket"); }

    if (ok)
        OK("prometheus render — all required fields present");
    else
        FAIL("prometheus render", "missing fields (see above)");
}

static void test_prometheus_small_buf(void) {
    routa_metrics_init();
    char tiny[10];
    int n = routa_metrics_prometheus(tiny, sizeof(tiny));
    if (n == -1)
        OK("prometheus render — overflow returns -1 for tiny buffer");
    else
        FAIL("prometheus render overflow", "expected -1 got %d", n);
}

static void test_clock_abstraction(void) {
    uint64_t a = routa_now_us();
    /* Busy-wait ~100us to ensure clock advances */
    volatile uint64_t dummy = 0;
    for (int i = 0; i < 100000; i++) dummy += (uint64_t)i;
    (void)dummy;
    uint64_t b = routa_now_us();

    if (b >= a)
        OK("routa_now_us — monotonic (b >= a)");
    else
        FAIL("routa_now_us", "time went backward: a=%llu b=%llu",
             (unsigned long long)a, (unsigned long long)b);

    uint64_t ms = routa_now_ms();
    uint64_t us = routa_now_us();
    /* ms and us should be within 10ms of each other */
    uint64_t diff = (us / 1000 > ms) ? (us / 1000 - ms) : (ms - us / 1000);
    if (diff < 10)
        OK("routa_now_ms — consistent with routa_now_us");
    else
        FAIL("routa_now_ms", "diff=%llu ms between ms and us/1000",
             (unsigned long long)diff);
}

static void test_concurrent_stress(void) {
    /* Single-threaded stress: 10000 records, check no corruption */
    routa_metrics_init();
    uint64_t base = routa_now_us();
    for (int i = 0; i < 10000; i++) {
        routa_metrics_record("GET", 200, base - (uint64_t)(i * 100), 64);
    }
    uint64_t cnt = ROUTA_METRIC_GET(requests_total[ROUTA_MIDX_GET][ROUTA_SC_2XX]);
    uint64_t lc  = ROUTA_METRIC_GET(latency_count);
    if (cnt == 10000 && lc == 10000)
        OK("stress 10k records — counters correct");
    else
        FAIL("stress", "requests=%llu latency_count=%llu",
             (unsigned long long)cnt, (unsigned long long)lc);
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(void) {
    printf("test_metrics\n");
    printf("─────────────────────────────────────\n");

    test_init();
    test_record_request();
    test_method_mapping();
    test_status_classes();
    test_conn_lifecycle();
    test_error_counters();
    test_prometheus_render();
    test_prometheus_small_buf();
    test_clock_abstraction();
    test_concurrent_stress();

    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}