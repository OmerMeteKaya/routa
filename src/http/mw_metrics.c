#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/mw_metrics.h"
#include "http/request.h"
#include "http/response.h"
#include "util/metrics.h"
#include <stdlib.h>
#include <string.h>

/* ── /metrics route handler ─────────────────────────────────────────────────
 *
 * Renders Prometheus text format on GET /metrics.
 * Register in your server setup:
 *
 *   event_loop_add_route(loop, "/metrics", 1 << HTTP_GET,
 *                        routa_metrics_handler, NULL);
 *
 * Prometheus scrape config:
 *   scrape_configs:
 *     - job_name: 'routa'
 *       static_configs:
 *         - targets: ['localhost:8080']
 *       metrics_path: '/metrics'
 * ─────────────────────────────────────────────────────────────────────────*/

#define METRICS_BUF_SZ (64 * 1024)   /* 64KB — comfortably fits all metrics */

int routa_metrics_handler(const http_request_t *req,
                           http_response_t      *resp,
                           void                 *ctx) {
    (void)req;
    (void)ctx;

    char *buf = malloc(METRICS_BUF_SZ);
    if (!buf) {
        http_response_set_status(resp, 500, "Internal Server Error");
        http_response_set_body(resp, "out of memory\n", 14);
        return 0;
    }

    int n = routa_metrics_prometheus(buf, METRICS_BUF_SZ);
    if (n < 0) {
        free(buf);
        http_response_set_status(resp, 500, "Internal Server Error");
        http_response_set_body(resp, "metrics buffer overflow\n", 24);
        return 0;
    }

    http_response_set_status(resp, 200, "OK");
    /* Prometheus requires this exact Content-Type */
    http_response_set_header(resp,
        "content-type",
        "text/plain; version=0.0.4; charset=utf-8");
    /* No caching — always fresh */
    http_response_set_header(resp, "cache-control", "no-cache");
    http_response_set_body(resp, buf, (size_t)n);

    free(buf);
    return 0;
}