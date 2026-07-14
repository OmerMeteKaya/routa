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
    /* ctx, if set, is the owning server_t* -- passed through so
     * routa_metrics_prometheus_lb() can walk its configured LB pools for
     * per-upstream metrics. NULL ctx (e.g. a server built directly via
     * server_new() rather than server_from_config()) just means the LB
     * section is skipped -- see routa_metrics_prometheus_lb()'s doc
     * comment. */

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

    int n2 = routa_metrics_prometheus_lb(buf, METRICS_BUF_SZ, ctx);
    /* BUG FIX: n2's return value convention is "bytes APPENDED by this
     * call" (0 when there were no LB pools to render at all -- see
     * routa_metrics_prometheus_lb()'s "if (!s) return 0" / "if
     * (s->lb_pool_count <= 0) return 0" early-outs), NOT "total buffer
     * length so far". The original code here did `n = n2`, which on a
     * server with no LB pools configured set n = 0 and discarded the
     * entire base routa_metrics_prometheus() output (n, at that point
     * holding the correct non-zero length) -- http_response_set_body()
     * then saw len==0 and skipped setting Content-Length entirely (see
     * its "if (!data || len == 0) return;" early-out in response.c),
     * which combined with a non-"Connection: close" response left the
     * client with no way to know where the body ends -- confirmed by
     * reproducing this manually: curl on GET /metrics hung waiting for
     * EOF that never arrived, on a server with no LB pools configured.
     * The buffer's actual total length is always strlen(buf) at this
     * point regardless of whether the LB section added anything -- that
     * is the only correct value for n here. */
    if (n2 < 0) {
        /* LB section didn't fit -- not fatal, the base metrics rendered
         * fine above; just serve what we have rather than erroring out
         * the whole endpoint over an optional section. */
    }
    n = (int)strlen(buf);

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