#ifndef ROUTA_HTTP_MW_METRICS_H
#define ROUTA_HTTP_MW_METRICS_H

#include "http/request.h"
#include "http/response.h"

/* Route handler for GET /metrics — Prometheus text format.
 *
 * Register:
 *   event_loop_add_route(loop, "/metrics", 1 << HTTP_GET,
 *                        routa_metrics_handler, NULL);        */
int routa_metrics_handler(const http_request_t *req,
                           http_response_t      *resp,
                           void                 *ctx);

#endif /* ROUTA_HTTP_MW_METRICS_H */