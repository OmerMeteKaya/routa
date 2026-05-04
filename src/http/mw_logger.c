#define _GNU_SOURCE
#include "http/mw_logger.h"
#include "util/logger.h"
#include <time.h>

void mw_logger(middleware_chain_t *chain, const http_request_t *req,
               http_response_t *resp, next_fn_t next, void *ctx) {
    (void)ctx;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    next(chain, req, resp);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000L +
              (t1.tv_nsec - t0.tv_nsec) / 1000000L;

    const char *method_str = "UNKNOWN";
    switch (req->method) {
        case HTTP_GET:     method_str = "GET";     break;
        case HTTP_POST:    method_str = "POST";    break;
        case HTTP_PUT:     method_str = "PUT";     break;
        case HTTP_DELETE:  method_str = "DELETE";  break;
        case HTTP_HEAD:    method_str = "HEAD";    break;
        case HTTP_PATCH:   method_str = "PATCH";   break;
        case HTTP_OPTIONS: method_str = "OPTIONS"; break;
        default: break;
    }

    LOG_INFO("%s %s %d (%ldms)", method_str, req->path,
             resp->status, ms);
}
