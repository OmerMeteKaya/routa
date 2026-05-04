#ifndef ROUTA_HTTP_MW_LOGGER_H
#define ROUTA_HTTP_MW_LOGGER_H

#include "http/middleware.h"
#include "http/request.h"
#include "http/response.h"

void mw_logger(middleware_chain_t *chain, const http_request_t *req,
               http_response_t *resp, next_fn_t next, void *ctx);

#endif /* ROUTA_HTTP_MW_LOGGER_H */
