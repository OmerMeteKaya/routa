#ifndef ROUTA_UTIL_LOGGER_H
#define ROUTA_UTIL_LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

void log_set_level(log_level_t level);
void log_msg(log_level_t level, const char *file, int line, const char *fmt, ...);

#define LOG_DEBUG(...) log_msg(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  log_msg(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_msg(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) log_msg(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

/* JSON structured access log — one line per completed request.
 *
 * Output example (single line, newline terminated):
 * {"ts":1748534400.123,"level":"ACCESS","trace_id":"a3f2b1c4d5e6f7a8",
 *  "method":"GET","path":"/api/users","status":200,"latency_ms":4.217,
 *  "remote_ip":"1.2.3.4","worker":0,"bytes":1024}
 *
 * Parameters:
 *   trace_id   : 16-char hex string from http_request_t.trace_id
 *   method_str : "GET", "POST", etc.
 *   path       : request path (no query string)
 *   status     : HTTP response status code
 *   latency_us : routa_now_us() - request start_us
 *   remote_ip  : client IP string
 *   worker_id  : worker index (0-based)
 *   bytes_sent : response body size in bytes                               */
void log_access_json(const char *trace_id,
                     const char *method_str,
                     const char *path,
                     int         status,
                     uint64_t    latency_us,
                     const char *remote_ip,
                     int         worker_id,
                     size_t      bytes_sent);



#endif // ROUTA_UTIL_LOGGER_H
