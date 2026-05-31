#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "util/logger.h"
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "util/metrics.h"
#include <stdio.h>

static log_level_t g_log_level = LOG_INFO;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

void log_set_level(log_level_t level) {
    g_log_level = level;
}

void log_msg(log_level_t level, const char *file, int line, const char *fmt, ...) {
    if (level < g_log_level) {
        return;
    }

    pthread_mutex_lock(&g_log_mutex);

    // Get timestamp
    time_t now;
    (void)time(&now);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0'; // Remove newline
    
    // Print log header
   // fprintf(stderr, "[%s] [%s] %s:%d ", timestamp, level_strings[level], file, line);
    
    // Print message
    va_list args;
    va_start(args, fmt);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);

    (void)fflush(stderr);
    
    pthread_mutex_unlock(&g_log_mutex);
}

void log_access_json(const char *trace_id,
                     const char *method_str,
                     const char *path,
                     int         status,
                     uint64_t    latency_us,
                     const char *remote_ip,
                     int         worker_id,
                     size_t      bytes_sent) {
    /* Wall-clock timestamp for human readability */
    struct timespec wts;
    clock_gettime(CLOCK_REALTIME, &wts);
    double ts = (double)wts.tv_sec + (double)wts.tv_nsec / 1e9;

    /* Latency: microseconds → milliseconds with 3 decimal places */
    double latency_ms = (double)latency_us / 1000.0;

    /* Sanitize path — avoid log injection via newline/quote */
    char safe_path[512];
    size_t pi = 0;
    const char *src = path ? path : "/";
    while (*src && pi < sizeof(safe_path) - 1) {
        char c = *src++;
        if (c == '"' || c == '\\' || c < 0x20)
            safe_path[pi++] = '?';
        else
            safe_path[pi++] = c;
    }
    safe_path[pi] = '\0';
#ifdef ROUTA_ACCESS_LOG
    fprintf(stderr,
        "{\"ts\":%.3f,\"level\":\"ACCESS\","
        "\"trace_id\":\"%s\","
        "\"method\":\"%s\","
        "\"path\":\"%s\","
        "\"status\":%d,"
        "\"latency_ms\":%.3f,"
        "\"remote_ip\":\"%s\","
        "\"worker\":%d,"
        "\"bytes\":%zu}\n",
        ts,
        trace_id  ? trace_id  : "0000000000000000",
        method_str ? method_str : "UNKNOWN",
        safe_path,
        status,
        latency_ms,
        remote_ip  ? remote_ip  : "",
        worker_id,
        bytes_sent
    );
#endif

}
