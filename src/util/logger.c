#define _GNU_SOURCE
#include "util/logger.h"
#include <pthread.h>
#include <string.h>
#include <time.h>

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
    time(&now);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0'; // Remove newline
    
    // Print log header
    fprintf(stderr, "[%s] [%s] %s:%d ", timestamp, level_strings[level], file, line);
    
    // Print message
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
    fflush(stderr);
    
    pthread_mutex_unlock(&g_log_mutex);
}
