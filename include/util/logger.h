#ifndef ROUTA_UTIL_LOGGER_H
#define ROUTA_UTIL_LOGGER_H

#include <stdio.h>
#include <stdarg.h>

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

#endif // ROUTA_UTIL_LOGGER_H
