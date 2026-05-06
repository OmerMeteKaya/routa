#ifndef ROUTA_HTTP_FILE_CACHE_H
#define ROUTA_HTTP_FILE_CACHE_H

#include <sys/stat.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    FILE_CACHE_TTL      = 0,
    FILE_CACHE_STAT_TTL = 1,
    FILE_CACHE_INOTIFY  = 2
} file_cache_strategy_t;

typedef struct {
    int                   enabled;
    int                   max_entries;
    int                   ttl_seconds;
    file_cache_strategy_t strategy;
} file_cache_config_t;

typedef struct {
    char     resolved[1024];   /* absolute path after realpath() */
    char     etag[64];         /* "mtime-size" hex */
    char     last_modified[64];/* HTTP date string */
    char     mime_type[64];
    off_t    size;
    time_t   mtime;
    time_t   cached_at;       /* when this entry was cached */
    uint32_t hash;            /* hash of original request path */
    int      valid;
} file_cache_entry_t;

/* Global init/free — call once at startup/shutdown */
int  file_cache_init(const file_cache_config_t *cfg);
void file_cache_free(void);

/* Lookup by request path. Returns 1 if hit (entry filled), 0 if miss. */
int  file_cache_get(const char *path, file_cache_entry_t *out);

/* Store entry. Call after successful stat(). */
void file_cache_put(const char *path, const file_cache_entry_t *entry);

/* Invalidate a specific path */
void file_cache_invalidate(const char *path);

#endif /* ROUTA_HTTP_FILE_CACHE_H */
