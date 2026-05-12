#ifndef ROUTA_HTTP_FILE_CACHE_H
#define ROUTA_HTTP_FILE_CACHE_H

#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
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

/* Threshold below which file content is mmap'd and cached inline.
 * Files >= this size are served via sendfile() as before.            */
#define FILE_CACHE_MMAP_THRESHOLD (64u * 1024u)   /* 64 KB */

typedef struct {
    char     resolved[1024];    /* absolute path after realpath()     */
    char     etag[64];          /* "mtime-size" hex                   */
    char     last_modified[64]; /* HTTP date string                   */
    char     mime_type[64];
    off_t    size;
    time_t   mtime;
    time_t   cached_at;         /* when this entry was cached         */
    uint32_t hash;              /* FNV-1a of original request path    */
    int      valid;

    /* mmap'd content — non-NULL only when size < FILE_CACHE_MMAP_THRESHOLD */
    void    *data;              /* mmap pointer, NULL for large files */
    size_t   data_len;          /* == size for full file, range subset not cached */
} file_cache_entry_t;

/* Global init/free — call once at startup/shutdown */
int  file_cache_init(const file_cache_config_t *cfg);
void file_cache_free(void);

/* Lookup by request path. Returns 1 if hit (entry filled), 0 if miss. */
int  file_cache_get(const char *path, file_cache_entry_t *out);

/* Store entry. Call after successful stat().
 * If entry->data is non-NULL the cache takes NO ownership —
 * the pointer is stored as-is; munmap is called on eviction. */
void file_cache_put(const char *path, const file_cache_entry_t *entry);

/* Invalidate a specific path */
void file_cache_invalidate(const char *path);

#endif /* ROUTA_HTTP_FILE_CACHE_H */