#ifndef ROUTA_HTTP_FILE_CACHE_H
#define ROUTA_HTTP_FILE_CACHE_H

#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* ── Modes ────────────────────────────────────────────────────────────────
 *
 * FILE_CACHE_MODE_LOCAL: legacy behavior. Each worker thread keeps a
 *   fully independent, thread-local cache (metadata + mmap'd content).
 *   No cross-worker coordination, no locking, simplest and safest, but
 *   file_cache_invalidate() only affects the calling thread's slots and
 *   N workers each pay the full stat()/open()/mmap() cost independently.
 *
 * FILE_CACHE_MODE_SHARED_METADATA (default): path -> {etag, mtime, size,
 *   generation} lives in a shared, lock-protected hash table. The mmap'd
 *   content itself stays per-worker (see the design rationale in the
 *   project notes: mmap()/munmap() churn is the real per-worker cost,
 *   not the mapped pages themselves, which the kernel page cache already
 *   shares across workers). A worker compares its last-seen generation
 *   against the shared entry's current generation on every lookup; a
 *   mismatch (from invalidate() or inotify) makes it drop and re-map its
 *   own copy. No refcounting, no shared pointers to mapped memory --
 *   each worker only ever munmaps its own mapping.
 *
 * FILE_CACHE_MODE_SHARED_CONTENT: reserved for future work. Would share
 *   the actual content buffer (refcounted) across workers. Deliberately
 *   not implemented in this revision -- see project notes for the
 *   tradeoff analysis (real dedup of stat()/open()/read() cost, at the
 *   price of refcount lifetime complexity across every static.c exit
 *   path). Selecting this mode currently falls back to
 *   FILE_CACHE_MODE_SHARED_METADATA with a warning log.
 */
typedef enum {
    FILE_CACHE_MODE_LOCAL            = 0,
    FILE_CACHE_MODE_SHARED_METADATA  = 1,
    FILE_CACHE_MODE_SHARED_CONTENT   = 2
} file_cache_mode_t;

typedef enum {
    FILE_CACHE_LOCK_GLOBAL  = 0,   /* n_shards forced to 1 */
    FILE_CACHE_LOCK_SHARDED = 1
} file_cache_lock_t;

typedef enum {
    FILE_CACHE_EVICT_LRU      = 0,
    FILE_CACHE_EVICT_LFU      = 1,
    FILE_CACHE_EVICT_TTL_ONLY = 2   /* no active ordering; see file_cache.c */
} file_cache_eviction_t;

typedef enum {
    FILE_CACHE_TTL      = 0,
    FILE_CACHE_STAT_TTL = 1,
    FILE_CACHE_INOTIFY  = 2
} file_cache_strategy_t;

typedef enum {
    FILE_CACHE_WATCH_NONE    = 0,
    FILE_CACHE_WATCH_INOTIFY = 1   /* Linux only */
} file_cache_watch_t;

typedef struct {
    int                    enabled;
    int                    max_entries;
    int                    ttl_seconds;
    file_cache_strategy_t  strategy;

    file_cache_mode_t      mode;
    file_cache_lock_t      lock_kind;
    int                    n_shards;          /* must be a power of 2 */
    file_cache_eviction_t  eviction;
    int                    negative_ttl_seconds; /* 0 = off */
    size_t                 mmap_threshold;    /* bytes */
    size_t                 max_memory_mb;     /* 0 = off */
    file_cache_watch_t     watch;
} file_cache_config_t;

/* Default mmap threshold, used only if config passes 0 (i.e. "unset"). */
#define FILE_CACHE_DEFAULT_MMAP_THRESHOLD (64u * 1024u)   /* 64 KB */

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
    int      negative;          /* 1 = cached "not found" result (no other
                                    fields but resolved/cached_at meaningful) */

    /* mmap'd content -- non-NULL only when size < mmap_threshold.
     * Always a mapping owned by the calling worker; never a pointer
     * shared with another thread (see mode doc comment above). */
    void    *data;
    size_t   data_len;          /* == size for full file, range subset not cached */
} file_cache_entry_t;

/* Global init/free -- call once at startup/shutdown, before any worker
 * thread starts. */
int  file_cache_init(const file_cache_config_t *cfg);
void file_cache_free(void);

/* Called once by each worker thread at startup, before serving any
 * requests (mirrors ws_registry_init()/conn_slab_new()'s per-worker init
 * pattern in event_loop.c's worker_run()). Required in every mode --
 * in LOCAL mode this just zeroes the thread-local slot table; in
 * SHARED_* modes it additionally registers the worker's per-thread mmap
 * slot table used to track generation numbers. */
void file_cache_worker_init(int worker_id);

/* Lookup by request path. Returns 1 if hit (entry filled), 0 if miss.
 * worker_id identifies the calling worker -- see request.h's doc
 * comment on http_request_t.worker_id for why this is an explicit
 * parameter rather than a thread-local. */
int  file_cache_get(int worker_id, const char *path, file_cache_entry_t *out);

/* Store entry. Call after successful stat().
 * If entry->data is non-NULL the cache takes NO ownership -- the
 * pointer is stored as-is (in the calling worker's own local mmap slot
 * table); munmap is called on eviction or generation mismatch, always
 * by the same worker that mapped it. */
void file_cache_put(int worker_id, const char *path, const file_cache_entry_t *entry);

/* Store a negative (miss) result for negative_ttl_seconds. No-op if
 * negative caching is disabled (negative_ttl_seconds == 0). */
void file_cache_put_negative(int worker_id, const char *path);

/* Invalidate a specific path. In LOCAL mode this only affects the
 * calling worker's own slots (legacy behavior, preserved for that
 * mode). In SHARED_* modes this bumps the shared generation counter,
 * so every worker will detect the mismatch and re-fetch on next
 * access -- this is the fix for the previously-dead cross-worker
 * invalidation gap. */
void file_cache_invalidate(int worker_id, const char *path);

/* Returns 1 if this worker should own the inotify watch fd in the
 * current mode (see event_loop.c's worker_should_own_inotify(), which
 * is the single call site -- this function only encodes the file-cache
 * side of that decision: "does file-cache watching require exactly one
 * owner in this mode, or can every worker own its own"). */
int  file_cache_watch_is_centralized(void);

/* ── inotify integration (event_loop.c calls these; see project notes
 * on the worker_should_own_inotify() single-decision-point pattern) ── */

/* Opens and configures an inotify fd suitable for poller_add(), or -1 if
 * watch is disabled/unsupported on this platform. worker_id is the
 * owning worker (see file_cache_watch_is_centralized()). */
int  file_cache_inotify_open(int worker_id);

/* Called when poller_wait() reports readability on the fd returned by
 * file_cache_inotify_open(). Drains and processes all pending inotify
 * events (bumping generation counters / invalidating LOCAL-mode slots
 * as appropriate). */
void file_cache_inotify_drain(int fd);

/* Returns the currently configured mmap threshold (bytes). static.c
 * uses this instead of the old compile-time FILE_CACHE_MMAP_THRESHOLD
 * constant, since the threshold is now runtime-configurable
 * (file_cache_mmap_threshold in config). Returns
 * FILE_CACHE_DEFAULT_MMAP_THRESHOLD if the cache hasn't been
 * initialized yet. */
size_t file_cache_get_mmap_threshold(void);

#endif /* ROUTA_HTTP_FILE_CACHE_H */
