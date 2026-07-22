#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/file_cache.h"
#include "util/logger.h"
#include "util/metrics.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#if defined(__linux__)
#include <sys/inotify.h>
#define ROUTA_HAVE_INOTIFY 1
#else
#define ROUTA_HAVE_INOTIFY 0
#endif

#define TL_MAX_ENTRIES     512
#define MAX_WORKERS        256   /* generous ceiling; see file_cache_worker_init() */
#define LFU_MAX_FREQ       255   /* clamp ceiling -- see freq bucket doc comment   */
#define LFU_DECAY_INTERVAL 4096  /* # of puts between global frequency decay sweeps */

/* ── FNV-1a ────────────────────────────────────────────────────────────────*/
static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

static file_cache_config_t g_cfg;
static int                 g_enabled = 0;

/* =========================================================================
 * MODE: LOCAL (legacy thread-local, one independent cache per worker)
 * ========================================================================= */

typedef struct {
    char               path[1024];
    file_cache_entry_t entry;
    int                in_use;
    /* LRU/LFU bookkeeping, local mode: index-based, O(n) per shard is
     * fine here since n == g_cfg.max_entries and this mode is meant for
     * simple/low-traffic/debug use (see file_cache.h mode doc comment). */
    uint64_t           access_count;
    time_t             last_access;
} tl_slot_t;

static __thread tl_slot_t tl_slots[TL_MAX_ENTRIES];
static __thread int       tl_initialized = 0;
static __thread int       tl_max         = 0;
#if ROUTA_HAVE_INOTIFY
static __thread int       tl_inotify_fd  = -1;
/* path -> inotify watch descriptor, so we can map IN_* events back to a
 * slot on drain. Local mode: parallel array is fine, bounded by
 * TL_MAX_ENTRIES same as tl_slots. */
static __thread int       tl_wd_for_slot[TL_MAX_ENTRIES];
#endif

static void tl_init(void) {
    if (tl_initialized) return;
    memset(tl_slots, 0, sizeof(tl_slots));
    tl_max         = g_cfg.max_entries;
    tl_initialized = 1;
#if ROUTA_HAVE_INOTIFY
    for (int i = 0; i < TL_MAX_ENTRIES; i++) tl_wd_for_slot[i] = -1;
#endif
}

static void slot_unmap(tl_slot_t *slot) {
    if (slot->entry.data) {
        munmap(slot->entry.data, slot->entry.data_len);
        slot->entry.data     = NULL;
        slot->entry.data_len = 0;
    }
}

static int tl_find_slot(const char *path, uint32_t hash) {
    for (int i = 0; i < tl_max; i++) {
        if (tl_slots[i].in_use &&
            tl_slots[i].entry.hash == hash &&
            strcmp(tl_slots[i].path, path) == 0)
            return i;
    }
    return -1;
}

static int tl_evict_slot(void) {
    for (int i = 0; i < tl_max; i++)
        if (!tl_slots[i].in_use) return i;

    if (g_cfg.eviction == FILE_CACHE_EVICT_LFU) {
        int    least   = 0;
        uint64_t least_c = tl_slots[0].access_count;
        for (int i = 1; i < tl_max; i++) {
            if (tl_slots[i].access_count < least_c) {
                least   = i;
                least_c = tl_slots[i].access_count;
            }
        }
        slot_unmap(&tl_slots[least]);
        tl_slots[least].in_use = 0;
        return least;
    }

    /* LRU (default) and TTL_ONLY (falls back to oldest-created, same as
     * the pre-revision behavior) both use "oldest" as the eviction key;
     * the difference is that LRU's cached_at gets bumped on every hit
     * (see entry_valid()/tl_touch()) while TTL_ONLY's doesn't. */
    int    oldest   = 0;
    time_t oldest_t = tl_slots[0].last_access;
    for (int i = 1; i < tl_max; i++) {
        if (tl_slots[i].last_access < oldest_t) {
            oldest   = i;
            oldest_t = tl_slots[i].last_access;
        }
    }
    slot_unmap(&tl_slots[oldest]);
    tl_slots[oldest].in_use = 0;
    return oldest;
}

static int tl_entry_valid(tl_slot_t *slot, time_t now) {
    if (!slot->in_use) return 0;
    int ttl = g_cfg.ttl_seconds > 0 ? g_cfg.ttl_seconds : 5;

    if (g_cfg.strategy == FILE_CACHE_TTL)
        return (now - slot->entry.cached_at) < ttl;

    if (g_cfg.strategy == FILE_CACHE_STAT_TTL) {
        if ((now - slot->entry.cached_at) < ttl) return 1;
        if (slot->entry.negative) {
            /* negative entries are pure TTL, nothing to stat() */
            return 0;
        }
        struct stat st;
        if (stat(slot->entry.resolved, &st) < 0) {
            slot_unmap(slot);
            slot->in_use = 0;
            return 0;
        }
        if (st.st_mtime != slot->entry.mtime ||
            st.st_size  != slot->entry.size) {
            slot_unmap(slot);
            slot->in_use = 0;
            return 0;
        }
        slot->entry.cached_at = now;
        return 1;
    }

    /* FILE_CACHE_INOTIFY strategy: if a real inotify watch is active
     * (g_cfg.watch == FILE_CACHE_WATCH_INOTIFY) validity is driven
     * entirely by tl_inotify_drain() clearing in_use on change events --
     * so as long as in_use is still set, the entry is considered valid
     * with no additional TTL ceiling. If inotify isn't actually enabled
     * (watch == FILE_CACHE_WATCH_NONE but strategy == INOTIFY was
     * requested anyway), fall back to the old TTLx10 approximation so
     * behavior degrades gracefully instead of caching forever. */
    if (g_cfg.watch == FILE_CACHE_WATCH_INOTIFY) return 1;
    return (now - slot->entry.cached_at) < ((time_t)ttl * 10);
}

static void tl_touch(tl_slot_t *slot, time_t now) {
    slot->access_count++;
    slot->last_access = now;
}

#if ROUTA_HAVE_INOTIFY
/* Registers (or re-registers) an inotify watch for a newly-cached path,
 * local mode. Best-effort: failure just means this entry falls back to
 * TTL-based revalidation, never a hard error. */
static void tl_watch_add(int slot_idx, const char *resolved) {
    if (tl_inotify_fd < 0) return;
    if (tl_wd_for_slot[slot_idx] >= 0) {
        inotify_rm_watch(tl_inotify_fd, tl_wd_for_slot[slot_idx]);
        tl_wd_for_slot[slot_idx] = -1;
    }
    int wd = inotify_add_watch(tl_inotify_fd, resolved,
                                IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_ATTRIB);
    tl_wd_for_slot[slot_idx] = wd; /* -1 on failure, fine */
}
#endif

/* =========================================================================
 * MODE: SHARED_METADATA
 *
 * path -> {etag, mtime, size, generation} in a shared, lock-protected
 * hash table. mmap'd content stays per-worker (see file_cache.h's mode
 * doc comment for the full rationale -- summary: mmap()/munmap() churn
 * is the real per-worker cost, not the mapped pages, which the kernel
 * page cache already shares).
 * ========================================================================= */

typedef struct shared_meta {
    char     path[1024];
    uint32_t hash;
    int      in_use;
    int      negative;

    char     resolved[1024];
    char     etag[64];
    char     last_modified[64];
    char     mime_type[64];
    off_t    size;
    time_t   mtime;
    time_t   cached_at;
    uint64_t generation;    /* bumped on invalidate()/inotify event */

    /* LRU intrusive list (per-shard) */
    struct shared_meta *lru_prev, *lru_next;

    /* LFU frequency-bucket membership (per-shard) */
    struct freq_bucket  *freq_bucket;
    struct shared_meta  *freq_prev, *freq_next;  /* siblings within the same bucket */

    /* hash chaining within the shard's bucket array */
    struct shared_meta *hash_next;
} shared_meta_t;

typedef struct freq_bucket {
    uint64_t             freq;
    shared_meta_t        *head, *tail;   /* nodes at this freq, LRU order among ties */
    struct freq_bucket   *lower, *higher; /* frequency-ordered doubly-linked list */
} freq_bucket_t;

#define SHARD_HASH_BUCKETS 128  /* per-shard bucket-array width; shard itself
                                   already partitions the keyspace, so this
                                   only needs to be big enough to keep each
                                   shard's own chains short */

typedef struct {
    pthread_rwlock_t lock;
    shared_meta_t   *buckets[SHARD_HASH_BUCKETS];
    shared_meta_t   *lru_head, *lru_tail;    /* used when eviction == LRU */
    freq_bucket_t   *freq_min;               /* used when eviction == LFU;
                                                 lowest-frequency bucket, O(1) evict */
    int              count;
    int              cap;                    /* entries budget for this shard */
    uint64_t         puts_since_decay;        /* LFU decay trigger, see freq_decay() */
} cache_shard_t;

static cache_shard_t *g_shards     = NULL;
static int             g_n_shards  = 0;

/* Per-worker mmap tracking for shared_metadata mode. Not shared -- each
 * worker only ever touches its own row. Indexed by worker_id, sized at
 * init time (see file_cache_worker_init()). */
typedef struct {
    char     path[1024];
    void    *mmap_ptr;
    size_t   mmap_len;
    uint64_t last_seen_generation;
    int      in_use;
} worker_mmap_slot_t;

typedef struct {
    worker_mmap_slot_t slots[TL_MAX_ENTRIES];
    int                initialized;
} worker_mmap_table_t;

static worker_mmap_table_t *g_worker_mmaps      = NULL; /* array[MAX_WORKERS] */
static int                  g_worker_mmaps_cap  = 0;

#if ROUTA_HAVE_INOTIFY
/* path -> inotify watch descriptor, centralized owner only (see
 * file_cache_watch_is_centralized()). Protected by g_shared_wd_lock
 * since the owner worker is the only writer but drain can run
 * concurrently with puts registering new watches. */
typedef struct wd_entry {
    int               wd;
    char              path[1024];
    struct wd_entry  *next;
} wd_entry_t;
static wd_entry_t      *g_wd_table[SHARD_HASH_BUCKETS];
static pthread_mutex_t  g_wd_lock = PTHREAD_MUTEX_INITIALIZER;
static int               g_shared_inotify_fd = -1;
#endif

static int shard_index(uint32_t hash) {
    return (int)(hash & (uint32_t)(g_n_shards - 1));
}

/* ── LFU frequency-bucket helpers ─────────────────────────────────────── */

static freq_bucket_t *freq_bucket_new(uint64_t freq) {
    freq_bucket_t *b = calloc(1, sizeof(*b));
    if (b) b->freq = freq;
    return b;
}

/* Removes node from its current freq bucket (if any), freeing the
 * bucket if it becomes empty and fixing up the shard's freq_min
 * pointer. Does not touch node->freq_bucket itself (caller sets it). */
static void freq_bucket_remove_node(cache_shard_t *shard, shared_meta_t *node) {
    freq_bucket_t *b = node->freq_bucket;
    if (!b) return;

    if (node->freq_prev) node->freq_prev->freq_next = node->freq_next;
    else                 b->head                    = node->freq_next;
    if (node->freq_next) node->freq_next->freq_prev = node->freq_prev;
    else                 b->tail                    = node->freq_prev;

    node->freq_prev = node->freq_next = NULL;

    if (b->head == NULL) {
        /* bucket now empty -- unlink from frequency list and free */
        if (b->lower)  b->lower->higher = b->higher;
        if (b->higher) b->higher->lower = b->lower;
        if (shard->freq_min == b) shard->freq_min = b->higher;
        free(b);
    }
    node->freq_bucket = NULL;
}

/* Inserts node into the bucket for `freq`, creating it in the correct
 * sorted position if it doesn't exist yet. */
static void freq_bucket_insert_node(cache_shard_t *shard, shared_meta_t *node, uint64_t freq) {
    /* find existing bucket with this exact freq, or the insertion point */
    freq_bucket_t *cur = shard->freq_min;
    while (cur && cur->freq < freq) cur = cur->higher;

    freq_bucket_t *target;
    if (cur && cur->freq == freq) {
        target = cur;
    } else {
        target = freq_bucket_new(freq);
        if (!target) return; /* allocation failure: node simply won't be
                                 tracked for LFU this cycle, degrades to
                                 "never evicted preferentially" rather
                                 than crashing */
        /* insert target before `cur` (or at the end if cur == NULL) */
        freq_bucket_t *prev = cur ? cur->lower : NULL;
        if (!cur) {
            /* find current tail of the frequency list */
            prev = shard->freq_min;
            if (prev) while (prev->higher) prev = prev->higher;
        }
        target->lower  = prev;
        target->higher = cur;
        if (prev) prev->higher = target; else shard->freq_min = target;
        if (cur)  cur->lower   = target;
    }

    /* insert node at the tail of target's list (most-recently-touched
     * among same-frequency nodes) */
    node->freq_next = NULL;
    node->freq_prev = target->tail;
    if (target->tail) target->tail->freq_next = node;
    else               target->head           = node;
    target->tail       = node;
    node->freq_bucket  = target;
}

static void freq_touch(cache_shard_t *shard, shared_meta_t *node) {
    uint64_t old_freq = node->freq_bucket ? node->freq_bucket->freq : 0;
    uint64_t new_freq = old_freq + 1;
    if (new_freq > LFU_MAX_FREQ) new_freq = LFU_MAX_FREQ; /* clamp -- see
        file_cache.h / project notes: an unbounded counter means an
        object that was popular once can never be evicted again, so we
        cap it and periodically decay (see freq_decay_maybe()) instead */
    freq_bucket_remove_node(shard, node);
    freq_bucket_insert_node(shard, node, new_freq);
}

/* Halves every node's effective frequency by re-inserting each node at
 * freq/2. Runs every LFU_DECAY_INTERVAL puts (see freq_decay_maybe()) so
 * that long-idle-but-once-popular entries eventually become evictable
 * again -- the classic LFU aging problem the doc comment above warns
 * about. O(n) over the shard's current entries; only runs periodically,
 * and shards are small by design (max_entries / n_shards), so this is
 * cheap relative to how rarely it fires. */
static void freq_decay(cache_shard_t *shard) {
    /* Collect all nodes first (walking freq buckets while mutating them
     * is exactly the iterate-while-mutate bug class fixed elsewhere in
     * this project's h2.c stream sweep -- snapshot first, then act). */
    shared_meta_t *nodes[TL_MAX_ENTRIES];
    int n = 0;
    for (freq_bucket_t *b = shard->freq_min; b && n < TL_MAX_ENTRIES; b = b->higher) {
        for (shared_meta_t *node = b->head; node && n < TL_MAX_ENTRIES; node = node->freq_next) {
            nodes[n++] = node;
        }
    }
    for (int i = 0; i < n; i++) {
        uint64_t old_freq = nodes[i]->freq_bucket ? nodes[i]->freq_bucket->freq : 0;
        freq_bucket_remove_node(shard, nodes[i]);
        freq_bucket_insert_node(shard, nodes[i], old_freq / 2);
    }
}

static void freq_decay_maybe(cache_shard_t *shard) {
    if (g_cfg.eviction != FILE_CACHE_EVICT_LFU) return;
    if (++shard->puts_since_decay >= LFU_DECAY_INTERVAL) {
        shard->puts_since_decay = 0;
        freq_decay(shard);
    }
}

/* ── LRU intrusive-list helpers (per-shard) ──────────────────────────── */

static void lru_remove(cache_shard_t *shard, shared_meta_t *node) {
    if (node->lru_prev) node->lru_prev->lru_next = node->lru_next;
    else                shard->lru_head           = node->lru_next;
    if (node->lru_next) node->lru_next->lru_prev = node->lru_prev;
    else                shard->lru_tail           = node->lru_prev;
    node->lru_prev = node->lru_next = NULL;
}

static void lru_push_front(cache_shard_t *shard, shared_meta_t *node) {
    node->lru_prev = NULL;
    node->lru_next = shard->lru_head;
    if (shard->lru_head) shard->lru_head->lru_prev = node;
    shard->lru_head = node;
    if (!shard->lru_tail) shard->lru_tail = node;
}

static void lru_touch(cache_shard_t *shard, shared_meta_t *node) {
    lru_remove(shard, node);
    lru_push_front(shard, node);
}

/* ── Shard hash-bucket helpers (chaining within a shard) ─────────────── */

static shared_meta_t *shard_find(cache_shard_t *shard, const char *path, uint32_t hash) {
    int b = (int)(hash % SHARD_HASH_BUCKETS);
    for (shared_meta_t *n = shard->buckets[b]; n; n = n->hash_next) {
        if (n->hash == hash && strcmp(n->path, path) == 0) return n;
    }
    return NULL;
}

static void shard_bucket_insert(cache_shard_t *shard, shared_meta_t *node) {
    int b = (int)(node->hash % SHARD_HASH_BUCKETS);
    node->hash_next     = shard->buckets[b];
    shard->buckets[b]   = node;
}

static void shard_bucket_remove(cache_shard_t *shard, shared_meta_t *node) {
    int b = (int)(node->hash % SHARD_HASH_BUCKETS);
    shared_meta_t **pp = &shard->buckets[b];
    while (*pp) {
        if (*pp == node) { *pp = node->hash_next; return; }
        pp = &(*pp)->hash_next;
    }
}

/* Removes and frees a node from every structure it's linked into
 * (hash chain, LRU list, LFU bucket). Caller must hold the shard's
 * write lock. */
static void shard_node_destroy(cache_shard_t *shard, shared_meta_t *node) {
    shard_bucket_remove(shard, node);
    if (g_cfg.eviction == FILE_CACHE_EVICT_LRU) lru_remove(shard, node);
    if (g_cfg.eviction == FILE_CACHE_EVICT_LFU) freq_bucket_remove_node(shard, node);
    shard->count--;
    free(node);
}

/* Picks a victim for eviction according to g_cfg.eviction and destroys
 * it. Caller must hold the shard's write lock. No-op if shard is
 * empty (shouldn't happen if called only when shard->count >= cap). */
static void shard_evict_one(cache_shard_t *shard) {
    shared_meta_t *victim = NULL;
    if (g_cfg.eviction == FILE_CACHE_EVICT_LFU) {
        if (shard->freq_min && shard->freq_min->head) victim = shard->freq_min->head;
    } else if (g_cfg.eviction == FILE_CACHE_EVICT_LRU) {
        victim = shard->lru_tail;
    } else {
        /* TTL_ONLY: no ordering maintained, just take the oldest by
         * cached_at via linear scan -- shards are small by design. */
        for (int b = 0; b < SHARD_HASH_BUCKETS; b++) {
            for (shared_meta_t *n = shard->buckets[b]; n; n = n->hash_next) {
                if (!victim || n->cached_at < victim->cached_at) victim = n;
            }
        }
    }
    if (victim) shard_node_destroy(shard, victim);
}

/* =========================================================================
 * Public init/free
 * ========================================================================= */

int file_cache_init(const file_cache_config_t *cfg) {
    if (!cfg || !cfg->enabled) return 0;
    g_cfg     = *cfg;
    g_enabled = 1;

    if (g_cfg.max_entries <= 0 || g_cfg.max_entries > TL_MAX_ENTRIES)
        g_cfg.max_entries = TL_MAX_ENTRIES;

    if (g_cfg.mmap_threshold == 0)
        g_cfg.mmap_threshold = FILE_CACHE_DEFAULT_MMAP_THRESHOLD;

    if (g_cfg.mode == FILE_CACHE_MODE_SHARED_CONTENT) {
        LOG_WARN("file_cache: shared_content mode not implemented in this "
                 "revision, falling back to shared_metadata");
        g_cfg.mode = FILE_CACHE_MODE_SHARED_METADATA;
    }

    if (g_cfg.mode != FILE_CACHE_MODE_LOCAL) {
        g_n_shards = (g_cfg.lock_kind == FILE_CACHE_LOCK_GLOBAL) ? 1 : g_cfg.n_shards;
        if (g_n_shards <= 0) g_n_shards = 1;
        /* must be a power of 2 for the & mask in shard_index() */
        int p = 1;
        while (p < g_n_shards) p <<= 1;
        g_n_shards = p;

        g_shards = calloc((size_t)g_n_shards, sizeof(cache_shard_t));
        if (!g_shards) {
            LOG_ERROR("file_cache: failed to allocate %d shards", g_n_shards);
            g_enabled = 0;
            return -1;
        }
        int per_shard_cap = g_cfg.max_entries / g_n_shards;
        if (per_shard_cap < 1) per_shard_cap = 1;
        for (int i = 0; i < g_n_shards; i++) {
            pthread_rwlock_init(&g_shards[i].lock, NULL);
            g_shards[i].cap = per_shard_cap;
        }

        g_worker_mmaps_cap = MAX_WORKERS;
        g_worker_mmaps = calloc((size_t)g_worker_mmaps_cap, sizeof(worker_mmap_table_t));
        if (!g_worker_mmaps) {
            LOG_ERROR("file_cache: failed to allocate worker mmap tables");
            g_enabled = 0;
            return -1;
        }
    }

    LOG_INFO("file_cache: mode=%d lock=%d shards=%d entries=%d ttl=%ds "
             "strategy=%d eviction=%d watch=%d",
             (int)g_cfg.mode, (int)g_cfg.lock_kind, g_n_shards,
             g_cfg.max_entries, g_cfg.ttl_seconds, (int)g_cfg.strategy,
             (int)g_cfg.eviction, (int)g_cfg.watch);
    return 0;
}

void file_cache_free(void) {
    g_enabled = 0;
    if (g_shards) {
        for (int i = 0; i < g_n_shards; i++) {
            for (int b = 0; b < SHARD_HASH_BUCKETS; b++) {
                shared_meta_t *n = g_shards[i].buckets[b];
                while (n) {
                    shared_meta_t *next = n->hash_next;
                    free(n);
                    n = next;
                }
            }
            /* free any remaining freq buckets */
            freq_bucket_t *fb = g_shards[i].freq_min;
            while (fb) {
                freq_bucket_t *next = fb->higher;
                free(fb);
                fb = next;
            }
            pthread_rwlock_destroy(&g_shards[i].lock);
        }
        free(g_shards);
        g_shards = NULL;
    }
    if (g_worker_mmaps) {
        /* Note: this frees the tracking tables, not the mmap'd regions
         * themselves -- those belong to worker threads which are
         * expected to already be stopped by the time file_cache_free()
         * runs (server shutdown path). If shutdown ever needs to run
         * with workers still live, this would leak mappings; today's
         * shutdown order (see server.c) stops workers first. */
        free(g_worker_mmaps);
        g_worker_mmaps = NULL;
    }
#if ROUTA_HAVE_INOTIFY
    if (g_shared_inotify_fd >= 0) { close(g_shared_inotify_fd); g_shared_inotify_fd = -1; }
    for (int b = 0; b < SHARD_HASH_BUCKETS; b++) {
        wd_entry_t *n = g_wd_table[b];
        while (n) { wd_entry_t *next = n->next; free(n); n = next; }
        g_wd_table[b] = NULL;
    }
#endif
}

void file_cache_worker_init(int worker_id) {
    if (!g_enabled) return;
    if (g_cfg.mode == FILE_CACHE_MODE_LOCAL) {
        tl_init();
#if ROUTA_HAVE_INOTIFY
        if (g_cfg.watch == FILE_CACHE_WATCH_INOTIFY && tl_inotify_fd < 0) {
            tl_inotify_fd = inotify_init1(IN_NONBLOCK);
        }
#endif
        return;
    }
    if (worker_id < 0 || worker_id >= g_worker_mmaps_cap) {
        LOG_WARN("file_cache: worker_id %d out of range (max %d), "
                 "per-worker mmap cache disabled for this worker",
                 worker_id, g_worker_mmaps_cap - 1);
        return;
    }
    if (!g_worker_mmaps[worker_id].initialized) {
        memset(&g_worker_mmaps[worker_id], 0, sizeof(worker_mmap_table_t));
        g_worker_mmaps[worker_id].initialized = 1;
    }
}

/* ── Generation high-water-mark table ─────────────────────────────────────
 * Tracks, per path, the highest generation number ever assigned -- even
 * after the corresponding shared_meta_t entry has been evicted or
 * invalidated. This is what lets shared_put() hand out a generation
 * strictly greater than any the path has had before, instead of
 * restarting at 0 on every fresh calloc'd entry (see the doc comment in
 * file_cache_invalidate() for why restarting at 0 would be a bug: a
 * worker whose last_seen_generation happens to also be 0 for this path
 * would otherwise wrongly treat a stale pre-invalidate mapping as still
 * current).
 *
 * Deliberately a small fixed-size open table rather than something
 * fancier -- entries here are tiny (path + one uint64_t) and only ever
 * added on put()/invalidate(), never on the request hot path, so O(n)
 * linear probing over a modest table is fine. Sized the same as the
 * overall entry budget; if it fills up, the oldest entries are simply
 * overwritten (worst case: a long-idle path's hwm is forgotten and it
 * restarts numbering from 0 again -- functionally identical to that
 * path never having been cached before, not a correctness issue, just
 * a missed optimization in an already-rare scenario). */
#define GEN_HWM_TABLE_SIZE TL_MAX_ENTRIES

typedef struct {
    char     path[1024];
    uint32_t hash;
    uint64_t hwm;
    int      in_use;
} gen_hwm_entry_t;

static gen_hwm_entry_t   g_gen_hwm[GEN_HWM_TABLE_SIZE];
static pthread_mutex_t   g_gen_hwm_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t generation_hwm_get_and_advance(const char *path, uint32_t hash) {
    pthread_mutex_lock(&g_gen_hwm_lock);
    int slot = (int)(hash % GEN_HWM_TABLE_SIZE);
    int i = slot;
    uint64_t result = 0;
    for (int probes = 0; probes < GEN_HWM_TABLE_SIZE; probes++) {
        gen_hwm_entry_t *e = &g_gen_hwm[i];
        if (e->in_use && e->hash == hash && strcmp(e->path, path) == 0) {
            e->hwm++;
            result = e->hwm;
            pthread_mutex_unlock(&g_gen_hwm_lock);
            return result;
        }
        if (!e->in_use) {
            e->in_use = 1;
            e->hash   = hash;
            strncpy(e->path, path, sizeof(e->path) - 1);
            e->path[sizeof(e->path) - 1] = '\0';
            e->hwm    = 1;
            pthread_mutex_unlock(&g_gen_hwm_lock);
            return 1;
        }
        i = (i + 1) % GEN_HWM_TABLE_SIZE;
    }
    /* table full: overwrite this path's home slot (see doc comment --
     * degrades to "numbering restarts", not a correctness break) */
    gen_hwm_entry_t *e = &g_gen_hwm[slot];
    e->in_use = 1;
    e->hash   = hash;
    strncpy(e->path, path, sizeof(e->path) - 1);
    e->path[sizeof(e->path) - 1] = '\0';
    e->hwm    = 1;
    pthread_mutex_unlock(&g_gen_hwm_lock);
    return 1;
}

/* Called from file_cache_invalidate() purely so the doc comment there
 * has a named call site to point at; the actual bump happens lazily on
 * the next generation_hwm_get_and_advance() call from shared_put(), so
 * this only needs to ensure a hwm row exists (advancing it here would
 * double-bump: once for the invalidate, once for the next put()). This
 * function intentionally does nothing beyond that -- kept as a distinct
 * name rather than inlined so the invalidate()-side intent stays
 * self-documenting at the call site. */
static void generation_hwm_bump(const char *path, uint32_t hash) {
    (void)path; (void)hash; /* no-op: see doc comment above */
}

/* =========================================================================
 * Public API: get / put / put_negative / invalidate
 * ========================================================================= */

static void fill_out_from_shared(const shared_meta_t *m, file_cache_entry_t *out,
                                  void *mmap_ptr, size_t mmap_len) {
    memset(out, 0, sizeof(*out));
    memcpy(out->resolved,      m->resolved,      sizeof(out->resolved));
    memcpy(out->etag,          m->etag,          sizeof(out->etag));
    memcpy(out->last_modified, m->last_modified, sizeof(out->last_modified));
    memcpy(out->mime_type,     m->mime_type,     sizeof(out->mime_type));
    out->size       = m->size;
    out->mtime      = m->mtime;
    out->cached_at  = m->cached_at;
    out->hash       = m->hash;
    out->valid      = 1;
    out->negative   = m->negative;
    out->data       = mmap_ptr;
    out->data_len   = mmap_len;
}

/* Opens (or re-opens, on generation mismatch) this worker's own mmap for
 * `resolved`, updating its local tracking slot. Never touches another
 * worker's mapping -- see file_cache.h's mode doc comment. Returns the
 * (possibly NULL, for large files) mmap pointer via out_ptr/out_len. */
static void worker_mmap_sync(int worker_id, const char *path, const char *resolved,
                              off_t size, uint64_t generation,
                              void **out_ptr, size_t *out_len) {
    *out_ptr = NULL;
    *out_len = 0;
    if (worker_id < 0 || worker_id >= g_worker_mmaps_cap) return;

    worker_mmap_table_t *table = &g_worker_mmaps[worker_id];
    if (!table->initialized) return; /* file_cache_worker_init() wasn't called --
                                         degrade to "no local mmap cache" rather
                                         than touch uninitialized memory */

    int idx = -1, free_idx = -1;
    for (int i = 0; i < TL_MAX_ENTRIES; i++) {
        if (table->slots[i].in_use && strcmp(table->slots[i].path, path) == 0) {
            idx = i;
            break;
        }
        if (free_idx < 0 && !table->slots[i].in_use) free_idx = i;
    }

    if (idx >= 0) {
        worker_mmap_slot_t *slot = &table->slots[idx];
        if (slot->last_seen_generation == generation) {
            /* still current -- reuse existing mapping unconditionally */
            *out_ptr = slot->mmap_ptr;
            *out_len = slot->mmap_len;
            return;
        }
        /* stale: drop old mapping before re-fetching */
        if (slot->mmap_ptr) munmap(slot->mmap_ptr, slot->mmap_len);
        slot->mmap_ptr = NULL;
        slot->mmap_len = 0;
    } else {
        if (free_idx < 0) {
            /* No free slot -- evict slot 0 as a simple fallback. Local
             * mmap tables are sized == TL_MAX_ENTRIES same as the shared
             * shard budget, so this should be rare in practice; a
             * smarter per-worker LRU here is possible future work but
             * isn't load-bearing for correctness. */
            if (table->slots[0].mmap_ptr)
                munmap(table->slots[0].mmap_ptr, table->slots[0].mmap_len);
            free_idx = 0;
        }
        idx = free_idx;
        memset(&table->slots[idx], 0, sizeof(worker_mmap_slot_t));
    }

    worker_mmap_slot_t *slot = &table->slots[idx];
    strncpy(slot->path, path, sizeof(slot->path) - 1);
    slot->path[sizeof(slot->path) - 1] = '\0';
    slot->in_use = 1;
    slot->last_seen_generation = generation;

    if ((size_t)size > 0 && (size_t)size < g_cfg.mmap_threshold) {
        int fd = open(resolved, O_RDONLY);
        if (fd >= 0) {
#if defined(__linux__)
            void *ptr = mmap(NULL, (size_t)size, PROT_READ,
                              MAP_PRIVATE | MAP_POPULATE, fd, 0);
#else
            void *ptr = mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, fd, 0);
#endif
            close(fd);
            if (ptr != MAP_FAILED) {
                madvise(ptr, (size_t)size, MADV_SEQUENTIAL);
                slot->mmap_ptr = ptr;
                slot->mmap_len = (size_t)size;
            }
        }
    }
    *out_ptr = slot->mmap_ptr;
    *out_len = slot->mmap_len;
}

static int shared_get(int worker_id, const char *path, file_cache_entry_t *out) {
    uint32_t hash = fnv1a(path);
    int      sidx = shard_index(hash);
    cache_shard_t *shard = &g_shards[sidx];

    pthread_rwlock_rdlock(&shard->lock);
    shared_meta_t *m = shard_find(shard, path, hash);
    int hit = 0;
    shared_meta_t snapshot;
    if (m) {
        time_t now = time(NULL);
        int ttl = g_cfg.ttl_seconds > 0 ? g_cfg.ttl_seconds : 5;
        int fresh;
        if (m->negative) {
            int neg_ttl = g_cfg.negative_ttl_seconds;
            fresh = neg_ttl > 0 && (now - m->cached_at) < neg_ttl;
        } else if (g_cfg.strategy == FILE_CACHE_TTL) {
            fresh = (now - m->cached_at) < ttl;
        } else {
            /* STAT_TTL and INOTIFY both treat "still in the shared table"
             * as fresh here -- STAT_TTL's revalidation and INOTIFY's
             * generation bump both work by removing/updating the shared
             * entry, not by a per-read stat() call (unlike local mode,
             * doing the stat() under the shard lock would serialize all
             * readers on disk I/O, which defeats the point of sharing
             * the table in the first place). A background sweep
             * revalidates STAT_TTL entries -- see shared_revalidate_sweep(). */
            fresh = 1;
        }
        if (fresh) {
            snapshot = *m;
            hit = 1;
        }
    }
    pthread_rwlock_unlock(&shard->lock);

    if (!hit) return 0;

    if (snapshot.negative) {
        fill_out_from_shared(&snapshot, out, NULL, 0);
        return 1;
    }

    void  *mmap_ptr = NULL;
    size_t mmap_len = 0;
    worker_mmap_sync(worker_id, path, snapshot.resolved, snapshot.size,
                      snapshot.generation, &mmap_ptr, &mmap_len);
    fill_out_from_shared(&snapshot, out, mmap_ptr, mmap_len);

    /* Touch LRU/LFU ordering under a (brief) write lock. Done as a
     * separate critical section from the read above so the common-case
     * read path only needs rdlock; this second lock is uncontended in
     * the overwhelming majority of cases (LRU/LFU pointer fixups are
     * O(1)) so the extra lock/unlock pair is cheap relative to the I/O
     * this cache exists to avoid. */
    pthread_rwlock_wrlock(&shard->lock);
    m = shard_find(shard, path, hash); /* re-find: may have been evicted
                                           between unlock and this relock */
    if (m) {
        if (g_cfg.eviction == FILE_CACHE_EVICT_LRU) lru_touch(shard, m);
        else if (g_cfg.eviction == FILE_CACHE_EVICT_LFU) freq_touch(shard, m);
    }
    pthread_rwlock_unlock(&shard->lock);

    return 1;
}

int file_cache_get(int worker_id, const char *path, file_cache_entry_t *out) {
    if (!g_enabled || !path || !out) return 0;

    if (g_cfg.mode == FILE_CACHE_MODE_LOCAL) {
        tl_init();
        uint32_t hash = fnv1a(path);
        time_t   now  = time(NULL);
        int idx = tl_find_slot(path, hash);
        if (idx >= 0 && tl_entry_valid(&tl_slots[idx], now)) {
            tl_touch(&tl_slots[idx], now);
            *out = tl_slots[idx].entry;
            ROUTA_METRIC_INC(file_cache_hits_total);
            return 1;
        }
        ROUTA_METRIC_INC(file_cache_misses_total);
        return 0;
    }

    int hit = shared_get(worker_id, path, out);
    if (hit) ROUTA_METRIC_INC(file_cache_hits_total);
    else     ROUTA_METRIC_INC(file_cache_misses_total);
    return hit;
}

static void shared_put(int worker_id, const char *path, const file_cache_entry_t *entry) {
    uint32_t hash = fnv1a(path);
    int      sidx = shard_index(hash);
    cache_shard_t *shard = &g_shards[sidx];

    /* Always draw the new generation from the high-water-mark table,
     * never from the entry being replaced (if any) and never a fresh
     * 0. Using the hwm here — not "keep old generation if this path was
     * already cached" — is what makes a put() following an
     * invalidate() actually produce a generation every worker's
     * worker_mmap_sync() recognizes as new: an invalidate() destroys
     * the shared_meta_t (see file_cache_invalidate()), so there would
     * otherwise be no "old generation" left to preserve, and a fresh
     * calloc'd entry would default back to 0 — indistinguishable from
     * this path's very first put() as far as a worker's
     * last_seen_generation comparison is concerned. */
    uint64_t generation = generation_hwm_get_and_advance(path, hash);

    pthread_rwlock_wrlock(&shard->lock);
    shared_meta_t *m = shard_find(shard, path, hash);
    if (m) {
        shard_node_destroy(shard, m);
        m = NULL;
    }

    if (shard->count >= shard->cap) shard_evict_one(shard);

    m = calloc(1, sizeof(shared_meta_t));
    if (!m) { pthread_rwlock_unlock(&shard->lock); return; }

    strncpy(m->path, path, sizeof(m->path) - 1);
    m->hash = hash;
    memcpy(m->resolved,      entry->resolved,      sizeof(m->resolved));
    memcpy(m->etag,          entry->etag,          sizeof(m->etag));
    memcpy(m->last_modified, entry->last_modified, sizeof(m->last_modified));
    memcpy(m->mime_type,     entry->mime_type,     sizeof(m->mime_type));
    m->size       = entry->size;
    m->mtime      = entry->mtime;
    m->cached_at  = time(NULL);
    m->negative   = entry->negative;
    m->generation = generation;
    m->in_use     = 1;

    shard_bucket_insert(shard, m);
    shard->count++;
    if (g_cfg.eviction == FILE_CACHE_EVICT_LRU) lru_push_front(shard, m);
    else if (g_cfg.eviction == FILE_CACHE_EVICT_LFU) {
        freq_bucket_insert_node(shard, m, 1);
        freq_decay_maybe(shard);
    }

    pthread_rwlock_unlock(&shard->lock);

    /* mmap creation itself happens lazily on the next file_cache_get()
     * call via worker_mmap_sync() -- put() only needs to seed the
     * shared metadata. This also means the worker that calls put()
     * (having just done the stat()/open() on a miss) will do one more
     * mmap immediately afterward on its own next get(), rather than
     * put() eagerly mmapping here -- kept this way so shared_put() has
     * no filesystem I/O of its own and callers can't be surprised by
     * put() blocking on disk. */
    (void)worker_id;

#if ROUTA_HAVE_INOTIFY
    if (g_cfg.watch == FILE_CACHE_WATCH_INOTIFY && !entry->negative &&
        g_shared_inotify_fd >= 0) {
        pthread_mutex_lock(&g_wd_lock);
        int b = (int)(hash % SHARD_HASH_BUCKETS);
        int already_watched = 0;
        for (wd_entry_t *n = g_wd_table[b]; n; n = n->next) {
            if (strcmp(n->path, entry->resolved) == 0) { already_watched = 1; break; }
        }
        if (!already_watched) {
            int wd = inotify_add_watch(g_shared_inotify_fd, entry->resolved,
                                        IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_ATTRIB);
            if (wd >= 0) {
                wd_entry_t *we = calloc(1, sizeof(wd_entry_t));
                if (we) {
                    we->wd = wd;
                    strncpy(we->path, entry->resolved, sizeof(we->path) - 1);
                    we->next = g_wd_table[b];
                    g_wd_table[b] = we;
                }
            }
        }
        pthread_mutex_unlock(&g_wd_lock);
    }
#endif
}

void file_cache_put(int worker_id, const char *path, const file_cache_entry_t *entry) {
    if (!g_enabled || !path || !entry) return;

    if (g_cfg.mode == FILE_CACHE_MODE_LOCAL) {
        tl_init();
        uint32_t hash = fnv1a(path);
        int idx = tl_find_slot(path, hash);
        if (idx < 0) idx = tl_evict_slot();
        else         slot_unmap(&tl_slots[idx]);

        strncpy(tl_slots[idx].path, path, sizeof(tl_slots[idx].path) - 1);
        tl_slots[idx].path[sizeof(tl_slots[idx].path) - 1] = '\0';
        tl_slots[idx].entry            = *entry;
        tl_slots[idx].entry.hash       = hash;
        tl_slots[idx].entry.cached_at  = time(NULL);
        tl_slots[idx].in_use           = 1;
        tl_touch(&tl_slots[idx], tl_slots[idx].entry.cached_at);
#if ROUTA_HAVE_INOTIFY
        if (g_cfg.watch == FILE_CACHE_WATCH_INOTIFY && !entry->negative)
            tl_watch_add(idx, entry->resolved);
#endif
        return;
    }

    shared_put(worker_id, path, entry);
}

void file_cache_put_negative(int worker_id, const char *path) {
    if (!g_enabled || !path) return;
    if (g_cfg.negative_ttl_seconds <= 0) return; /* negative caching off */

    file_cache_entry_t neg;
    memset(&neg, 0, sizeof(neg));
    neg.valid    = 1;
    neg.negative = 1;
    strncpy(neg.resolved, path, sizeof(neg.resolved) - 1);

    file_cache_put(worker_id, path, &neg);
}

void file_cache_invalidate(int worker_id, const char *path) {
    if (!g_enabled || !path) return;

    if (g_cfg.mode == FILE_CACHE_MODE_LOCAL) {
        tl_init();
        uint32_t hash = fnv1a(path);
        int idx = tl_find_slot(path, hash);
        if (idx >= 0) {
            slot_unmap(&tl_slots[idx]);
            tl_slots[idx].in_use = 0;
#if ROUTA_HAVE_INOTIFY
            if (tl_inotify_fd >= 0 && tl_wd_for_slot[idx] >= 0) {
                inotify_rm_watch(tl_inotify_fd, tl_wd_for_slot[idx]);
                tl_wd_for_slot[idx] = -1;
            }
#endif
        }
        return;
    }

    (void)worker_id;
    uint32_t hash = fnv1a(path);
    int      sidx = shard_index(hash);
    cache_shard_t *shard = &g_shards[sidx];

    pthread_rwlock_wrlock(&shard->lock);
    shared_meta_t *m = shard_find(shard, path, hash);
    if (m) {
        /* Removing the metadata entry entirely (rather than just
         * bumping its generation and leaving the rest as-is) is
         * required here: leaving stale etag/mtime/size in the shared
         * table while only bumping generation would let a request
         * serve a freshly re-mapped file body alongside a now-wrong
         * ETag/Last-Modified pair (shared_get() would still return the
         * old metadata fields, only the mmap would change).
         *
         * We persist the generation counter itself into a small
         * per-path "high-water mark" table (generation_hwm) rather than
         * losing it when the entry is destroyed: without that, a
         * worker's worker_mmap_sync() compares its last_seen_generation
         * against whatever generation the *next* put() assigns, and if
         * that next put() naively started back at 0 (a fresh calloc'd
         * shared_meta_t), a worker whose last_seen_generation also
         * happens to be 0 (this path was never invalidated from that
         * worker's point of view before) would wrongly consider its
         * stale pre-invalidate mapping still current. Handing the next
         * put() a generation strictly greater than any previously seen
         * closes that gap -- see generation_hwm_bump()/shared_put(). */
        generation_hwm_bump(path, hash);
        shard_node_destroy(shard, m);
    }
    pthread_rwlock_unlock(&shard->lock);
}

size_t file_cache_get_mmap_threshold(void) {
    if (!g_enabled || g_cfg.mmap_threshold == 0)
        return FILE_CACHE_DEFAULT_MMAP_THRESHOLD;
    return g_cfg.mmap_threshold;
}

int file_cache_watch_is_centralized(void) {
    /* LOCAL mode: every worker owns its own independent inotify fd
     * (each only watches paths it personally cached), so no central
     * ownership is required. SHARED_* modes: a single owner bumps the
     * shared generation counters that every worker already checks on
     * each get() -- see worker_should_own_inotify() in event_loop.c for
     * the single decision point on *which* worker that is. */
    return g_cfg.mode != FILE_CACHE_MODE_LOCAL;
}

/* =========================================================================
 * inotify integration
 * ========================================================================= */

int file_cache_inotify_open(int worker_id) {
    if (!g_enabled || g_cfg.watch != FILE_CACHE_WATCH_INOTIFY) return -1;
#if !ROUTA_HAVE_INOTIFY
    (void)worker_id;
    LOG_WARN("file_cache: inotify requested but not supported on this "
             "platform, falling back to TTL-based revalidation");
    return -1;
#else
    if (g_cfg.mode == FILE_CACHE_MODE_LOCAL) {
        /* Local mode: each worker opens (or reuses, if
         * file_cache_worker_init() already did) its own fd. */
        file_cache_worker_init(worker_id);
        return tl_inotify_fd;
    }

    /* Shared modes: only the centralized owner should ever call this
     * (event_loop.c's worker_should_own_inotify() gate ensures that) --
     * but guard here too rather than trust the caller blindly, since a
     * second fd would silently duplicate watches for no benefit. */
    if (g_shared_inotify_fd >= 0) return g_shared_inotify_fd;
    g_shared_inotify_fd = inotify_init1(IN_NONBLOCK);
    return g_shared_inotify_fd;
#endif
}

#if ROUTA_HAVE_INOTIFY
/* Shared-mode drain: an inotify event fired for some watched path.
 * We don't get the original cache path back from inotify (it only
 * gives us the watch descriptor), so we look up which resolved path
 * that wd corresponds to, then bump generation for every shard entry
 * whose resolved path matches -- in practice this is exactly one entry,
 * since watches are added 1:1 with resolved paths in shared_put(). */
static void shared_handle_wd_event(int wd, uint32_t mask) {
    char matched_path[1024] = {0};
    int  found = 0;

    pthread_mutex_lock(&g_wd_lock);
    for (int b = 0; b < SHARD_HASH_BUCKETS && !found; b++) {
        for (wd_entry_t *n = g_wd_table[b]; n; n = n->next) {
            if (n->wd == wd) {
                strncpy(matched_path, n->path, sizeof(matched_path) - 1);
                found = 1;
                if (mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) {
                    /* watch is gone (file removed/moved); drop our
                     * bookkeeping entry too so a future put() re-adds
                     * a fresh watch instead of thinking one exists */
                    wd_entry_t **pp = &g_wd_table[b];
                    while (*pp) {
                        if (*pp == n) { *pp = n->next; free(n); break; }
                        pp = &(*pp)->next;
                    }
                }
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_wd_lock);

    if (!found) return;

    /* bump generation on every shard entry whose resolved path matches --
     * O(total entries) worst case, but this only runs on an actual
     * filesystem change event, never on the request hot path. */
    for (int i = 0; i < g_n_shards; i++) {
        cache_shard_t *shard = &g_shards[i];
        pthread_rwlock_wrlock(&shard->lock);
        for (int b = 0; b < SHARD_HASH_BUCKETS; b++) {
            for (shared_meta_t *n = shard->buckets[b]; n; n = n->hash_next) {
                if (strcmp(n->resolved, matched_path) == 0) n->generation++;
            }
        }
        pthread_rwlock_unlock(&shard->lock);
    }
}
#endif

void file_cache_inotify_drain(int fd) {
#if !ROUTA_HAVE_INOTIFY
    (void)fd;
    return;
#else
    if (fd < 0) return;
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break; /* EAGAIN (non-blocking, drained) or error */

        ssize_t off = 0;
        while (off < n) {
            struct inotify_event *ev = (struct inotify_event *)(buf + off);

            if (g_cfg.mode == FILE_CACHE_MODE_LOCAL) {
                /* Local mode: this fd belongs to the calling worker, so
                 * wd -> slot lookup uses this thread's own tl_wd_for_slot
                 * table directly. */
                for (int i = 0; i < tl_max; i++) {
                    if (tl_wd_for_slot[i] == ev->wd) {
                        slot_unmap(&tl_slots[i]);
                        tl_slots[i].in_use = 0;
                        if (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED))
                            tl_wd_for_slot[i] = -1;
                        break;
                    }
                }
            } else {
                shared_handle_wd_event(ev->wd, ev->mask);
            }

            off += (ssize_t)(sizeof(struct inotify_event) + ev->len);
        }
    }
#endif
}
