#define _GNU_SOURCE
#include "http/file_cache.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>

#define TL_MAX_ENTRIES 512

typedef struct {
    char               path[1024];
    file_cache_entry_t entry;
    int                in_use;
} tl_slot_t;

static __thread tl_slot_t tl_slots[TL_MAX_ENTRIES];
static __thread int       tl_initialized = 0;
static __thread int       tl_max         = 0;

static file_cache_config_t g_cfg;
static int                 g_enabled = 0;

/* ── FNV-1a ────────────────────────────────────────────────────────────────*/
static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

/* ── Public init/free ───────────────────────────────────────────────────── */
int file_cache_init(const file_cache_config_t *cfg) {
    if (!cfg || !cfg->enabled) return 0;
    g_cfg     = *cfg;
    g_enabled = 1;
    if (g_cfg.max_entries <= 0 || g_cfg.max_entries > TL_MAX_ENTRIES)
        g_cfg.max_entries = TL_MAX_ENTRIES;
    LOG_INFO("file_cache: thread-local mode, entries=%d ttl=%ds strategy=%d",
             g_cfg.max_entries, g_cfg.ttl_seconds, (int)g_cfg.strategy);
    return 0;
}

void file_cache_free(void) { g_enabled = 0; }

/* ── Thread-local init ──────────────────────────────────────────────────── */
static void tl_init(void) {
    if (tl_initialized) return;
    memset(tl_slots, 0, sizeof(tl_slots));
    tl_max         = g_cfg.max_entries;
    tl_initialized = 1;
}

/* ── Slot helpers ───────────────────────────────────────────────────────── */
static int find_slot(const char *path, uint32_t hash) {
    for (int i = 0; i < tl_max; i++) {
        if (tl_slots[i].in_use &&
            tl_slots[i].entry.hash == hash &&
            strcmp(tl_slots[i].path, path) == 0)
            return i;
    }
    return -1;
}

/* Release mmap'd content of a slot without touching other fields. */
static void slot_unmap(tl_slot_t *slot) {
    if (slot->entry.data) {
        munmap(slot->entry.data, slot->entry.data_len);
        slot->entry.data     = NULL;
        slot->entry.data_len = 0;
    }
}

static int evict_slot(void) {
    /* prefer a free slot */
    for (int i = 0; i < tl_max; i++)
        if (!tl_slots[i].in_use) return i;

    /* evict oldest */
    int    oldest   = 0;
    time_t oldest_t = tl_slots[0].entry.cached_at;
    for (int i = 1; i < tl_max; i++) {
        if (tl_slots[i].entry.cached_at < oldest_t) {
            oldest   = i;
            oldest_t = tl_slots[i].entry.cached_at;
        }
    }
    slot_unmap(&tl_slots[oldest]);   /* release mmap before reuse */
    tl_slots[oldest].in_use = 0;
    return oldest;
}

/* ── Validity check ─────────────────────────────────────────────────────── */
static int entry_valid(tl_slot_t *slot, time_t now) {
    if (!slot->in_use) return 0;
    int ttl = g_cfg.ttl_seconds > 0 ? g_cfg.ttl_seconds : 5;

    if (g_cfg.strategy == FILE_CACHE_TTL)
        return (now - slot->entry.cached_at) < ttl;

    if (g_cfg.strategy == FILE_CACHE_STAT_TTL) {
        if ((now - slot->entry.cached_at) < ttl) return 1;
        struct stat st;
        if (stat(slot->entry.resolved, &st) < 0) {
            slot_unmap(slot);
            slot->in_use = 0;
            return 0;
        }
        if (st.st_mtime != slot->entry.mtime ||
            st.st_size  != slot->entry.size) {
            /* file changed — drop mmap'd content, caller will re-open */
            slot_unmap(slot);
            slot->in_use = 0;
            return 0;
        }
        /* unchanged — bump timestamp */
        slot->entry.cached_at = now;
        return 1;
    }

    /* INOTIFY fallback: TTL x10 */
    return (now - slot->entry.cached_at) < (ttl * 10);
}

/* ── Public API ─────────────────────────────────────────────────────────── */
int file_cache_get(const char *path, file_cache_entry_t *out) {
    if (!g_enabled || !path || !out) return 0;
    tl_init();
    uint32_t hash = fnv1a(path);
    time_t   now  = time(NULL);
    int idx = find_slot(path, hash);
    if (idx >= 0 && entry_valid(&tl_slots[idx], now)) {
        *out = tl_slots[idx].entry;
        return 1;
    }
    return 0;
}

void file_cache_put(const char *path, const file_cache_entry_t *entry) {
    if (!g_enabled || !path || !entry) return;
    tl_init();
    uint32_t hash = fnv1a(path);

    int idx = find_slot(path, hash);
    if (idx < 0) {
        idx = evict_slot();   /* evict_slot calls slot_unmap internally */
    } else {
        /* updating existing slot — release old mmap if any */
        slot_unmap(&tl_slots[idx]);
    }

    strncpy(tl_slots[idx].path, path, sizeof(tl_slots[idx].path) - 1);
    tl_slots[idx].path[sizeof(tl_slots[idx].path) - 1] = '\0';
    tl_slots[idx].entry           = *entry;
    tl_slots[idx].entry.hash      = hash;
    tl_slots[idx].entry.cached_at = time(NULL);
    tl_slots[idx].in_use          = 1;
}

void file_cache_invalidate(const char *path) {
    if (!g_enabled || !path) return;
    tl_init();
    uint32_t hash = fnv1a(path);
    int idx = find_slot(path, hash);
    if (idx >= 0) {
        slot_unmap(&tl_slots[idx]);
        tl_slots[idx].in_use = 0;
    }
}