// test_file_cache.c
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "http/file_cache.h"

/* ── Test helpers ─────────────────────────────────────────────────── */
static void make_file(const char *path, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd >= 0);
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    size_t written = 0;
    while (written < size) {
        size_t chunk = size - written < sizeof(buf)
                     ? size - written : sizeof(buf);
        write(fd, buf, chunk);
        written += chunk;
    }
    close(fd);
}

static void remove_file(const char *path) { unlink(path); }

/* ── Tests ────────────────────────────────────────────────────────── */

/* 1. Basic Put → get */
static void test_basic_put_get(void) {
    file_cache_entry_t e = {0};
    strncpy(e.resolved,      "/tmp/routa_tc_basic.txt", sizeof(e.resolved)-1);
    strncpy(e.etag,          "\"abc\"",                 sizeof(e.etag)-1);
    strncpy(e.last_modified, "Thu, 01 Jan 2026 00:00:00 GMT",
            sizeof(e.last_modified)-1);
    strncpy(e.mime_type,     "text/plain",              sizeof(e.mime_type)-1);
    e.size  = 42;
    e.mtime = 1234567890;
    e.valid = 1;

    file_cache_put("/tmp/routa_tc_basic.txt", &e);

    file_cache_entry_t out = {0};
    int hit = file_cache_get("/tmp/routa_tc_basic.txt", &out);
    assert(hit == 1);
    assert(out.size == 42);
    assert(out.mtime == 1234567890);
    assert(strcmp(out.etag, "\"abc\"") == 0);
    assert(strcmp(out.mime_type, "text/plain") == 0);

    printf("  [OK] basic put/get\n");
}

/* 2. Miss */
static void test_cache_miss(void) {
    file_cache_entry_t out = {0};
    int hit = file_cache_get("/tmp/routa_tc_NONEXISTENT_xyz", &out);
    assert(hit == 0);
    printf("  [OK] cache miss\n");
}

/* 3. Invalidate */
static void test_invalidate(void) {
    file_cache_entry_t e = {0};
    strncpy(e.resolved, "/tmp/routa_tc_inv.txt", sizeof(e.resolved)-1);
    e.size = 10; e.valid = 1;

    file_cache_put("/tmp/routa_tc_inv.txt", &e);

    file_cache_entry_t out = {0};
    assert(file_cache_get("/tmp/routa_tc_inv.txt", &out) == 1);

    file_cache_invalidate("/tmp/routa_tc_inv.txt");
    assert(file_cache_get("/tmp/routa_tc_inv.txt", &out) == 0);

    printf("  [OK] invalidate\n");
}

/* 4. Double put — slot reuse */
static void test_update_existing(void) {
    file_cache_entry_t e = {0};
    strncpy(e.resolved, "/tmp/routa_tc_upd.txt", sizeof(e.resolved)-1);
    e.size = 100; e.valid = 1;
    file_cache_put("/tmp/routa_tc_upd.txt", &e);

    e.size = 200;
    file_cache_put("/tmp/routa_tc_upd.txt", &e);

    file_cache_entry_t out = {0};
    assert(file_cache_get("/tmp/routa_tc_upd.txt", &out) == 1);
    assert(out.size == 200);

    printf("  [OK] update existing slot\n");
}

/* 5. mmap path  */
static void test_mmap_small_file(void) {
    const char *path = "/tmp/routa_tc_small.bin";
    make_file(path, 1024);   /* 1 KB */

    file_cache_entry_t e = {0};
    strncpy(e.resolved, path, sizeof(e.resolved)-1);
    e.size = 1024; e.valid = 1;
    /* data intentionally NULL — simulating metadata-only put */
    file_cache_put(path, &e);

    file_cache_entry_t out = {0};
    assert(file_cache_get(path, &out) == 1);
    assert(out.size == 1024);
    assert(out.data == NULL);

    remove_file(path);
    printf("  [OK] small file metadata cache\n");
}

/* 6. Eviction */
static void test_eviction_capacity(void) {
    char path[64];
    for (int i = 0; i < 512; i++) {
        snprintf(path, sizeof(path), "/tmp/routa_tc_ev_%03d", i);
        file_cache_entry_t e = {0};
        strncpy(e.resolved, path, sizeof(e.resolved)-1);
        e.size = (size_t)i + 1; e.valid = 1;
        file_cache_put(path, &e);
    }

    file_cache_entry_t e = {0};
    strncpy(e.resolved, "/tmp/routa_tc_ev_NEW", sizeof(e.resolved)-1);
    e.size = 9999; e.valid = 1;
    file_cache_put("/tmp/routa_tc_ev_NEW", &e);

    file_cache_entry_t out = {0};
    assert(file_cache_get("/tmp/routa_tc_ev_NEW", &out) == 1);
    assert(out.size == 9999);

    for (int i = 0; i < 512; i++) {
        snprintf(path, sizeof(path), "/tmp/routa_tc_ev_%03d", i);
        file_cache_invalidate(path);
    }
    file_cache_invalidate("/tmp/routa_tc_ev_NEW");

    printf("  [OK] eviction at capacity\n");
}

/* 7. Multifile  */
static void test_multifile_hit_rate(void) {
    char path[64];
    for (int i = 0; i < 100; i++) {
        snprintf(path, sizeof(path), "/tmp/routa_tc_mf_%03d", i);
        file_cache_entry_t e = {0};
        strncpy(e.resolved, path, sizeof(e.resolved)-1);
        e.size = (size_t)(i * 100 + 1); e.valid = 1;
        file_cache_put(path, &e);
    }

    int hits = 0;
    for (int i = 0; i < 100; i++) {
        snprintf(path, sizeof(path), "/tmp/routa_tc_mf_%03d", i);
        file_cache_entry_t out = {0};
        if (file_cache_get(path, &out)) hits++;
    }
    assert(hits == 100);

    printf("  [OK] multifile hit rate 100/100\n");
}

/* 8. NULL guard */
static void test_null_guards(void) {
    file_cache_put(NULL, NULL);
    file_cache_put("/tmp/x", NULL);
    file_cache_invalidate(NULL);
    file_cache_entry_t out = {0};
    int r = file_cache_get(NULL, &out);
    assert(r == 0);
    printf("  [OK] null guards\n");
}

int main(void) {
    printf("=== test_file_cache ===\n");

    file_cache_config_t cfg = {
        .enabled     = 1,
        .max_entries = 512,
        .ttl_seconds = 60,
        .strategy    = FILE_CACHE_TTL,
    };
    file_cache_init(&cfg);

    test_basic_put_get();
    test_cache_miss();
    test_invalidate();
    test_update_existing();
    test_mmap_small_file();
    test_eviction_capacity();
    test_multifile_hit_rate();
    test_null_guards();

    printf("=== ALL PASSED ===\n");
    return 0;
}