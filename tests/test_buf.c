#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "util/buf.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* ── Test harness ────────────────────────────────────────────────────────── */
static int g_pass = 0;
static int g_fail = 0;

#define OK(label)   do { printf("[OK] %s\n",   label); g_pass++; } while(0)
#define FAIL(label, ...) do { \
    printf("[FAIL] %s: ", label); \
    printf(__VA_ARGS__); \
    printf("\n"); \
    g_fail++; \
} while(0)

/* ═══════════════════════════════════════════════════════════════════════════
 * Original tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_init(void) {
    buf_t b;
    buf_init(&b);
    if (b.len != 0 || b.off != 0)
        FAIL("init", "len=%zu off=%zu", b.len, b.off);
    else
        OK("init — len=0 off=0 (lazy alloc)");
    buf_free(&b);
}

static void test_append_basic(void) {
    buf_t b;
    buf_init(&b);
    if (buf_append(&b, "Hello", 5) != 0) { FAIL("append basic", "returned error"); buf_free(&b); return; }
    if (b.len != 5 || memcmp(b.data, "Hello", 5) != 0)
        FAIL("append basic", "len=%zu or content wrong", b.len);
    else
        OK("append basic — 5 bytes");
    buf_free(&b);
}

static void test_append_realloc(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "Hello", 5);
    buf_append(&b, " World!", 7);
    if (b.len != 12 || memcmp(b.data, "Hello World!", 12) != 0)
        FAIL("append realloc", "len=%zu content wrong", b.len);
    else
        OK("append realloc — 12 bytes");
    buf_free(&b);
}

static void test_consume(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "Hello World!", 12);
    buf_consume(&b, 6);
    if (b.len != 6 || memcmp(buf_data(&b), "World!", 6) != 0)
        FAIL("consume", "len=%zu content wrong", b.len);
    else
        OK("consume — 6 bytes shifted");
    buf_free(&b);
}

static void test_reset(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "data", 4);
    size_t old_cap = b.cap;
    buf_reset(&b);
    if (b.len != 0 || b.cap != old_cap)
        FAIL("reset", "len=%zu cap changed from %zu to %zu", b.len, old_cap, b.cap);
    else
        OK("reset — len=0, cap preserved");
    buf_free(&b);
}

static void test_append_after_reset(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "old", 3);
    buf_reset(&b);
    buf_append(&b, "New data", 8);
    if (b.len != 8 || memcmp(b.data, "New data", 8) != 0)
        FAIL("append after reset", "len=%zu or content wrong", b.len);
    else
        OK("append after reset");
    buf_free(&b);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Boundary tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_append_zero_bytes(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "abc", 3);
    size_t before = b.len;
    int rc = buf_append(&b, "", 0);
    if (rc != 0)
        FAIL("append zero bytes", "returned %d", rc);
    else if (b.len != before)
        FAIL("append zero bytes", "len changed from %zu to %zu", before, b.len);
    else
        OK("append zero bytes — len unchanged");
    buf_free(&b);
}

static void test_append_one_byte(void) {
    buf_t b;
    buf_init(&b);
    int rc = buf_append(&b, "X", 1);
    if (rc != 0 || b.len != 1 || *(char*)b.data != 'X')
        FAIL("append one byte", "rc=%d len=%zu", rc, b.len);
    else
        OK("append one byte");
    buf_free(&b);
}

static void test_exact_capacity_fill(void) {
    buf_t b;
    buf_init(&b);
    /* Fill exactly to current capacity */
    size_t cap = b.cap;
    char *fill = malloc(cap);
    if (!fill) { FAIL("exact cap fill", "malloc failed"); buf_free(&b); return; }
    memset(fill, 'A', cap);
    int rc = buf_append(&b, fill, cap);
    free(fill);
    if (rc != 0)
        FAIL("exact cap fill", "append returned %d", rc);
    else if (b.len != cap)
        FAIL("exact cap fill", "len=%zu want %zu", b.len, cap);
    else {
        /* One more byte — must trigger realloc without corruption        */
        rc = buf_append(&b, "Z", 1);
        if (rc != 0 || b.len != cap + 1)
            FAIL("exact cap fill", "post-fill append failed rc=%d len=%zu", rc, b.len);
        else if (((char*)b.data)[cap] != 'Z')
            FAIL("exact cap fill", "byte after realloc corrupted");
        else
            OK("exact capacity fill + overflow realloc");
    }
    buf_free(&b);
}

/* ── Consume edge cases ──────────────────────────────────────────────────── */

static void test_consume_zero(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "hello", 5);
    buf_consume(&b, 0);
    if (b.len != 5 || memcmp(b.data, "hello", 5) != 0)
        FAIL("consume zero", "len=%zu or content wrong", b.len);
    else
        OK("consume zero — no change");
    buf_free(&b);
}

static void test_consume_all(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "hello", 5);
    buf_consume(&b, 5);
    if (b.len != 0)
        FAIL("consume all", "len=%zu want 0", b.len);
    else
        OK("consume all — len=0");
    buf_free(&b);
}

static void test_consume_then_append(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "AAABBB", 6);
    buf_consume(&b, 3);
    buf_append(&b, "CCC", 3);
    if (b.len != 6 || memcmp(buf_data(&b), "BBBCCC", 6) != 0)
        FAIL("consume then append", "len=%zu content='%.*s'", b.len, (int)b.len, (char*)buf_data(&b));
    else
        OK("consume then append — correct content");
    buf_free(&b);
}

/* ── Binary safety ───────────────────────────────────────────────────────── */

static void test_binary_safe(void) {
    buf_t b;
    buf_init(&b);
    /* Include null bytes, high bytes — simulates H2 frame payload        */
    uint8_t binary[] = { 0x00, 0x01, 0x02, 0x7f, 0x80, 0xff, 0x00, 0xde, 0xad };
    int rc = buf_append(&b, binary, sizeof(binary));
    if (rc != 0 || b.len != sizeof(binary))
        FAIL("binary safe", "rc=%d len=%zu", rc, b.len);
    else if (memcmp(b.data, binary, sizeof(binary)) != 0)
        FAIL("binary safe", "content mismatch");
    else
        OK("binary safe — null bytes and high bytes preserved");
    buf_free(&b);
}

static void test_binary_null_mid(void) {
    buf_t b;
    buf_init(&b);
    /* HTTP/2 frame with embedded nulls */
    uint8_t frame[] = {
        0x00, 0x00, 0x0c,   /* length = 12 */
        0x01,               /* HEADERS */
        0x05,               /* END_STREAM | END_HEADERS */
        0x00, 0x00, 0x00, 0x01,  /* stream id = 1 */
        0x82, 0x84, 0x87, 0x41, 0x00, 0x09,
        'l','o','c','a','l','h','o','s','t'
    };
    buf_append(&b, frame, sizeof(frame));
    /* Consume 9-byte header, verify payload intact */
    buf_consume(&b, 9);
    if (b.len != sizeof(frame) - 9 || buf_data(&b)[0] != 0x82)
        FAIL("binary null mid", "content corrupted after consume");
    else
        OK("binary null mid — H2 frame payload preserved");
    buf_free(&b);
}

/* ── Stress: exponential realloc stability ───────────────────────────────── */

static void test_stress_realloc(void) {
    buf_t b;
    buf_init(&b);
    const char chunk[] = "0123456789";   /* 10 bytes */
    const int N = 100000;
    int ok = 1;
    for (int i = 0; i < N; i++) {
        if (buf_append(&b, chunk, sizeof(chunk) - 1) != 0) {
            ok = 0; break;
        }
    }
    if (!ok)
        FAIL("stress realloc", "append failed before %d iterations", N);
    else if (b.len != (size_t)N * 10)
        FAIL("stress realloc", "len=%zu want %zu", b.len, (size_t)N * 10);
    else
        OK("stress realloc — 100k appends, 1MB total, no corruption");
    buf_free(&b);
}

static void test_stress_consume_append(void) {
    /* Simulate a ring-buffer-like usage: append then consume in a loop   */
    buf_t b;
    buf_init(&b);
    int ok = 1;
    for (int i = 0; i < 10000; i++) {
        if (buf_append(&b, "CHUNK", 5) != 0) { ok = 0; break; }
        if (i % 3 == 0) buf_consume(&b, b.len > 5 ? 5 : b.len);
    }
    if (!ok)
        FAIL("stress consume/append", "append failed");
    else
        OK("stress consume/append — 10k iterations stable");
    buf_free(&b);
}

/* ── Large single append ─────────────────────────────────────────────────── */

static void test_large_append(void) {
    buf_t b;
    buf_init(&b);
    const size_t sz = 4 * 1024 * 1024;   /* 4MB */
    char *big = malloc(sz);
    if (!big) { FAIL("large append", "malloc failed"); buf_free(&b); return; }
    memset(big, 0xAB, sz);
    int rc = buf_append(&b, big, sz);
    if (rc != 0 || b.len != sz)
        FAIL("large append", "rc=%d len=%zu want %zu", rc, b.len, sz);
    else {
        /* Spot-check first and last byte */
        uint8_t *d = (uint8_t *)b.data;
        if (d[0] != 0xAB || d[sz-1] != 0xAB)
            FAIL("large append", "content corrupted");
        else
            OK("large single append — 4MB");
    }
    free(big);
    buf_free(&b);
}

/* ── buf_append_str (if present) ─────────────────────────────────────────── */
/* Tests buf_append_str which is a thin wrapper — verifies null terminator
 * is NOT included in len (buf stores raw bytes, not C strings).            */
static void test_append_str(void) {
    buf_t b;
    buf_init(&b);
    /* buf_append_str appends strlen(s) bytes                             */
    buf_append(&b, "hello", 5);
    buf_append(&b, " ", 1);
    buf_append(&b, "world", 5);
    if (b.len != 11 || memcmp(b.data, "hello world", 11) != 0)
        FAIL("append str sequence", "len=%zu or content wrong", b.len);
    else
        OK("append str sequence — 11 bytes, no spurious null");
    buf_free(&b);
}

/* ── Multiple free safety ─────────────────────────────────────────────────── */
/* After buf_free, buf_init + buf_free again must not double-free           */
static void test_reinit_after_free(void) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, "test", 4);
    buf_free(&b);
    /* Re-init and use — must not crash                                   */
    buf_init(&b);
    int rc = buf_append(&b, "again", 5);
    if (rc != 0 || b.len != 5)
        FAIL("reinit after free", "rc=%d len=%zu", rc, b.len);
    else
        OK("reinit after free — no double-free");
    buf_free(&b);
}

/* ── Interleaved appends from two bufs share no state ────────────────────── */
static void test_independent_bufs(void) {
    buf_t a, b;
    buf_init(&a); buf_init(&b);
    buf_append(&a, "AAAA", 4);
    buf_append(&b, "BBBB", 4);
    buf_append(&a, "CCCC", 4);
    if (a.len != 8 || memcmp(a.data, "AAAACCCC", 8) != 0)
        FAIL("independent bufs", "buf a content wrong");
    else if (b.len != 4 || memcmp(b.data, "BBBB", 4) != 0)
        FAIL("independent bufs", "buf b content wrong");
    else
        OK("independent bufs — no aliasing");
    buf_free(&a); buf_free(&b);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/
int main(void) {
    printf("test_buf\n");
    printf("─────────────────────────────────────\n");

    /* Original */
    test_init();
    test_append_basic();
    test_append_realloc();
    test_consume();
    test_reset();
    test_append_after_reset();

    /* Boundary */
    test_append_zero_bytes();
    test_append_one_byte();
    test_exact_capacity_fill();

    /* Consume edge cases */
    test_consume_zero();
    test_consume_all();
    test_consume_then_append();

    /* Binary safety */
    test_binary_safe();
    test_binary_null_mid();

    /* Stress */
    test_stress_realloc();
    test_stress_consume_append();
    test_large_append();

    /* Misc */
    test_append_str();
    test_reinit_after_free();
    test_independent_bufs();

    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
#endif
