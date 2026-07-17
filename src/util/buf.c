#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "util/buf.h"
#include "util/logger.h"
#include <string.h>

#define BUF_INITIAL_CAP 4096

void buf_init(buf_t *b) {
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
    b->off  = 0;
}

int buf_append(buf_t *b, const void *src, size_t n) {
    if (!b || !src || n == 0) return 0;
    /* BUG FIX: the old code compacted (memmove) on EVERY append once
     * b->off crossed cap/2, regardless of whether a realloc was
     * actually needed. Under a slow-drain pattern (e.g. H2 DATA frames
     * appended faster than the socket can absorb them, so b->off creeps
     * up via repeated buf_consume() calls while b->len stays large),
     * this meant every single append -- even a tiny one -- triggered a
     * memmove of potentially hundreds of KB of not-yet-sent data. Over
     * a large response body this degraded to O(n^2) work and dominated
     * CPU time (confirmed via perf: ~70% of samples landed in a single
     * memmove-shaped libc symbol during large-file H2/H2C benchmarks,
     * with H2C ruling out TLS as the cause). Fix: only ever compact
     * when we've confirmed a realloc would otherwise be required --
     * i.e. compaction now pays for itself by avoiding a strictly more
     * expensive allocation, instead of running speculatively on a
     * schedule tied to b->off's position. */
    if (b->off + b->len + n > b->cap) {
        /* First, see if reclaiming the already-consumed prefix (b->off)
         * makes enough room without growing the allocation at all. */
        if (b->off > 0 && b->len + n <= b->cap) {
            memmove(b->data, b->data + b->off, b->len);
            b->off = 0;
        } else {
            size_t new_cap = b->cap == 0 ? 4096 : b->cap * 2;
            while (new_cap < b->off + b->len + n) new_cap *= 2;
            uint8_t *nd = realloc(b->data, new_cap);
            if (!nd) { LOG_ERROR("buf_append: realloc failed"); return -1; }
            b->data = nd;
            b->cap  = new_cap;
        }
    }
    memcpy(b->data + b->off + b->len, src, n);
    b->len += n;
    return 0;
}
int buf_append_str(buf_t *b, const char *s) {
    if (!s) return 0;
    return buf_append(b, s, strlen(s));
}
void buf_consume(buf_t *b, size_t n) {
    if (!b || n == 0) return;
    if (n >= b->len) { b->len = 0; b->off = 0; return; }
    b->off += n;
    b->len -= n;
}
void buf_reset(buf_t *b) {
    if (b) { b->len = 0; b->off = 0; }
}
void buf_free(buf_t *b) {
    if (b) {
        free(b->data);
        b->data = NULL;
        b->len = 0;
        b->cap = 0;
        b->off = 0;
    }
}
