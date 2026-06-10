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
    if (b->off > 0 && b->off >= b->cap / 2) {
        memmove(b->data, b->data + b->off, b->len);
        b->off = 0;
    }
    if (b->off + b->len + n > b->cap) {
        size_t new_cap = b->cap == 0 ? 4096 : b->cap * 2;
        while (new_cap < b->off + b->len + n) new_cap *= 2;
        uint8_t *nd = realloc(b->data, new_cap);
        if (!nd) { LOG_ERROR("buf_append: realloc failed"); return -1; }
        b->data = nd;
        b->cap  = new_cap;
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
