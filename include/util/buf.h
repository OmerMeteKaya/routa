#ifndef ROUTA_UTIL_BUF_H
#define ROUTA_UTIL_BUF_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
    size_t off;
} buf_t;

static inline uint8_t *buf_data(const buf_t *b) { return b->data + b->off; }
static inline size_t   buf_len(const buf_t *b)  { return b->len; }
void buf_init(buf_t *b);
int  buf_append(buf_t *b, const void *src, size_t n);
void buf_consume(buf_t *b, size_t n);
void buf_reset(buf_t *b);
void buf_free(buf_t *b);
int buf_append_str(buf_t *b, const char *s);

#endif // ROUTA_UTIL_BUF_H
