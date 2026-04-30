#ifndef ROUTA_UTIL_BUF_H
#define ROUTA_UTIL_BUF_H

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_init(buf_t *b);
int  buf_append(buf_t *b, const void *src, size_t n);
void buf_consume(buf_t *b, size_t n);
void buf_reset(buf_t *b);
void buf_free(buf_t *b);

#endif // ROUTA_UTIL_BUF_H
