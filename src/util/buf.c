#define _GNU_SOURCE
#include "util/buf.h"
#include "util/logger.h"
#include <string.h>

#define BUF_INITIAL_CAP 4096

void buf_init(buf_t *b) {
    b->data = malloc(BUF_INITIAL_CAP);
    if (!b->data) {
        LOG_ERROR("Failed to allocate buffer");
        b->len = 0;
        b->cap = 0;
        return;
    }
    b->len = 0;
    b->cap = BUF_INITIAL_CAP;
}

int buf_append(buf_t *b, const void *src, size_t n) {
    if (!b || !src || n == 0) {
        return 0;
    }

    // Check if we need to resize
    if (b->len + n > b->cap) {
        size_t new_cap = b->cap * 2;
        while (new_cap < b->len + n) {
            new_cap *= 2;
        }
        
        uint8_t *new_data = realloc(b->data, new_cap);
        if (!new_data) {
            LOG_ERROR("Failed to reallocate buffer");
            return -1;
        }
        
        b->data = new_data;
        b->cap = new_cap;
    }

    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

void buf_consume(buf_t *b, size_t n) {
    if (!b || n == 0) {
        return;
    }
    
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

void buf_reset(buf_t *b) {
    if (b) {
        b->len = 0;
    }
}

void buf_free(buf_t *b) {
    if (b) {
        free(b->data);
        b->data = NULL;
        b->len = 0;
        b->cap = 0;
    }
}
