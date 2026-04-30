#include "util/buf.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main() {
    buf_t b;
    
    // Test initialization
    buf_init(&b);
    assert(b.len == 0);
    assert(b.cap >= 4096);
    assert(b.data != NULL);
    
    // Test small append
    const char *test1 = "Hello";
    assert(buf_append(&b, test1, strlen(test1)) == 0);
    assert(b.len == 5);
    assert(memcmp(b.data, "Hello", 5) == 0);
    
    // Test append causing realloc
    const char *test2 = " World!";
    assert(buf_append(&b, test2, strlen(test2)) == 0);
    assert(b.len == 12);
    assert(memcmp(b.data, "Hello World!", 12) == 0);
    
    // Test consume
    buf_consume(&b, 6);
    assert(b.len == 6);
    assert(memcmp(b.data, "World!", 6) == 0);
    
    // Test reset
    buf_reset(&b);
    assert(b.len == 0);
    assert(b.cap >= 4096); // Capacity should remain unchanged
    
    // Test append after reset
    const char *test3 = "New data";
    assert(buf_append(&b, test3, strlen(test3)) == 0);
    assert(b.len == 8);
    assert(memcmp(b.data, "New data", 8) == 0);
    
    buf_free(&b);
    
    printf("All buf tests passed.\n");
    return 0;
}
