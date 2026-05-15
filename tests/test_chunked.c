#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "http/response.h"
#include "util/buf.h"

static int buf_contains(const buf_t *b, const char *needle) {
    return memmem(b->data, b->len, needle, strlen(needle)) != NULL;
}
static int buf_not_contains(const buf_t *b, const char *needle) {
    return memmem(b->data, b->len, needle, strlen(needle)) == NULL;
}

static void test_chunk_append_normal(void) {
    buf_t b;
    buf_init(&b);
    int r = http_chunk_append(&b, "Hello", 5);
    assert(r == 0);
    assert(b.len == 10);
    assert(memcmp(b.data, "5\r\nHello\r\n", 10) == 0);
    buf_free(&b);
    printf("  [OK] chunk_append normal\n");
}

static void test_chunk_append_terminator(void) {
    buf_t b;
    buf_init(&b);
    int r = http_chunk_append(&b, NULL, 0);
    assert(r == 0);
    assert(b.len == 5);
    assert(memcmp(b.data, "0\r\n\r\n", 5) == 0);
    buf_free(&b);
    printf("  [OK] chunk_append terminator\n");
}

static void test_chunked_response_no_content_length(void) {
    http_response_t resp;
    http_response_init(&resp);
    http_response_set_status(&resp, 200, "OK");
    resp.chunked = 1;
    http_response_set_body(&resp, "Hello World", 11);

    buf_t out;
    buf_init(&out);
    assert(http_response_serialize(&resp, &out) == 0);

    assert(buf_not_contains(&out, "Content-Length"));
    assert(buf_contains(&out, "Transfer-Encoding: chunked"));

    buf_free(&out);
    http_response_destroy(&resp);
    printf("  [OK] chunked response no Content-Length\n");
}

static void test_chunked_response_body_format(void) {
    http_response_t resp;
    http_response_init(&resp);
    http_response_set_status(&resp, 200, "OK");
    resp.chunked = 1;
    http_response_set_body(&resp, "Hello", 5);

    buf_t out;
    buf_init(&out);
    http_response_serialize(&resp, &out);

    assert(buf_contains(&out, "5\r\nHello\r\n"));
    assert(buf_contains(&out, "0\r\n\r\n"));

    buf_free(&out);
    http_response_destroy(&resp);
    printf("  [OK] chunked body format correct\n");
}

static void test_non_chunked_unchanged(void) {
    http_response_t resp;
    http_response_init(&resp);
    http_response_set_status(&resp, 200, "OK");
    http_response_set_body(&resp, "Hello", 5);

    buf_t out;
    buf_init(&out);
    http_response_serialize(&resp, &out);

    assert(buf_contains(&out, "Content-Length: 5"));
    assert(buf_not_contains(&out, "Transfer-Encoding"));

    buf_free(&out);
    http_response_destroy(&resp);
    printf("  [OK] non-chunked response unchanged\n");
}

static void test_chunked_empty_body(void) {
    http_response_t resp;
    http_response_init(&resp);
    http_response_set_status(&resp, 200, "OK");
    resp.chunked = 1;

    buf_t out;
    buf_init(&out);
    http_response_serialize(&resp, &out);

    assert(buf_contains(&out, "Transfer-Encoding: chunked"));
    assert(buf_not_contains(&out, "Content-Length"));

    buf_free(&out);
    http_response_destroy(&resp);
    printf("  [OK] chunked empty body\n");
}

int main(void) {
    printf("=== test_chunked ===\n");
    test_chunk_append_normal();
    test_chunk_append_terminator();
    test_chunked_response_no_content_length();
    test_chunked_response_body_format();
    test_non_chunked_unchanged();
    test_chunked_empty_body();
    printf("=== ALL PASSED ===\n");
    return 0;
}