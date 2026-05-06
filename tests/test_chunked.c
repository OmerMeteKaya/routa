//
// Created by mete on 6.05.2026.
//
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "http/response.h"
#include "util/buf.h"

static void test_chunk_append_normal(void) {
    buf_t b;
    buf_init(&b);

    int r = http_chunk_append(&b, "Hello", 5);
    assert(r == 0);
    /* Expected: "5\r\nHello\r\n" */
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
    int r = http_response_serialize(&resp, &out);
    assert(r == 0);

    /* Must NOT contain Content-Length */
    char *s = (char *)out.data;
    assert(strstr(s, "Content-Length") == NULL);

    /* Must contain Transfer-Encoding: chunked */
    assert(strstr(s, "Transfer-Encoding: chunked") != NULL);

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

    char *s = (char *)out.data;

    /* Body section must contain chunk header "5\r\n" */
    assert(strstr(s, "5\r\nHello\r\n") != NULL);

    /* Must end with terminator */
    assert(strstr(s, "0\r\n\r\n") != NULL);

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

    char *s = (char *)out.data;
    assert(strstr(s, "Content-Length: 5") != NULL);
    assert(strstr(s, "Transfer-Encoding") == NULL);

    buf_free(&out);
    http_response_destroy(&resp);
    printf("  [OK] non-chunked response unchanged\n");
}

static void test_chunked_empty_body(void) {
    http_response_t resp;
    http_response_init(&resp);
    http_response_set_status(&resp, 200, "OK");
    resp.chunked = 1;
    /* no body set */

    buf_t out;
    buf_init(&out);
    http_response_serialize(&resp, &out);

    char *s = (char *)out.data;
    assert(strstr(s, "Transfer-Encoding: chunked") != NULL);
    assert(strstr(s, "Content-Length") == NULL);
    /* No chunk data, no terminator — body is NULL, correct behavior */

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