#include "http/request.h"
#include "util/buf.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main() {
    // Test 1: Simple GET
    buf_t buf1;
    buf_init(&buf1);
    const char *test1 = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    buf_append(&buf1, test1, strlen(test1));
    
    http_request_t req1;
    size_t consumed1;
    int result1 = http_request_parse(&req1, &buf1, &consumed1);
    assert(result1 == 0); // Success
    assert(req1.method == HTTP_GET);
    assert(strcmp(req1.path, "/") == 0);
    assert(req1.keep_alive == 1); // HTTP/1.1 default
    http_request_free(&req1);
    buf_free(&buf1);
    
    // Test 2: POST with body
    buf_t buf2;
    buf_init(&buf2);
    const char *test2 = "POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    buf_append(&buf2, test2, strlen(test2));
    
    http_request_t req2;
    size_t consumed2;
    int result2 = http_request_parse(&req2, &buf2, &consumed2);
    assert(result2 == 0); // Success
    assert(req2.method == HTTP_POST);
    assert(strcmp(req2.path, "/echo") == 0);
    assert(req2.body_len == 5);
    assert(memcmp(req2.body, "hello", 5) == 0);
    http_request_free(&req2);
    buf_free(&buf2);
    
    // Test 3: Incomplete header
    buf_t buf3;
    buf_init(&buf3);
    const char *test3 = "GET / HTTP/1.1\r\nHost: localhost\r\n";
    buf_append(&buf3, test3, strlen(test3));
    
    http_request_t req3;
    size_t consumed3;
    int result3 = http_request_parse(&req3, &buf3, &consumed3);
    assert(result3 == 1); // Incomplete
    buf_free(&buf3);
    
    // Test 4: Incomplete body
    buf_t buf4;
    buf_init(&buf4);
    const char *test4 = "POST /echo HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel";
    buf_append(&buf4, test4, strlen(test4));
    
    http_request_t req4;
    size_t consumed4;
    int result4 = http_request_parse(&req4, &buf4, &consumed4);
    assert(result4 == 1); // Incomplete
    buf_free(&buf4);
    
    // Test 5: Path traversal
    buf_t buf5;
    buf_init(&buf5);
    const char *test5 = "GET /../etc/passwd HTTP/1.1\r\n\r\n";
    buf_append(&buf5, test5, strlen(test5));
    
    http_request_t req5;
    size_t consumed5;
    int result5 = http_request_parse(&req5, &buf5, &consumed5);
    assert(result5 == -1); // Error - path traversal
    buf_free(&buf5);
    
    // Test 6: HTTP/1.0 without Connection header
    buf_t buf6;
    buf_init(&buf6);
    const char *test6 = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    buf_append(&buf6, test6, strlen(test6));
    
    http_request_t req6;
    size_t consumed6;
    int result6 = http_request_parse(&req6, &buf6, &consumed6);
    assert(result6 == 0); // Success
    assert(req6.method == HTTP_GET);
    assert(strcmp(req6.path, "/") == 0);
    assert(req6.keep_alive == 0); // HTTP/1.0 default
    http_request_free(&req6);
    buf_free(&buf6);
    
    // Test 7: HTTP/1.1 with Connection: close
    buf_t buf7;
    buf_init(&buf7);
    const char *test7 = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    buf_append(&buf7, test7, strlen(test7));
    
    http_request_t req7;
    size_t consumed7;
    int result7 = http_request_parse(&req7, &buf7, &consumed7);
    assert(result7 == 0); // Success
    assert(req7.method == HTTP_GET);
    assert(strcmp(req7.path, "/") == 0);
    assert(req7.keep_alive == 0); // Connection: close
    http_request_free(&req7);
    buf_free(&buf7);
    
    printf("All request tests passed.\n");
    return 0;
}
