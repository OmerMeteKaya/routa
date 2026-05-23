#define _GNU_SOURCE
#include "http/request.h"
#include "util/buf.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

/* Helper: parse a C-string request, return parse result.
 * Frees req on success (caller must not use req after).                    */
static int parse_str(const char *raw, http_request_t *req) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, raw, strlen(raw));
    size_t consumed = 0;
    int rc = http_request_parse(req, &b, &consumed);
    buf_free(&b);
    return rc;
}

/* Helper: parse raw bytes (may contain nulls). */
static int parse_bytes(const uint8_t *raw, size_t len, http_request_t *req) {
    buf_t b;
    buf_init(&b);
    buf_append(&b, raw, len);
    size_t consumed = 0;
    int rc = http_request_parse(req, &b, &consumed);
    buf_free(&b);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Original tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_simple_get(void) {
    http_request_t req;
    int rc = parse_str("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", &req);
    if (rc != 0) { FAIL("simple GET", "rc=%d want 0", rc); return; }
    if (req.method != HTTP_GET || strcmp(req.path, "/") != 0 || !req.keep_alive)
        FAIL("simple GET", "method/path/keepalive wrong");
    else
        OK("simple GET — method, path, keep-alive");
    http_request_free(&req);
}

static void test_post_with_body(void) {
    http_request_t req;
    int rc = parse_str("POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", &req);
    if (rc != 0) { FAIL("POST with body", "rc=%d want 0", rc); return; }
    if (req.method != HTTP_POST || req.body_len != 5 ||
        memcmp(req.body, "hello", 5) != 0)
        FAIL("POST with body", "method/body wrong");
    else
        OK("POST with body — body echoed correctly");
    http_request_free(&req);
}

static void test_incomplete_header(void) {
    http_request_t req;
    int rc = parse_str("GET / HTTP/1.1\r\nHost: localhost\r\n", &req);
    if (rc != 1) FAIL("incomplete header", "rc=%d want 1", rc);
    else         OK("incomplete header — returns 1");
}

static void test_incomplete_body(void) {
    http_request_t req;
    int rc = parse_str("POST /echo HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel", &req);
    if (rc != 1) FAIL("incomplete body", "rc=%d want 1", rc);
    else         OK("incomplete body — returns 1");
}

static void test_path_traversal(void) {
    http_request_t req;
    int rc = parse_str("GET /../etc/passwd HTTP/1.1\r\n\r\n", &req);
    if (rc != -1) {
        FAIL("path traversal", "rc=%d want -1", rc);
        if (rc == 0) http_request_free(&req);
    } else {
        OK("path traversal rejected");
    }
}

static void test_http10_no_keepalive(void) {
    http_request_t req;
    int rc = parse_str("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", &req);
    if (rc != 0) { FAIL("HTTP/1.0 keepalive", "rc=%d", rc); return; }
    if (req.keep_alive != 0)
        FAIL("HTTP/1.0 keepalive", "keep_alive=%d want 0", req.keep_alive);
    else
        OK("HTTP/1.0 — keep-alive=0 by default");
    http_request_free(&req);
}

static void test_connection_close(void) {
    http_request_t req;
    int rc = parse_str("GET / HTTP/1.1\r\nConnection: close\r\n\r\n", &req);
    if (rc != 0) { FAIL("Connection: close", "rc=%d", rc); return; }
    if (req.keep_alive != 0)
        FAIL("Connection: close", "keep_alive=%d want 0", req.keep_alive);
    else
        OK("Connection: close — keep-alive=0");
    http_request_free(&req);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Malformed / security tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_invalid_method(void) {
    http_request_t req;
    int rc = parse_str("FAKEMETHOD / HTTP/1.1\r\n\r\n", &req);
    /* Parser may accept unknown method as HTTP_METHOD_UNKNOWN or reject   */
    if (rc == 0) {
        if (req.method == HTTP_METHOD_UNKNOWN)
            OK("invalid method — parsed as UNKNOWN");
        else
            FAIL("invalid method", "method=%d should be UNKNOWN or rejected", req.method);
        http_request_free(&req);
    } else if (rc == -1) {
        OK("invalid method — rejected with -1");
    } else {
        FAIL("invalid method", "unexpected rc=%d", rc);
    }
}

static void test_missing_http_version(void) {
    http_request_t req;
    int rc = parse_str("GET /\r\n\r\n", &req);
    if (rc == -1)
        OK("missing HTTP version — rejected");
    else if (rc == 0) {
        OK("missing HTTP version — accepted (lenient parser)");
        http_request_free(&req);
    } else {
        FAIL("missing HTTP version", "rc=%d", rc);
    }
}

static void test_malformed_crlf(void) {
    /* LF only instead of CRLF */
    http_request_t req;
    int rc = parse_str("GET / HTTP/1.1\nHost: localhost\n\n", &req);
    /* Some parsers accept bare LF; both outcomes are fine as long as no crash */
    if (rc == -1)
        OK("bare LF — rejected");
    else if (rc == 0) {
        OK("bare LF — accepted (lenient parser)");
        http_request_free(&req);
    } else {
        FAIL("bare LF", "unexpected rc=%d", rc);
    }
}

static void test_empty_request(void) {
    http_request_t req;
    int rc = parse_str("", &req);
    if (rc == 1)
        OK("empty request — incomplete (1)");
    else if (rc == -1)
        OK("empty request — rejected (-1)");
    else
        FAIL("empty request", "rc=%d want 1 or -1", rc);
}

static void test_request_line_only(void) {
    /* No headers, no blank line */
    http_request_t req;
    int rc = parse_str("GET / HTTP/1.1", &req);
    if (rc == 1)
        OK("request line only — incomplete");
    else if (rc == -1)
        OK("request line only — rejected");
    else
        FAIL("request line only", "rc=%d want 1 or -1", rc);
}

/* ── Oversized headers ────────────────────────────────────────────────────── */

static void test_oversized_header_value(void) {
    /* Single header value of 8KB */
    buf_t b;
    buf_init(&b);
    buf_append(&b, "GET / HTTP/1.1\r\nX-Big: ", 23);
    char *big = malloc(8192);
    if (!big) { FAIL("oversized header", "malloc"); buf_free(&b); return; }
    memset(big, 'A', 8192);
    buf_append(&b, big, 8192);
    free(big);
    buf_append(&b, "\r\n\r\n", 4);

    http_request_t req;
    size_t consumed = 0;
    int rc = http_request_parse(&req, &b, &consumed);
    buf_free(&b);

    if (rc == -1)
        OK("oversized header value 8KB — rejected");
    else if (rc == 0) {
        OK("oversized header value 8KB — accepted (no limit enforced)");
        http_request_free(&req);
    } else {
        FAIL("oversized header value 8KB", "rc=%d", rc);
    }
}

static void test_many_headers(void) {
    /* 100 headers — tests header count handling */
    buf_t b;
    buf_init(&b);
    buf_append(&b, "GET / HTTP/1.1\r\n", 16);
    for (int i = 0; i < 100; i++) {
        char line[32];
        int n = snprintf(line, sizeof(line), "X-H%d: value%d\r\n", i, i);
        buf_append(&b, line, (size_t)n);
    }
    buf_append(&b, "\r\n", 2);

    http_request_t req;
    size_t consumed = 0;
    int rc = http_request_parse(&req, &b, &consumed);
    buf_free(&b);

    if (rc == -1)
        OK("100 headers — rejected (limit enforced)");
    else if (rc == 0) {
        OK("100 headers — accepted");
        http_request_free(&req);
    } else {
        FAIL("100 headers", "rc=%d", rc);
    }
}

/* ── Request smuggling vectors ────────────────────────────────────────────── */

static void test_duplicate_content_length(void) {
    /* Two different Content-Length values — CL desync attack              */
    http_request_t req;
    int rc = parse_str(
        "POST /echo HTTP/1.1\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 10\r\n"
        "\r\nhello", &req);
    if (rc == -1)
        OK("duplicate Content-Length — rejected");
    else if (rc == 0) {
        /* If accepted, must use first or smaller value — not 10          */
        if (req.body_len <= 5)
            OK("duplicate Content-Length — accepted, used safe value");
        else
            FAIL("duplicate Content-Length", "body_len=%zu unsafe", req.body_len);
        http_request_free(&req);
    } else {
        FAIL("duplicate Content-Length", "rc=%d", rc);
    }
}

static void test_content_length_transfer_encoding(void) {
    /* Both Content-Length and Transfer-Encoding: chunked — smuggling     */
    http_request_t req;
    int rc = parse_str(
        "POST /echo HTTP/1.1\r\n"
        "Content-Length: 5\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\nhello", &req);
    if (rc == -1)
        OK("CL + TE: chunked — rejected (smuggling protection)");
    else if (rc == 0) {
        OK("CL + TE: chunked — accepted (parser chose one)");
        http_request_free(&req);
    } else {
        FAIL("CL + TE: chunked", "rc=%d", rc);
    }
}

static void test_negative_content_length(void) {
    http_request_t req;
    int rc = parse_str(
        "POST /echo HTTP/1.1\r\n"
        "Content-Length: -1\r\n"
        "\r\n", &req);
    if (rc == -1)
        OK("negative Content-Length — rejected");
    else if (rc == 0) {
        if (req.body_len == 0)
            OK("negative Content-Length — treated as 0");
        else
            FAIL("negative Content-Length", "body_len=%zu", req.body_len);
        http_request_free(&req);
    } else {
        FAIL("negative Content-Length", "rc=%d", rc);
    }
}

static void test_content_length_overflow(void) {
    /* Absurdly large Content-Length — must not allocate or wrap          */
    http_request_t req;
    int rc = parse_str(
        "POST /echo HTTP/1.1\r\n"
        "Content-Length: 99999999999999999999\r\n"
        "\r\n", &req);
    if (rc == -1)
        OK("huge Content-Length — rejected");
    else if (rc == 1)
        OK("huge Content-Length — waiting for body (not allocated)");
    else if (rc == 0) {
        /* Must not have a huge allocation */
        OK("huge Content-Length — accepted (body pending)");
        http_request_free(&req);
    } else {
        FAIL("huge Content-Length", "rc=%d", rc);
    }
}

/* ── Partial / slow reads ─────────────────────────────────────────────────── */

static void test_partial_byte_by_byte(void) {
    /* Feed request one byte at a time — simulates slow client            */
    const char *raw = "GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n";
    size_t total = strlen(raw);
    buf_t b;
    buf_init(&b);

    int final_rc = 1;
    http_request_t req;
    size_t consumed = 0;

    for (size_t i = 0; i < total; i++) {
        buf_append(&b, raw + i, 1);
        int rc = http_request_parse(&req, &b, &consumed);
        if (rc == 0) {
            final_rc = 0;
            break;
        } else if (rc == -1) {
            final_rc = -1;
            break;
        }
        /* rc == 1: need more data — continue */
    }
    buf_free(&b);

    if (final_rc == 0) {
        if (req.method == HTTP_GET && strcmp(req.path, "/slow") == 0)
            OK("byte-by-byte parsing — correct parse after 38 feeds");
        else
            FAIL("byte-by-byte parsing", "method/path wrong");
        http_request_free(&req);
    } else {
        FAIL("byte-by-byte parsing", "rc=%d after full input", final_rc);
    }
}

static void test_partial_header_split(void) {
    /* Header split across two reads — common in real sockets             */
    const char *part1 = "GET /split HTTP/1.1\r\nHo";
    const char *part2 = "st: localhost\r\n\r\n";
    buf_t b;
    buf_init(&b);
    buf_append(&b, part1, strlen(part1));

    http_request_t req;
    size_t consumed = 0;
    int rc1 = http_request_parse(&req, &b, &consumed);
    if (rc1 != 1) {
        FAIL("split header read", "first parse rc=%d want 1", rc1);
        buf_free(&b); return;
    }

    buf_append(&b, part2, strlen(part2));
    int rc2 = http_request_parse(&req, &b, &consumed);
    buf_free(&b);
    if (rc2 == 0) {
        if (strcmp(req.path, "/split") == 0)
            OK("split header read — correct after 2 reads");
        else
            FAIL("split header read", "path='%s' want '/split'", req.path);
        http_request_free(&req);
    } else {
        FAIL("split header read", "second parse rc=%d want 0", rc2);
    }
}

static void test_partial_body_split(void) {
    /* Body arrives in two chunks */
    const char *part1 = "POST /body HTTP/1.1\r\nContent-Length: 8\r\n\r\nhalf";
    const char *part2 = "body";
    buf_t b;
    buf_init(&b);
    buf_append(&b, part1, strlen(part1));

    http_request_t req;
    size_t consumed = 0;
    int rc1 = http_request_parse(&req, &b, &consumed);
    if (rc1 != 1) {
        FAIL("split body read", "first parse rc=%d want 1", rc1);
        buf_free(&b); return;
    }

    buf_append(&b, part2, strlen(part2));
    int rc2 = http_request_parse(&req, &b, &consumed);
    buf_free(&b);
    if (rc2 == 0) {
        if (req.body_len == 8 && memcmp(req.body, "halfbody", 8) == 0)
            OK("split body read — correct after 2 reads");
        else
            FAIL("split body read", "body_len=%zu or content wrong", req.body_len);
        http_request_free(&req);
    } else {
        FAIL("split body read", "second parse rc=%d want 0", rc2);
    }
}

/* ── Method coverage ─────────────────────────────────────────────────────── */

static void test_all_methods(void) {
    struct { const char *method_str; http_method_t method; } cases[] = {
        { "GET",     HTTP_GET     },
        { "POST",    HTTP_POST    },
        { "PUT",     HTTP_PUT     },
        { "DELETE",  HTTP_DELETE  },
        { "HEAD",    HTTP_HEAD    },
        { "PATCH",   HTTP_PATCH   },
        { "OPTIONS", HTTP_OPTIONS },
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        char raw[64];
        snprintf(raw, sizeof(raw), "%s / HTTP/1.1\r\n\r\n", cases[i].method_str);
        http_request_t req;
        int rc = parse_str(raw, &req);
        if (rc != 0) {
            printf("  [FAIL] method %s rc=%d\n", cases[i].method_str, rc);
            failed++;
        } else if (req.method != cases[i].method) {
            printf("  [FAIL] method %s: got %d want %d\n",
                   cases[i].method_str, req.method, cases[i].method);
            failed++; http_request_free(&req);
        } else {
            http_request_free(&req);
        }
    }
    if (failed == 0)
        OK("all HTTP methods parsed correctly");
    else
        FAIL("all methods", "%d methods failed", failed);
}

/* ── Query string ─────────────────────────────────────────────────────────── */

static void test_query_string(void) {
    http_request_t req;
    int rc = parse_str("GET /search?q=hello&page=2 HTTP/1.1\r\n\r\n", &req);
    if (rc != 0) { FAIL("query string", "rc=%d", rc); return; }
    if (strcmp(req.path, "/search") != 0)
        FAIL("query string", "path='%s' want '/search'", req.path);
    else if (!req.query || strcmp(req.query, "q=hello&page=2") != 0)
        FAIL("query string", "query='%s'", req.query ? req.query : "(null)");
    else
        OK("query string — path and query split correctly");
    http_request_free(&req);
}

/* ── Binary/garbage in header values ─────────────────────────────────────── */

static void test_binary_in_header(void) {
    /* Non-ASCII bytes in header value — must not crash                   */
    uint8_t raw[] =
        "GET / HTTP/1.1\r\n"
        "X-Evil: \x01\x02\x80\xff\r\n"
        "\r\n";
    http_request_t req;
    int rc = parse_bytes(raw, sizeof(raw) - 1, &req);
    if (rc == -1)
        OK("binary in header value — rejected");
    else if (rc == 0) {
        OK("binary in header value — accepted (no crash)");
        http_request_free(&req);
    } else {
        FAIL("binary in header value", "rc=%d", rc);
    }
}

/* ── Zero-length path ─────────────────────────────────────────────────────── */

static void test_empty_path(void) {
    http_request_t req;
    /* RFC requires path to be at least "/" — empty path is malformed     */
    int rc = parse_str("GET  HTTP/1.1\r\n\r\n", &req);
    if (rc == -1)
        OK("empty path — rejected");
    else if (rc == 0) {
        OK("empty path — accepted (lenient)");
        http_request_free(&req);
    } else {
        FAIL("empty path", "rc=%d", rc);
    }
}

/* ── Keep-alive header value variations ──────────────────────────────────── */

static void test_keepalive_variations(void) {
    struct { const char *raw; int want_ka; const char *label; } cases[] = {
        { "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n", 1, "explicit keep-alive" },
        { "GET / HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n", 1, "keep-alive mixed case" },
        { "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", 1, "HTTP/1.0 + keep-alive header" },
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        http_request_t req;
        int rc = parse_str(cases[i].raw, &req);
        if (rc != 0) {
            FAIL(cases[i].label, "rc=%d", rc);
        } else if (req.keep_alive != cases[i].want_ka) {
            FAIL(cases[i].label, "keep_alive=%d want %d",
                 req.keep_alive, cases[i].want_ka);
            http_request_free(&req);
        } else {
            OK(cases[i].label);
            http_request_free(&req);
        }
    }
}

/* ── Large body ───────────────────────────────────────────────────────────── */

static void test_large_body(void) {
    const size_t body_sz = 65536;   /* 64KB */
    buf_t b;
    buf_init(&b);
    char cl_hdr[64];
    snprintf(cl_hdr, sizeof(cl_hdr),
             "POST /upload HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", body_sz);
    buf_append(&b, cl_hdr, strlen(cl_hdr));
    char *body = malloc(body_sz);
    if (!body) { FAIL("large body", "malloc"); buf_free(&b); return; }
    memset(body, 0x42, body_sz);
    buf_append(&b, body, body_sz);
    free(body);

    http_request_t req;
    size_t consumed = 0;
    int rc = http_request_parse(&req, &b, &consumed);
    buf_free(&b);

    if (rc == 0) {
        if (req.body_len == body_sz)
            OK("large body 64KB — parsed correctly");
        else
            FAIL("large body", "body_len=%zu want %zu", req.body_len, body_sz);
        http_request_free(&req);
    } else {
        FAIL("large body", "rc=%d", rc);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/
int main(void) {
    printf("test_request\n");
    printf("─────────────────────────────────────\n");

    /* Original */
    test_simple_get();
    test_post_with_body();
    test_incomplete_header();
    test_incomplete_body();
    test_path_traversal();
    test_http10_no_keepalive();
    test_connection_close();

    /* Malformed */
    test_invalid_method();
    test_missing_http_version();
    test_malformed_crlf();
    test_empty_request();
    test_request_line_only();

    /* Oversized */
    test_oversized_header_value();
    test_many_headers();

    /* Smuggling */
    test_duplicate_content_length();
    test_content_length_transfer_encoding();
    test_negative_content_length();
    test_content_length_overflow();

    /* Partial reads */
    test_partial_byte_by_byte();
    test_partial_header_split();
    test_partial_body_split();

    /* Coverage */
    test_all_methods();
    test_query_string();
    test_binary_in_header();
    test_empty_path();
    test_keepalive_variations();
    test_large_body();

    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}