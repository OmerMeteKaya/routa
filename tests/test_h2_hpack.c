#include "http/h2_hpack.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ── Test harness ────────────────────────────────────────────────────────── */
static int g_pass = 0;
static int g_fail = 0;

#define OK(label) do { printf("[OK] %s\n", label); g_pass++; } while(0)
#define FAIL(label, ...) do { \
    printf("[FAIL] %s: ", label); \
    printf(__VA_ARGS__); \
    printf("\n"); \
    g_fail++; \
} while(0)

/* ═══════════════════════════════════════════════════════════════════════════
 * RFC 7541 Appendix C examples — ground truth for decode tests
 * ═══════════════════════════════════════════════════════════════════════════*/

/* C.3.1 — First Request (literal, incremental indexing, no Huffman)
 * Headers: :method GET, :scheme http, :path /, :authority www.example.com
 * Wire bytes from RFC:                                                      */
static const uint8_t rfc_c31[] = {
    0x82, 0x86, 0x84, 0x41, 0x0f,
    'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m'
};

/* C.4.1 — First Request with Huffman encoding
 * Same headers as C.3.1 but Huffman-coded                                   */
static const uint8_t rfc_c41[] = {
    0x82, 0x86, 0x84, 0x41, 0x8c,
    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
};

/* ── Test 1: Static table indexed lookup ─────────────────────────────────── */
static void test_static_indexed(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 1, 1);

    /* 0x82 = indexed, index 2 = :method GET */
    uint8_t wire[] = { 0x82 };
    hpack_header_t headers[8];
    int n = hpack_decode(&ctx, wire, sizeof(wire), headers, 8);

    if (n != 1) { FAIL("static indexed", "got %d headers, want 1", n); goto done; }
    if (strcmp(headers[0].name, ":method") != 0) {
        FAIL("static indexed", "name '%s' want ':method'", headers[0].name);
        goto done;
    }
    if (strcmp(headers[0].value, "GET") != 0) {
        FAIL("static indexed", "value '%s' want 'GET'", headers[0].value);
        goto done;
    }
    OK("static indexed :method GET");
done:
    hpack_headers_free(headers, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

/* ── Test 2: RFC C.3.1 — literal incremental, no Huffman ────────────────── */
static void test_rfc_c31(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);

    hpack_header_t headers[8];
    int n = hpack_decode(&ctx, rfc_c31, sizeof(rfc_c31), headers, 8);

    if (n != 4) { FAIL("RFC C.3.1", "got %d headers, want 4", n); goto done; }

    if (strcmp(headers[0].name,  ":method") != 0 ||
        strcmp(headers[0].value, "GET")     != 0) {
        FAIL("RFC C.3.1", ":method mismatch"); goto done;
    }
    if (strcmp(headers[1].name,  ":scheme") != 0 ||
        strcmp(headers[1].value, "http")    != 0) {
        FAIL("RFC C.3.1", ":scheme mismatch"); goto done;
    }
    if (strcmp(headers[2].name,  ":path") != 0 ||
        strcmp(headers[2].value, "/")     != 0) {
        FAIL("RFC C.3.1", ":path mismatch"); goto done;
    }
    if (strcmp(headers[3].name,  ":authority")       != 0 ||
        strcmp(headers[3].value, "www.example.com")  != 0) {
        FAIL("RFC C.3.1", ":authority mismatch"); goto done;
    }

    /* Dynamic table should now have 1 entry (:authority www.example.com) */
    if (ctx.table.count != 1) {
        FAIL("RFC C.3.1", "dyntab count %zu want 1", ctx.table.count);
        goto done;
    }
    OK("RFC C.3.1 four headers + dyntab entry");
done:
    hpack_headers_free(headers, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

/* ── Test 3: RFC C.4.1 — Huffman decode ─────────────────────────────────── */
static void test_rfc_c41_huffman(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 1, 1);

    hpack_header_t headers[8];
    int n = hpack_decode(&ctx, rfc_c41, sizeof(rfc_c41), headers, 8);

    if (n != 4) { FAIL("RFC C.4.1", "got %d headers, want 4", n); goto done; }
    if (strcmp(headers[3].value, "www.example.com") != 0) {
        FAIL("RFC C.4.1", "authority '%s' want 'www.example.com'",
             headers[3].value);
        goto done;
    }
    OK("RFC C.4.1 Huffman decode www.example.com");
done:
    hpack_headers_free(headers, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

/* ── Test 4: Dynamic table eviction ─────────────────────────────────────── */
static void test_dyntab_eviction(void) {
    hpack_ctx_t ctx;
    /* Small table — forces eviction */
    hpack_ctx_init(&ctx, 64, 0, 1);

    /* Encode two headers that together exceed table size */
    hpack_header_t h[2] = {
        { "x-foo", "aaaaaaaaaaaaaaaa" },   /* 5+16+32 = 53 bytes */
        { "x-bar", "bbbbbbbbbbbbbbbb" },   /* 5+16+32 = 53 bytes */
    };

    uint8_t wire[256];
    /* Encode with dynamic_table_update=1 so decode will add to table */
    hpack_ctx_t enc;
    hpack_ctx_init(&enc, 64, 0, 1);
    int wlen = hpack_encode(&enc, h, 2, wire, sizeof(wire));
    hpack_ctx_free(&enc);

    if (wlen < 0) { FAIL("dyntab eviction", "encode failed"); goto done; }

    hpack_header_t out[8];
    int n = hpack_decode(&ctx, wire, (size_t)wlen, out, 8);
    if (n != 2) { FAIL("dyntab eviction", "got %d headers want 2", n); goto done; }

    /* Table should have evicted x-foo, only x-bar remains */
    if (ctx.table.count != 1) {
        FAIL("dyntab eviction", "table count %zu want 1", ctx.table.count);
        goto done;
    }
    OK("dynamic table eviction");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

/* ── Test 5: Encode → Decode roundtrip ──────────────────────────────────── */
static void test_roundtrip(void) {
    hpack_header_t in[] = {
        { ":method",    "GET"             },
        { ":path",      "/api/v1/users"   },
        { ":scheme",    "https"           },
        { ":authority", "api.example.com" },
        { "content-type", "application/json" },
        { "x-custom",   "hello-world"     },
    };
    int in_count = 6;

    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 1, 1);
    hpack_ctx_init(&dec, 4096, 1, 1);

    uint8_t wire[1024];
    int wlen = hpack_encode(&enc, in, in_count, wire, sizeof(wire));
    if (wlen < 0) { FAIL("roundtrip", "encode failed"); goto done; }

    hpack_header_t out[16];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 16);
    if (n != in_count) {
        FAIL("roundtrip", "got %d headers want %d", n, in_count);
        goto done;
    }

    for (int i = 0; i < in_count; i++) {
        if (strcmp(in[i].name, out[i].name) != 0 ||
            strcmp(in[i].value, out[i].value) != 0) {
            FAIL("roundtrip", "header %d mismatch: got %s:%s want %s:%s",
                 i, out[i].name, out[i].value, in[i].name, in[i].value);
            goto done;
        }
    }
    OK("encode → decode roundtrip (6 headers, Huffman on)");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc);
    hpack_ctx_free(&dec);
}

/* ── Test 6: Roundtrip Huffman kapalı ───────────────────────────────────── */
static void test_roundtrip_no_huffman(void) {
    hpack_header_t in[] = {
        { ":status",      "200"        },
        { "content-type", "text/plain" },
        { "x-trace-id",   "abc123"     },
    };

    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 0, 1);   /* huffman off */
    hpack_ctx_init(&dec, 4096, 0, 1);

    uint8_t wire[512];
    int wlen = hpack_encode(&enc, in, 3, wire, sizeof(wire));
    if (wlen < 0) { FAIL("roundtrip no-huffman", "encode failed"); goto done; }

    hpack_header_t out[8];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 8);
    if (n != 3) { FAIL("roundtrip no-huffman", "got %d want 3", n); goto done; }

    for (int i = 0; i < 3; i++) {
        if (strcmp(in[i].name, out[i].name) != 0 ||
            strcmp(in[i].value, out[i].value) != 0) {
            FAIL("roundtrip no-huffman", "header %d mismatch", i);
            goto done;
        }
    }
    OK("encode → decode roundtrip (Huffman off)");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc);
    hpack_ctx_free(&dec);
}

/* ── Test 7: dynamic table resize ───────────────────────────────────────── */
static void test_dyntab_resize(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);

    hpack_header_t h[] = {
        { "x-a", "val1" }, { "x-b", "val2" }, { "x-c", "val3" },
    };
    hpack_ctx_t enc;
    hpack_ctx_init(&enc, 4096, 0, 1);
    uint8_t wire[512];
    int wlen = hpack_encode(&enc, h, 3, wire, sizeof(wire));
    hpack_ctx_free(&enc);
    if (wlen < 0) { FAIL("dyntab resize", "encode failed"); return; }

    hpack_header_t out[8];
    int n = hpack_decode(&ctx, wire, (size_t)wlen, out, 8);
    hpack_headers_free(out, n < 0 ? 0 : n);

    size_t before = ctx.table.count;

    /* Shrink table — should evict entries */
    hpack_dynamic_table_resize(&ctx, 0);

    if (ctx.table.count != 0) {
        FAIL("dyntab resize", "after resize to 0: count %zu want 0",
             ctx.table.count);
    } else {
        OK("dynamic table resize to 0 evicts all");
    }
    (void)before;
    hpack_ctx_free(&ctx);
}

/* ── Test 8: Malformed input ─────────────────────────────────────────────── */
static void test_malformed(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);

    /* Index 0 — invalid per RFC */
    uint8_t bad_idx[] = { 0x80 };
    hpack_header_t out[4];
    int n = hpack_decode(&ctx, bad_idx, sizeof(bad_idx), out, 4);
    if (n >= 0) {
        FAIL("malformed index 0", "expected error, got %d", n);
    } else {
        OK("malformed: index 0 rejected");
    }

    /* Truncated string length */
    uint8_t truncated[] = { 0x40, 0x0f };  /* literal, name length=15 but no data */
    n = hpack_decode(&ctx, truncated, sizeof(truncated), out, 4);
    if (n >= 0) {
        FAIL("malformed truncated", "expected error, got %d", n);
    } else {
        OK("malformed: truncated string rejected");
    }

    hpack_ctx_free(&ctx);
}

/* ── Test 9: dynamic_table_update=0 encode, hiç dyntab yazılmamalı ──────── */
static void test_no_dyntab_write(void) {
    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 1, 0);   /* dynamic_table_update off */
    hpack_ctx_init(&dec, 4096, 1, 0);

    hpack_header_t in[] = {
        { "x-custom", "value" },
        { "x-other",  "data"  },
    };
    uint8_t wire[256];
    int wlen = hpack_encode(&enc, in, 2, wire, sizeof(wire));
    if (wlen < 0) { FAIL("no dyntab write", "encode failed"); goto done; }

    if (enc.table.count != 0) {
        FAIL("no dyntab write", "encoder wrote to dyntab: count=%zu",
             enc.table.count);
        goto done;
    }

    hpack_header_t out[8];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 8);
    if (n != 2) { FAIL("no dyntab write", "decode got %d want 2", n); goto done; }
    OK("dynamic_table_update=0 encoder does not write to table");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc);
    hpack_ctx_free(&dec);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/
int main(void) {
    printf("test_h2_hpack\n");
    printf("─────────────────────────────────────\n");

    test_static_indexed();
    test_rfc_c31();
    test_rfc_c41_huffman();
    test_dyntab_eviction();
    test_roundtrip();
    test_roundtrip_no_huffman();
    test_dyntab_resize();
    test_malformed();
    test_no_dyntab_write();

    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}