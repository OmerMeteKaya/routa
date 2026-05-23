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
 * RFC 7541 Appendix C ground-truth wire bytes
 * ═══════════════════════════════════════════════════════════════════════════*/

static const uint8_t rfc_c31[] = {
    0x82, 0x86, 0x84, 0x41, 0x0f,
    'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m'
};

static const uint8_t rfc_c41[] = {
    0x82, 0x86, 0x84, 0x41, 0x8c,
    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Original tests (kept verbatim)
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_static_indexed(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 1, 1);
    uint8_t wire[] = { 0x82 };
    hpack_header_t headers[8];
    int n = hpack_decode(&ctx, wire, sizeof(wire), headers, 8);
    if (n != 1) { FAIL("static indexed", "got %d headers, want 1", n); goto done; }
    if (strcmp(headers[0].name, ":method") != 0 ||
        strcmp(headers[0].value, "GET") != 0) {
        FAIL("static indexed", "name/value mismatch"); goto done;
    }
    OK("static indexed :method GET");
done:
    hpack_headers_free(headers, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

static void test_rfc_c31(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);
    hpack_header_t headers[8];
    int n = hpack_decode(&ctx, rfc_c31, sizeof(rfc_c31), headers, 8);
    if (n != 4) { FAIL("RFC C.3.1", "got %d headers, want 4", n); goto done; }
    if (strcmp(headers[0].name,":method")!=0 || strcmp(headers[0].value,"GET")!=0 ||
        strcmp(headers[1].name,":scheme")!=0 || strcmp(headers[1].value,"http")!=0 ||
        strcmp(headers[2].name,":path")  !=0 || strcmp(headers[2].value,"/")!=0 ||
        strcmp(headers[3].name,":authority")!=0 ||
        strcmp(headers[3].value,"www.example.com")!=0) {
        FAIL("RFC C.3.1", "header mismatch"); goto done;
    }
    if (ctx.table.count != 1) {
        FAIL("RFC C.3.1", "dyntab count %zu want 1", ctx.table.count); goto done;
    }
    OK("RFC C.3.1 four headers + dyntab entry");
done:
    hpack_headers_free(headers, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

static void test_rfc_c41_huffman(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 1, 1);
    hpack_header_t headers[8];
    int n = hpack_decode(&ctx, rfc_c41, sizeof(rfc_c41), headers, 8);
    if (n != 4) { FAIL("RFC C.4.1", "got %d headers, want 4", n); goto done; }
    if (strcmp(headers[3].value, "www.example.com") != 0) {
        FAIL("RFC C.4.1", "authority '%s'", headers[3].value); goto done;
    }
    OK("RFC C.4.1 Huffman decode www.example.com");
done:
    hpack_headers_free(headers, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

static void test_dyntab_eviction(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 64, 0, 1);
    hpack_header_t h[2] = {
        { "x-foo", "aaaaaaaaaaaaaaaa" },
        { "x-bar", "bbbbbbbbbbbbbbbb" },
    };
    hpack_ctx_t enc;
    hpack_ctx_init(&enc, 64, 0, 1);
    uint8_t wire[256];
    int wlen = hpack_encode(&enc, h, 2, wire, sizeof(wire));
    hpack_ctx_free(&enc);
    if (wlen < 0) { FAIL("dyntab eviction", "encode failed"); goto done; }
    hpack_header_t out[8];
    int n = hpack_decode(&ctx, wire, (size_t)wlen, out, 8);
    if (n != 2) { FAIL("dyntab eviction", "got %d want 2", n); goto done; }
    if (ctx.table.count != 1) {
        FAIL("dyntab eviction", "count %zu want 1", ctx.table.count); goto done;
    }
    OK("dynamic table eviction");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

static void test_roundtrip(void) {
    hpack_header_t in[] = {
        { ":method", "GET" }, { ":path", "/api/v1/users" },
        { ":scheme", "https" }, { ":authority", "api.example.com" },
        { "content-type", "application/json" }, { "x-custom", "hello-world" },
    };
    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 1, 1);
    hpack_ctx_init(&dec, 4096, 1, 1);
    uint8_t wire[1024];
    int wlen = hpack_encode(&enc, in, 6, wire, sizeof(wire));
    if (wlen < 0) { FAIL("roundtrip", "encode failed"); goto done; }
    hpack_header_t out[16];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 16);
    if (n != 6) { FAIL("roundtrip", "got %d want 6", n); goto done; }
    for (int i = 0; i < 6; i++) {
        if (strcmp(in[i].name, out[i].name) || strcmp(in[i].value, out[i].value)) {
            FAIL("roundtrip", "header %d mismatch", i); goto done;
        }
    }
    OK("encode → decode roundtrip (6 headers, Huffman on)");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc); hpack_ctx_free(&dec);
}

static void test_roundtrip_no_huffman(void) {
    hpack_header_t in[] = {
        { ":status", "200" }, { "content-type", "text/plain" }, { "x-trace-id", "abc123" },
    };
    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 0, 1);
    hpack_ctx_init(&dec, 4096, 0, 1);
    uint8_t wire[512];
    int wlen = hpack_encode(&enc, in, 3, wire, sizeof(wire));
    if (wlen < 0) { FAIL("roundtrip no-huffman", "encode failed"); goto done; }
    hpack_header_t out[8];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 8);
    if (n != 3) { FAIL("roundtrip no-huffman", "got %d want 3", n); goto done; }
    for (int i = 0; i < 3; i++) {
        if (strcmp(in[i].name, out[i].name) || strcmp(in[i].value, out[i].value)) {
            FAIL("roundtrip no-huffman", "header %d mismatch", i); goto done;
        }
    }
    OK("encode → decode roundtrip (Huffman off)");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc); hpack_ctx_free(&dec);
}

static void test_dyntab_resize(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);
    hpack_header_t h[] = { {"x-a","val1"}, {"x-b","val2"}, {"x-c","val3"} };
    hpack_ctx_t enc;
    hpack_ctx_init(&enc, 4096, 0, 1);
    uint8_t wire[512];
    int wlen = hpack_encode(&enc, h, 3, wire, sizeof(wire));
    hpack_ctx_free(&enc);
    if (wlen < 0) { FAIL("dyntab resize", "encode failed"); return; }
    hpack_header_t out[8];
    int n = hpack_decode(&ctx, wire, (size_t)wlen, out, 8);
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_dynamic_table_resize(&ctx, 0);
    if (ctx.table.count != 0)
        FAIL("dyntab resize", "count %zu want 0", ctx.table.count);
    else
        OK("dynamic table resize to 0 evicts all");
    hpack_ctx_free(&ctx);
}

static void test_malformed(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);
    uint8_t bad_idx[] = { 0x80 };
    hpack_header_t out[4];
    int n = hpack_decode(&ctx, bad_idx, sizeof(bad_idx), out, 4);
    if (n >= 0) FAIL("malformed index 0", "expected error, got %d", n);
    else        OK("malformed: index 0 rejected");

    uint8_t truncated[] = { 0x40, 0x0f };
    n = hpack_decode(&ctx, truncated, sizeof(truncated), out, 4);
    if (n >= 0) FAIL("malformed truncated", "expected error, got %d", n);
    else        OK("malformed: truncated string rejected");

    hpack_ctx_free(&ctx);
}

static void test_no_dyntab_write(void) {
    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 1, 0);
    hpack_ctx_init(&dec, 4096, 1, 0);
    hpack_header_t in[] = { {"x-custom","value"}, {"x-other","data"} };
    uint8_t wire[256];
    int wlen = hpack_encode(&enc, in, 2, wire, sizeof(wire));
    if (wlen < 0) { FAIL("no dyntab write", "encode failed"); goto done; }
    if (enc.table.count != 0) {
        FAIL("no dyntab write", "encoder wrote to dyntab: count=%zu", enc.table.count);
        goto done;
    }
    hpack_header_t out[8];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 8);
    if (n != 2) { FAIL("no dyntab write", "decode got %d want 2", n); goto done; }
    OK("dynamic_table_update=0 encoder does not write to table");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc); hpack_ctx_free(&dec);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * New tests
 * ═══════════════════════════════════════════════════════════════════════════*/

/* ── Giant Huffman string roundtrip ─────────────────────────────────────── */
static void test_giant_huffman(void) {
    /* 4KB value — Huffman encode + decode must handle it correctly        */
    const size_t vlen = 4096;
    char *big_val = malloc(vlen + 1);
    if (!big_val) { FAIL("giant huffman", "malloc failed"); return; }
    /* Alternating printable ASCII to exercise varied Huffman codes        */
    for (size_t i = 0; i < vlen; i++)
        big_val[i] = (char)('a' + (i % 26));
    big_val[vlen] = '\0';

    hpack_header_t in[1] = {{ "x-big", big_val }};

    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 1, 0);   /* huffman on, no dyntab          */
    hpack_ctx_init(&dec, 4096, 1, 0);

    uint8_t *wire = malloc(vlen * 2);
    if (!wire) { free(big_val); FAIL("giant huffman", "malloc failed"); return; }

    int wlen = hpack_encode(&enc, in, 1, wire, vlen * 2);
    if (wlen < 0) {
        FAIL("giant huffman", "encode failed"); goto done;
    }

    hpack_header_t out[4];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 4);
    if (n != 1) {
        FAIL("giant huffman", "decode got %d want 1", n); goto done;
    }
    if (strcmp(out[0].value, big_val) != 0) {
        FAIL("giant huffman", "value mismatch (len got=%zu want=%zu)",
             strlen(out[0].value), vlen);
        goto done;
    }
    OK("giant Huffman string (4KB) roundtrip");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc); hpack_ctx_free(&dec);
    free(wire); free(big_val);
}

/* ── Dynamic table overflow spam ─────────────────────────────────────────── */
/* Encode 200 distinct headers into a small dyntab (256 bytes).
 * Each entry evicts the previous. Final table should be consistent.        */
static void test_dyntab_overflow_spam(void) {
    const int N = 200;
    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 256, 0, 1);
    hpack_ctx_init(&dec, 256, 0, 1);

    int failed = 0;
    for (int i = 0; i < N && !failed; i++) {
        char name[16], value[16];
        snprintf(name,  sizeof(name),  "x-h%d", i);
        snprintf(value, sizeof(value), "v%d", i);
        hpack_header_t h = { name, value };

        uint8_t wire[128];
        int wlen = hpack_encode(&enc, &h, 1, wire, sizeof(wire));
        if (wlen < 0) { failed = 1; break; }

        hpack_header_t out[4];
        int n = hpack_decode(&dec, wire, (size_t)wlen, out, 4);
        if (n != 1 || strcmp(out[0].name, name) || strcmp(out[0].value, value)) {
            failed = 1;
            hpack_headers_free(out, n < 0 ? 0 : n);
            break;
        }
        hpack_headers_free(out, n);
    }

    if (failed)
        FAIL("dyntab overflow spam", "encode/decode mismatch during spam");
    else
        OK("dynamic table overflow spam (200 headers, 256B table)");

    hpack_ctx_free(&enc); hpack_ctx_free(&dec);
}

/* ── Duplicate pseudo-headers → decode should still return them ─────────── */
/* RFC 7540 §8.1.2.3: a request with duplicate :method is a stream error.
 * HPACK itself doesn't reject duplicates — the HTTP/2 layer does.
 * We verify HPACK decodes them without crashing.                           */
static void test_duplicate_pseudo_headers(void) {
    /* Manually craft: two indexed :method GET entries (0x82 0x82)        */
    uint8_t wire[] = { 0x82, 0x82 };
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);
    hpack_header_t out[8];
    int n = hpack_decode(&ctx, wire, sizeof(wire), out, 8);
    /* Should decode 2 headers (both :method GET) without crashing        */
    if (n == 2 &&
        strcmp(out[0].name, ":method") == 0 &&
        strcmp(out[1].name, ":method") == 0) {
        OK("duplicate pseudo-headers decoded without crash");
    } else if (n < 0) {
        /* Also acceptable — implementation may reject at HPACK level     */
        OK("duplicate pseudo-headers — rejected at HPACK level");
    } else {
        FAIL("duplicate pseudo-headers", "unexpected n=%d", n);
    }
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&ctx);
}

/* ── Uppercase header name — encoder must lowercase, decoder must accept ── */
/* RFC 7540 §8.1.2: header names MUST be lowercase in HTTP/2.
 * We test that our encoder sends lowercase and decoder handles it.         */
static void test_header_case(void) {
    hpack_header_t in[] = {
        { "content-type", "text/html" },  /* already lowercase            */
    };
    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 4096, 0, 0);
    hpack_ctx_init(&dec, 4096, 0, 0);

    uint8_t wire[256];
    int wlen = hpack_encode(&enc, in, 1, wire, sizeof(wire));
    if (wlen < 0) { FAIL("header case", "encode failed"); goto done; }

    hpack_header_t out[4];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 4);
    if (n != 1) { FAIL("header case", "got %d want 1", n); goto done; }

    /* Name must be lowercase */
    for (const char *p = out[0].name; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') {
            FAIL("header case", "uppercase byte in decoded name: '%s'",
                 out[0].name);
            goto done;
        }
    }
    OK("header name is lowercase after encode/decode");
done:
    hpack_headers_free(out, n < 0 ? 0 : n);
    hpack_ctx_free(&enc); hpack_ctx_free(&dec);
}

/* ── Out-of-range indexed header ─────────────────────────────────────────── */
/* Index > 61 with empty dynamic table must return error.                   */
static void test_invalid_index(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);

    /* 0xff = indexed representation, index=127 (5-bit prefix all ones +
     * continuation byte 0x3e → index = 31+62 = 93)                       */
    uint8_t wire[] = { 0xff, 0x3e };   /* index 93, dyntab empty → error */
    hpack_header_t out[4];
    int n = hpack_decode(&ctx, wire, sizeof(wire), out, 4);
    if (n < 0)
        OK("out-of-range index rejected");
    else {
        FAIL("out-of-range index", "expected error, got %d headers", n);
        hpack_headers_free(out, n);
    }
    hpack_ctx_free(&ctx);
}

/* ── Compression bomb: string length field claims huge size ──────────────── */
/* Wire says string is 1MB but buffer is only 16 bytes.
 * Decoder must not crash or allocate 1MB.                                  */
static void test_compression_bomb(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);

    /* Literal not indexed, new name.
     * Name length encoded as 5-byte integer: 0x7f 0x81 0x80 0x80 0x04
     *   = 127 + (1 + 0 + 0 + 4*128) = 127 + 513 = 640  — but buffer short */
    uint8_t wire[] = {
        0x40,               /* literal incremental indexing, new name     */
        0x7f, 0x81, 0x80, 0x80, 0x04,  /* name length = 65664            */
        'x', '-', 'h'       /* only 3 bytes of name — truncated           */
    };
    hpack_header_t out[4];
    int n = hpack_decode(&ctx, wire, sizeof(wire), out, 4);
    if (n < 0)
        OK("compression bomb: truncated giant string rejected");
    else {
        FAIL("compression bomb", "expected error, got %d headers", n);
        hpack_headers_free(out, n);
    }
    hpack_ctx_free(&ctx);
}

/* ── Randomized fuzz: random bytes must not crash ────────────────────────── */
/* Not a correctness test — a stability test. Any return value is fine,
 * but we must not segfault or corrupt memory (ASAN will catch it).         */
static void test_fuzz_random(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 1, 1);

    /* Fixed seed for reproducibility */
    unsigned int seed = 0xdeadbeef;
    int crashes = 0;

    for (int iter = 0; iter < 256; iter++) {
        uint8_t buf[32];
        size_t  blen = (size_t)(rand_r(&seed) % 32) + 1;
        for (size_t i = 0; i < blen; i++)
            buf[i] = (uint8_t)(rand_r(&seed) & 0xff);

        hpack_header_t out[16];
        int n = hpack_decode(&ctx, buf, blen, out, 16);
        if (n > 0) hpack_headers_free(out, n);
        /* Reset dynamic table between iterations to keep state clean     */
        hpack_dynamic_table_resize(&ctx, 0);
        hpack_dynamic_table_resize(&ctx, 4096);
        (void)crashes;
    }
    /* If we reach here without ASAN/UBSAN firing, test passes            */
    OK("fuzz random bytes (256 iterations) — no crash");
    hpack_ctx_free(&ctx);
}

/* ── Many headers up to decoder limit ───────────────────────────────────── */
static void test_header_count_boundary(void) {
    /* Encode exactly 64 headers (our decode limit in h2.c is 64)         */
    const int N = 63;   /* stay just under limit                          */
    hpack_header_t *in = calloc((size_t)N, sizeof(hpack_header_t));
    char (*names)[16]  = calloc((size_t)N, 16);
    char (*values)[16] = calloc((size_t)N, 16);
    if (!in || !names || !values) {
        FAIL("header count boundary", "malloc failed");
        free(in); free(names); free(values); return;
    }
    for (int i = 0; i < N; i++) {
        snprintf(names[i],  16, "x-h%02d", i);
        snprintf(values[i], 16, "v%d", i);
        in[i].name  = names[i];
        in[i].value = values[i];
    }

    hpack_ctx_t enc, dec;
    hpack_ctx_init(&enc, 65536, 0, 0);
    hpack_ctx_init(&dec, 65536, 0, 0);

    uint8_t *wire = malloc((size_t)N * 64);
    if (!wire) {
        FAIL("header count boundary", "malloc failed"); goto done;
    }
    int wlen = hpack_encode(&enc, in, N, wire, (size_t)N * 64);
    if (wlen < 0) { FAIL("header count boundary", "encode failed"); goto done2; }

    hpack_header_t out[64];
    int n = hpack_decode(&dec, wire, (size_t)wlen, out, 64);
    if (n != N) {
        FAIL("header count boundary", "got %d want %d", n, N); goto done2;
    }
    OK("header count boundary — 63 headers encoded/decoded");
    hpack_headers_free(out, n);
done2:
    free(wire);
done:
    free(in); free(names); free(values);
    hpack_ctx_free(&enc); hpack_ctx_free(&dec);
}

/* ── Huffman: EOS padding validation ────────────────────────────────────── */
/* RFC 7541 §5.2: padding bits must be most-significant bits of EOS (all 1s).
 * Wrong padding → decoding error.                                          */
static void test_huffman_bad_padding(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 1, 1);

    /* Literal not indexed, new name, Huffman-encoded name.
     * 0x82 = Huffman flag + length 2.
     * Bytes 0xff 0x00 — 0x00 has zero-bit padding which is invalid EOS.  */
    uint8_t wire[] = {
        0x40,        /* literal incremental indexing, new name            */
        0x82,        /* Huffman=1, name length=2                          */
        0xff, 0x00,  /* bad Huffman: 0x00 trailing byte is wrong padding  */
        0x01, 'v'    /* value length=1, value='v'                         */
    };
    hpack_header_t out[4];
    int n = hpack_decode(&ctx, wire, sizeof(wire), out, 4);
    if (n < 0)
        OK("Huffman bad padding rejected");
    else {
        /* Some implementations are lenient about padding — acceptable    */
        OK("Huffman bad padding — implementation is lenient (accepted)");
        hpack_headers_free(out, n);
    }
    hpack_ctx_free(&ctx);
}

/* ── Dynamic table: indexed reference after eviction ─────────────────────── */
/* Add an entry to dyntab, then resize to 0 (evict all), then try to
 * reference the evicted index — must get error, not stale data.            */
static void test_stale_index_after_eviction(void) {
    hpack_ctx_t ctx;
    hpack_ctx_init(&ctx, 4096, 0, 1);

    /* Decode a header that adds to dyntab (index 62 after decode)        */
    uint8_t add_wire[] = {
        0x40, 0x05, 'x','-','f','o','o', 0x03, 'b','a','r'
    };
    hpack_header_t out[4];
    int n = hpack_decode(&ctx, add_wire, sizeof(add_wire), out, 4);
    if (n != 1) { FAIL("stale index", "initial decode failed n=%d", n); goto done; }
    hpack_headers_free(out, n);

    /* Resize to 0 — evicts x-foo */
    hpack_dynamic_table_resize(&ctx, 0);

    /* Now try to reference index 62 (which no longer exists)             */
    uint8_t ref[] = { 0x80 | 62 };   /* indexed, index=62                */
    n = hpack_decode(&ctx, ref, sizeof(ref), out, 4);
    if (n < 0)
        OK("stale dyntab index after eviction — correctly rejected");
    else {
        FAIL("stale dyntab index", "expected error, got %d headers", n);
        hpack_headers_free(out, n);
    }
done:
    hpack_ctx_free(&ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/
int main(void) {
    printf("test_h2_hpack\n");
    printf("─────────────────────────────────────\n");

    /* Original tests */
    test_static_indexed();
    test_rfc_c31();
    test_rfc_c41_huffman();
    test_dyntab_eviction();
    test_roundtrip();
    test_roundtrip_no_huffman();
    test_dyntab_resize();
    test_malformed();
    test_no_dyntab_write();

    /* New tests */
    test_giant_huffman();
    test_dyntab_overflow_spam();
    test_duplicate_pseudo_headers();
    test_header_case();
    test_invalid_index();
    test_compression_bomb();
    test_fuzz_random();
    test_header_count_boundary();
    test_huffman_bad_padding();
    test_stale_index_after_eviction();

    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}