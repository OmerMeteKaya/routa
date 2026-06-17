#include "../include/http/h2_hpack.h"

#include <pthread.h>

#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * RFC 7541 Appendix A — Static Header Table (61 entries, 1-indexed)
 * ═══════════════════════════════════════════════════════════════════════════*/
static const hpack_header_t hpack_static_table[] = {
    /* 0 — unused (table is 1-indexed) */
    {NULL, NULL},
    /* 1  */ {":authority",                  ""},
    /* 2  */ {":method",                     "GET"},
    /* 3  */ {":method",                     "POST"},
    /* 4  */ {":path",                       "/"},
    /* 5  */ {":path",                       "/index.html"},
    /* 6  */ {":scheme",                     "http"},
    /* 7  */ {":scheme",                     "https"},
    /* 8  */ {":status",                     "200"},
    /* 9  */ {":status",                     "204"},
    /* 10 */ {":status",                     "206"},
    /* 11 */ {":status",                     "304"},
    /* 12 */ {":status",                     "400"},
    /* 13 */ {":status",                     "404"},
    /* 14 */ {":status",                     "500"},
    /* 15 */ {"accept-charset",              ""},
    /* 16 */ {"accept-encoding",             "gzip, deflate"},
    /* 17 */ {"accept-language",             ""},
    /* 18 */ {"accept-ranges",               ""},
    /* 19 */ {"accept",                      ""},
    /* 20 */ {"access-control-allow-origin", ""},
    /* 21 */ {"age",                         ""},
    /* 22 */ {"allow",                       ""},
    /* 23 */ {"authorization",               ""},
    /* 24 */ {"cache-control",               ""},
    /* 25 */ {"content-disposition",         ""},
    /* 26 */ {"content-encoding",            ""},
    /* 27 */ {"content-language",            ""},
    /* 28 */ {"content-length",              ""},
    /* 29 */ {"content-location",            ""},
    /* 30 */ {"content-range",               ""},
    /* 31 */ {"content-type",                ""},
    /* 32 */ {"cookie",                      ""},
    /* 33 */ {"date",                        ""},
    /* 34 */ {"etag",                        ""},
    /* 35 */ {"expect",                      ""},
    /* 36 */ {"expires",                     ""},
    /* 37 */ {"from",                        ""},
    /* 38 */ {"host",                        ""},
    /* 39 */ {"if-match",                    ""},
    /* 40 */ {"if-modified-since",           ""},
    /* 41 */ {"if-none-match",               ""},
    /* 42 */ {"if-range",                    ""},
    /* 43 */ {"if-unmodified-since",         ""},
    /* 44 */ {"last-modified",               ""},
    /* 45 */ {"link",                        ""},
    /* 46 */ {"location",                    ""},
    /* 47 */ {"max-forwards",                ""},
    /* 48 */ {"proxy-authenticate",          ""},
    /* 49 */ {"proxy-authorization",         ""},
    /* 50 */ {"range",                       ""},
    /* 51 */ {"referer",                     ""},
    /* 52 */ {"refresh",                     ""},
    /* 53 */ {"retry-after",                 ""},
    /* 54 */ {"server",                      ""},
    /* 55 */ {"set-cookie",                  ""},
    /* 56 */ {"strict-transport-security",   ""},
    /* 57 */ {"transfer-encoding",           ""},
    /* 58 */ {"user-agent",                  ""},
    /* 59 */ {"vary",                        ""},
    /* 60 */ {"via",                         ""},
    /* 61 */ {"www-authenticate",            ""},
};
#define HPACK_STATIC_COUNT 61
static int static_name_idx[256];   /* hash → static table index */
static pthread_once_t static_hash_once = PTHREAD_ONCE_INIT;

static uint8_t header_hash(const char *s) {
    uint8_t h = 0;
    while (*s) h = (uint8_t)(h * 31 + (uint8_t)*s++);
    return h;
}

static void build_static_hash(void) {
    memset(static_name_idx, 0, sizeof(static_name_idx));
    for (int i = 1; i <= HPACK_STATIC_COUNT; i++) {
        uint8_t h = header_hash(hpack_static_table[i].name);
        if (!static_name_idx[h]) static_name_idx[h] = i;
    }
}
/* ═══════════════════════════════════════════════════════════════════════════
 * RFC 7541 Appendix B — Huffman Code Table
 * Each entry: { code (MSB-aligned uint32), bit_length }
 * ═══════════════════════════════════════════════════════════════════════════*/
typedef struct { uint32_t code; uint8_t bits; } huff_entry_t;

static const huff_entry_t hpack_huffman_table[256] = {
    /*   0 */ {0x1ff8, 13},
    /*   1 */ {0x7fffd8, 23},
    /*   2 */ {0xfffffe2, 28},
    /*   3 */ {0xfffffe3, 28},
    /*   4 */ {0xfffffe4, 28},
    /*   5 */ {0xfffffe5, 28},
    /*   6 */ {0xfffffe6, 28},
    /*   7 */ {0xfffffe7, 28},
    /*   8 */ {0xfffffe8, 28},
    /*   9 */ {0xffffea, 24},
    /*  10 */ {0x3fffffff, 30},
    /*  11 */ {0xfffffe9, 28},
    /*  12 */ {0xfffffea, 28},
    /*  13 */ {0x3fffffff, 30},
    /*  14 */ {0xfffffeb, 28},
    /*  15 */ {0xfffffec, 28},
    /*  16 */ {0xfffffed, 28},
    /*  17 */ {0xfffffee, 28},
    /*  18 */ {0xfffffef, 28},
    /*  19 */ {0xffffff0, 28},
    /*  20 */ {0xffffff1, 28},
    /*  21 */ {0xffffff2, 28},
    /*  22 */ {0x3fffffff, 30},
    /*  23 */ {0xffffff3, 28},
    /*  24 */ {0xffffff4, 28},
    /*  25 */ {0xffffff5, 28},
    /*  26 */ {0xffffff6, 28},
    /*  27 */ {0xffffff7, 28},
    /*  28 */ {0xffffff8, 28},
    /*  29 */ {0xffffff9, 28},
    /*  30 */ {0xffffffa, 28},
    /*  31 */ {0xffffffb, 28},
    /*  32 */ {0x14, 6},
    /*  33 */ {0x3f8, 10},
    /*  34 */ {0x3f9, 10},
    /*  35 */ {0xffa, 12},
    /*  36 */ {0x1ff9, 13},
    /*  37 */ {0x15, 6},
    /*  38 */ {0xf8, 8},
    /*  39 */ {0x7fa, 11},
    /*  40 */ {0x3fa, 10},
    /*  41 */ {0x3fb, 10},
    /*  42 */ {0xf9, 8},
    /*  43 */ {0x7fb, 11},
    /*  44 */ {0xfa, 8},
    /*  45 */ {0x16, 6},
    /*  46 */ {0x17, 6},
    /*  47 */ {0x18, 6},
    /*  48 */ {0x0, 5},
    /*  49 */ {0x1, 5},
    /*  50 */ {0x2, 5},
    /*  51 */ {0x19, 6},
    /*  52 */ {0x1a, 6},
    /*  53 */ {0x1b, 6},
    /*  54 */ {0x1c, 6},
    /*  55 */ {0x1d, 6},
    /*  56 */ {0x1e, 6},
    /*  57 */ {0x1f, 6},
    /*  58 */ {0x5c, 7},
    /*  59 */ {0xfb, 8},
    /*  60 */ {0x7ffc, 15},
    /*  61 */ {0x20, 6},
    /*  62 */ {0xffb, 12},
    /*  63 */ {0x3fc, 10},
    /*  64 */ {0x1ffa, 13},
    /*  65 */ {0x21, 6},
    /*  66 */ {0x5d, 7},
    /*  67 */ {0x5e, 7},
    /*  68 */ {0x5f, 7},
    /*  69 */ {0x60, 7},
    /*  70 */ {0x61, 7},
    /*  71 */ {0x62, 7},
    /*  72 */ {0x63, 7},
    /*  73 */ {0x64, 7},
    /*  74 */ {0x65, 7},
    /*  75 */ {0x66, 7},
    /*  76 */ {0x67, 7},
    /*  77 */ {0x68, 7},
    /*  78 */ {0x69, 7},
    /*  79 */ {0x6a, 7},
    /*  80 */ {0x6b, 7},
    /*  81 */ {0x6c, 7},
    /*  82 */ {0x6d, 7},
    /*  83 */ {0x6e, 7},
    /*  84 */ {0x6f, 7},
    /*  85 */ {0x70, 7},
    /*  86 */ {0x71, 7},
    /*  87 */ {0x72, 7},
    /*  88 */ {0xfc, 8},
    /*  89 */ {0x73, 7},
    /*  90 */ {0xfd, 8},
    /*  91 */ {0x1ffb, 13},
    /*  92 */ {0x7fff0, 19},
    /*  93 */ {0x1ffc, 13},
    /*  94 */ {0x3ffc, 14},
    /*  95 */ {0x22, 6},
    /*  96 */ {0x7ffd, 15},
    /*  97 */ {0x3, 5},
    /*  98 */ {0x23, 6},
    /*  99 */ {0x4, 5},
    /* 100 */ {0x24, 6},
    /* 101 */ {0x5, 5},
    /* 102 */ {0x25, 6},
    /* 103 */ {0x26, 6},
    /* 104 */ {0x27, 6},
    /* 105 */ {0x6, 5},
    /* 106 */ {0x74, 7},
    /* 107 */ {0x75, 7},
    /* 108 */ {0x28, 6},
    /* 109 */ {0x29, 6},
    /* 110 */ {0x2a, 6},
    /* 111 */ {0x7, 5},
    /* 112 */ {0x2b, 6},
    /* 113 */ {0x76, 7},
    /* 114 */ {0x2c, 6},
    /* 115 */ {0x8, 5},
    /* 116 */ {0x9, 5},
    /* 117 */ {0x2d, 6},
    /* 118 */ {0x77, 7},
    /* 119 */ {0x78, 7},
    /* 120 */ {0x79, 7},
    /* 121 */ {0x7a, 7},
    /* 122 */ {0x7b, 7},
    /* 123 */ {0x7ffe, 15},
    /* 124 */ {0x7fc, 11},
    /* 125 */ {0x3ffd, 14},
    /* 126 */ {0x1ffd, 13},
    /* 127 */ {0xffffffc, 28},
    /* 128 */ {0xfffe6, 20},
    /* 129 */ {0x3fffd2, 22},
    /* 130 */ {0xfffe7, 20},
    /* 131 */ {0xfffe8, 20},
    /* 132 */ {0x3fffd3, 22},
    /* 133 */ {0x3fffd4, 22},
    /* 134 */ {0x3fffd5, 22},
    /* 135 */ {0x7fffd9, 23},
    /* 136 */ {0x3fffd6, 22},
    /* 137 */ {0x7fffda, 23},
    /* 138 */ {0x7fffdb, 23},
    /* 139 */ {0x7fffdc, 23},
    /* 140 */ {0x7fffdd, 23},
    /* 141 */ {0x7fffde, 23},
    /* 142 */ {0xffffeb, 24},
    /* 143 */ {0x7fffdf, 23},
    /* 144 */ {0xffffec, 24},
    /* 145 */ {0xffffed, 24},
    /* 146 */ {0x3fffd7, 22},
    /* 147 */ {0x7fffe0, 23},
    /* 148 */ {0xffffee, 24},
    /* 149 */ {0x7fffe1, 23},
    /* 150 */ {0x7fffe2, 23},
    /* 151 */ {0x7fffe3, 23},
    /* 152 */ {0x7fffe4, 23},
    /* 153 */ {0x3fffd8, 22},
    /* 154 */ {0xffffef, 24},
    /* 155 */ {0x3fffd9, 22},
    /* 156 */ {0x3fffda, 22},
    /* 157 */ {0x3fffdb, 22},
    /* 158 */ {0x7fffe5, 23},
    /* 159 */ {0x3fffdc, 22},
    /* 160 */ {0x3fffdd, 22},
    /* 161 */ {0x3fffde, 22},
    /* 162 */ {0xfffff0, 24},
    /* 163 */ {0x3fffdf, 22},
    /* 164 */ {0x7fffe6, 23},
    /* 165 */ {0x7fffe7, 23},
    /* 166 */ {0xfffff1, 24},
    /* 167 */ {0x3fffe0, 22},
    /* 168 */ {0x3fffe1, 22},
    /* 169 */ {0x7fffe8, 23},
    /* 170 */ {0x7fffe9, 23},
    /* 171 */ {0x3fffe2, 22},
    /* 172 */ {0x7fffea, 23},
    /* 173 */ {0x3fffe3, 22},
    /* 174 */ {0x3fffe4, 22},
    /* 175 */ {0x7fffeb, 23},
    /* 176 */ {0x7fffec, 23},
    /* 177 */ {0x3fffe5, 22},
    /* 178 */ {0x3fffe6, 22},
    /* 179 */ {0x7fffed, 23},
    /* 180 */ {0x3fffe7, 22},
    /* 181 */ {0x7fffee, 23},
    /* 182 */ {0x7fffef, 23},
    /* 183 */ {0xfffff2, 24},
    /* 184 */ {0x3fffe8, 22},
    /* 185 */ {0x3fffe9, 22},
    /* 186 */ {0xfffff3, 24},
    /* 187 */ {0xfffff4, 24},
    /* 188 */ {0xfffff5, 24},
    /* 189 */ {0x3fffea, 22},
    /* 190 */ {0x7ffff0, 23},
    /* 191 */ {0x3fffeb, 22},
    /* 192 */ {0x7ffff1, 23},
    /* 193 */ {0x3ffffe0, 26},
    /* 194 */ {0x3ffffe1, 26},
    /* 195 */ {0xfffff6, 24},
    /* 196 */ {0x3ffffe2, 26},
    /* 197 */ {0x7ffff2, 23},
    /* 198 */ {0x3ffffe3, 26},
    /* 199 */ {0x3ffffe4, 26},
    /* 200 */ {0x7ffff3, 23},
    /* 201 */ {0x3ffffe5, 26},
    /* 202 */ {0x3ffffe6, 26},
    /* 203 */ {0x7ffff4, 23},
    /* 204 */ {0x3ffffe7, 26},
    /* 205 */ {0x3ffffe8, 26},
    /* 206 */ {0x1ffffec, 25},
    /* 207 */ {0x3ffffe9, 26},
    /* 208 */ {0x3ffffea, 26},
    /* 209 */ {0x7ffff5, 23},
    /* 210 */ {0x1ffffed, 25},
    /* 211 */ {0x7ffff6, 23},
    /* 212 */ {0x3ffffeb, 26},
    /* 213 */ {0x7ffff7, 23},
    /* 214 */ {0x3ffffec, 26},
    /* 215 */ {0x3ffffed, 26},
    /* 216 */ {0x3ffffee, 26},
    /* 217 */ {0x3ffffef, 26},
    /* 218 */ {0x3fffff0, 26},
    /* 219 */ {0x3fffff1, 26},
    /* 220 */ {0x3fffff2, 26},
    /* 221 */ {0x3fffff3, 26},
    /* 222 */ {0x3fffff4, 26},
    /* 223 */ {0x3fffff5, 26},
    /* 224 */ {0x3fffff6, 26},
    /* 225 */ {0x3fffff7, 26},
    /* 226 */ {0x3fffff8, 26},
    /* 227 */ {0x3fffff9, 26},
    /* 228 */ {0x3fffffa, 26},
    /* 229 */ {0x3fffffb, 26},
    /* 230 */ {0x3fffffc, 26},
    /* 231 */ {0x3fffffd, 26},
    /* 232 */ {0x3fffffe, 26},
    /* 233 */ {0x7fffffd, 27},
    /* 234 */ {0x3ffffff, 26},
    /* 235 */ {0xfffffff, 28},
    /* 236 */ {0xfffffff, 28},
    /* 237 */ {0xfffffff, 28},
    /* 238 */ {0xfffffff, 28},
    /* 239 */ {0xfffffff, 28},
    /* 240 */ {0xfffffff, 28},
    /* 241 */ {0xfffffff, 28},
    /* 242 */ {0xfffffff, 28},
    /* 243 */ {0xfffffff, 28},
    /* 244 */ {0xfffffff, 28},
    /* 245 */ {0xfffffff, 28},
    /* 246 */ {0xfffffff, 28},
    /* 247 */ {0xfffffff, 28},
    /* 248 */ {0xfffffff, 28},
    /* 249 */ {0xfffffff, 28},
    /* 250 */ {0xfffffff, 28},
    /* 251 */ {0xfffffff, 28},
    /* 252 */ {0xfffffff, 28},
    /* 253 */ {0xfffffff, 28},
    /* 254 */ {0xfffffff, 28},
    /* 255 */ {0xfffffff, 28},
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Integer encoding/decoding (RFC 7541 §5.1)
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Decode a prefix-N integer starting at *src.
 * Returns bytes consumed, -1 on error.
 * Result written to *out.                                                   */
static int hpack_decode_int(const uint8_t *src, size_t src_len,
                             int prefix_bits, uint64_t *out) {
    if (src_len == 0) return -1;
    uint64_t max_prefix = (1u << prefix_bits) - 1;
    uint64_t val = src[0] & (uint8_t)max_prefix;

    if (val < max_prefix) { *out = val; return 1; }

    size_t i = 1;
    uint64_t m = 0;
    do {
        if (i >= src_len) return -1;
        val += ((uint64_t)(src[i] & 0x7f)) << m;
        m += 7;
        if (m > 63) return -1;
        /* Overflow guard: HPACK index cannot exceed 2^20 in practice    */
        if (val > 0xFFFFF) return -1;
    } while (src[i++] & 0x80);

    *out = val;
    return (int)i;
}

/* Encode integer with prefix_bits prefix into dst.
 * Returns bytes written, -1 if dst too small.                               */
static int hpack_encode_int(uint8_t *dst, size_t dst_len,
                             uint8_t prefix_byte, int prefix_bits,
                             uint64_t val) {
    if (dst_len == 0) return -1;
    uint64_t max_prefix = (1u << prefix_bits) - 1;

    if (val < max_prefix) {
        dst[0] = prefix_byte | (uint8_t)val;
        return 1;
    }

    dst[0] = prefix_byte | (uint8_t)max_prefix;
    val -= max_prefix;
    size_t i = 1;
    while (val >= 0x80) {
        if (i >= dst_len) return -1;
        dst[i++] = (uint8_t)((val & 0x7f) | 0x80);
        val >>= 7;
    }
    if (i >= dst_len) return -1;
    dst[i++] = (uint8_t)val;
    return (int)i;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Huffman decode
 * Simple bit-by-bit FSM — good enough for header sizes we deal with.
 * High-perf servers use a 256-entry lookup table; we can upgrade later.
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Huffman decode lookup table — build once at startup */
typedef struct {
    uint8_t  sym;
    uint8_t  bits;   /* how many bits consumed */
    uint8_t  valid;
} huff_lut_entry_t;

/* 256-entry table indexed by next 8 bits */
static huff_lut_entry_t huff_lut[256];
static pthread_once_t huff_lut_once = PTHREAD_ONCE_INIT;

static void build_huff_lut(void) {
    memset(huff_lut, 0, sizeof(huff_lut));
    for (int sym = 0; sym < 256; sym++) {
        int      bl   = hpack_huffman_table[sym].bits;
        uint32_t code = hpack_huffman_table[sym].code;
        if (bl > 8) continue;   /* only short codes fit in 8-bit LUT */
        /* All 8-bit patterns that start with this code */
        int pad = 8 - bl;
        uint32_t base = code << pad;
        uint32_t count = 1u << pad;
        for (uint32_t i = 0; i < count; i++) {
            uint8_t idx = (uint8_t)(base | i);
            if (!huff_lut[idx].valid) {
                huff_lut[idx].sym   = (uint8_t)sym;
                huff_lut[idx].bits  = (uint8_t)bl;
                huff_lut[idx].valid = 1;
            }
        }
    }
}
/* Build a simple decode table on first use (lazy, done once per process).
 * Maps (state, bit) → (next_state, symbol, is_terminal).
 * For now we use a straightforward approach: walk the Huffman tree.        */

/* Decode Huffman-encoded src into dst (plain string, no NUL).
 * Returns decoded byte count, -1 on error.
 *
 * Fast path: 8-bit LUT (huff_lut) resolves codes ≤ 8 bits in O(1).
 * All printable ASCII used in HTTP headers falls in this range (5–8 bits),
 * so the slow 256-symbol scan is hit only for rare >8-bit codepoints.
 * Combined complexity: O(n) for typical header content.                      */
static int huffman_decode(const uint8_t *src, size_t src_len,
                           char *dst, size_t dst_len) {
    pthread_once(&huff_lut_once, build_huff_lut);

    uint64_t bits   = 0;
    int      n_bits = 0;
    size_t   out    = 0;

    for (size_t i = 0; i < src_len; i++) {
        bits   = (bits << 8) | src[i];
        n_bits += 8;

        int progress = 1;
        while (progress && n_bits > 0) {
            progress = 0;

            /* Fast path: O(1) lookup for codes ≤ 8 bits */
            if (n_bits >= 8) {
                uint8_t top8 = (uint8_t)((bits >> (n_bits - 8)) & 0xffu);
                const huff_lut_entry_t *e = &huff_lut[top8];
                if (e->valid) {
                    if (out >= dst_len) return -1;
                    dst[out++] = (char)e->sym;
                    n_bits    -= e->bits;
                    bits      &= n_bits ? ((uint64_t)1 << n_bits) - 1 : 0;
                    progress   = 1;
                    continue;
                }
            }

            /*
             * Slow path: linear scan for codes that need more than a byte.
             * When n_bits >= 8 the LUT already tried all codes ≤ 8 bits,
             * so only scan long codes here.  When n_bits < 8 there are not
             * enough bits for the LUT, so scan every code that fits.
             */
            for (int sym = 0; sym < 256; sym++) {
                int      bl   = hpack_huffman_table[sym].bits;
                uint32_t code = hpack_huffman_table[sym].code;
                if (bl > n_bits) continue;
                if (n_bits >= 8 && bl <= 8) continue;  /* LUT handled these */
                uint32_t top = (uint32_t)(bits >> (n_bits - bl));
                top &= (bl == 32) ? 0xffffffffu : ((1u << bl) - 1);
                if (top == code) {
                    if (out >= dst_len) return -1;
                    dst[out++] = (char)sym;
                    n_bits    -= bl;
                    bits      &= n_bits ? ((uint64_t)1 << n_bits) - 1 : 0;
                    progress   = 1;
                    break;
                }
            }
        }
    }

    if (n_bits > 7) return -1;
    if (n_bits > 0) {
        uint32_t pad = (uint32_t)(bits & ((1u << n_bits) - 1));
        uint32_t exp = (1u << n_bits) - 1;
        if (pad != exp) return -1;
    }
    return (int)out;
}
/* Encode plain string src into Huffman-coded dst.
 * Returns encoded byte count, -1 if dst too small.                          */
static int huffman_encode(const char *src, size_t src_len,
                           uint8_t *dst, size_t dst_len) {
    uint64_t bits   = 0;
    int      n_bits = 0;
    size_t   out    = 0;

    for (size_t i = 0; i < src_len; i++) {
        uint8_t  sym  = (uint8_t)src[i];
        uint32_t code = hpack_huffman_table[sym].code;
        int      bl   = hpack_huffman_table[sym].bits;

        /* Shift in new code bits */
        bits = (bits << bl) | (uint64_t)code;
        n_bits += bl;

        /* Flush complete bytes */
        while (n_bits >= 8) {
            if (out >= dst_len) return -1;
            n_bits -= 8;
            dst[out++] = (uint8_t)(bits >> n_bits);
            bits &= ((uint64_t)1 << n_bits) - 1;
        }
    }

    /* EOS padding — pad remaining bits with 1s */
    if (n_bits > 0) {
        if (out >= dst_len) return -1;
        dst[out++] = (uint8_t)((bits << (8 - n_bits)) |
                               ((1u << (8 - n_bits)) - 1));
    }
    return (int)out;
}
/* ═══════════════════════════════════════════════════════════════════════════
 * Dynamic table
 * Ring buffer: head = oldest, entries added at (head+count) % cap
 * RFC §4.1: entry size = name_len + value_len + 32
 * ═══════════════════════════════════════════════════════════════════════════*/

static void dyntab_evict_to_fit(hpack_dynamic_table_t *t, size_t needed) {
    while (t->count > 0 && t->size + needed > t->max_size) {
        hpack_entry_t *oldest = &t->entries[t->head];
        t->size -= oldest->size;
        free(oldest->name);   /* value = name + nl + 1, same block */
        oldest->name  = NULL;
        oldest->value = NULL;
        t->head  = (t->head + 1) % t->cap;
        t->count--;
    }
}

static int dyntab_add(hpack_dynamic_table_t *t,
                       const char *name, const char *value) {
    size_t nl    = strlen(name);
    size_t vl    = strlen(value);
    size_t esz   = nl + vl + 32;

    if (esz > t->max_size) {
        /* Entry alone exceeds table — evict all per RFC §4.4 */
        dyntab_evict_to_fit(t, t->max_size + 1);
        return 0;
    }

    dyntab_evict_to_fit(t, esz);

    /* Grow ring buffer if needed */
    if (t->count == t->cap) {
        size_t new_cap = t->cap ? t->cap * 2 : 16;
        hpack_entry_t *nb = realloc(t->entries,
                                     new_cap * sizeof(hpack_entry_t));
        if (!nb) return -1;
        /* Linearize ring on grow */
        if (t->head != 0 && t->count > 0) {
            hpack_entry_t *tmp = malloc(t->count * sizeof(hpack_entry_t));
            if (!tmp) { free(nb); return -1; }
            for (size_t i = 0; i < t->count; i++)
                tmp[i] = nb[(t->head + i) % t->cap];
            memcpy(nb, tmp, t->count * sizeof(hpack_entry_t));
            free(tmp);
            t->head = 0;
        }
        t->entries = nb;
        t->cap     = new_cap;
    }

    size_t idx = (t->head + t->count) % t->cap;
    /* Single allocation: name\0value\0 — value ptr = name + nl + 1 */
    char *buf = malloc(nl + vl + 2);
    if (!buf) return -1;
    memcpy(buf, name, nl + 1);
    memcpy(buf + nl + 1, value, vl + 1);
    t->entries[idx].name  = buf;
    t->entries[idx].value = buf + nl + 1;
    t->entries[idx].size  = esz;
    t->count++;
    t->size += esz;
    return 0;
}

/* Lookup by HPACK index (1-based).
 * 1..61 → static table, 62+ → dynamic table (newest first).               */
static const hpack_header_t *static_lookup(int idx) {
    if (idx < 1 || idx > HPACK_STATIC_COUNT) return NULL;
    return &hpack_static_table[idx];
}

static int dyntab_lookup(const hpack_dynamic_table_t *t, int idx,
                          const char **name, const char **value) {
    /* Dynamic index 1 = most recently added */
    int dyn_idx = idx - HPACK_STATIC_COUNT - 1;
    if (dyn_idx < 0 || (size_t)dyn_idx >= t->count) return -1;
    /* newest = (head + count - 1 - dyn_idx) % cap */
    size_t slot = (t->head + t->count - 1 - (size_t)dyn_idx) % t->cap;
    *name  = t->entries[slot].name;
    *value = t->entries[slot].value;
    return 0;
}

/* Decode a string (RFC 7541 §5.2): length-prefixed, optionally Huffman.
 * Returns bytes consumed from src, -1 on error.
 * *out is malloc'd — caller frees.                                          */
/* Hard limit: single header name or value cannot exceed 64KB             */
#define HPACK_MAX_STRING_LEN  65536

static int decode_string(const uint8_t *src, size_t src_len, char **out) {
    if (src_len == 0) return -1;
    int is_huffman = (src[0] & 0x80) != 0;
    uint64_t slen;
    int consumed = hpack_decode_int(src, src_len, 7, &slen);
    if (consumed < 0 || (size_t)consumed + slen > src_len) return -1;
    if (slen > HPACK_MAX_STRING_LEN) return -1;  /* bomb protection      */

    const uint8_t *data = src + consumed;
    if (is_huffman) {
        /* Huffman expands at most 8/5 — safe upper bound                 */
        size_t   cap = (size_t)slen * 2 + 16;
        if (cap > (size_t)HPACK_MAX_STRING_LEN * 2) cap = (size_t)HPACK_MAX_STRING_LEN * 2;
        char    *tmp = malloc(cap);
        if (!tmp) return -1;
        int n = huffman_decode(data, (size_t)slen, tmp, cap);
        if (n < 0 || (size_t)n > HPACK_MAX_STRING_LEN) {
            free(tmp); return -1;
        }
        *out = malloc((size_t)n + 1);
        if (!*out) { free(tmp); return -1; }
        memcpy(*out, tmp, (size_t)n);
        (*out)[n] = '\0';
        free(tmp);
    } else {
        *out = malloc((size_t)slen + 1);
        if (!*out) return -1;
        memcpy(*out, data, (size_t)slen);
        (*out)[slen] = '\0';
    }
    return consumed + (int)slen;
}

/* Encode a string into dst.
 * huffman=1 → try Huffman if shorter, else literal.
 * Returns bytes written, -1 on error.                                       */
static int encode_string(uint8_t *dst, size_t dst_len,
                          const char *str, int huffman) {
    size_t str_len = strlen(str);

    if (huffman) {
        uint8_t tmp[8192];
        int hn = huffman_encode(str, str_len, tmp, sizeof(tmp));
        if (hn > 0 && (size_t)hn < str_len) {
            /* Huffman is shorter — use it */
            int hdr = hpack_encode_int(dst, dst_len, 0x80, 7, (uint64_t)hn);
            if (hdr < 0 || (size_t)hdr + (size_t)hn > dst_len) return -1;
            memcpy(dst + hdr, tmp, (size_t)hn);
            return hdr + hn;
        }
    }

    /* Literal */
    int hdr = hpack_encode_int(dst, dst_len, 0x00, 7, str_len);
    if (hdr < 0 || (size_t)hdr + str_len > dst_len) return -1;
    memcpy(dst + hdr, str, str_len);  // NOLINT(bugprone-not-null-terminated-result)
    return hdr + (int)str_len;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════*/

int hpack_ctx_init(hpack_ctx_t *ctx, size_t max_size,
                   int huffman_encode, int dynamic_table_update,
                   size_t max_header_list_size) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->table.max_size           = max_size;
    ctx->huffman_encode           = huffman_encode;
    ctx->dynamic_table_update     = dynamic_table_update;
    ctx->max_header_list_size     = max_header_list_size;
    ctx->current_header_list_size = 0;
    return 0;
}

void hpack_ctx_free(hpack_ctx_t *ctx) {
    if (!ctx) return;
    hpack_dynamic_table_t *t = &ctx->table;
    for (size_t i = 0; i < t->count; i++) {
        size_t slot = (t->head + i) % t->cap;
        free(t->entries[slot].name);   /* single block, value shares it */
    }
    free(t->entries);
    memset(ctx, 0, sizeof(*ctx));
}

int hpack_dynamic_table_resize(hpack_ctx_t *ctx, size_t new_max) {
    ctx->table.max_size = new_max;
    dyntab_evict_to_fit(&ctx->table, 0);
    return 0;
}

/* ── Decode ──────────────────────────────────────────────────────────────── */
int hpack_decode(hpack_ctx_t *ctx,
                 const uint8_t *src, size_t src_len,
                 hpack_header_t *headers, int max_headers) {
    size_t pos   = 0;
    int    count = 0;

    /* Zero all slots so cleanup on error is safe */
    for (int i = 0; i < max_headers; i++)
        headers[i].name = headers[i].value = NULL;
    ctx->current_header_list_size = 0;
    while (pos < src_len && count < max_headers) {
        uint8_t first = src[pos];
        hpack_header_t *h = &headers[count];

        /* ── Indexed Header Field ── */
        if (first & 0x80) {
            uint64_t idx;
            int n = hpack_decode_int(src + pos, src_len - pos, 7, &idx);
            if (n < 0 || idx == 0) goto fail;
            pos += (size_t)n;

            if ((int)idx <= HPACK_STATIC_COUNT) {
                const hpack_header_t *e = &hpack_static_table[idx];
                h->name  = strdup(e->name);
                h->value = strdup(e->value);
            } else {
                const char *name, *value;
                /* Bounds check before dynamic table lookup              */
                int dyn_idx = (int)idx - HPACK_STATIC_COUNT - 1;
                if (dyn_idx < 0 || (size_t)dyn_idx >= ctx->table.count)
                    goto fail;
                if (dyntab_lookup(&ctx->table, (int)idx,
                                  &name, &value) < 0) goto fail;
                h->name  = strdup(name);
                h->value = strdup(value);
            }
            /* RFC 7541 §4.1: header list size = sum of (name_len + value_len + 32) */
            if (h->name && h->value) {
                size_t entry_size = strlen(h->name) + strlen(h->value) + 32;
                ctx->current_header_list_size += entry_size;
                if (ctx->max_header_list_size > 0 &&
                    ctx->current_header_list_size > ctx->max_header_list_size) {
                    goto fail;
                    }
            }
            if (!h->name || !h->value) goto fail;
            count++;
            continue;
        }

        /* ── Dynamic table size update ── */
        if ((first & 0xe0) == 0x20) {
            uint64_t new_sz;
            int n = hpack_decode_int(src + pos, src_len - pos, 5, &new_sz);
            if (n < 0) goto fail;
            pos += (size_t)n;
            hpack_dynamic_table_resize(ctx, (size_t)new_sz);
            continue;
        }

        /* ── Literal ── */
        int incremental = 0;
        int prefix_bits = 0;
        uint64_t idx    = 0;

        if ((first & 0xc0) == 0x40) {
            incremental = 1; prefix_bits = 6;
        } else if ((first & 0xf0) == 0x00 || (first & 0xf0) == 0x10) {
            prefix_bits = 4;  /* both literal without and never indexed use 4-bit prefix */
        } else {
            goto fail;
        }

        int n = hpack_decode_int(src + pos, src_len - pos, prefix_bits, &idx);
        if (n < 0) goto fail;
        pos += (size_t)n;

        if (idx == 0) {
            int ns = decode_string(src + pos, src_len - pos, &h->name);
            if (ns < 0) goto fail;
            pos += (size_t)ns;
        } else if ((int)idx <= HPACK_STATIC_COUNT) {
            h->name = strdup(hpack_static_table[idx].name);
            if (!h->name) goto fail;
        } else {
            const char *name, *value;
            if (dyntab_lookup(&ctx->table, (int)idx, &name, &value) < 0)
                goto fail;
            h->name = strdup(name);
            if (!h->name) goto fail;
        }

        int vs = decode_string(src + pos, src_len - pos, &h->value);
        if (vs < 0) goto fail;
        pos += (size_t)vs;

        if (incremental)
            dyntab_add(&ctx->table, h->name, h->value);
        /* RFC 7541 §4.1: header list size = sum of (name_len + value_len + 32) */
        if (h->name && h->value) {
            size_t entry_size = strlen(h->name) + strlen(h->value) + 32;
            ctx->current_header_list_size += entry_size;
            if (ctx->max_header_list_size > 0 &&
                ctx->current_header_list_size > ctx->max_header_list_size) {
                goto fail;
                }
        }
        count++;
    }
    return count;

fail:
    /* Free everything allocated so far — caller gets -1, no leak */
    hpack_headers_free(headers, count);
    /* Also free partially filled current slot */
    free(headers[count].name);
    free(headers[count].value);
    headers[count].name = headers[count].value = NULL;
    return -1;
}

/* ── Encode ──────────────────────────────────────────────────────────────── */
int hpack_encode(hpack_ctx_t *ctx,
                 const hpack_header_t *headers, int count,
                 uint8_t *dst, size_t dst_len) {
    pthread_once(&static_hash_once, build_static_hash);
    size_t pos = 0;

    for (int i = 0; i < count; i++) {
        const char *name  = headers[i].name;
        const char *value = headers[i].value;
        if (!name || !value) continue;   /* skip null headers */

        /* Static table full match? */
        uint8_t h          = header_hash(name);
        int full_match = 0;
        int name_match = 0;
        int match_idx  = 0;

        int start_idx = static_name_idx[h];
        if (start_idx > 0) {
            for (int s = start_idx; s <= HPACK_STATIC_COUNT; s++) {
                if (strcmp(hpack_static_table[s].name, name) != 0) continue;
                if (strcmp(hpack_static_table[s].value, value) == 0) {
                    full_match = s; break;
                }
                if (!name_match) { name_match = 1; match_idx = s; }
            }
        }

        if (full_match) {
            /* Indexed representation — 1 byte most of the time */
            int n = hpack_encode_int(dst + pos, dst_len - pos,
                                     0x80, 7, (uint64_t)full_match);
            if (n < 0) return -1;
            pos += (size_t)n;
            continue;
        }

        if (ctx->dynamic_table_update) {
            /* Literal with incremental indexing (0x40 prefix, 6-bit index) */
            int n;
            if (name_match) {
                n = hpack_encode_int(dst + pos, dst_len - pos,
                                     0x40, 6, (uint64_t)match_idx);
            } else {
                /* New name — literal name */
                n = hpack_encode_int(dst + pos, dst_len - pos, 0x40, 6, 0);
                if (n < 0) return -1;
                pos += (size_t)n;
                n = encode_string(dst + pos, dst_len - pos,
                                  name, ctx->huffman_encode);
            }
            if (n < 0) return -1;
            pos += (size_t)n;

            int vn = encode_string(dst + pos, dst_len - pos,
                                   value, ctx->huffman_encode);
            if (vn < 0) return -1;
            pos += (size_t)vn;

            dyntab_add(&ctx->table, name, value);
        } else {
            /* Literal without indexing (0x00 prefix, 4-bit index) */
            int n;
            if (name_match) {
                n = hpack_encode_int(dst + pos, dst_len - pos,
                                     0x00, 4, (uint64_t)match_idx);
            } else {
                n = hpack_encode_int(dst + pos, dst_len - pos, 0x00, 4, 0);
                if (n < 0) return -1;
                pos += (size_t)n;
                n = encode_string(dst + pos, dst_len - pos,
                                  name, ctx->huffman_encode);
            }
            if (n < 0) return -1;
            pos += (size_t)n;

            int vn = encode_string(dst + pos, dst_len - pos,
                                   value, ctx->huffman_encode);
            if (vn < 0) return -1;
            pos += (size_t)vn;
        }
    }
    return (int)pos;
}

/* ── Cleanup ─────────────────────────────────────────────────────────────── */
void hpack_headers_free(hpack_header_t *headers, int count) {
    for (int i = 0; i < count; i++) {
        free(headers[i].name);
        free(headers[i].value);
    }
}