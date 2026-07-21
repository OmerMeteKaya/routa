#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/h2.h"
#include "http/router.h"
#include "core/event_loop.h"
#include "http/middleware.h"
#include "http/request.h"
#include "http/response.h"
#include "core/conn.h"
#include "core/proxy.h"
#include "core/server.h"
#include "net/io.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include "util/metrics.h"

/* Return value from dispatch_stream when the stream was handed to the proxy.
 * The caller must NOT close or free the stream — it stays alive until the
 * upstream response arrives and h2_proxy_send_response() closes it.          */
#define H2_DISPATCH_PROXY  1

static const char *req_method_str(http_method_t m) {
    switch (m) {
        case HTTP_GET:     return "GET";
        case HTTP_POST:    return "POST";
        case HTTP_PUT:     return "PUT";
        case HTTP_DELETE:  return "DELETE";
        case HTTP_HEAD:    return "HEAD";
        case HTTP_PATCH:   return "PATCH";
        case HTTP_OPTIONS: return "OPTIONS";
        default:           return "UNKNOWN";
    }
}
/* ── Client connection preface (RFC 7540 §3.5) ───────────────────────────── */
static const uint8_t H2_CLIENT_PREFACE[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_CLIENT_PREFACE_LEN 24

/* ── Frame header size ───────────────────────────────────────────────────── */
#define H2_FRAME_HDR_SZ 9

/* ── Default flow control window (RFC 7540 §6.9.2) ──────────────────────── */
#define H2_DEFAULT_WINDOW 65535

/* ── Flood / hardening limits ────────────────────────────────────────────── */
#define H2_MAX_CONTINUATION_BYTES  ((size_t)256 * 1024)   /* 256 KB per header block */
#define H2_MAX_SETTINGS_BURST      200            /* SETTINGS frames per conn */

/* ═══════════════════════════════════════════════════════════════════════════
 * Stream storage — pool (linear) backend
 * ═══════════════════════════════════════════════════════════════════════════*/

static h2_stream_t *pool_find(h2_stream_pool_t *p, uint32_t id) {
    for (int i = 0; i < p->count; i++) {
        if (p->slots[i].id == id &&
            p->slots[i].state != H2_STREAM_CLOSED)
            return &p->slots[i];
    }
    return NULL;
}

static h2_stream_t *pool_create(h2_stream_pool_t *p, uint32_t id,
                                 int32_t initial_window) {
    if (p->count >= H2_MAX_STREAMS) return NULL;
    h2_stream_t *s = &p->slots[p->count++];
    memset(s, 0, sizeof(*s));
    s->id          = id;
    s->state       = H2_STREAM_OPEN;
    s->send_window = initial_window;
    buf_init(&s->body);
    buf_init(&s->header_block);
    buf_init(&s->pending_data);
    s->pending_offset = 0;
    s->pending_body_fd = -1;
    s->pending_body_fd_remaining = 0;
    return s;
}

static void pool_remove(h2_stream_pool_t *p, uint32_t id) {
    for (int i = 0; i < p->count; i++) {
        if (p->slots[i].id == id) {
            buf_free(&p->slots[i].body);
            buf_free(&p->slots[i].pending_data);
            buf_free(&p->slots[i].header_block);
            if (p->slots[i].headers) {
                hpack_headers_free(p->slots[i].headers,
                                   p->slots[i].header_count);
                free(p->slots[i].headers);
                p->slots[i].headers = NULL;
            }
            if (i != p->count - 1)
                p->slots[i] = p->slots[p->count - 1];
            p->count--;
            return;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Stream storage — hashmap backend
 * ═══════════════════════════════════════════════════════════════════════════*/

static int map_init(h2_stream_map_t *m, int capacity) {
    m->capacity = capacity;
    m->count    = 0;
    m->buckets  = (h2_stream_t **)calloc((size_t)capacity, sizeof(h2_stream_t *));
    m->keys     = (uint32_t *)calloc((size_t)capacity, sizeof(uint32_t));
    if (!m->buckets || !m->keys) {
        free((void *)m->buckets);
        free((void *)m->keys);
        return -1;
    }
    return 0;
}

static void map_free_entries(h2_stream_map_t *m) {
    for (int i = 0; i < m->capacity; i++) {
        if (m->keys[i] && m->buckets[i]) {
            buf_free(&m->buckets[i]->body);
            buf_free(&m->buckets[i]->pending_data);
            buf_free(&m->buckets[i]->header_block);
            if (m->buckets[i]->headers) {
                hpack_headers_free(m->buckets[i]->headers,
                                   m->buckets[i]->header_count);
                free(m->buckets[i]->headers);
            }
            free(m->buckets[i]);
        }
    }
    free((void *)m->buckets);
    free((void *)m->keys);
    m->buckets  = NULL;
    m->keys     = NULL;
    m->capacity = 0;
    m->count    = 0;
}

static h2_stream_t *map_find(h2_stream_map_t *m, uint32_t id) {
    int mask = m->capacity - 1;
    int idx  = (int)(id & (uint32_t)mask);
    for (int i = 0; i < m->capacity; i++) {
        int slot = (idx + i) & mask;
        if (m->keys[slot] == 0)   return NULL;
        if (m->keys[slot] == id &&
            m->buckets[slot]->state != H2_STREAM_CLOSED)
            return m->buckets[slot];
    }
    return NULL;
}

static h2_stream_t *map_create(h2_stream_map_t *m, uint32_t id,
                                int32_t initial_window) {
    if (m->count >= m->capacity / 2) return NULL;

    h2_stream_t *s = calloc(1, sizeof(h2_stream_t));
    if (!s) return NULL;
    s->id          = id;
    s->state       = H2_STREAM_OPEN;
    s->send_window = initial_window;
    buf_init(&s->body);
    buf_init(&s->header_block);
    buf_init(&s->pending_data);
    s->pending_offset = 0;
    s->pending_body_fd = -1;
    s->pending_body_fd_remaining = 0;

    int mask = m->capacity - 1;
    int idx  = (int)(id & (uint32_t)mask);
    for (int i = 0; i < m->capacity; i++) {
        int slot = (idx + i) & mask;
        if (m->keys[slot] == 0) {
            m->keys[slot]    = id;
            m->buckets[slot] = s;
            m->count++;
            return s;
        }
    }
    free(s);
    return NULL;
}

static void map_remove(h2_stream_map_t *m, uint32_t id) {
    int mask = m->capacity - 1;
    int idx  = (int)(id & (uint32_t)mask);
    for (int i = 0; i < m->capacity; i++) {
        int slot = (idx + i) & mask;
        if (m->keys[slot] == 0) return;
        if (m->keys[slot] == id) {
            buf_free(&m->buckets[slot]->body);
            buf_free(&m->buckets[slot]->pending_data);
            buf_free(&m->buckets[slot]->header_block);
            if (m->buckets[slot]->headers) {
                hpack_headers_free(m->buckets[slot]->headers,
                                   m->buckets[slot]->header_count);
                free(m->buckets[slot]->headers);
            }
            free(m->buckets[slot]);
            m->buckets[slot] = NULL;
            m->keys[slot]    = 0;
            m->count--;

            int j = (slot + 1) & mask;
            while (m->keys[j]) {
                uint32_t     k = m->keys[j];
                h2_stream_t *v = m->buckets[j];
                m->keys[j]    = 0;
                m->buckets[j] = NULL;
                m->count--;
                int home = (int)(k & (uint32_t)mask);
                for (int n = 0; n < m->capacity; n++) {
                    int ns = (home + n) & mask;
                    if (m->keys[ns] == 0) {
                        m->keys[ns]    = k;
                        m->buckets[ns] = v;
                        m->count++;
                        break;
                    }
                }
                j = (j + 1) & mask;
            }
            return;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Unified stream API
 * ═══════════════════════════════════════════════════════════════════════════*/

static h2_stream_t *stream_find(h2_conn_t *hc, uint32_t id) {
    if (hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP)
        return map_find(&hc->streams.map, id);
    return pool_find(&hc->streams.pool, id);
}

static h2_stream_t *stream_create(h2_conn_t *hc, uint32_t id) {
    int32_t win = (int32_t)hc->initial_send_window;
    if (hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP)
        return map_create(&hc->streams.map, id, win);
    return pool_create(&hc->streams.pool, id, win);
}

static void stream_remove(h2_conn_t *hc, uint32_t id) {
    if (hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP)
        map_remove(&hc->streams.map, id);
    else
        pool_remove(&hc->streams.pool, id);
}

static int stream_count(h2_conn_t *hc) {
    if (hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP)
        return hc->streams.map.count;
    return hc->streams.pool.count;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Frame serialization helpers
 * ═══════════════════════════════════════════════════════════════════════════*/

static int write_frame_hdr(buf_t *buf, uint32_t length,
                            uint8_t type, uint8_t flags, uint32_t sid) {
    uint8_t hdr[H2_FRAME_HDR_SZ];
    hdr[0] = (length >> 16) & 0xff;
    hdr[1] = (length >>  8) & 0xff;
    hdr[2] =  length        & 0xff;
    hdr[3] = type;
    hdr[4] = flags;
    hdr[5] = (sid >> 24) & 0x7f;
    hdr[6] = (sid >> 16) & 0xff;
    hdr[7] = (sid >>  8) & 0xff;
    hdr[8] =  sid        & 0xff;
    return buf_append(buf, hdr, H2_FRAME_HDR_SZ);
}

static int write_settings(buf_t *buf,
                           const uint16_t *ids,
                           const uint32_t *vals,
                           int count) {
    uint32_t payload_len = (uint32_t)(count * 6);
    if (write_frame_hdr(buf, payload_len,
                        H2_FRAME_SETTINGS, 0x0, 0) < 0) return -1;
    for (int i = 0; i < count; i++) {
        uint8_t p[6];
        p[0] = (uint8_t)((ids[i] >> 8) & 0xff);
        p[1] = (uint8_t)(ids[i]        & 0xff);
        p[2] = (uint8_t)((vals[i] >> 24) & 0xff);
        p[3] = (uint8_t)((vals[i] >> 16) & 0xff);
        p[4] = (uint8_t)((vals[i] >>  8) & 0xff);
        p[5] = (uint8_t)(vals[i]         & 0xff);
        if (buf_append(buf, p, 6) < 0) return -1;
    }
    return 0;
}

static int write_settings_ack(buf_t *buf) {
    return write_frame_hdr(buf, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
}

static int write_goaway(buf_t *buf, uint32_t last_stream_id,
                         h2_error_code_t error) {
    if (write_frame_hdr(buf, 8, H2_FRAME_GOAWAY, 0x0, 0) < 0) return -1;
    uint8_t p[8];
    p[0] = (last_stream_id >> 24) & 0x7f;
    p[1] = (last_stream_id >> 16) & 0xff;
    p[2] = (last_stream_id >>  8) & 0xff;
    p[3] =  last_stream_id        & 0xff;
    p[4] = ((uint32_t)error >> 24) & 0xff;
    p[5] = ((uint32_t)error >> 16) & 0xff;
    p[6] = ((uint32_t)error >>  8) & 0xff;
    p[7] =  (uint32_t)error        & 0xff;
    return buf_append(buf, p, 8);
}

static int write_rst_stream(buf_t *buf, uint32_t stream_id,
                              h2_error_code_t error) {
    if (write_frame_hdr(buf, 4, H2_FRAME_RST_STREAM, 0x0, stream_id) < 0)
        return -1;
    uint8_t p[4];
    p[0] = ((uint32_t)error >> 24) & 0xff;
    p[1] = ((uint32_t)error >> 16) & 0xff;
    p[2] = ((uint32_t)error >>  8) & 0xff;
    p[3] =  (uint32_t)error        & 0xff;
    return buf_append(buf, p, 4);
}

static int write_window_update(buf_t *buf, uint32_t stream_id,
                                uint32_t increment) {
    if (write_frame_hdr(buf, 4, H2_FRAME_WINDOW_UPDATE,
                        0x0, stream_id) < 0) return -1;
    uint8_t p[4];
    p[0] = (increment >> 24) & 0x7f;
    p[1] = (increment >> 16) & 0xff;
    p[2] = (increment >>  8) & 0xff;
    p[3] =  increment        & 0xff;
    return buf_append(buf, p, 4);
}

static int write_ping_ack(buf_t *buf, const uint8_t *payload) {
    if (write_frame_hdr(buf, 8, H2_FRAME_PING, H2_FLAG_ACK, 0) < 0)
        return -1;
    return buf_append(buf, payload, 8);
}

/* ── PUSH_PROMISE serialization ──────────────────────────────────────────── */

/* Write a PUSH_PROMISE frame.
 * promised_id: the server-initiated (even) stream ID being promised.
 * hdr_block / hdr_len: HPACK-encoded request headers for the promised req. */
static int write_push_promise(buf_t *buf, uint32_t stream_id,
                               uint32_t promised_id,
                               const uint8_t *hdr_block, size_t hdr_len) {
    /* payload = 4-byte promised stream ID + encoded header block          */
    uint32_t pay_len = 4 + (uint32_t)hdr_len;
    if (write_frame_hdr(buf, pay_len,
                        H2_FRAME_PUSH_PROMISE,
                        H2_FLAG_END_HEADERS,
                        stream_id) < 0) return -1;
    uint8_t p[4];
    p[0] = (promised_id >> 24) & 0x7f;   /* R bit = 0 */
    p[1] = (promised_id >> 16) & 0xff;
    p[2] = (promised_id >>  8) & 0xff;
    p[3] =  promised_id        & 0xff;
    if (buf_append(buf, p, 4) < 0) return -1;
    return buf_append(buf, hdr_block, hdr_len);
}

/* ── 103 Early Hints serialization ──────────────────────────────────────── */

/* Write a 103 Early Hints response as an HTTP/2 HEADERS frame.
 * hints: array of Link header values (e.g. "</style.css>; rel=preload")
 * n:     number of hints                                                    */


/* ═══════════════════════════════════════════════════════════════════════════
 * h2_conn_new
 * ═══════════════════════════════════════════════════════════════════════════*/

h2_conn_t *h2_conn_new(struct conn *conn, const routa_h2_config_t *cfg) {
    h2_conn_t *hc = calloc(1, sizeof(h2_conn_t));
    if (!hc) return NULL;
    hc->conn         = conn;
    hc->lookup_mode  = cfg->stream_lookup;
    hc->send_window         = H2_DEFAULT_WINDOW;
    hc->recv_window         = (int32_t)cfg->initial_window_size;
    hc->initial_send_window = H2_DEFAULT_WINDOW;
    hc->cfg_stream_timeout_ms    = cfg->stream_timeout_ms    > 0
                                   ? (uint32_t)cfg->stream_timeout_ms    : 30000;
    hc->cfg_keepalive_timeout_ms = cfg->keepalive_timeout_ms > 0
                                   ? (uint32_t)cfg->keepalive_timeout_ms : 120000;
    hc->max_concurrent_streams       = cfg->max_concurrent_streams;
    hc->peer_header_table_size      = 4096;
    hc->peer_max_concurrent_streams = 128;
    hc->peer_max_frame_size         = 16384;
    hc->peer_initial_window_size    = H2_DEFAULT_WINDOW;
    hc->push_enabled          = cfg->server_push_enabled;
    hc->next_push_stream_id   = 2;

    /* Push: enabled by default, client may disable via SETTINGS           */
    hc->push_enabled = cfg->server_push_enabled;
    hc->next_push_stream_id = 2;   /* server-initiated streams are even    */

    if (hpack_ctx_init(&hc->hpack_rx, cfg->header_table_size,
                      0, 0,
                      cfg->max_header_list_size) < 0) goto fail;
    if (hpack_ctx_init(&hc->hpack_tx, cfg->header_table_size,
                       cfg->huffman_encoding,
                       cfg->dynamic_table_update,
                       cfg->max_header_list_size) < 0) goto fail;

    if (hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP) {
        int cap = 1;
        while (cap < (int)cfg->max_concurrent_streams * 2) cap <<= 1;
        if (map_init(&hc->streams.map, cap) < 0) goto fail;
    }

    buf_init(&hc->write_buf);

    /* RFC 8441 3: always advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1.
     * Harmless for clients that never attempt WebSocket-over-H2 (they
     * simply ignore an unrecognized-to-them capability), and required
     * for any that do -- browsers will not attempt Extended CONNECT for
     * WS without seeing this advertised first. */
    uint16_t ids[6] = {
        H2_SETTINGS_HEADER_TABLE_SIZE,
        H2_SETTINGS_MAX_CONCURRENT_STREAMS,
        H2_SETTINGS_INITIAL_WINDOW_SIZE,
        H2_SETTINGS_MAX_FRAME_SIZE,
        H2_SETTINGS_MAX_HEADER_LIST_SIZE,
        H2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    };
    uint32_t vals[6] = {
        cfg->header_table_size,
        cfg->max_concurrent_streams,
        cfg->initial_window_size,
        cfg->max_frame_size,
        cfg->max_header_list_size,
        1,
    };
    hc->our_max_frame_size = cfg->max_frame_size;
    if (write_settings(&hc->write_buf, ids, vals, 6) < 0) goto fail;
    hc->settings_ack_pending = 1;

    /* Connection-level recv window advertisement (one-time)               */
    write_window_update(&hc->write_buf, 0, 1048576);
    /* Initialize timeout tracking */
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    uint64_t _now = (uint64_t)_ts.tv_sec * 1000ULL + (uint64_t)_ts.tv_nsec / 1000000ULL;
    hc->last_recv_ts   = _now;
    hc->last_stream_ts = _now;
    return hc;

fail:
    h2_conn_free(hc);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2_conn_free
 * ═══════════════════════════════════════════════════════════════════════════*/

void h2_conn_free(h2_conn_t *hc) {
    if (!hc) return;

    hpack_ctx_free(&hc->hpack_rx);
    hpack_ctx_free(&hc->hpack_tx);

    if (hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP) {
        map_free_entries(&hc->streams.map);
    } else {
        for (int i = 0; i < hc->streams.pool.count; i++) {
            h2_stream_t *s = &hc->streams.pool.slots[i];
            buf_free(&s->body);
            buf_free(&s->pending_data);
            buf_free(&s->header_block);
            if (s->headers) {
                hpack_headers_free(s->headers, s->header_count);
                free(s->headers);
            }
        }
    }

    buf_free(&hc->write_buf);
    free(hc);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Frame reader helpers
 * ═══════════════════════════════════════════════════════════════════════════*/

static uint32_t frame_length(const uint8_t *hdr) {
    return ((uint32_t)hdr[0] << 16) |
           ((uint32_t)hdr[1] <<  8) |
            (uint32_t)hdr[2];
}

static uint8_t  frame_type(const uint8_t *hdr)  { return hdr[3]; }
static uint8_t  frame_flags(const uint8_t *hdr)  { return hdr[4]; }
static uint32_t frame_stream(const uint8_t *hdr) {
    return (((uint32_t)hdr[5] & 0x7f) << 24) |
            ((uint32_t)hdr[6] << 16) |
            ((uint32_t)hdr[7] <<  8) |
             (uint32_t)hdr[8];
}

static int conn_error(h2_conn_t *hc, h2_error_code_t code) {
    if (!hc->goaway_sent) {
        /* Rate-limited log */
        LOG_WARN("h2: connection error code=%u stream=%u",
                 (unsigned)code, hc->last_stream_id);
        ROUTA_METRIC_INC(h2_goaway_sent_total);
        write_goaway(&hc->write_buf, hc->last_stream_id, code);
        hc->goaway_sent = 1;
    }
    hc->error = 1;
    return -1;
}

/* ── Frame handlers ──────────────────────────────────────────────────────── */

static int handle_settings(h2_conn_t *hc,
                            const uint8_t *payload, uint32_t length,
                            uint8_t flags, uint32_t stream_id) {
    /* RFC 7540 6.5: SETTINGS always applies to the whole connection, so
     * its stream identifier MUST be 0x0 -- h2spec 6.5#2 confirmed this
     * wasn't checked at all. */
    if (stream_id != 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if (flags & H2_FLAG_ACK) {
        if (length != 0)
            return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
        hc->settings_ack_pending = 0;
        return 0;
    }

    /* FIX: SETTINGS flood protection                                      */
    hc->settings_recv_count++;
    if (hc->settings_recv_count > H2_MAX_SETTINGS_BURST)
        return conn_error(hc, H2_ERR_ENHANCE_YOUR_CALM);

    if (length % 6 != 0)
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

    for (uint32_t i = 0; i < length; i += 6) {
        uint16_t id = (uint16_t)(((uint16_t)payload[i] << 8) | (uint16_t)payload[i+1]);
        uint32_t val = ((uint32_t)payload[i+2] << 24) |
                       ((uint32_t)payload[i+3] << 16) |
                       ((uint32_t)payload[i+4] <<  8) |
                        (uint32_t)payload[i+5];
        switch (id) {
        case H2_SETTINGS_HEADER_TABLE_SIZE:
            hc->peer_header_table_size = val;
            hpack_dynamic_table_resize(&hc->hpack_tx, val);
            break;
            case H2_SETTINGS_ENABLE_PUSH:
                if (val > 1) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
                if (val == 0) hc->push_enabled = 0;
                break;
        case H2_SETTINGS_MAX_CONCURRENT_STREAMS:
            hc->peer_max_concurrent_streams = val;
            break;
            case H2_SETTINGS_INITIAL_WINDOW_SIZE:
                if (val > 0x7fffffff)
                    return conn_error(hc, H2_ERR_FLOW_CONTROL_ERROR);
            {
            int32_t delta = (int32_t)val -
                            (int32_t)hc->peer_initial_window_size;
            hc->peer_initial_window_size = val;
            hc->initial_send_window      = val;
            /* ── EKLE: connection-level send window'u da güncelle ── */
            {
                /* RFC 7540 6.9.2: adjusting SETTINGS_INITIAL_WINDOW_SIZE can
                 * push a stream's or the connection's send_window above
                 * 2^31-1. send_window is int32_t, so checking AFTER the
                 * add (as the old code did: "hc->send_window += delta; if
                 * (hc->send_window > 0x7fffffff)") is a signed-integer-
                 * overflow check performed on a value that already
                 * overflowed -- 0x7fffffff (INT32_MAX) is the maximum
                 * possible int32_t value, so a real overflow wraps to
                 * negative and this comparison can never be true (this is
                 * why h2spec's "SETTINGS_INITIAL_WINDOW_SIZE ... window to
                 * be negative" test failed: the overflow was silently
                 * accepted instead of triggering FLOW_CONTROL_ERROR).
                 * Compute in a wider (int64_t) type and validate BEFORE
                 * narrowing back to int32_t. */
                int64_t wide = (int64_t)hc->send_window + (int64_t)delta;
                if (wide > 0x7fffffffLL)
                    return conn_error(hc, H2_ERR_FLOW_CONTROL_ERROR);
                hc->send_window = (int32_t)wide;
            }
            /* stream window'ları güncelle */
            if (hc->lookup_mode == H2_STREAM_LOOKUP_LINEAR) {
                for (int j = 0; j < hc->streams.pool.count; j++)
                    hc->streams.pool.slots[j].send_window += delta;
            } else {
                for (int j = 0; j < hc->streams.map.capacity; j++) {
                    if (hc->streams.map.keys[j])
                        hc->streams.map.buckets[j]->send_window += delta;
                }
            }
            }
                break;
        case H2_SETTINGS_MAX_FRAME_SIZE:
            if (val < 16384 || val > 16777215)
                return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
            hc->peer_max_frame_size = val;
            break;
        case H2_SETTINGS_MAX_HEADER_LIST_SIZE:  // NOLINT(bugprone-branch-clone)
            /* not used */
            break;
        default:
            /* unknown settings are ignored */
            break;
        }
    }

    if (write_settings_ack(&hc->write_buf) < 0) return -1;
    /* BUG FIX (h2spec 6.9.2#1): a peer's SETTINGS_INITIAL_WINDOW_SIZE
     * change can immediately unblock streams that were previously
     * flow-control-stalled (send_window <= 0, data queued in
     * s->pending_data waiting for room) -- the case block above already
     * grows every stream's send_window by the resulting delta, but
     * nothing was ever queued to actually FLUSH that now-unblocked
     * pending data. It only went out later if/when a POLLER_WRITE event
     * happened to fire independently (see h2_conn_flush_pending()'s
     * other call site in event_loop.c) -- which, on a connection that's
     * otherwise idle from the socket's point of view right after this
     * SETTINGS frame, may not happen for a long time or at all within a
     * test's timeout. Flushing here makes the unblock immediate, as RFC
     * 7540 6.9.2 implies ("the endpoint MUST adjust the size of all
     * stream flow-control windows that it maintains by the difference"
     * -- adjusting the window without ever using the newly-available
     * room to send is not a meaningful adjustment from the peer's
     * observable point of view). */
    h2_conn_flush_pending(hc);
    return 0;
}

static int handle_ping(h2_conn_t *hc, const uint8_t *payload,
                        uint32_t length, uint8_t flags, uint32_t stream_id) {
    if (stream_id != 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if (length != 8)    return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
    if (flags & H2_FLAG_ACK) return 0;
    return write_ping_ack(&hc->write_buf, payload);
}

static void flush_pending(h2_conn_t *hc, h2_stream_t *s) {
    if (s->pending_data.len == 0 && s->pending_body_fd < 0) return;

    if (s->pending_data.len > 0) {
        size_t rem = s->pending_data.len - s->pending_offset;
        const uint8_t *ptr = (const uint8_t *)buf_data(&s->pending_data)
                         + s->pending_offset;
        while (rem > 0) {
            int32_t conn_win   = hc->send_window;
            int32_t stream_win = s->send_window;
            int32_t win        = conn_win < stream_win ? conn_win : stream_win;
            if (win <= 0) return;
            size_t can_send = (size_t)win < rem ? (size_t)win : rem;
            size_t chunk    = can_send < hc->peer_max_frame_size
                              ? can_send : hc->peer_max_frame_size;
            /* ROOT CAUSE FIX (see investigation report): END_STREAM here
             * was computed as "this is the last chunk of pending_data AND
             * the body_fd is already closed" -- but pending_body_fd is
             * only set to -1 much later, in this same function's cleanup
             * block, strictly after this drain completes. On the specific
             * (and, under TLS, fairly common) timing where a flow-control
             * stall lands inside the FINAL read() of the file --
             * pending_body_fd_remaining reaches exactly 0 at the same
             * moment the unsent tail is stashed into pending_data --
             * pending_body_fd is still >= 0 here (correctly: the fd isn't
             * closed yet), so `end` was wrongly false on the true last
             * DATA frame of the response. The stream was then torn down
             * (see the pending_data==0 && pending_body_fd<0 check further
             * down) without ever having sent END_STREAM, leaving the
             * client waiting forever despite having received every byte
             * of the body. The correct condition is "no bytes left
             * anywhere" -- pending_body_fd already closed, OR nothing
             * left to read from disk even though the fd is still open. */
            int end = (chunk == rem) &&
                      (s->pending_body_fd < 0 || s->pending_body_fd_remaining == 0);
            if (write_frame_hdr(&hc->write_buf, (uint32_t)chunk,
                                H2_FRAME_DATA,
                                end ? H2_FLAG_END_STREAM : 0,
                                s->id) < 0) return;
            if (buf_append(&hc->write_buf, ptr, chunk) < 0) return;
            hc->send_window   -= (int32_t)chunk;
            s->send_window    -= (int32_t)chunk;
            s->pending_offset += chunk;
            ptr += chunk;
            rem -= chunk;
        }
        if (s->pending_offset >= s->pending_data.len) {
            buf_reset(&s->pending_data);
            s->pending_offset = 0;
        } else {
            return;
        }
    }

    /* Cap how much we stuff into hc->write_buf per call -- send_response()
     * (h2.c's main body_fd path) and h2_conn_flush() both enforce/expect
     * write_buf to stay under H2_WRITE_BUF_SOFT_LIMIT; without this check
     * a single flush_pending() call for a large file (e.g. a 20MB video)
     * would keep reading and appending as long as the flow-control window
     * allowed, blowing straight through h2_conn_flush()'s 4MB hard cap
     * (H2_ERR_ENHANCE_YOUR_CALM connection abort) before the socket ever
     * got a chance to drain any of it. Instead, stop once write_buf has a
     * healthy amount queued and let the normal POLLER_WRITE -> h2_conn_flush
     * -> h2_conn_flush_pending cycle (see event_loop.c) drain it and come
     * back for more. */
    #define H2_WRITE_BUF_SOFT_LIMIT (1024 * 1024)
    while (s->pending_body_fd >= 0 && s->pending_body_fd_remaining > 0) {
        if (hc->write_buf.len >= H2_WRITE_BUF_SOFT_LIMIT) {
            /* Use worker_conn_flush(), not a bare h2_conn_flush() --
             * h2_conn_flush() only writes to the socket, it never
             * touches the connection's epoll registration. If write_buf
             * fully drains here, the connection's poller interest could
             * be left in whatever state it was in when we got here
             * (potentially POLLER_WRITE-only, with no POLLER_READ, if
             * that's what an earlier code path had armed) -- silently
             * orphaning the fd from ever being polled for read again
             * (confirmed via strace: exactly this call pattern preceded
             * a connection receiving zero further read/write/epoll_ctl
             * syscalls for the rest of its life, until the peer's own
             * timeout closed it). worker_conn_flush() re-arms POLLER_READ
             * (and POLLER_WRITE if still needed) correctly in all cases. */
            if (hc->worker) worker_conn_flush((worker_t *)hc->worker, hc->conn);
            if (hc->write_buf.len >= H2_WRITE_BUF_SOFT_LIMIT) return; /* genuinely stalled, wait for real event */
        }

        int32_t conn_win   = hc->send_window;
        int32_t stream_win = s->send_window;
        int32_t win        = conn_win < stream_win ? conn_win : stream_win;
        if (win <= 0) return;

        uint8_t fbuf[65536];
        size_t want = s->pending_body_fd_remaining;
        if (want > sizeof(fbuf)) want = sizeof(fbuf);

        ssize_t nr = read(s->pending_body_fd, fbuf, want);
        if (nr <= 0) {
            close(s->pending_body_fd);
            s->pending_body_fd = -1;
            s->pending_body_fd_remaining = 0;
            break;
        }

        size_t rem = (size_t)nr;
        const uint8_t *ptr = fbuf;
        while (rem > 0) {
            conn_win   = hc->send_window;
            stream_win = s->send_window;
            win        = conn_win < stream_win ? conn_win : stream_win;
            if (win <= 0) {
                /* ROOT CAUSE FIX (round 2 investigation, confirmed via
                 * live instrumentation): rem bytes were already read()
                 * from disk as part of this nr-byte read() -- the fd's
                 * file position has already advanced past them, they are
                 * NOT "still on disk to be read again." The previous
                 * comment here claimed pending_body_fd_remaining must NOT
                 * be decremented for these bytes, reasoning that only
                 * bytes actually chunked into a DATA frame should count
                 * against it -- that reasoning was wrong. It caused
                 * pending_body_fd_remaining to permanently leak by `rem`
                 * bytes on every stall-mid-read event, since these bytes
                 * are consumed from the fd but never subtracted anywhere.
                 * Confirmed by live trace: across one failing 20MB H2-
                 * over-TLS transfer, the cumulative leak across 319 stall
                 * events summed to exactly 10,504,032 bytes -- bit-for-
                 * bit identical to the bogus "remaining" value logged at
                 * the moment the fd legitimately hit real EOF. Because
                 * pending_body_fd_remaining never reached 0 while the fd
                 * was still open, the nr<=0 EOF branch a few lines below
                 * silently closed the fd and zeroed the counter without
                 * ever emitting END_STREAM -- despite every real byte of
                 * the file having already been sent in DATA frames. This
                 * mirrors send_response()'s OWN correct sibling logic
                 * (its equivalent stash site subtracts total-offset-nr,
                 * i.e. the ENTIRE current read, sent and unsent portions
                 * alike) -- this copy is now brought in line with that. */
                s->pending_body_fd_remaining -= rem;
                if (buf_append(&s->pending_data, ptr, rem) < 0) return;
                s->pending_offset = 0;
                return;
            }
            size_t can_send = (size_t)win < rem ? (size_t)win : rem;
            size_t chunk    = can_send < hc->peer_max_frame_size
                              ? can_send : hc->peer_max_frame_size;
            s->pending_body_fd_remaining -= chunk;
            int end = (chunk == rem) && s->pending_body_fd_remaining == 0;
            if (write_frame_hdr(&hc->write_buf, (uint32_t)chunk,
                                H2_FRAME_DATA,
                                end ? H2_FLAG_END_STREAM : 0,
                                s->id) < 0) return;
            if (buf_append(&hc->write_buf, ptr, chunk) < 0) return;
            hc->send_window   -= (int32_t)chunk;
            s->send_window    -= (int32_t)chunk;
            ptr += chunk;
            rem -= chunk;
        }
    }

    if (s->pending_body_fd >= 0 && s->pending_body_fd_remaining == 0) {
        close(s->pending_body_fd);
        s->pending_body_fd = -1;
    }

    /* Always attempt a flush before returning, regardless of which path
     * got us here (pending_data drained, body_fd resume drained, or
     * mid-stream after queuing more DATA frames). Uses worker_conn_flush()
     * rather than a bare h2_conn_flush() -- see the matching comment in
     * handle_window_update() for why a partial TLS flush needs the
     * poller re-armed for POLLER_WRITE, not just a single write attempt. */
    if (hc->write_buf.len > 0 && hc->worker) {
        worker_conn_flush((worker_t *)hc->worker, hc->conn);
    }

    if (s->pending_data.len == 0 && s->pending_body_fd < 0 &&
        s->state == H2_STREAM_HALF_CLOSED_REMOTE) {
        s->state = H2_STREAM_CLOSED;
        stream_remove(hc, s->id);
    }
}
/* BUG FIX (H2 stall investigation): this used to iterate hc->streams.pool
 * (or .map) directly by index while calling flush_pending() -- but
 * flush_pending() can, on completing a stream, call stream_remove() on
 * it, which for the LINEAR/pool backend does a swap-with-last removal
 * (pool_remove(): the struct at the last live index is copied down into
 * the just-removed index to keep the array packed) and for the HASHMAP
 * backend does a backward-shift deletion (map_remove()) -- both mutate
 * the very container this loop is walking, out from under it, mid-sweep.
 * Concretely (pool backend): if stream at index i finishes and gets
 * removed, the stream that was previously at the LAST index (which this
 * forward loop hasn't visited yet this pass) gets moved down into index
 * i -- an index the loop already passed. The loop's `i < count` bound
 * (re-read fresh each iteration, so it correctly shrinks) still lets it
 * finish "normally", but it silently never revisits index i again this
 * pass, so the just-moved-in stream's still-pending data (if any) never
 * gets a flush_pending() call this sweep. If that stream has no other
 * pending per-stream WINDOW_UPDATE incoming (the client, from its own
 * point of view, is just waiting on bytes it already granted window
 * for), NOTHING ever revisits it again -- confirmed live: with >=2
 * concurrent large-file streams sharing one connection's flow-control
 * window, this reliably (if intermittently -- exact timing-dependent)
 * left a stream permanently stuck in H2_STREAM_HALF_CLOSED_REMOTE with
 * unflushed pending_data/pending_body_fd: routa_h2_active_streams stayed
 * elevated forever, with zero GOAWAY, zero protocol error, and (proving
 * flush_pending() was never even CALLED for the stuck stream, as
 * opposed to being called and stalling again inside it) zero hits on
 * debug instrumentation placed inside every one of flush_pending()'s own
 * `win <= 0` branches.
 *
 * Fix: snapshot every candidate stream's ID into a fixed-size array
 * FIRST, while the container is still untouched, then re-look-up each
 * ID (via the backend-agnostic stream_find()) and flush it. A stream
 * that closes and is removed mid-sweep by an earlier flush_pending()
 * call simply won't be found on its later turn (stream_find() returns
 * NULL for a closed/removed ID) and is skipped safely -- no
 * already-queued-but-not-yet-visited stream can ever be silently
 * dropped, because the ID list itself doesn't change once captured,
 * regardless of how the underlying pool/map array gets shuffled by
 * removals during the sweep. */
void h2_conn_flush_pending(h2_conn_t *hc) {
    if (!hc || hc->send_window <= 0) return;

    uint32_t ids[H2_MAX_STREAMS];
    int      n_ids = 0;

    if (hc->lookup_mode == H2_STREAM_LOOKUP_LINEAR) {
        for (int i = 0; i < hc->streams.pool.count && n_ids < H2_MAX_STREAMS; i++) {
            h2_stream_t *s = &hc->streams.pool.slots[i];
            if (s->pending_data.len > s->pending_offset || s->pending_body_fd >= 0)
                ids[n_ids++] = s->id;
        }
    } else {
        for (int i = 0; i < hc->streams.map.capacity && n_ids < H2_MAX_STREAMS; i++) {
            if (!hc->streams.map.keys[i]) continue;
            h2_stream_t *s = hc->streams.map.buckets[i];
            if (s->pending_data.len > s->pending_offset || s->pending_body_fd >= 0)
                ids[n_ids++] = s->id;
        }
    }

    for (int i = 0; i < n_ids; i++) {
        h2_stream_t *s = stream_find(hc, ids[i]);
        if (s && (s->pending_data.len > s->pending_offset || s->pending_body_fd >= 0))
            flush_pending(hc, s);
    }
}
/* RFC 7540 5.1: a frame referencing a stream ID that has never been
 * opened (greater than the highest stream ID seen so far) targets an
 * IDLE stream. Receiving DATA, RST_STREAM, or WINDOW_UPDATE for an idle
 * stream MUST be a CONNECTION error of type PROTOCOL_ERROR (h2spec
 * 5.1#1/#2/#3), distinct from a stream that was legitimately opened and
 * has since closed (a lenient stream-level response is fine there --
 * previously both cases were treated identically via stream_find()
 * returning NULL for both). */
static int is_idle_stream(h2_conn_t *hc, uint32_t stream_id) {
    return stream_id > hc->last_stream_id;
}

/* RFC 7540 6.3: a standalone PRIORITY frame. Previously not validated at
 * all (dispatch simply did `case H2_FRAME_PRIORITY: break;`, silently
 * accepting anything) -- h2spec 6.3#1/#2 and 5.3.1#2 confirmed this let
 * through a zero stream_id, a wrong-length payload, and a stream
 * depending on itself, none of which should ever reach the application. */
static int handle_priority(h2_conn_t *hc, const uint8_t *payload,
                            uint32_t length, uint32_t stream_id) {
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if (length != 5)    return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

    uint32_t dependency = (((uint32_t)payload[0] & 0x7f) << 24) |
                          ((uint32_t)payload[1] << 16) |
                          ((uint32_t)payload[2] <<  8) |
                           (uint32_t)payload[3];
    /* RFC 7540 5.3.1: a stream cannot depend on itself. */
    if (dependency == stream_id) {
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_PROTOCOL_ERROR);
        return 0;
    }
    return 0;
}

static int handle_window_update(h2_conn_t *hc, const uint8_t *payload,
                                 uint32_t length, uint32_t stream_id) {
    if (length != 4) return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
    if (stream_id != 0 && is_idle_stream(hc, stream_id))
        return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    uint32_t increment = (((uint32_t)payload[0] & 0x7f) << 24) |
                          ((uint32_t)payload[1] << 16) |
                          ((uint32_t)payload[2] <<  8) |
                           (uint32_t)payload[3];
    if (increment == 0) {
        if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_PROTOCOL_ERROR);
        return 0;
    }

    /* Same wide-type-then-narrow overflow check as the SETTINGS path
     * above (see that comment) -- checking send_window AFTER adding to it
     * in-place, as int32_t, cannot detect an overflow because a real
     * overflow already wrapped the value before the comparison runs.
     * RFC 7540 6.9.1: a client can legally send WINDOW_UPDATE increments
     * that are individually valid (up to 2^31-1 each) but whose
     * cumulative sum pushes the window over 2^31-1 -- this MUST be
     * rejected with FLOW_CONTROL_ERROR, not silently wrapped into an
     * undefined/garbage window value (confirmed via h2spec 6.9.1#2/#3,
     * and observed directly in this session: repeated large
     * WINDOW_UPDATEs from curl drove hc->send_window into the billions,
     * which is exactly this unchecked overflow -- a strong suspect for
     * this session's still-unresolved H2-over-TLS large-file race
     * condition, since a wrapped/garbage window value feeding into every
     * subsequent min(conn_win, stream_win) flow-control decision would
     * produce exactly the kind of nondeterministic, hard-to-reproduce
     * stalls observed). */
    if (stream_id == 0) {
        int64_t wide = (int64_t)hc->send_window + (int64_t)increment;
        if (wide > 0x7fffffffLL)
            return conn_error(hc, H2_ERR_FLOW_CONTROL_ERROR);
        hc->send_window = (int32_t)wide;
    } else {
        h2_stream_t *s = stream_find(hc, stream_id);
        if (s) {
            int64_t wide = (int64_t)s->send_window + (int64_t)increment;
            if (wide > 0x7fffffffLL) {
                write_rst_stream(&hc->write_buf, stream_id,
                                 H2_ERR_FLOW_CONTROL_ERROR);
            } else {
                s->send_window = (int32_t)wide;
            }
        }
    }

    /* NOTE: also check pending_body_fd, not just pending_data -- a stream
     * can be stalled purely on a body_fd resume (e.g. the write_buf
     * soft-limit path in send_response()/flush_pending()) with an empty
     * pending_data buffer. Without this, a WINDOW_UPDATE for such a
     * stream never re-invoked flush_pending(), leaving the response
     * stalled forever even once the peer granted more flow-control
     * window (this was the actual root cause of large H2 responses
     * hanging indefinitely just past the write_buf soft limit). */
    /* BUG FIX (H2 stall investigation): same sweep-vs-mutation bug as
     * h2_conn_flush_pending() (see that function's doc comment for the
     * full mechanism) -- this connection-level WINDOW_UPDATE branch is
     * in fact the actual workhorse that was hitting it in practice: a
     * multi-stream connection with a small shared connection-level
     * send_window (H2_DEFAULT_WINDOW = 65535 bytes) stalls nearly every
     * concurrent large-file stream almost immediately, and this sweep
     * (triggered on every client WINDOW_UPDATE(stream=0) frame) is what
     * drives ALL of their forward progress from then on -- making it the
     * highest-traffic sweep site and the most likely to hit the
     * skip-on-removal bug. Fixed the same way: snapshot stream IDs
     * before flushing any of them, then re-look-up each by ID (safe
     * against pool/hashmap mutation from an earlier flush_pending() call
     * in this same loop removing a completed stream out from under a
     * live index). */
    if (stream_id == 0) {
        uint32_t ids[H2_MAX_STREAMS];
        int      n_ids = 0;

        if (hc->lookup_mode == H2_STREAM_LOOKUP_LINEAR) {
            for (int i = 0; i < hc->streams.pool.count && n_ids < H2_MAX_STREAMS; i++) {
                h2_stream_t *ps = &hc->streams.pool.slots[i];
                if (ps->pending_data.len > ps->pending_offset || ps->pending_body_fd >= 0)
                    ids[n_ids++] = ps->id;
            }
        } else {
            for (int i = 0; i < hc->streams.map.capacity && n_ids < H2_MAX_STREAMS; i++) {
                if (!hc->streams.map.keys[i]) continue;
                h2_stream_t *ps = hc->streams.map.buckets[i];
                if (ps->pending_data.len > ps->pending_offset || ps->pending_body_fd >= 0)
                    ids[n_ids++] = ps->id;
            }
        }

        for (int i = 0; i < n_ids; i++) {
            h2_stream_t *ps = stream_find(hc, ids[i]);
            if (ps && (ps->pending_data.len > ps->pending_offset || ps->pending_body_fd >= 0))
                flush_pending(hc, ps);
        }
    } else {
        h2_stream_t *ps = stream_find(hc, stream_id);
        if (ps && (ps->pending_data.len > ps->pending_offset || ps->pending_body_fd >= 0))
            flush_pending(hc, ps);
    }
    /* flush_pending() only enqueues DATA frames into hc->write_buf -- it
     * never writes to the actual socket (only its own internal soft-limit
     * check does, and only once write_buf crosses ~1MB). A WINDOW_UPDATE
     * that resumes a body_fd transfer near its end can leave a
     * perfectly well-formed, fully-queued response (including the
     * END_STREAM-flagged final DATA frame) sitting in write_buf
     * indefinitely if nothing else forces a flush before the next real
     * socket-write event -- which, on an already-writable loopback
     * socket under edge-triggered epoll, may never arrive. This was the
     * actual root cause of H2-over-TLS large file/video downloads
     * completing all their internal bookkeeping (END_STREAM flag set,
     * pending_body_fd drained to 0) but the client never receiving the
     * final bytes. Flush eagerly here whenever this WINDOW_UPDATE caused
     * anything to be queued. */
    /* Use worker_conn_flush() instead of a bare h2_conn_flush() call --
     * on TLS connections, a single flush attempt here can be a PARTIAL
     * flush (SSL_write hitting SSL_ERROR_WANT_WRITE mid-buffer, far more
     * likely under TLS's extra encrypt/memcpy overhead than on a raw
     * socket, which is why this only reproduced over TLS and not h2c).
     * A bare h2_conn_flush() call has no way to re-arm the poller for
     * POLLER_WRITE if it can't finish, so any bytes left in write_buf
     * after a partial flush here just sat forever with nothing watching
     * for the socket to become writable again -- this was the root cause
     * of the ~80% failure rate on large (>1MB) H2-over-TLS responses.
     * worker_conn_flush() (event_loop.c) already handles exactly this:
     * flush, and if write_buf.len is still > 0 afterward, re-register
     * POLLER_WRITE. */
    if (hc->write_buf.len > 0 && hc->worker) {
        worker_conn_flush((worker_t *)hc->worker, hc->conn);
    }
    return 0;
}

static int handle_rst_stream(h2_conn_t *hc, const uint8_t *payload,
                              uint32_t length, uint32_t stream_id) {
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if (length != 4)    return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
    if (is_idle_stream(hc, stream_id))
        return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    uint32_t error_code = ((uint32_t)payload[0] << 24) |
                          ((uint32_t)payload[1] << 16) |
                          ((uint32_t)payload[2] <<  8) |
                           (uint32_t)payload[3];
    (void)error_code;

    h2_stream_t *s = stream_find(hc, stream_id);
    if (s) {
        ROUTA_METRIC_INC(h2_rst_streams_total);
        buf_reset(&s->pending_data);
        s->pending_offset = 0;
        /* Close any in-flight body_fd (e.g. a large static file transfer
         * stalled on flow control) instead of leaking the fd -- the
         * client is telling us it no longer wants this stream's data,
         * same as the pending_data buffer being discarded above. */
        if (s->pending_body_fd >= 0) {
            close(s->pending_body_fd);
            s->pending_body_fd = -1;
            s->pending_body_fd_remaining = 0;
        }
        s->state = H2_STREAM_CLOSED;
        stream_remove(hc, stream_id);
    }
    return 0;
}

static int handle_goaway(h2_conn_t *hc, const uint8_t *payload,
                          uint32_t length) {
    hc->goaway_received = 1;
    (void)payload;
    (void)length;
    return -1;
}

/* ── Build http_request_t from decoded HPACK headers ────────────────────── */
/* RFC 7540 §8.1.2.1/§8.1.2.3/§8.1.2.6 request validation.
 *
 * Prior to this fix, stream_to_request() accepted essentially any header
 * block: missing/duplicate/malformed pseudo-headers, pseudo-headers
 * arriving after regular headers, unknown pseudo-headers, connection-
 * specific headers (forbidden in H2), a "te" value other than "trailers",
 * and a content-length that didn't match the actual body -- all were
 * silently accepted and dispatched to the application as if the request
 * were well-formed (confirmed via h2spec section 8.1.2.1/.2/.3/.6, all
 * failing before this fix: expected GOAWAY/RST_STREAM PROTOCOL_ERROR,
 * actual was a normal 2xx response). Returns 0 if the header block is
 * valid, -1 if it must be rejected with a stream-level PROTOCOL_ERROR
 * (caller does the actual RST_STREAM/error bookkeeping -- this function
 * only validates). */
static int validate_request_headers(h2_stream_t *s) {
    int seen_method = 0, seen_scheme = 0, seen_path = 0, seen_authority = 0;
    int seen_protocol = 0, seen_regular_header = 0;
    int is_connect = 0;
    const char *path_value = NULL;

    for (int i = 0; i < s->header_count; i++) {
        const char *name  = s->headers[i].name;
        const char *value = s->headers[i].value;
        if (!name) continue;

        /* RFC 7540 8.1.2: header field names MUST be lowercase (this
         * applies to pseudo-headers too, though in practice HPACK huffman
         * decoding of a compliant client never produces uppercase -- an
         * uppercase name here means the client deliberately sent one). */
        for (const char *p = name; *p; p++) {
            if (*p >= 'A' && *p <= 'Z') return -1;
        }

        if (name[0] == ':') {
            /* RFC 7540 8.1.2.1: all pseudo-headers MUST appear before any
             * regular header field in the block. */
            if (seen_regular_header) return -1;

            if (strcmp(name, ":method") == 0) {
                if (seen_method) return -1;
                seen_method = 1;
                if (value && strcmp(value, "CONNECT") == 0) is_connect = 1;
            } else if (strcmp(name, ":scheme") == 0) {
                if (seen_scheme) return -1;
                seen_scheme = 1;
            } else if (strcmp(name, ":path") == 0) {
                if (seen_path) return -1;
                seen_path = 1;
                path_value = value;
            } else if (strcmp(name, ":authority") == 0) {
                if (seen_authority) return -1;
                seen_authority = 1;
            } else if (strcmp(name, ":protocol") == 0) {
                /* RFC 8441 4: the Extended CONNECT pseudo-header --
                 * legality relative to :method is checked after this
                 * loop, once the whole block (and is_connect) is known. */
                if (seen_protocol) return -1;
                seen_protocol = 1;
            } else {
                /* Unknown pseudo-header, or a response-only one (:status)
                 * appearing on a request -- both forbidden. */
                return -1;
            }
        } else {
            seen_regular_header = 1;

            /* RFC 7540 8.1.2.2: connection-specific fields are forbidden
             * in HTTP/2. */
            if (strcasecmp(name, "connection")        == 0 ||
                strcasecmp(name, "keep-alive")         == 0 ||
                strcasecmp(name, "proxy-connection")   == 0 ||
                strcasecmp(name, "transfer-encoding")  == 0 ||
                strcasecmp(name, "upgrade")            == 0) {
                return -1;
            }
            /* RFC 7540 8.1.2.2: "te" MUST NOT contain any value other
             * than "trailers". */
            if (strcasecmp(name, "te") == 0 &&
                (!value || strcasecmp(value, "trailers") != 0)) {
                return -1;
            }
        }
    }

    /* RFC 7540 8.1.2.3: :method, :scheme, :path are required for ordinary
     * requests (:authority is not, Host can substitute). :path
     * additionally MUST NOT be empty.
     *
     * RFC 8441 4 changes this for Extended CONNECT (:method: CONNECT
     * WITH a :protocol pseudo-header present): unlike plain CONNECT
     * (RFC 7540 8.3, which forbids :scheme/:path entirely -- a raw TCP
     * tunnel has no HTTP semantics), Extended CONNECT REQUIRES
     * :scheme/:path, since the tunneled protocol (WebSocket here) is
     * itself an HTTP-shaped exchange. :protocol without CONNECT, or
     * plain CONNECT with :scheme/:path/:protocol present, are both
     * protocol violations. */
    if (is_connect && seen_protocol) {
        /* Extended CONNECT: :scheme and :path become required. */
        if (!seen_method || !seen_scheme || !seen_path) return -1;
    } else if (is_connect) {
        /* Plain CONNECT: :scheme/:path/:protocol must be ABSENT. */
        if (seen_scheme || seen_path || seen_protocol) return -1;
    } else {
        /* Ordinary request: :protocol only ever makes sense on CONNECT. */
        if (seen_protocol) return -1;
        if (!seen_method || !seen_scheme || !seen_path) return -1;
    }
    if (path_value && path_value[0] == '\0') return -1;

    return 0;
}

static int stream_to_request(h2_stream_t *s, http_request_t *req) {
    if (validate_request_headers(s) < 0) return -1;

    memset(req, 0, sizeof(*req));
    req->version_major = 2;
    req->version_minor = 0;
    req->keep_alive    = 1;
    req->headers_owned = 1;
    for (int i = 0; i < s->header_count; i++) {
        const char *name  = s->headers[i].name;
        const char *value = s->headers[i].value;
        if (!name || !value) continue;

        if (strcmp(name, ":method") == 0) {
            if      (strcmp(value, "GET")     == 0) req->method = HTTP_GET;
            else if (strcmp(value, "POST")    == 0) req->method = HTTP_POST;
            else if (strcmp(value, "PUT")     == 0) req->method = HTTP_PUT;
            else if (strcmp(value, "DELETE")  == 0) req->method = HTTP_DELETE;
            else if (strcmp(value, "HEAD")    == 0) req->method = HTTP_HEAD;
            else if (strcmp(value, "PATCH")   == 0) req->method = HTTP_PATCH;
            else if (strcmp(value, "OPTIONS") == 0) req->method = HTTP_OPTIONS;
            /* RFC 8441: Extended CONNECT (:method: CONNECT with a
             * :protocol pseudo-header, validated in
             * validate_request_headers()) is how WebSocket-over-H2 is
             * bootstrapped -- this needs to reach dispatch_stream() as
             * HTTP_CONNECT so it can be routed to a WS handler instead
             * of the normal HTTP route table. */
            else if (strcmp(value, "CONNECT") == 0) req->method = HTTP_CONNECT;
        } else if (strcmp(name, ":protocol") == 0) {
            /* Stashed in req->query is a hack -- but :protocol's value
             * ("websocket") needs to survive into dispatch_stream()
             * somehow, and adding a whole new http_request_t field for a
             * single H2-only pseudo-header felt like overkill for what
             * is, in practice, always exactly one value. Revisit if a
             * second Extended CONNECT protocol ever needs supporting. */
            req->query = strdup(value);
        } else if (strcmp(name, ":path") == 0) {
            const char *q = strchr(value, '?');
            if (q) {
                req->path  = strndup(value, (size_t)(q - value));
                req->query = strdup(q + 1);
            } else {
                req->path  = strdup(value);
            }
        }

        if (req->header_count < 64) {
            /* STEAL pointer — no strdup, no copy */
            req->headers[req->header_count].key   = s->headers[i].name;
            req->headers[req->header_count].value = s->headers[i].value;
            req->header_count++;
            /* Mark as stolen so stream cleanup doesn't double-free */
            s->headers[i].name  = NULL;
            s->headers[i].value = NULL;
        }
    }
    if (!req->path) req->path = strdup("/");

    if (s->body.len > 0) {
        req->body     = (char *)buf_data(&s->body);
        req->body_len = s->body.len;
        routa_metrics_record_bytes_received(req->body_len);
        /* Steal body buffer */
        s->body.data = NULL;
        s->body.len  = 0;
        s->body.cap  = 0;
        s->body.off  = 0;
    }

    /* RFC 7540 8.1.2.6: if content-length is present, it MUST match the
     * actual body size assembled from DATA frames. A mismatch (either
     * direction) is a framing inconsistency and MUST be a stream error. */
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].key, "content-length") == 0) {
            char *endptr = NULL;
            long long declared = strtoll(req->headers[i].value, &endptr, 10);
            if (endptr == req->headers[i].value || declared < 0 ||
                (size_t)declared != req->body_len) {
                return -1;
            }
            break;
        }
    }

    /* Trailers (RFC 7540 8.1), if any were sent -- see handle_headers()'s
     * is_trailers handling, which stores them on the stream (s->trailer_*)
     * because they arrive in a separate HEADERS frame from the one this
     * function is otherwise built from, at a point after this request's
     * body is already fully assembled. STEAL the pointers (same pattern
     * as the main headers loop above) rather than copying, since s is
     * about to be torn down by the caller. */
    for (int i = 0; i < s->trailer_count && i < 16; i++) {
        req->trailers[i].key   = s->trailer_headers[i].name;
        req->trailers[i].value = s->trailer_headers[i].value;
        s->trailer_headers[i].name  = NULL;
        s->trailer_headers[i].value = NULL;
    }
    req->trailer_count = s->trailer_count;

    return 0;
}
/* ── Write HTTP response as H2 HEADERS + DATA frames ────────────────────── */
static int send_response(h2_conn_t *hc, uint32_t stream_id, h2_stream_t *s,
                          http_response_t *resp) {
    int saved_dtu = hc->hpack_tx.dynamic_table_update;
    hc->hpack_tx.dynamic_table_update = 0;
    char status_str[4];
    (void)snprintf(status_str, sizeof(status_str), "%d", resp->status);

    hpack_header_t enc_headers[35];
    memset(enc_headers, 0, sizeof(enc_headers));

    int nhdr = 0;
    enc_headers[nhdr].name  = ":status";
    enc_headers[nhdr].value = status_str;
    nhdr++;

    /* resp->body_fd responses (static.c's sendfile path) carry their
     * length in body_fd_len, not body_len -- http_response_set_body_fd()
     * deliberately zeroes body_len (see response.c). Every body_len check
     * in this function needs the same body_fd-aware fallback, or H2
     * responses for large/sendfile-served files silently ship zero body
     * bytes while still claiming :status 200 (this was completely broken
     * before this fix -- H1 had its own separate bug in the same area,
     * now fixed, but H2 needed this independent fix). */
    size_t effective_body_len = resp->body_fd >= 0 ? resp->body_fd_len : resp->body_len;

    char cl_val[32];
    if (effective_body_len > 0) {
        (void)snprintf(cl_val, sizeof(cl_val), "%zu", effective_body_len);
        enc_headers[nhdr].name  = "content-length";
        enc_headers[nhdr].value = cl_val;
        nhdr++;
    }

    enc_headers[nhdr].name  = "server";
    enc_headers[nhdr].value = "routa";
    nhdr++;

    /* RFC 7540 §8.1.2: header field names MUST be lowercase. resp->headers
     * may carry names as set by application code (e.g. static.c's
     * "Content-Type"), so lowercase a copy here rather than assuming
     * every caller already did -- HTTP/1.1 is case-insensitive so this
     * bug was invisible there, but strict H2 clients (curl, nghttp2)
     * correctly reject any uppercase header name with PROTOCOL_ERROR. */
    char lname_buf[35][128];  /* stack, not static -- send_response() runs on multiple worker threads */
    for (int i = 0; i < resp->header_count && i < 35; i++) {
        const char *hname = resp->headers[i][0];
        const char *hval  = resp->headers[i][1];
        if (!hname || hname[0] == '\0') continue;
        if (!hval) continue;
        /* content-length is emitted above; skip duplicates from set_body */
        if (strcasecmp(hname, "content-length") == 0) continue;
        if (strcasecmp(hname, "server") == 0) continue;

        size_t k = 0;
        for (; hname[k] != '\0' && k < sizeof(lname_buf[i]) - 1; k++)
            lname_buf[i][k] = (char)tolower((unsigned char)hname[k]);
        lname_buf[i][k] = '\0';

        enc_headers[nhdr].name  = lname_buf[i];
        enc_headers[nhdr].value = (char *)hval;
        nhdr++;
    }

    uint8_t hdr_block[4096];
    int hdr_len = hpack_encode(&hc->hpack_tx, enc_headers, nhdr,
                                hdr_block, sizeof(hdr_block));
    hc->hpack_tx.dynamic_table_update = saved_dtu;
    if (hdr_len < 0) return -1;

    int has_body = (resp->body && resp->body_len > 0) ||
                   (resp->body_fd >= 0 && resp->body_fd_len > 0);
    /* RFC 8441: a WebSocket-over-H2 upgrade response (the 200 OK
     * confirming an Extended CONNECT) has no body in the ordinary sense
     * -- but MUST NOT set END_STREAM either, since the stream stays
     * open for the WS connection's entire lifetime (DATA frames keep
     * flowing bidirectionally as WS traffic afterward). The
     * has_body-implies-END_STREAM logic below is correct for every
     * OTHER response type, but was incorrectly closing the stream
     * immediately after the 200 OK for WS upgrades -- confirmed live: a
     * client saw ResponseReceived+StreamEnded on the 200 OK, so by the
     * time the server's subsequent WS echo DATA frame arrived, the
     * client's own H2 stack had already torn the stream down and
     * reported it as StreamReset instead of DataReceived, discarding a
     * perfectly valid echo. */
    uint8_t hflags = H2_FLAG_END_HEADERS |
                     ((has_body || s->is_websocket) ? 0 : H2_FLAG_END_STREAM);

    if (write_frame_hdr(&hc->write_buf, (uint32_t)hdr_len,
                        H2_FRAME_HEADERS, hflags, stream_id) < 0) {
        return -1;
    }
    if (buf_append(&hc->write_buf, hdr_block, (size_t)hdr_len) < 0)
        return -1;

    /* ── body_fd path (read into buffer, then flow-control-aware send) ──
     * total must come from body_fd_len (see effective_body_len comment
     * above). Also seek to body_fd_off first -- static.c sets this to a
     * nonzero value for Range requests (see resolve_path()/range parsing
     * in static.c), and without the seek this path always re-read from
     * byte 0 regardless of the requested range. */
    if (resp->body_fd >= 0 && resp->body_fd_len > 0) {
        #define FBUF_SZ 65536
        uint8_t *fbuf = malloc(FBUF_SZ);
        if (!fbuf) return -1;

        lseek(resp->body_fd, resp->body_fd_off, SEEK_SET);

        size_t total  = resp->body_fd_len;
        size_t offset = 0;  /* bytes sent to write_buf so far */
        int    rc     = 0;

        while (offset < total) {
            /* Same write_buf soft-limit reasoning as flush_pending()'s
             * resume loop -- once write_buf has a healthy amount queued,
             * proactively flush it to the socket right here (synchronous,
             * non-blocking write -- h2_conn_flush() is just a thin
             * io_write_from_buf() wrapper, safe to call reentrantly from
             * here) instead of just stopping and hoping a later
             * POLLER_WRITE event resumes us. On a fast/loopback socket
             * that's already writable, edge-triggered epoll may not
             * deliver a fresh writable edge after we re-arm for
             * POLLER_WRITE, so relying on that alone left multi-MB
             * responses (large static files, video-sized files) stalled
             * forever just past the soft limit. Only fall back to
             * stashing body_fd state + returning (relying on the next
             * real POLLER_WRITE/WINDOW_UPDATE-driven flush_pending call)
             * if the socket genuinely can't take more right now. */
            if (hc->write_buf.len >= H2_WRITE_BUF_SOFT_LIMIT) {
                /* worker_conn_flush(), not bare h2_conn_flush() -- see
                 * the matching comment in flush_pending()'s resume loop
                 * for why a fully-drained write_buf still needs the
                 * connection's poller registration explicitly re-armed,
                 * not just the socket written to. */
                if (hc->worker) worker_conn_flush((worker_t *)hc->worker, hc->conn);
                if (hc->write_buf.len >= H2_WRITE_BUF_SOFT_LIMIT) {
                    /* Socket truly can't absorb more right now (EAGAIN) --
                     * genuinely defer to the event loop. */
                    ROUTA_METRIC_INC(h2_flow_control_stalls_total);
                    s->pending_body_fd = resp->body_fd;
                    s->pending_body_fd_remaining = total - offset;
                    resp->body_fd = -1;
                    free(fbuf);
                    return 0;
                }
            }

            size_t want = total - offset;
            if (want > FBUF_SZ) want = FBUF_SZ;

            ssize_t nr = read(resp->body_fd, fbuf, want);
            if (nr <= 0) break;

            size_t rem = (size_t)nr;
            const uint8_t *ptr = fbuf;

            while (rem > 0) {
                int32_t conn_win   = hc->send_window;
                int32_t stream_win = s->send_window;
                int32_t win        = conn_win < stream_win ? conn_win : stream_win;
                if (win <= 0) {
                    /* Stash the unsent tail of THIS read into pending_data,
                     * and remember the fd + remaining on-disk bytes so
                     * flush_pending()'s body_fd resume logic can pick up
                     * where we left off once WINDOW_UPDATE arrives.
                     * Previously nothing preserved this state -- whatever
                     * hadn't been read from disk yet was silently
                     * dropped, truncating every H2 response whose
                     * body_fd content exceeded one flow-control window's
                     * worth of data (the H2-side counterpart of the H1
                     * send_file_tls() truncation bug fixed earlier). */
                    ROUTA_METRIC_INC(h2_flow_control_stalls_total);
                    if (buf_append(&s->pending_data, ptr, rem) < 0) { free(fbuf); return -1; }
                    s->pending_offset = 0;
                    s->pending_body_fd = resp->body_fd;
                    /* Bytes not yet even read from disk = total minus
                     * everything read so far (offset + nr). rem (the
                     * unsent tail of THIS read) is already accounted for
                     * separately via pending_data -- adding it here again
                     * double-counted it, overestimating the on-disk
                     * remainder by `rem` bytes on every stall (same class
                     * of bug as flush_pending()'s underflow, fixed
                     * alongside this). */
                    s->pending_body_fd_remaining = total - offset - (size_t)nr;
                    resp->body_fd = -1; /* ownership transferred to the stream */
                    free(fbuf);
                    return 0;
                }

                size_t can_send = (size_t)win < rem ? (size_t)win : rem;
                size_t chunk    = can_send < hc->peer_max_frame_size
                                  ? can_send : hc->peer_max_frame_size;

                int end = (chunk == rem) && (offset + (size_t)nr == total);

                if (write_frame_hdr(&hc->write_buf, (uint32_t)chunk,
                                    H2_FRAME_DATA,
                                    end ? H2_FLAG_END_STREAM : 0,
                                    s->id) < 0) break;
                if (buf_append(&hc->write_buf, ptr, chunk) < 0) break;

                hc->send_window   -= (int32_t)chunk;
                s->send_window    -= (int32_t)chunk;
                ptr += chunk;
                rem -= chunk;
            }

            offset += (size_t)nr;
        }

        free(fbuf);
        return rc;
    }

    /* ── in-memory body path ─────────────────────────────────────────── */
    if (resp->body && resp->body_len > 0) {
        size_t rem = resp->body_len;
        const uint8_t *ptr = (const uint8_t *)resp->body;

        while (rem > 0) {
            int32_t conn_win   = hc->send_window;
            int32_t stream_win = s->send_window;
            int32_t win        = conn_win < stream_win ? conn_win : stream_win;
            if (win <= 0) {
                ROUTA_METRIC_INC(h2_flow_control_stalls_total);
                if (buf_append(&s->pending_data, ptr, rem) < 0) return -1;
                s->pending_offset = 0;
                return 0;
            }

            size_t can_send = (size_t)win < rem ? (size_t)win : rem;
            size_t chunk    = can_send < hc->peer_max_frame_size
                              ? can_send : hc->peer_max_frame_size;
            int end = (chunk == rem);

            if (write_frame_hdr(&hc->write_buf, (uint32_t)chunk,
                                H2_FRAME_DATA,
                                end ? H2_FLAG_END_STREAM : 0,
                                s->id) < 0) break;
            if (buf_append(&hc->write_buf, ptr, chunk) < 0) break;

            hc->send_window   -= (int32_t)chunk;
            s->send_window    -= (int32_t)chunk;
            ptr += chunk;
            rem -= chunk;
        }
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2_proxy_send_response — public API
 *
 * Relay a completed upstream HTTP response to the client on stream_id.
 * Called by proxy_on_upstream_readable once the full response is buffered.
 * Closes the stream after sending (mirrors the push-response lifecycle).     */
int h2_proxy_send_response(h2_conn_t *hc, uint32_t stream_id,
                            http_response_t *resp) {
    if (!hc || !resp) return -1;
    h2_stream_t *s = stream_find(hc, stream_id);
    if (!s) return -1;

    int rc = send_response(hc, stream_id, s, resp);

    if (s->pending_data.len == 0 && s->pending_body_fd < 0) {
        s->state = H2_STREAM_CLOSED;
        ROUTA_METRIC_INC(h2_streams_closed_total);
        ROUTA_METRIC_DEC(h2_active_streams);
        stream_remove(hc, stream_id);
    }
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2_push_promise  — public API
 *
 * Call from a route handler (before or after sending the main response) to
 * proactively push a resource to the client.
 *
 * stream_id:   the client request stream that triggered the push
 * push_path:   the path of the resource being pushed  (e.g. "/style.css")
 * push_method: almost always "GET"
 * scheme:      "https" or "http"
 * authority:   value of :authority (e.g. "example.com")
 *
 * Returns 0 on success, -1 if push is disabled or an error occurred.
 * The caller is responsible for also sending the push response via
 * h2_push_response() immediately after.
 *
 * RFC 7540 §8.2                                                             */
int h2_push_promise(h2_conn_t *hc,
                    uint32_t   stream_id,
                    const char *push_path,
                    const char *push_method,
                    const char *scheme,
                    const char *authority) {
    if (!hc || !hc->push_enabled) return -1;
    if (hc->goaway_sent || hc->error) return -1;

    /* Allocate next even (server-initiated) stream ID                    */
    uint32_t promised_id = hc->next_push_stream_id;
    hc->next_push_stream_id += 2;

    /* Build synthetic request headers for the promised stream            */
    hpack_header_t req_hdrs[4];
    req_hdrs[0].name = ":method"; req_hdrs[0].value = (char *)push_method;
    req_hdrs[1].name = ":path";   req_hdrs[1].value = (char *)push_path;
    req_hdrs[2].name = ":scheme"; req_hdrs[2].value = (char *)scheme;
    req_hdrs[3].name = ":authority"; req_hdrs[3].value = (char *)authority;

    uint8_t hdr_block[4096];
    int hdr_len = hpack_encode(&hc->hpack_tx, req_hdrs, 4,
                               hdr_block, sizeof(hdr_block));
    if (hdr_len < 0) return -1;

    if (write_push_promise(&hc->write_buf, stream_id, promised_id,
                           hdr_block, (size_t)hdr_len) < 0) return -1;

    /* Create the server-push stream so h2_push_response can send DATA   */
    h2_stream_t *ps = stream_create(hc, promised_id);
    if (!ps) return -1;
    ps->state = H2_STREAM_HALF_CLOSED_REMOTE;   /* server push: no client body */

    return (int)promised_id;   /* caller uses this as stream_id for push response */
}

/* Send the actual response for a previously promised push stream.
 * promised_stream_id: value returned by h2_push_promise()                  */
int h2_push_response(h2_conn_t *hc,
                     uint32_t promised_stream_id,
                     http_response_t *resp) {
    if (!hc || !hc->push_enabled) return -1;
    h2_stream_t *ps = stream_find(hc, promised_stream_id);
    if (!ps) return -1;

    int rc = send_response(hc, promised_stream_id, ps, resp);

    /* Clean up if all data sent                                          */
    if (ps->pending_data.len == 0 && ps->pending_body_fd < 0) {
        ps->state = H2_STREAM_CLOSED;
        stream_remove(hc, promised_stream_id);
    }
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2_early_hints — public API
 *
 * Send a 103 Early Hints response on stream_id before the main response.
 * hints: NULL-terminated array of Link header values.
 *
 * Example:
 *   const char *hints[] = {
 *       "</style.css>; rel=preload; as=style",
 *       "</app.js>; rel=preload; as=script",
 *       NULL
 *   };
 *   h2_early_hints(hc, stream_id, hints);
 *
 * RFC 8297                                                                  */
int h2_early_hints(h2_conn_t *hc, uint32_t stream_id,
                   const char **hints) {
    if (!hc || !hints) return -1;
    if (hc->goaway_sent || hc->error) return -1;

    int n = 0;
    while (hints[n]) n++;
    if (n == 0) return 0;

    /* Build HEADERS frame: :status 103 + link headers                   */
    hpack_header_t enc_hdrs[65];
    int nhdr = 0;
    enc_hdrs[nhdr].name  = ":status";
    enc_hdrs[nhdr].value = "103";
    nhdr++;
    for (int i = 0; i < n && nhdr < 64; i++) {
        enc_hdrs[nhdr].name  = "link";
        enc_hdrs[nhdr].value = (char *)hints[i];
        nhdr++;
    }

    uint8_t hdr_block[4096];
    int hdr_len = hpack_encode(&hc->hpack_tx, enc_hdrs, nhdr,
                               hdr_block, sizeof(hdr_block));
    if (hdr_len < 0) return -1;

    /* Intermediate response: END_HEADERS set, END_STREAM NOT set         */
    if (write_frame_hdr(&hc->write_buf, (uint32_t)hdr_len,
                        H2_FRAME_HEADERS,
                        H2_FLAG_END_HEADERS,
                        stream_id) < 0) return -1;
    if (buf_append(&hc->write_buf, hdr_block, (size_t)hdr_len) < 0)
        return -1;
    return 0;
}

static int dispatch_stream(h2_conn_t *hc, h2_stream_t *s,
                            uint32_t stream_id,
                            struct router *router,
                            struct middleware_chain *chain) {
    uint64_t dispatch_start = routa_now_us();
    http_request_t  req;
    http_response_t resp;
    if (stream_to_request(s, &req) < 0) {
        /* RFC 7540 8.1.2.1/.2/.3/.6: malformed request headers (missing/
         * duplicate/misordered pseudo-headers, forbidden connection-
         * specific headers, bad content-length, etc.) -- see
         * validate_request_headers() in stream_to_request(). MUST be
         * rejected as a stream error, not dispatched to the application. */
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_PROTOCOL_ERROR);
        s->state = H2_STREAM_CLOSED;
        stream_remove(hc, stream_id);
        return 0;
    }
    req.start_us = dispatch_start;
    strncpy(req.remote_ip, hc->conn->remote_ip, sizeof(req.remote_ip) - 1);
    req.remote_ip[sizeof(req.remote_ip) - 1] = '\0';

    /* RFC 8441: Extended CONNECT bootstrapping WebSocket-over-H2. The
     * :protocol value ("websocket") was stashed into req.query by
     * stream_to_request() (see the :protocol parsing there for why).
     * This is intercepted BEFORE normal route matching -- a WS route
     * lives in a separate table (ws_handler_find(), shared with the H1
     * upgrade path in event_loop.c) from the regular HTTP router,
     * exactly mirroring how the H1 WS upgrade path never touches the
     * normal router either. */
    if (req.method == HTTP_CONNECT && req.query &&
        strcmp(req.query, "websocket") == 0) {
        ws_handler_t *wsh = ws_handler_find(req.path ? req.path : "/");
        if (!wsh) {
            http_response_init(&resp);
            http_response_set_status(&resp, 404, "Not Found");
            http_response_set_body(&resp, "Not Found\n", 10);
            int rc = send_response(hc, stream_id, s, &resp);
            http_response_destroy(&resp);
            http_request_free(&req);
            return rc;
        }
        /* Confirm the upgrade with a normal :status 200 -- H2 has no
         * "101 Switching Protocols" equivalent (there is no protocol
         * switch at the H2 framing level; this stream just continues
         * exchanging DATA frames, whose payload is now WS frames
         * instead of a request/response body -- RFC 8441 5).
         *
         * CRITICAL ORDERING: s->is_websocket MUST be set to 1 BEFORE
         * calling send_response(), not after -- send_response() reads
         * it to decide whether to suppress END_STREAM on this 200 OK's
         * HEADERS frame (see send_response()'s has_body/is_websocket
         * flag logic). Setting it after send_response() returns meant
         * send_response() always saw is_websocket==0 and closed the
         * stream immediately (END_STREAM on the 200 OK), which made
         * RFC 8441-aware clients tear the stream down right after the
         * handshake -- confirmed live: a client saw
         * ResponseReceived+StreamEnded on the 200 OK, so the server's
         * subsequent WS echo DATA frame arrived on an already-closed
         * stream and was reported as StreamReset instead of
         * DataReceived, discarding a perfectly valid echo. */
        s->is_websocket = 1;
        s->ws_handler   = wsh;
        ws_frame_state_init(&s->ws_fs);
        http_response_init(&resp);
        http_response_set_status(&resp, 200, "OK");
        int rc = send_response(hc, stream_id, s, &resp);
        http_response_destroy(&resp);
        if (rc < 0) { http_request_free(&req); return rc; }
        if (wsh->on_open) wsh->on_open((conn_t *)hc->conn, wsh->ctx);
        http_request_free(&req);
        return 0;
    }

    http_response_init(&resp);

    int allowed = 0;
    route_t *route = router_match(router, &req, &allowed);
    if (!route && allowed == 0) {
        http_response_set_status(&resp, 404, "Not Found");
        http_response_set_body(&resp, "Not Found\n", 10);
    } else if (!route) {
        http_response_set_status(&resp, 405, "Method Not Allowed");
        http_response_set_body(&resp, "Method Not Allowed\n", 20);
    } else {
        if (chain) {
            middleware_chain_set_handler(chain, route->handler, route->ctx);
            middleware_chain_execute(chain, &req, &resp);
        } else {
            route->handler(&req, &resp, route->ctx);
        }
    }
    /* H2 async proxy: handler left resp.status == 0 → hand off to upstream.
     * Resolve the lb_t for THIS route from route->ctx (an
     * lb_handler_ctx_t*) rather than a single connection-wide hc->lb, so a
     * server with multiple independently configured upstream pools routes
     * each request to the correct one. Falls back to hc->lb for requests
     * that matched no route object (defensive; shouldn't normally happen
     * given the resp.status==0 + route->ctx contract above). */
    lb_t *route_lb = hc->lb;
    if (route && route->ctx) {
        route_lb = ((lb_handler_ctx_t *)route->ctx)->lb;
    }
    if (resp.status == 0 && route_lb && hc->worker) {
        http_response_destroy(&resp);
        if (proxy_begin((struct worker *)hc->worker, hc->conn, &req,
                        stream_id, route_lb) == 0) {
            /* Per-stream ctx is registered in the map; event loop dispatches
             * upstream events directly to it via the PROXY_CTX_MAGIC tag.   */
            http_request_free(&req);
            return H2_DISPATCH_PROXY;
        }
        /* proxy_begin failed — send 503 */
        http_response_init(&resp);
        http_response_set_status(&resp, 503, "Service Unavailable");
        http_response_set_body(&resp, "Service Unavailable\n", 20);
        int rc = send_response(hc, stream_id, s, &resp);
        http_response_destroy(&resp);
        http_request_free(&req);
        return rc;
    }

    int rc = send_response(hc, stream_id, s, &resp);

    const char *mstr = req_method_str(req.method);
    uint64_t latency = routa_now_us() - dispatch_start;
    routa_metrics_record(mstr, resp.status, dispatch_start, resp.body_len);
    log_access_json(req.trace_id[0] ? req.trace_id : "0000000000000000",
                    mstr,
                    req.path ? req.path : "/",
                    resp.status,
                    latency,
                    hc->conn->remote_ip,
                    0,
                    resp.body_len);

    http_response_destroy(&resp);
    http_request_free(&req);
    return rc;
}

/* ── HEADERS frame handler ───────────────────────────────────────────────── */
static int handle_headers(h2_conn_t *hc, uint32_t stream_id,
                           const uint8_t *payload, uint32_t length,
                           uint8_t flags,
                           struct router *router,
                           struct middleware_chain *chain) {

    if (stream_count(hc) >= (int)hc->max_concurrent_streams) {
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_REFUSED_STREAM);
        return 0;
    }
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if ((stream_id & 1) == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    /* See our_max_frame_size's doc comment in h2.h -- incoming frame size
     * is checked against our own advertised limit, not the peer's. */
    if (length > hc->our_max_frame_size)
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

    /* ── Strip padding and priority BEFORE creating the stream ────────── */
    const uint8_t *hdr_data = payload;
    uint32_t       hdr_len  = length;

    uint8_t pad_len = 0;
    if (flags & H2_FLAG_PADDED) {
        if (length < 1) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        pad_len  = payload[0];
        hdr_data = payload + 1;
        hdr_len  = length  - 1;
        if (pad_len >= hdr_len) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        hdr_len -= pad_len;
    }

    if (flags & H2_FLAG_PRIORITY) {
        if (hdr_len < 5) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        /* RFC 7540 5.3.1: a stream cannot depend on itself, including via
         * the inline PRIORITY fields carried in a HEADERS frame (not just
         * a standalone PRIORITY frame -- see handle_priority() for that
         * path). Previously these 5 bytes were skipped without being
         * interpreted at all (h2spec 5.3.1#1 confirmed self-dependency
         * via HEADERS was silently accepted). */
        uint32_t hdr_dependency = (((uint32_t)hdr_data[0] & 0x7f) << 24) |
                                  ((uint32_t)hdr_data[1] << 16) |
                                  ((uint32_t)hdr_data[2] <<  8) |
                                   (uint32_t)hdr_data[3];
        if (hdr_dependency == stream_id) {
            write_rst_stream(&hc->write_buf, stream_id, H2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        hdr_data += 5;
        hdr_len  -= 5;
    }

    /* ── Now create stream — all frame-level validation passed ─────────── */
    h2_stream_t *s = stream_find(hc, stream_id);
    /* RFC 7540 8.1: a second HEADERS frame on a stream that's already had
     * its request headers processed (state is HALF_CLOSED_REMOTE, i.e.
     * we're waiting for END_STREAM after DATA frames) is TRAILERS, not a
     * new/duplicate request. Trailers MUST carry END_STREAM (a client
     * sending them without ending the stream makes no sense -- RFC 7540
     * 8.1, confirmed via h2spec 8.1#1) and MUST NOT contain pseudo-
     * headers (only regular header fields are valid in a trailer
     * block). Previously this whole case was silently treated as if it
     * were a brand-new HEADERS block for the request (overwriting
     * s->headers), which is why h2spec 8.1#1 failed: a malformed
     * trailers-without-END_STREAM sequence was accepted and dispatched
     * as if nothing were wrong, instead of PROTOCOL_ERROR. */
    /* Broadened from "state == HALF_CLOSED_REMOTE" -- h2spec 8.1#1's
     * actual scenario sends HEADERS (no END_STREAM) -> DATA (no
     * END_STREAM either) -> a second HEADERS (no END_STREAM), i.e. the
     * stream is still OPEN, not yet HALF_CLOSED_REMOTE, when the second
     * HEADERS arrives. Any second HEADERS frame on a stream that
     * already has its initial request headers (s->headers != NULL) is
     * either legitimate trailers (which MUST carry END_STREAM) or a
     * protocol violation -- there is no valid reason for a THIRD set of
     * non-trailer headers on one stream. */
    int is_trailers = (s && s->headers != NULL);
    if (is_trailers && !(flags & H2_FLAG_END_STREAM)) {
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_PROTOCOL_ERROR);
        return 0;
    }
    if (!s) {
        if (stream_id <= hc->last_stream_id)
            return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        s = stream_create(hc, stream_id);
        if (!s) {
            write_rst_stream(&hc->write_buf, stream_id, H2_ERR_STREAM_CLOSED);
            return 0;
        }
        hc->last_stream_id = stream_id;
        ROUTA_METRIC_INC(h2_streams_opened_total);
        ROUTA_METRIC_INC(h2_active_streams);
    }

    if (buf_append(&s->header_block, hdr_data, hdr_len) < 0)
        if (s->header_block.len > 262144)  /* 256 KB CONTINUATION flood limit */
            return conn_error(hc, H2_ERR_ENHANCE_YOUR_CALM);

    if (s->header_block.len > H2_MAX_CONTINUATION_BYTES)
        return conn_error(hc, H2_ERR_ENHANCE_YOUR_CALM);

    if (!(flags & H2_FLAG_END_HEADERS)) {
        s->expect_continuation      = 1;
        hc->continuation_stream_id  = stream_id;
        return 0;
    }

    hpack_header_t headers[64];
    int n = hpack_decode(&hc->hpack_rx,
                         (const uint8_t *)buf_data(&s->header_block),
                         s->header_block.len,
                         headers, 64);
    buf_reset(&s->header_block);
    if (is_trailers) {
        /* RFC 7540 8.1.2.1: trailers MUST NOT contain pseudo-headers --
         * check before storing/dispatching anything. */
        int rejected = 0;
        for (int i = 0; i < n; i++) {
            if (headers[i].name && headers[i].name[0] == ':') {
                rejected = 1;
                break;
            }
        }
        if (rejected) {
            hpack_headers_free(headers, n);
            write_rst_stream(&hc->write_buf, stream_id, H2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        int copy_n = n < 16 ? n : 16;
        for (int i = 0; i < copy_n; i++) {
            s->trailer_headers[i] = headers[i];
        }
        /* Free anything beyond the 16-trailer cap we didn't keep a
         * reference to, to avoid leaking them -- mirrors the >64 header
         * truncation pattern used for regular headers elsewhere. */
        for (int i = copy_n; i < n; i++) {
            free(headers[i].name);
            free(headers[i].value);
        }
        s->trailer_count = copy_n;
        /* Trailers always carry END_STREAM (checked above), so THIS is
         * the point where the request is actually complete -- dispatch
         * now, same pattern as the END_STREAM-on-HEADERS and
         * END_STREAM-on-DATA paths elsewhere in this file. Previously
         * this just tore the stream down (stream_remove()) without ever
         * dispatching, which is why h2spec's "POST request with
         * trailers" test got no response at all -- the request was
         * silently discarded once trailers arrived instead of being
         * completed and answered. */
        s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        int drc = dispatch_stream(hc, s, stream_id, router, chain);
        /* BUG FIX: this was a bare io_write_from_buf() call, which writes
         * to the socket but -- unlike worker_conn_flush() -- never re-arms
         * the connection's epoll registration for POLLER_WRITE if the
         * write is partial (EAGAIN mid-buffer). Every other write_buf
         * flush site in this file (flush_pending(), handle_window_update(),
         * send_response()'s soft-limit checks) already learned this lesson
         * and uses worker_conn_flush() instead -- this trailers-dispatch
         * site was the one place that still didn't, so a response queued
         * here (post-dispatch_stream()) that didn't fit in one write()
         * call could sit in write_buf forever with nothing watching the
         * socket for writability again. Especially likely for large
         * (>=64KB-ish) H2 responses to trailers-bearing requests under any
         * concurrency, since multiple streams sharing one connection's
         * write_buf makes a full single-write flush far less reliable. */
        if (hc->write_buf.len > 0 && hc->worker) {
            worker_conn_flush((worker_t *)hc->worker, hc->conn);
        }
        if (drc == H2_DISPATCH_PROXY) return 0;
        return drc;
    }
    s->expect_continuation = 0;

    if (n < 0) return conn_error(hc, H2_ERR_COMPRESSION_ERROR);

    if (s->headers) {
        hpack_headers_free(s->headers, s->header_count);
        free(s->headers);
    }
    s->headers = malloc((size_t)n * sizeof(hpack_header_t));
    if (!s->headers) { hpack_headers_free(headers, n); return -1; }
    memcpy(s->headers, headers, (size_t)n * sizeof(hpack_header_t));
    s->header_count = n;

    /* RFC 8441: Extended CONNECT (:method CONNECT + :protocol) has a
     * fundamentally different exchange shape than a normal request --
     * the "response" (confirming or rejecting the upgrade) must be sent
     * as soon as the HEADERS frame arrives, NOT after END_STREAM,
     * because for a bootstrapped WebSocket there IS no END_STREAM on
     * the request side until the WS connection itself closes (DATA
     * frames keep flowing bidirectionally for the connection's whole
     * lifetime). The general dispatch_stream()-on-END_STREAM path below
     * would simply never fire for this case, since the client never
     * sends END_STREAM on a still-open WS stream -- confirmed via a
     * live RFC 8441 client test that timed out waiting for any response
     * at all before this fix, despite the HEADERS frame having been
     * parsed and validated successfully. Detect this case up front by
     * checking the still-raw header block for :method=CONNECT (a full,
     * generic "is this an Extended CONNECT" check happens inside
     * dispatch_stream() itself via stream_to_request() -- this is just
     * routing the call to happen at the right TIME). */
    int is_connect_request = 0;
    for (int hi = 0; hi < n; hi++) {
        if (headers[hi].name && strcmp(headers[hi].name, ":method") == 0 &&
            headers[hi].value && strcmp(headers[hi].value, "CONNECT") == 0) {
            is_connect_request = 1;
            break;
        }
    }

    if ((flags & H2_FLAG_END_STREAM) || is_connect_request) {
        s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        int drc = dispatch_stream(hc, s, stream_id, router, chain);
        /* BUG FIX: see the matching comment at the trailers-dispatch site
         * above -- this was also a bare io_write_from_buf() call that
         * silently dropped the poller re-arm on a partial write. This is
         * the MAIN request-dispatch path (the common case for every
         * ordinary H2 request), making it the primary suspect for
         * intermittent large-response / high-concurrency H2 stalls: a
         * response whose HEADERS+DATA frames didn't fit in a single
         * write() here (very likely once several concurrent streams are
         * all queuing into the same connection's write_buf) would leave
         * its remaining bytes stuck in write_buf with no POLLER_WRITE
         * interest registered to ever drain them. */
        if (hc->write_buf.len > 0 && hc->worker) {
            worker_conn_flush((worker_t *)hc->worker, hc->conn);
        }
        if (drc == H2_DISPATCH_PROXY) {
            return 0;  /* stream kept alive; upstream response will close it */
        }
        /* A successfully upgraded WS stream must NOT be torn down here --
         * it's about to start receiving DATA frames as WS traffic for
         * potentially its entire (long) lifetime. Only fall through to
         * the normal close-if-nothing-pending logic for requests that
         * really did end (flags & END_STREAM) or failed to upgrade. */
        if (s->is_websocket) {
            return drc;
        }
        buf_reset(&s->body);
        if (s->pending_data.len == 0 && s->pending_body_fd < 0) {
            s->state = H2_STREAM_CLOSED;
            ROUTA_METRIC_INC(h2_streams_closed_total);
            ROUTA_METRIC_DEC(h2_active_streams);
            stream_remove(hc, stream_id);
        } else {
            s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        }
    }
    return 0;
}

/* ── CONTINUATION frame handler ─────────────────────────────────────────── */
static int handle_continuation(h2_conn_t *hc, uint32_t stream_id,
                                const uint8_t *payload, uint32_t length,
                                uint8_t flags,
                                struct router *router,
                                struct middleware_chain *chain) {
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if (stream_id != hc->continuation_stream_id)
        return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    /* max_frame_size enforcement on CONTINUATION -- checked against our
     * own advertised limit, not the peer's (see our_max_frame_size's doc
     * comment in h2.h). */
    if (length > hc->our_max_frame_size)
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

    h2_stream_t *s = stream_find(hc, stream_id);
    if (!s) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    if (buf_append(&s->header_block, payload, length) < 0)
        if (s->header_block.len > 262144)
        return conn_error(hc, H2_ERR_INTERNAL_ERROR);

    /* FIX: CONTINUATION flood — cumulative size check                   */
    if (s->header_block.len > H2_MAX_CONTINUATION_BYTES)
        return conn_error(hc, H2_ERR_ENHANCE_YOUR_CALM);

    if (flags & H2_FLAG_END_HEADERS) {
        hpack_header_t headers[64];
        int n = hpack_decode(&hc->hpack_rx,
                             (const uint8_t *)buf_data(&s->header_block) ,
                             s->header_block.len,
                             headers, 64);
        buf_reset(&s->header_block);
        s->expect_continuation     = 0;
        hc->continuation_stream_id = 0;

        if (n < 0) return conn_error(hc, H2_ERR_COMPRESSION_ERROR);

        if (s->headers) {
            hpack_headers_free(s->headers, s->header_count);
            free(s->headers);
        }
        s->headers = malloc((size_t)n * sizeof(hpack_header_t));
        if (!s->headers) { hpack_headers_free(headers, n); return -1; }
        memcpy(s->headers, headers, (size_t)n * sizeof(hpack_header_t));
        s->header_count = n;

        /* FIX: match handle_headers pending_data pattern                */
        s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        int drc = dispatch_stream(hc, s, stream_id, router, chain);
        /* BUG FIX: the old comment here ("partial flush OK -- remainder
         * handled by POLLER_WRITE") was wrong -- a bare io_write_from_buf()
         * call does NOT re-arm POLLER_WRITE on a partial write, it only
         * writes to whatever the socket's CURRENT poller registration
         * already covers. If this connection wasn't already registered
         * for POLLER_WRITE at this exact moment, a partial write here left
         * the remainder of write_buf stuck with nothing ever watching the
         * socket for writability again -- see the matching fix (and
         * fuller explanation) at the other two dispatch_stream() call
         * sites in this file. worker_conn_flush() correctly re-arms the
         * poller when needed. */
        if (hc->write_buf.len > 0 && hc->worker) {
            worker_conn_flush((worker_t *)hc->worker, hc->conn);
        }
        if (drc == H2_DISPATCH_PROXY) {
            return 0;  /* stream kept alive; upstream response will close it */
        }
        buf_reset(&s->body);
        if (s->pending_data.len == 0 && s->pending_body_fd < 0) {
            s->state = H2_STREAM_CLOSED;
            stream_remove(hc, stream_id);
        }
        /* else: stream stays alive until pending_data is flushed        */
    }
    return 0;
}

/* ── DATA frame handler ──────────────────────────────────────────────────── */
/* RFC 8441: process a chunk of WS-frame bytes carried in an H2 DATA
 * frame's payload, for a stream already confirmed as a bootstrapped
 * WebSocket (dispatch_stream()'s CONNECT+:protocol=websocket handling).
 *
 * ws_recv() (ws.c) is the single source of truth for WS frame parsing
 * and expects to work against a conn_t's ws_state/ws_fs/read_buf/
 * write_buf/ws_pmd_enabled fields directly -- rather than duplicating
 * that (substantial, easy to let drift out of sync) logic here, this
 * temporarily swaps hc->conn's WS-related fields for this stream's own
 * (s->ws_fs, and a throwaway buf_t pair for read/write), calls the real
 * ws_recv() unmodified, then restores hc->conn's original fields and
 * forwards whatever ws_recv() queued into the throwaway write_buf as
 * H2 DATA frame(s) on this stream. This keeps H1 WS's own state
 * (whichever connection that actually is) completely untouched even
 * though we're borrowing the same conn_t struct's fields as scratch
 * space -- H1 and H2-WS never share a live conn_t at the same time
 * (an H2 connection's conn_t doesn't have its OWN ws_state used for
 * anything else, since routa's H1 WS upgrade path only ever runs on
 * an H1 conn_t, never one that's also carrying H2 streams). */
static int h2_ws_process_data(h2_conn_t *hc, h2_stream_t *s,
                               const uint8_t *data, size_t len) {
    conn_t *conn = (conn_t *)hc->conn;

    ws_conn_state_t   saved_state = conn->ws_state;
    ws_frame_state_t  saved_fs    = conn->ws_fs;
    int               saved_pmd  = conn->ws_pmd_enabled;
    buf_t             saved_read = conn->read_buf;
    buf_t             saved_write = conn->write_buf;

    conn->ws_state       = WS_STATE_OPEN;
    conn->ws_fs          = s->ws_fs;
    conn->ws_pmd_enabled = 0;  /* permessage-deflate over H2-WS: not yet supported */

    buf_init(&conn->read_buf);
    buf_init(&conn->write_buf);
    if (len > 0) buf_append(&conn->read_buf, data, len);

    /* handler->ctx is threaded through so on_message()/on_open() work
     * identically to the H1 path -- ws_recv() reads it off
     * conn->ws_handler, so stash it there for the duration of this call. */
    conn->ws_handler = (ws_handler_t *)s->ws_handler;

    /* BUG FIX: this used to pass NULL for cfg unconditionally (a copy-
     * paste mistake -- "hc->conn->tls ? NULL : NULL" is NULL either way),
     * which made ws_recv() return -1 immediately from its own `if (!conn
     * || !handler || !cfg) return -1;` guard, before ever looking at the
     * frame data. Every single WS-over-H2 message was silently dropped
     * as a result -- confirmed via a live client test where the Extended
     * CONNECT handshake succeeded (200 OK) but no echo ever came back.
     * Use the same per-route-config-or-worker-default resolution pattern
     * as handle_ws_read() (event_loop.c) uses for the H1 WS path. */
    const ws_config_t *ws_cfg = (s->ws_handler && s->ws_handler->cfg.max_frame_size > 0)
                                ? &s->ws_handler->cfg
                                : (hc->worker ? &((worker_t *)hc->worker)->ws_cfg : NULL);
    int rc = ws_recv(conn, s->ws_handler, ws_cfg);
    (void)rc;  /* ws_recv()'s own error signaling is via conn->ws_state below */

    /* Persist this stream's WS parser state back for the next DATA frame. */
    s->ws_fs = conn->ws_fs;

    /* Anything ws_recv() queued (echoes, pongs, close frames) needs to go
     * out as H2 DATA frame(s) on this stream, gated by this stream's
     * actual H2 send_window/peer_max_frame_size -- NOT written raw to
     * the socket the way H1's conn->write_buf normally would be. */
    int result = 0;
    if (conn->write_buf.len > 0) {
        const uint8_t *out_ptr = buf_data(&conn->write_buf);
        size_t         out_rem = conn->write_buf.len;
        while (out_rem > 0) {
            int32_t conn_win   = hc->send_window;
            int32_t stream_win = s->send_window;
            int32_t win        = conn_win < stream_win ? conn_win : stream_win;
            if (win <= 0) {
                /* Flow-control stalled -- stash the rest for later via
                 * the existing pending_data resume mechanism
                 * (flush_pending()), same as any other stalled stream. */
                buf_append(&s->pending_data, out_ptr, out_rem);
                s->pending_offset = 0;
                break;
            }
            size_t chunk = out_rem;
            if ((size_t)win < chunk) chunk = (size_t)win;
            if (chunk > hc->peer_max_frame_size) chunk = hc->peer_max_frame_size;
            if (write_frame_hdr(&hc->write_buf, (uint32_t)chunk,
                                H2_FRAME_DATA, 0, s->id) < 0) { result = -1; break; }
            if (buf_append(&hc->write_buf, out_ptr, chunk) < 0) { result = -1; break; }
            hc->send_window   -= (int32_t)chunk;
            s->send_window    -= (int32_t)chunk;
            out_ptr += chunk;
            out_rem -= chunk;
        }
    }

    int closed = (conn->ws_state == WS_STATE_CLOSED);

    buf_free(&conn->read_buf);
    buf_free(&conn->write_buf);

    conn->ws_state       = saved_state;
    conn->ws_fs          = saved_fs;
    conn->ws_pmd_enabled = saved_pmd;
    conn->read_buf       = saved_read;
    conn->write_buf      = saved_write;

    if (closed && result == 0) {
        if (s->ws_handler && s->ws_handler->on_close)
            s->ws_handler->on_close(conn, WS_CLOSE_NORMAL, NULL, s->ws_handler->ctx);
        write_rst_stream(&hc->write_buf, s->id, H2_ERR_NO_ERROR);
        s->state = H2_STREAM_CLOSED;
        stream_remove(hc, s->id);
        if (hc->worker) worker_conn_flush((worker_t *)hc->worker, hc->conn);
        return 0;
    }

    /* Flush whatever DATA frame(s) were just queued above. */
    if (hc->write_buf.len > 0 && hc->worker) {
        worker_conn_flush((worker_t *)hc->worker, hc->conn);
    }

    return result;
}

static int handle_data(h2_conn_t *hc, uint32_t stream_id,
                        const uint8_t *payload, uint32_t length,
                        uint8_t flags,
                        struct router *router,
                        struct middleware_chain *chain) {
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    /* RFC 7540 4.2: incoming DATA length is checked against OUR OWN
     * advertised SETTINGS_MAX_FRAME_SIZE (our_max_frame_size), not the
     * peer's (peer_max_frame_size governs what WE may send THEM). See
     * our_max_frame_size's doc comment in h2.h for the full story --
     * this was previously checked against the wrong field. */
    if (length > hc->our_max_frame_size)
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

    if (is_idle_stream(hc, stream_id))
        return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    h2_stream_t *s = stream_find(hc, stream_id);
    if (!s) {
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_STREAM_CLOSED);
        return 0;
    }

    const uint8_t *data = payload;
    uint32_t       dlen = length;
    if (flags & H2_FLAG_PADDED) {
        if (dlen < 1) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        uint8_t pad = payload[0];
        data = payload + 1;
        dlen = length  - 1;
        if (pad >= dlen) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        dlen -= pad;
    }

    if ((int32_t)dlen > hc->recv_window) {
        return conn_error(hc, H2_ERR_FLOW_CONTROL_ERROR);
    }
    hc->recv_window -= (int32_t)dlen;

    /* RFC 8441 5: on a bootstrapped WebSocket stream, DATA frame
     * payloads are WS frames, not a normal request body -- do NOT
     * accumulate them into s->body (never drained for a long-lived WS
     * stream, would grow unbounded). Feed the raw bytes directly to the
     * WS frame parser instead. Flow-control window accounting still
     * applies identically either way (RFC 8441 doesn't exempt
     * WS-carrying streams from ordinary H2 flow control). */
    if (s->is_websocket) {
        if (dlen > 0) {
            hc->recv_window += (int32_t)dlen;
            hc->recv_pending_update += dlen;
            if (hc->recv_pending_update >= (uint32_t)(hc->recv_window / 2)) {
                write_window_update(&hc->write_buf, 0, hc->recv_pending_update);
                hc->recv_pending_update = 0;
            }
            write_window_update(&hc->write_buf, stream_id, dlen);
        }
        int wrc = h2_ws_process_data(hc, s, data, dlen);
        if (flags & H2_FLAG_END_STREAM) {
            if (s->ws_handler && s->ws_handler->on_close)
                s->ws_handler->on_close((conn_t *)hc->conn, WS_CLOSE_NORMAL, NULL,
                                        s->ws_handler->ctx);
            s->state = H2_STREAM_CLOSED;
            stream_remove(hc, stream_id);
            return 0;
        }
        return wrc;
    }

    if (buf_append(&s->body, data, dlen) < 0)
        return conn_error(hc, H2_ERR_INTERNAL_ERROR);

    if (dlen > 0) {
        hc->recv_window += (int32_t)dlen;
        hc->recv_pending_update += dlen;
        if (hc->recv_pending_update >= (uint32_t)(hc->recv_window / 2)) {
            write_window_update(&hc->write_buf, 0, hc->recv_pending_update);
            hc->recv_pending_update = 0;
        }
        write_window_update(&hc->write_buf, stream_id, dlen);
    }

    if (flags & H2_FLAG_END_STREAM) {
        s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        int drc = dispatch_stream(hc, s, stream_id, router, chain);
        /* BUG FIX: this call site had NO flush at all after
         * dispatch_stream() -- not even a bare io_write_from_buf(), let
         * alone worker_conn_flush(). dispatch_stream() -> send_response()
         * queues the HEADERS+DATA frames of the reply into hc->write_buf,
         * but nothing here ever wrote that buffer to the socket or armed
         * POLLER_WRITE for it. This is the DATA-frame (request-body-
         * bearing, e.g. POST) completion path -- the GET-only benchmark
         * that surfaced the other three sites in handle_headers() never
         * exercises this one, but any request with a body ending on a
         * DATA frame's END_STREAM would have its response left sitting
         * unsent in write_buf, relying entirely on some unrelated later
         * event on the same connection to incidentally flush it (or
         * never, if none came before the client's own timeout). Mirrors
         * the same fix applied to the three dispatch_stream() call sites
         * in handle_headers(). */
        if (hc->write_buf.len > 0 && hc->worker) {
            worker_conn_flush((worker_t *)hc->worker, hc->conn);
        }
        if (drc == H2_DISPATCH_PROXY) {
            return 0;  /* stream kept alive; upstream response will close it */
        }
        buf_reset(&s->body);
        if (s->pending_data.len == 0 && s->pending_body_fd < 0) {
            s->state = H2_STREAM_CLOSED;
            ROUTA_METRIC_INC(h2_streams_closed_total);
            ROUTA_METRIC_DEC(h2_active_streams);
            stream_remove(hc, stream_id);
        } else {
            s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        }
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2c Upgrade path (RFC 7540 §3.2)
 *
 * Called from the HTTP/1.1 parser when it detects:
 *   Upgrade: h2c
 *   HTTP2-Settings: <base64url of a SETTINGS payload>
 *
 * We:
 *   1. Send "101 Switching Protocols"
 *   2. Send our server SETTINGS + connection window update
 *   3. Synthesize stream 1 (the upgrading HTTP/1.1 request) as if we
 *      received it over H2, so the existing route handler fires normally.
 *
 * Returns 0 on success, -1 on error.
 * After return, the caller must switch the connection to H2 mode.          */
int h2_upgrade_from_h1(h2_conn_t      *hc,
                        http_request_t *req,
                        struct router  *router,
                        struct middleware_chain *chain) {
    if (!hc || !req) return -1;
    buf_t saved;
    buf_init(&saved);
    if (hc->write_buf.len > 0) {
        if (buf_append(&saved, buf_data(&hc->write_buf),
               hc->write_buf.len) < 0) return -1;
        hc->write_buf.len = 0;
    }
    /* ── 1. 101 Switching Protocols ──────────────────────────────────── */
    static const char switching[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: h2c\r\n"
        "\r\n";
    if (buf_append(&hc->write_buf, (const uint8_t *)switching,
                   sizeof(switching) - 1) < 0) {
        buf_free(&saved); return -1;
                   }
    if (saved.len > 0) {
        if (buf_append(&hc->write_buf, buf_data(&saved), saved.len) < 0) {
            buf_free(&saved); return -1;
        }
    }
    buf_free(&saved);
    /* ── 2. Server preface: SETTINGS + WINDOW_UPDATE already written by
     *       h2_conn_new — nothing extra needed here.                    */

    /* ── 3. Synthesize stream 1 from the HTTP/1.1 request ───────────── */
    h2_stream_t *s = stream_create(hc, 1);
    if (!s) return -1;
    hc->last_stream_id = 1;
    s->state = H2_STREAM_HALF_CLOSED_REMOTE;

    /* Build minimal pseudo-header set from the HTTP/1.1 request         */
    const char *method_str = "GET";
    switch (req->method) {
        case HTTP_POST:    method_str = "POST";    break;
        case HTTP_PUT:     method_str = "PUT";     break;
        case HTTP_DELETE:  method_str = "DELETE";  break;
        case HTTP_HEAD:    method_str = "HEAD";    break;
        case HTTP_PATCH:   method_str = "PATCH";   break;
        case HTTP_OPTIONS: method_str = "OPTIONS"; break;
        default: break;
    }

    /* Allocate headers: 3 pseudo + real headers                         */
    int nhdr = 3 + req->header_count;
    hpack_header_t *hdrs = calloc((size_t)nhdr, sizeof(hpack_header_t));
    if (!hdrs) return -1;

    int k = 0;
    hdrs[k].name  = strdup(":method");
    hdrs[k].value = strdup(method_str); k++;
    hdrs[k].name  = strdup(":path");
    hdrs[k].value = strdup(req->path ? req->path : "/"); k++;
    hdrs[k].name  = strdup(":scheme");
    hdrs[k].value = strdup("http"); k++;

    for (int i = 0; i < req->header_count; i++) {
        const char *n = req->headers[i].key;
        const char *v = req->headers[i].value;
        if (!n || !v) continue;
        /* Skip connection-specific headers forbidden in H2               */
        if (strcasecmp(n, "connection")     == 0 ||
            strcasecmp(n, "keep-alive")     == 0 ||
            strcasecmp(n, "upgrade")        == 0 ||
            strcasecmp(n, "http2-settings") == 0) continue;
        hdrs[k].name  = strdup(n);
        hdrs[k].value = strdup(v);
        k++;
    }
    s->headers      = hdrs;
    s->header_count = k;

    /* Copy body if present                                               */
    if (req->body && req->body_len > 0) {
        if (buf_append(&s->body, (const uint8_t *)req->body,
                       req->body_len) < 0) return -1;
    }

    /* Dispatch — same path as a normal H2 stream                        */
    int drc = dispatch_stream(hc, s, 1, router, chain);

    if (drc != H2_DISPATCH_PROXY) {
        s->body.data = NULL; s->body.len = 0; s->body.cap = 0; s->body.off  = 0;
        if (s->pending_data.len == 0 && s->pending_body_fd < 0) {
            s->state = H2_STREAM_CLOSED;
            stream_remove(hc, 1);
        }
    }

    /* Mark preface as done — client will send the H2 client preface next */
    hc->preface_done = 1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2_conn_recv — main entry point from event_loop
 * ═══════════════════════════════════════════════════════════════════════════*/

int h2_conn_recv(h2_conn_t *hc,
                 struct router *router,
                 struct middleware_chain *chain) {
    int frames_this_call = 0;
#define H2_MAX_FRAMES_PER_RECV 1000
    if (!hc || !hc->conn) return -1;

    buf_t *rb = &hc->conn->read_buf;

    if (!hc->preface_done) {
        if (rb->len < H2_CLIENT_PREFACE_LEN) return 0;
        if (memcmp(buf_data(rb), H2_CLIENT_PREFACE,
                   H2_CLIENT_PREFACE_LEN) != 0) {
            LOG_WARN("h2: bad client preface");
            return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        }
        buf_consume(rb, H2_CLIENT_PREFACE_LEN);
        /* Update last_recv_ts on every frame */
        {
            struct timespec _ts;
            clock_gettime(CLOCK_MONOTONIC, &_ts);
            hc->last_recv_ts = (uint64_t)_ts.tv_sec * 1000 +
                               (uint64_t)_ts.tv_nsec / 1000000;
        }
        hc->preface_done = 1;
    }

    size_t offset = 0;
    if (hc->write_buf.len > 4 * 1024 * 1024) {
        LOG_WARN("h2: write buffer exceeded 4MB, closing connection");
        return conn_error(hc, H2_ERR_ENHANCE_YOUR_CALM);
    }
while (rb->len - offset >= H2_FRAME_HDR_SZ) {
    const uint8_t *hdr     = (const uint8_t *)buf_data(rb) + offset;
    uint32_t       pay_len = frame_length(hdr);
    uint8_t        type    = frame_type(hdr);
    uint8_t        flags   = frame_flags(hdr);
    uint32_t       sid     = frame_stream(hdr);

    if (rb->len - offset < H2_FRAME_HDR_SZ + pay_len) break;

    /* RFC 7540 4.2: any incoming frame's payload length is checked
     * against OUR OWN advertised SETTINGS_MAX_FRAME_SIZE (our_max_frame_size),
     * not the peer's (peer_max_frame_size governs what WE may send THEM,
     * not what they may send us) -- see our_max_frame_size's doc comment
     * in h2.h. This was the actual root cause of h2spec 4.2#1: a
     * perfectly valid DATA frame within our own advertised limit was
     * rejected here, in the general frame-size gate, before handle_data()
     * (which had its own, now-also-fixed, separate copy of the same
     * wrong-field bug) ever got a chance to look at it. */
    if (pay_len > hc->our_max_frame_size &&
        type != H2_FRAME_SETTINGS) {
        buf_consume(rb, offset);
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
    }

    const uint8_t *payload = hdr + H2_FRAME_HDR_SZ;

    if (hc->continuation_stream_id != 0 &&
        type != H2_FRAME_CONTINUATION) {
        buf_consume(rb, offset);
        return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    }

    int rc = 0;
    switch (type) {
    case H2_FRAME_SETTINGS:
        rc = handle_settings(hc, payload, pay_len, flags, sid);
        break;
    case H2_FRAME_PING:
        rc = handle_ping(hc, payload, pay_len, flags, sid);
        break;
    case H2_FRAME_WINDOW_UPDATE:
        rc = handle_window_update(hc, payload, pay_len, sid);
        break;
    case H2_FRAME_RST_STREAM:
        rc = handle_rst_stream(hc, payload, pay_len, sid);
        break;
    case H2_FRAME_GOAWAY:
        rc = handle_goaway(hc, payload, pay_len);
        break;
    case H2_FRAME_HEADERS:
        rc = handle_headers(hc, sid, payload, pay_len, flags,
                            router, chain);
        break;
    case H2_FRAME_CONTINUATION:
        rc = handle_continuation(hc, sid, payload, pay_len, flags,
                                 router, chain);
        break;
    case H2_FRAME_DATA:
        rc = handle_data(hc, sid, payload, pay_len, flags,
                         router, chain);
        break;
    case H2_FRAME_PRIORITY:
        rc = handle_priority(hc, payload, pay_len, sid);
        break;
    case H2_FRAME_PUSH_PROMISE:
        buf_consume(rb, offset);
        return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    default:
        break;
    }
    

    hc->frame_count++;
    if ((hc->frame_count & 15) == 0) {
        struct timespec _rts;
        clock_gettime(CLOCK_MONOTONIC, &_rts);
        hc->last_recv_ts = (uint64_t)_rts.tv_sec * 1000 +
                           (uint64_t)_rts.tv_nsec / 1000000;
    }

    /* CRITICAL FIX: last_stream_ts was previously set exactly once, in
     * h2_conn_new() at connection creation time, and NEVER updated again
     * anywhere -- not on stream open, not on DATA/WINDOW_UPDATE activity,
     * nothing. h2_conn_check_timeouts() (called every ~1s by the worker's
     * sweep loop) uses (now_ms - last_stream_ts) > stream_timeout_ms
     * (default 30000ms) to decide whether an open stream has gone idle
     * and should be GOAWAY'd -- but since last_stream_ts never advanced
     * past connection creation, ANY connection with an open stream still
     * alive 30+ seconds after the TCP/TLS handshake -- including one
     * actively streaming a large response, with WINDOW_UPDATEs and DATA
     * frames flowing the whole time -- would be treated as "idle" and
     * forcibly GOAWAY'd purely based on connection age. This was a
     * genuine, confirmed contributor to this session's H2-over-TLS
     * large-file race condition. Update on every frame here -- any frame
     * at all is evidence the stream/connection is alive. */
    {
        struct timespec _sts;
        clock_gettime(CLOCK_MONOTONIC, &_sts);
        hc->last_stream_ts = (uint64_t)_sts.tv_sec * 1000 +
                             (uint64_t)_sts.tv_nsec / 1000000;
    }

    offset += H2_FRAME_HDR_SZ + pay_len;
    frames_this_call++;
    if (frames_this_call >= H2_MAX_FRAMES_PER_RECV) {
        buf_consume(rb, offset);
        return 0;
    }

    if (rc < 0) {
        buf_consume(rb, offset);
        return -1;
    }
}

if (offset > 0)
    buf_consume(rb, offset);
return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2_conn_flush — drain write_buf to socket
 * ═══════════════════════════════════════════════════════════════════════════*/

int h2_conn_flush(h2_conn_t *hc) {
    if (!hc || !hc->conn) return -1;
    if (hc->write_buf.len == 0) return 0;
    ssize_t n = io_write_from_buf(hc->conn->fd,
                                   &hc->write_buf,
                                   hc->conn->tls);
    /* BUG FIX (H2-over-TLS large-file stream-idle-timeout false positive):
     * last_stream_ts was only ever updated in h2_conn_recv() when a frame
     * arrived FROM the client -- never when this server was actively
     * SENDING a response (e.g. streaming a large file's DATA frames over
     * several io_write_from_buf() calls under TLS, where per-write TLS
     * record framing/encryption overhead plus concurrent-stream socket
     * contention can make a single response take longer than
     * stream_timeout_ms, default 30s, to fully drain -- confirmed via
     * live instrumentation: h2_conn_check_timeouts()'s "stream idle
     * timeout" fired and GOAWAY'd connections that were, at that exact
     * moment, mid-flight actively writing DATA frames for an open
     * stream's response, with the client having sent nothing further
     * simply because it was still waiting on that same in-progress
     * response). h2_conn_check_timeouts()'s idle check
     * ((now_ms - last_stream_ts) > stream_timeout_ms) treats "no frames
     * received" as "idle" -- but a connection that's busy SENDING is
     * exactly as alive as one that's busy RECEIVING, and needs the same
     * exemption. Any attempted write here (n >= 0, i.e. the write call
     * didn't hard-fail) is evidence of that activity -- update the same
     * way the receive side already does. This did not reproduce over
     * H2C because a plain write() syscall has none of TLS's per-record
     * encrypt/memcpy overhead, so large-file drains there almost never
     * approach the 30s threshold in the first place -- masking this gap
     * rather than avoiding the underlying bug. */
    if (n >= 0 && hc->conn) {
        struct timespec _fts;
        clock_gettime(CLOCK_MONOTONIC, &_fts);
        hc->last_stream_ts = (uint64_t)_fts.tv_sec * 1000 +
                             (uint64_t)_fts.tv_nsec / 1000000;
    }
    if (n < 0) return -1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2_conn_check_timeouts
 * ═══════════════════════════════════════════════════════════════════════════*/

int h2_conn_check_timeouts(h2_conn_t *hc, uint64_t now_ms) {
    if (!hc || hc->error || hc->goaway_sent) return 0;
    
    /* Timeouts come from config stored at conn_new time.
     * We use hardcoded defaults here; event_loop passes now_ms.
     * stream_timeout_ms default: 30000, keepalive_timeout_ms default: 120000 */
    uint32_t stream_timeout_ms    = hc->cfg_stream_timeout_ms;
    uint32_t keepalive_timeout_ms = hc->cfg_keepalive_timeout_ms;

    /* Connection-level idle: no frames received for keepalive_timeout_ms */
    if (keepalive_timeout_ms > 0 &&
        (now_ms - hc->last_recv_ts) > keepalive_timeout_ms) {
        LOG_WARN("h2: connection idle timeout (%u ms)", keepalive_timeout_ms);
        write_goaway(&hc->write_buf, hc->last_stream_id,
                     H2_ERR_NO_ERROR);
        hc->goaway_sent = 1;
        hc->error       = 1;
        return -1;
        }

    /* Stream-level: open streams with no activity for stream_timeout_ms  */
    if (stream_timeout_ms > 0 &&
        stream_count(hc) > 0 &&
        (now_ms - hc->last_stream_ts) > stream_timeout_ms) {
        LOG_WARN("h2: stream idle timeout (%u ms)", stream_timeout_ms);
        write_goaway(&hc->write_buf, hc->last_stream_id,
                     H2_ERR_SETTINGS_TIMEOUT);
        hc->goaway_sent = 1;
        hc->error       = 1;
        return -1;
        }

    return 0;
}
