#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/h2.h"
#include "http/router.h"
#include "http/middleware.h"
#include "http/request.h"
#include "http/response.h"
#include "core/conn.h"
#include "net/io.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "util/metrics.h"

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
    hc->send_window  = H2_DEFAULT_WINDOW;
    hc->recv_window  = 1048576;
    hc->initial_send_window = H2_DEFAULT_WINDOW;
    hc->cfg_stream_timeout_ms    = cfg->stream_timeout_ms    > 0
                                   ? (uint32_t)cfg->stream_timeout_ms    : 30000;
    hc->cfg_keepalive_timeout_ms = cfg->keepalive_timeout_ms > 0
                                   ? (uint32_t)cfg->keepalive_timeout_ms : 120000;
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

    uint16_t ids[5] = {
        H2_SETTINGS_HEADER_TABLE_SIZE,
        H2_SETTINGS_MAX_CONCURRENT_STREAMS,
        H2_SETTINGS_INITIAL_WINDOW_SIZE,
        H2_SETTINGS_MAX_FRAME_SIZE,
        H2_SETTINGS_MAX_HEADER_LIST_SIZE,
    };
    uint32_t vals[5] = {
        cfg->header_table_size,
        cfg->max_concurrent_streams,
        cfg->initial_window_size,
        cfg->max_frame_size,
        cfg->max_header_list_size,
    };
    if (write_settings(&hc->write_buf, ids, vals, 5) < 0) goto fail;
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
                            uint8_t flags) {
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
    if (s->pending_data.len == 0) return;

    size_t rem = s->pending_data.len - s->pending_offset;
    const uint8_t *ptr = (const uint8_t *)s->pending_data.data
                         + s->pending_offset;

    while (rem > 0) {
        int32_t conn_win   = hc->send_window;
        int32_t stream_win = s->send_window;
        int32_t win        = conn_win < stream_win ? conn_win : stream_win;
        if (win <= 0) break;

        size_t can_send = (size_t)win < rem ? (size_t)win : rem;
        size_t chunk    = can_send < hc->peer_max_frame_size
                          ? can_send : hc->peer_max_frame_size;
        int end = (chunk == rem);

        if (write_frame_hdr(&hc->write_buf, (uint32_t)chunk,
                            H2_FRAME_DATA,
                            end ? H2_FLAG_END_STREAM : 0,
                            s->id) < 0) break;
        if (buf_append(&hc->write_buf, ptr, chunk) < 0) break;

        hc->send_window    -= (int32_t)chunk;
        s->send_window     -= (int32_t)chunk;
        s->pending_offset  += chunk;
        ptr += chunk;
        rem -= chunk;
    }

    if (s->pending_offset >= s->pending_data.len) {
        buf_reset(&s->pending_data);
        s->pending_offset = 0;
        if (s->state == H2_STREAM_HALF_CLOSED_REMOTE) {
            s->state = H2_STREAM_CLOSED;
            stream_remove(hc, s->id);
        }
    }
}

static int handle_window_update(h2_conn_t *hc, const uint8_t *payload,
                                 uint32_t length, uint32_t stream_id) {
    if (length != 4) return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
    uint32_t increment = (((uint32_t)payload[0] & 0x7f) << 24) |
                          ((uint32_t)payload[1] << 16) |
                          ((uint32_t)payload[2] <<  8) |
                           (uint32_t)payload[3];
    if (increment == 0) {
        if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_PROTOCOL_ERROR);
        return 0;
    }

    if (stream_id == 0) {
        hc->send_window += (int32_t)increment;
        if (hc->send_window > 0x7fffffff)
            return conn_error(hc, H2_ERR_FLOW_CONTROL_ERROR);
    } else {
        h2_stream_t *s = stream_find(hc, stream_id);
        if (s) {
            s->send_window += (int32_t)increment;
            if (s->send_window > 0x7fffffff) {
                write_rst_stream(&hc->write_buf, stream_id,
                                 H2_ERR_FLOW_CONTROL_ERROR);
            }
        }
    }

    if (stream_id == 0) {
        if (hc->lookup_mode == H2_STREAM_LOOKUP_LINEAR) {
            for (int i = 0; i < hc->streams.pool.count; i++) {
                h2_stream_t *ps = &hc->streams.pool.slots[i];
                if (ps->pending_data.len > ps->pending_offset)
                    flush_pending(hc, ps);
            }
        } else {
            for (int i = 0; i < hc->streams.map.capacity; i++) {
                if (!hc->streams.map.keys[i]) continue;
                h2_stream_t *ps = hc->streams.map.buckets[i];
                if (ps->pending_data.len > ps->pending_offset)
                    flush_pending(hc, ps);
            }
        }
    } else {
        h2_stream_t *ps = stream_find(hc, stream_id);
        if (ps && ps->pending_data.len > ps->pending_offset)
            flush_pending(hc, ps);
    }
    return 0;
}

static int handle_rst_stream(h2_conn_t *hc, const uint8_t *payload,
                              uint32_t length, uint32_t stream_id) {
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if (length != 4)    return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

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
static int stream_to_request(h2_stream_t *s, http_request_t *req) {
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
        req->body     = s->body.data;
        req->body_len = s->body.len;
        /* Steal body buffer */
        s->body.data = NULL;
        s->body.len  = 0;
        s->body.cap  = 0;
    }
    return 0;
}
/* ── Write HTTP response as H2 HEADERS + DATA frames ────────────────────── */
static int send_response(h2_conn_t *hc, uint32_t stream_id, h2_stream_t *s,
                          http_response_t *resp) {
    char status_str[4];
    (void)snprintf(status_str, sizeof(status_str), "%d", resp->status);

    hpack_header_t enc_headers[35];
    memset(enc_headers, 0, sizeof(enc_headers));

    int nhdr = 0;
    enc_headers[nhdr].name  = ":status";
    enc_headers[nhdr].value = status_str;
    nhdr++;

    char cl_val[32];
    if (resp->body_len > 0) {
        (void)snprintf(cl_val, sizeof(cl_val), "%zu", resp->body_len);
        enc_headers[nhdr].name  = "content-length";
        enc_headers[nhdr].value = cl_val;
        nhdr++;
    }

    for (int i = 0; i < resp->header_count; i++) {
        const char *hname = resp->headers[i][0];
        const char *hval  = resp->headers[i][1];
        if (!hname || hname[0] == '\0') continue;
        if (!hval) continue;
        /* content-length is emitted above; skip duplicates from set_body */
        if (strcasecmp(hname, "content-length") == 0) continue;
        enc_headers[nhdr].name  = (char *)hname;
        enc_headers[nhdr].value = (char *)hval;
        nhdr++;
    }

    uint8_t hdr_block[4096];
    int hdr_len = hpack_encode(&hc->hpack_tx, enc_headers, nhdr,
                                hdr_block, sizeof(hdr_block));
    if (hdr_len < 0) return -1;

    /* FIX: correctly detect body presence including fd path              */
    int has_body = (resp->body && resp->body_len > 0) ||
                   (resp->body_fd >= 0 && resp->body_len > 0);
    uint8_t hflags = H2_FLAG_END_HEADERS |
                     (has_body ? 0 : H2_FLAG_END_STREAM);

    if (write_frame_hdr(&hc->write_buf, (uint32_t)hdr_len,
                        H2_FRAME_HEADERS, hflags, stream_id) < 0) {
        return -1;
    }
    if (buf_append(&hc->write_buf, hdr_block, (size_t)hdr_len) < 0)
        return -1;

    /* ── body_fd path (read into buffer, then flow-control-aware send) ── */
    if (resp->body_fd >= 0 && resp->body_len > 0) {
        #define FBUF_SZ 65536
        uint8_t *fbuf = malloc(FBUF_SZ);
        if (!fbuf) return -1;

        size_t total  = resp->body_len;
        size_t offset = 0;  /* bytes sent to write_buf so far */
        int    rc     = 0;

        while (offset < total) {
            size_t want = total - offset;
            if (want > FBUF_SZ) want = FBUF_SZ;

            ssize_t nr = read(resp->body_fd, fbuf, want);
            if (nr <= 0) break;

            size_t rem = (size_t)nr;
            const uint8_t *ptr = fbuf;

            while (rem > 0) {
                int32_t conn_win   = hc->send_window;
                int32_t stream_win = s->send_window;
                int32_t win = conn_win < stream_win ? conn_win : stream_win;

                if (win <= 0) {
                    /*
                     * Window exhausted. Save the unprocessed bytes from the
                     * current read (ptr..ptr+rem) plus ALL remaining file
                     * content into pending_data. Without draining the fd here,
                     * http_response_destroy() would close body_fd and those
                     * bytes would be silently lost, producing a truncated
                     * response followed by a broken-pipe or RST_STREAM.
                     *
                     * fd_rem = total - offset - rem:
                     *   offset = bytes already sent
                     *   rem    = bytes read into fbuf but not yet sent
                     *   fd_rem = bytes still unread in the file
                     */
                    if (buf_append(&s->pending_data, ptr, rem) < 0) {
                        rc = -1; goto fd_done;
                    }
                    size_t fd_rem = total - offset - rem;
                    while (fd_rem > 0) {
                        size_t want2 = fd_rem < FBUF_SZ ? fd_rem : FBUF_SZ;
                        ssize_t nr2 = read(resp->body_fd, fbuf, want2);
                        if (nr2 <= 0) break;
                        if (buf_append(&s->pending_data, fbuf,
                                       (size_t)nr2) < 0) {
                            rc = -1; goto fd_done;
                        }
                        fd_rem -= (size_t)nr2;
                    }
                    s->pending_offset = 0;
                    goto fd_done;
                }

                size_t can_send = (size_t)win < rem ? (size_t)win : rem;
                size_t chunk    = can_send < hc->peer_max_frame_size
                                  ? can_send : hc->peer_max_frame_size;
                offset += chunk;
                int end = (offset >= total) && (chunk == rem);

                if (write_frame_hdr(&hc->write_buf, (uint32_t)chunk,
                                    H2_FRAME_DATA,
                                    end ? H2_FLAG_END_STREAM : 0,
                                    stream_id) < 0) {
                    rc = -1; goto fd_done;
                }
                if (buf_append(&hc->write_buf, ptr, chunk) < 0) {
                    rc = -1; goto fd_done;
                }

                hc->send_window -= (int32_t)chunk;
                s->send_window  -= (int32_t)chunk;
                ptr += chunk;
                rem -= chunk;
            }
        }

        fd_done:
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
                                stream_id) < 0) return -1;
            if (buf_append(&hc->write_buf, ptr, chunk) < 0) return -1;

            hc->send_window -= (int32_t)chunk;
            s->send_window  -= (int32_t)chunk;
            ptr += chunk;
            rem -= chunk;
        }
    }
    return 0;
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
    if (ps->pending_data.len == 0) {
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
    stream_to_request(s, &req);
    req.start_us = dispatch_start;
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
    http_response_set_header(&resp, "server", "routa");
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
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if ((stream_id & 1) == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    if (length > hc->peer_max_frame_size)
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

    if (stream_count(hc) >= (int)hc->peer_max_concurrent_streams) {
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_STREAM_CLOSED);
        return 0;
    }

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
        hdr_data += 5;
        hdr_len  -= 5;
    }

    /* ── Now create stream — all frame-level validation passed ─────────── */
    h2_stream_t *s = stream_find(hc, stream_id);
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
                         (const uint8_t *)s->header_block.data,
                         s->header_block.len,
                         headers, 64);
    buf_reset(&s->header_block);
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

    if (flags & H2_FLAG_END_STREAM) {
        s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        dispatch_stream(hc, s, stream_id, router, chain);
        buf_reset(&s->body);
        if (s->pending_data.len == 0) {
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

    /* FIX: max_frame_size enforcement on CONTINUATION                   */
    if (length > hc->peer_max_frame_size)
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
                             (const uint8_t *)s->header_block.data,
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
        dispatch_stream(hc, s, stream_id, router, chain);
        buf_reset(&s->body);
        if (s->pending_data.len == 0) {
            s->state = H2_STREAM_CLOSED;
            stream_remove(hc, stream_id);
        }
        /* else: stream stays alive until pending_data is flushed        */
    }
    return 0;
}

/* ── DATA frame handler ──────────────────────────────────────────────────── */
static int handle_data(h2_conn_t *hc, uint32_t stream_id,
                        const uint8_t *payload, uint32_t length,
                        uint8_t flags,
                        struct router *router,
                        struct middleware_chain *chain) {
    if (stream_id == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    /* FIX: max_frame_size enforcement on DATA                           */
    if (length > hc->peer_max_frame_size)
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

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
        dispatch_stream(hc, s, stream_id, router, chain);
        buf_reset(&s->body);
        if (s->pending_data.len == 0) {
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
        if (buf_append(&saved, hc->write_buf.data,
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
        if (buf_append(&hc->write_buf, saved.data, saved.len) < 0) {
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
    dispatch_stream(hc, s, 1, router, chain);

    s->body.data = NULL; s->body.len = 0; s->body.cap = 0;
    if (s->pending_data.len == 0) {
        s->state = H2_STREAM_CLOSED;
        stream_remove(hc, 1);
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
    if (!hc || !hc->conn) return -1;

    buf_t *rb = &hc->conn->read_buf;

    if (!hc->preface_done) {
        if (rb->len < H2_CLIENT_PREFACE_LEN) return 0;
        if (memcmp(rb->data, H2_CLIENT_PREFACE,
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
    const uint8_t *hdr     = (const uint8_t *)rb->data + offset;
    uint32_t       pay_len = frame_length(hdr);
    uint8_t        type    = frame_type(hdr);
    uint8_t        flags   = frame_flags(hdr);
    uint32_t       sid     = frame_stream(hdr);

    if (rb->len - offset < H2_FRAME_HDR_SZ + pay_len) break;

    if (pay_len > hc->peer_max_frame_size &&
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
        rc = handle_settings(hc, payload, pay_len, flags);
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
        break;
    case H2_FRAME_PUSH_PROMISE:
        buf_consume(rb, offset);
        return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    default:
        break;
    }

    if (hc->send_window > 0) {
        if (hc->lookup_mode == H2_STREAM_LOOKUP_LINEAR) {
            for (int _i = 0; _i < hc->streams.pool.count; _i++) {
                h2_stream_t *_s = &hc->streams.pool.slots[_i];
                if (_s->pending_data.len > _s->pending_offset)
                    flush_pending(hc, _s);
            }
        } else {
            for (int _i = 0; _i < hc->streams.map.capacity; _i++) {
                if (!hc->streams.map.keys[_i]) continue;
                h2_stream_t *_s = hc->streams.map.buckets[_i];
                if (_s->pending_data.len > _s->pending_offset)
                    flush_pending(hc, _s);
            }
        }
    }

    hc->frame_count++;
    if ((hc->frame_count & 15) == 0) {
        struct timespec _rts;
        clock_gettime(CLOCK_MONOTONIC, &_rts);
        hc->last_recv_ts = (uint64_t)_rts.tv_sec * 1000 +
                           (uint64_t)_rts.tv_nsec / 1000000;
    }

    offset += H2_FRAME_HDR_SZ + pay_len;

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
