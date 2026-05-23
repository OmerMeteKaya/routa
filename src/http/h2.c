#define _GNU_SOURCE
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

/* ── Client connection preface (RFC 7540 §3.5) ───────────────────────────── */
static const uint8_t H2_CLIENT_PREFACE[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_CLIENT_PREFACE_LEN 24

/* ── Frame header size ───────────────────────────────────────────────────── */
#define H2_FRAME_HDR_SZ 9

/* ── Default flow control window (RFC 7540 §6.9.2) ──────────────────────── */
#define H2_DEFAULT_WINDOW 65535

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
            /* Swap with last to keep array compact */
            if (i != p->count - 1)
                p->slots[i] = p->slots[p->count - 1];
            p->count--;
            return;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Stream storage — hashmap backend
 * Open addressing, power-of-2 capacity, linear probing.
 * key=0 means empty slot (stream IDs are always > 0).
 * ═══════════════════════════════════════════════════════════════════════════*/

static int map_init(h2_stream_map_t *m, int capacity) {
    m->capacity = capacity;
    m->count    = 0;
    m->buckets  = calloc((size_t)capacity, sizeof(h2_stream_t *));
    m->keys     = calloc((size_t)capacity, sizeof(uint32_t));
    if (!m->buckets || !m->keys) {
        free(m->buckets);
        free(m->keys);
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
    free(m->buckets);
    free(m->keys);
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
        if (m->keys[slot] == 0)   return NULL;   /* empty — not found    */
        if (m->keys[slot] == id &&
            m->buckets[slot]->state != H2_STREAM_CLOSED)
            return m->buckets[slot];
    }
    return NULL;
}

static h2_stream_t *map_create(h2_stream_map_t *m, uint32_t id,
                                int32_t initial_window) {
    if (m->count >= m->capacity / 2) return NULL;  /* load factor 0.5    */

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

            /* Rehash subsequent entries to maintain probe chain           */
            int j = (slot + 1) & mask;
            while (m->keys[j]) {
                uint32_t k   = m->keys[j];
                h2_stream_t *v = m->buckets[j];
                m->keys[j]    = 0;
                m->buckets[j] = NULL;
                m->count--;
                /* Re-insert */
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
 * Unified stream API — dispatches to pool or map
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

/* Write a 9-byte frame header into buf.
 * length: payload size (24-bit)
 * type:   frame type
 * flags:  frame flags
 * sid:    stream ID (31-bit, MSB=0)                                         */
static int write_frame_hdr(buf_t *buf, uint32_t length,
                            uint8_t type, uint8_t flags, uint32_t sid) {
    uint8_t hdr[H2_FRAME_HDR_SZ];
    hdr[0] = (length >> 16) & 0xff;
    hdr[1] = (length >>  8) & 0xff;
    hdr[2] =  length        & 0xff;
    hdr[3] = type;
    hdr[4] = flags;
    hdr[5] = (sid >> 24) & 0x7f;   /* clear reserved bit                  */
    hdr[6] = (sid >> 16) & 0xff;
    hdr[7] = (sid >>  8) & 0xff;
    hdr[8] =  sid        & 0xff;
    return buf_append(buf, hdr, H2_FRAME_HDR_SZ);
}

/* Write a SETTINGS frame.
 * params: array of (id, value) pairs, count: number of pairs.
 * sid=0 always for SETTINGS.                                                */
static int write_settings(buf_t *buf,
                           const uint16_t *ids,
                           const uint32_t *vals,
                           int count) {
    uint32_t payload_len = (uint32_t)(count * 6);   /* 6 bytes per param   */
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

/* Write a SETTINGS ACK frame (empty SETTINGS with ACK flag).               */
static int write_settings_ack(buf_t *buf) {
    return write_frame_hdr(buf, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
}

/* Write a GOAWAY frame.                                                     */
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

/* Write a RST_STREAM frame.                                                 */
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

/* Write a WINDOW_UPDATE frame.                                              */
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

/* Write a PING ACK frame.                                                   */
static int write_ping_ack(buf_t *buf, const uint8_t *payload) {
    if (write_frame_hdr(buf, 8, H2_FRAME_PING, H2_FLAG_ACK, 0) < 0)
        return -1;
    return buf_append(buf, payload, 8);
}
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

    /* Peer SETTINGS defaults (before client sends SETTINGS)               */
    hc->peer_header_table_size      = 4096;
    hc->peer_max_concurrent_streams = 128;
    hc->peer_max_frame_size         = 16384;
    hc->peer_initial_window_size    = H2_DEFAULT_WINDOW;

    /* HPACK contexts */
    if (hpack_ctx_init(&hc->hpack_rx, cfg->header_table_size,
                       0, 0) < 0) goto fail;   /* rx: never encode        */
    if (hpack_ctx_init(&hc->hpack_tx, cfg->header_table_size,
                       cfg->huffman_encoding,
                       cfg->dynamic_table_update) < 0) goto fail;

    /* Stream storage */
    if (hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP) {
        /* Next power of 2 >= max_concurrent_streams * 2 (load factor 0.5) */
        int cap = 1;
        while (cap < (int)cfg->max_concurrent_streams * 2) cap <<= 1;
        if (map_init(&hc->streams.map, cap) < 0) goto fail;
    }
    /* pool mode: zero-initialized by calloc, nothing extra needed         */

    buf_init(&hc->write_buf);

    /* Send our SETTINGS to client                                         */
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
    write_window_update(&hc->write_buf, 0, 1048576);
   /* LOG_INFO("h2: new connection (mode=%s)",
             hc->lookup_mode == H2_STREAM_LOOKUP_HASHMAP ? "hashmap" : "pool");*/
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
        /* Pool: free each live stream's buffers                           */
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

/* Read a 24-bit big-endian length from frame header.                       */
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

/* Send GOAWAY and mark connection done.                                     */
static int conn_error(h2_conn_t *hc, h2_error_code_t code) {
    if (!hc->goaway_sent) {
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
    /* ACK — our SETTINGS was accepted      */
    if (flags & H2_FLAG_ACK) {
        if (length != 0)
            return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
        hc->settings_ack_pending = 0;
        return 0;
    }
    /* Must be multiple of 6                                               */
    if (length % 6 != 0)
        return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);

    for (uint32_t i = 0; i < length; i += 6) {
        uint16_t id  = ((uint16_t)payload[i] << 8) | payload[i+1];
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
            break;
        case H2_SETTINGS_MAX_CONCURRENT_STREAMS:
            hc->peer_max_concurrent_streams = val;
            break;
        case H2_SETTINGS_INITIAL_WINDOW_SIZE:
            if (val > 0x7fffffff)
                return conn_error(hc, H2_ERR_FLOW_CONTROL_ERROR);
            /* Adjust existing stream windows by delta                     */
            {
                int32_t delta = (int32_t)val -
                                (int32_t)hc->peer_initial_window_size;
                hc->peer_initial_window_size = val;
                hc->initial_send_window      = val;
                /* Apply delta to all open streams                         */
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
        case H2_SETTINGS_MAX_HEADER_LIST_SIZE:
            /* Advisory — we note but don't enforce strictly               */
            break;
        default:
            /* Unknown settings MUST be ignored (RFC 7540 §6.5)           */
            break;
        }
    }

    /* Always ACK                                                          */
    if (write_settings_ack(&hc->write_buf) < 0) return -1;

    /* Advertise our receive window                                        */
    write_window_update(&hc->write_buf, 0, 65535);
    return 0;
}

static int handle_ping(h2_conn_t *hc, const uint8_t *payload,
                        uint32_t length, uint8_t flags, uint32_t stream_id) {
    if (stream_id != 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
    if (length != 8)    return conn_error(hc, H2_ERR_FRAME_SIZE_ERROR);
    if (flags & H2_FLAG_ACK) return 0;   /* ignore PING ACK               */
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
        /* All pending data sent                                           */
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
        /* Connection window update — try to flush all pending streams    */
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
    (void)error_code;   /* logged below if needed */

    h2_stream_t *s = stream_find(hc, stream_id);
    if (s) {
        /* Discard any pending outbound data for this stream              */
        buf_reset(&s->pending_data);
        s->pending_offset = 0;
        s->state = H2_STREAM_CLOSED;
        stream_remove(hc, stream_id);
    }
    /* Unknown stream ID in RST_STREAM is silently ignored (RFC 7540 §6.4) */
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

    for (int i = 0; i < s->header_count; i++) {
        const char *name  = s->headers[i].name;
        const char *value = s->headers[i].value;
        if (strcmp(name, ":method") == 0) {
            if      (strcmp(value, "GET")     == 0) req->method = HTTP_GET;
            else if (strcmp(value, "POST")    == 0) req->method = HTTP_POST;
            else if (strcmp(value, "PUT")     == 0) req->method = HTTP_PUT;
            else if (strcmp(value, "DELETE")  == 0) req->method = HTTP_DELETE;
            else if (strcmp(value, "HEAD")    == 0) req->method = HTTP_HEAD;
            else if (strcmp(value, "PATCH")   == 0) req->method = HTTP_PATCH;
            else if (strcmp(value, "OPTIONS") == 0) req->method = HTTP_OPTIONS;
            else req->method = HTTP_METHOD_UNKNOWN;

        } else if (strcmp(name, ":path") == 0) {
            const char *q = strchr(value, '?');
            if (q) {
                req->path  = strndup(value, (size_t)(q - value));
                req->query = strdup(q + 1);
            } else {
                req->path  = strdup(value);
                req->query = NULL;
            }
        } else if (strcmp(name, ":authority") == 0) {
        } else if (strcmp(name, "content-length") == 0) {
        }

        if (req->header_count < 64) {
            req->headers[req->header_count].key   = strdup(name);
            req->headers[req->header_count].value = strdup(value);
            if (req->headers[req->header_count].key &&
                req->headers[req->header_count].value)
                req->header_count++;
        }
    }
    if (!req->path) req->path = strdup("/");

    if (s->body.len > 0) {
        req->body = malloc(s->body.len);
        if (req->body) {
            memcpy(req->body, s->body.data, s->body.len);
            req->body_len = s->body.len;
        }
    }
    return 0;
}

/* ── Write HTTP response as H2 HEADERS + DATA frames ────────────────────── */
static int send_response(h2_conn_t *hc, uint32_t stream_id, h2_stream_t *s,
                          http_response_t *resp) {
    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%d", resp->status);

    int max_h = resp->header_count + 3;
    hpack_header_t *enc_headers = calloc((size_t)max_h,
                                          sizeof(hpack_header_t));
    if (!enc_headers) return -1;

    int nhdr = 0;
    enc_headers[nhdr].name  = ":status";
    enc_headers[nhdr].value = status_str;
    nhdr++;
    char cl_val[32];
    if (resp->body_len > 0) {
        snprintf(cl_val, sizeof(cl_val), "%zu", resp->body_len);
        enc_headers[nhdr].name  = "content-length";
        enc_headers[nhdr].value = cl_val;
        nhdr++;
    }

    for (int i = 0; i < resp->header_count; i++) {
        const char *hname = resp->headers[i][0];
        if (!hname || hname[0] == '\0') continue;
        if (strcasecmp(hname, "connection")        == 0 ||
            strcasecmp(hname, "keep-alive")        == 0 ||
            strcasecmp(hname, "transfer-encoding") == 0 ||
            strcasecmp(hname, "upgrade")           == 0 ||
            strcasecmp(hname, "content-length")    == 0) continue;
        const char *hval = resp->headers[i][1];
        if (!hval) continue;
        enc_headers[nhdr].name  = (char *)hname;
        enc_headers[nhdr].value = (char *)hval;
        nhdr++;
    }

    uint8_t hdr_block[16384];
    for (int i = 0; i < nhdr; i++);
    int hdr_len = hpack_encode(&hc->hpack_tx, enc_headers, nhdr,
                                hdr_block, sizeof(hdr_block));
    free(enc_headers);
    if (hdr_len < 0) return -1;

    int has_body = (resp->body && resp->body_len > 0) ||
                   (resp->body_fd >= 0);
    uint8_t flags = H2_FLAG_END_HEADERS |
                    (has_body ? 0 : H2_FLAG_END_STREAM);

    if (write_frame_hdr(&hc->write_buf, (uint32_t)hdr_len,
                        H2_FRAME_HEADERS, flags, stream_id) < 0) {
        return -1;
    }
    if (buf_append(&hc->write_buf, hdr_block, (size_t)hdr_len) < 0)
        return -1;
    if (resp->body && resp->body_len > 0) {
        size_t rem = resp->body_len;
        const uint8_t *ptr = (const uint8_t *)resp->body;

        while (rem > 0) {
            /* How much can we send right now? */
            int32_t conn_win   = hc->send_window;
            int32_t stream_win = s->send_window;
            int32_t win        = conn_win < stream_win ? conn_win : stream_win;
            if (win <= 0) {
                /* Window exhausted — buffer remaining data in stream     */
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

static int dispatch_stream(h2_conn_t *hc, h2_stream_t *s,
                            uint32_t stream_id,
                            struct router *router,
                            struct middleware_chain *chain) {
    http_request_t  req;
    http_response_t resp;
    stream_to_request(s, &req);
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

    /* Client streams must be odd                                          */
    if ((stream_id & 1) == 0) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    /* Concurrent stream limit                                             */
    if (stream_count(hc) >= (int)hc->peer_max_concurrent_streams) {
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_STREAM_CLOSED);
        return 0;
    }

    const uint8_t *hdr_data = payload;
    uint32_t       hdr_len  = length;

    /* Strip padding                                                       */
    uint8_t pad_len = 0;
    if (flags & H2_FLAG_PADDED) {
        if (length < 1) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        pad_len  = payload[0];
        hdr_data = payload + 1;
        hdr_len  = length  - 1;
        if (pad_len >= hdr_len) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        hdr_len -= pad_len;
    }

    /* Strip priority                                                      */
    if (flags & H2_FLAG_PRIORITY) {
        if (hdr_len < 5) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        hdr_data += 5;
        hdr_len  -= 5;
    }

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
    }

    /* Accumulate header block fragment                                    */
    if (buf_append(&s->header_block, hdr_data, hdr_len) < 0)
        return conn_error(hc, H2_ERR_INTERNAL_ERROR);

    if (!(flags & H2_FLAG_END_HEADERS)) {
        /* Wait for CONTINUATION frames                                    */
        s->expect_continuation          = 1;
        hc->continuation_stream_id      = stream_id;
        return 0;
    }

    /* END_HEADERS — decode full header block                              */
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
        s->body.data = NULL; s->body.len = 0; s->body.cap = 0;
        write_window_update(&hc->write_buf, 0, (uint32_t)length);
        /* Keep stream alive if pending data remains                      */
        if (s->pending_data.len == 0) {
            s->state = H2_STREAM_CLOSED;
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

    h2_stream_t *s = stream_find(hc, stream_id);
    if (!s) return conn_error(hc, H2_ERR_PROTOCOL_ERROR);

    if (buf_append(&s->header_block, payload, length) < 0)
        return conn_error(hc, H2_ERR_INTERNAL_ERROR);

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

        s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        dispatch_stream(hc, s, stream_id, router, chain);
        s->body.data = NULL;
        s->body.len  = 0;
        s->body.cap  = 0;
        s->state = H2_STREAM_CLOSED;
        stream_remove(hc, stream_id);
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

    h2_stream_t *s = stream_find(hc, stream_id);
    if (!s) {
       // LOG_WARN("h2: DATA for unknown stream %u", stream_id);
        write_rst_stream(&hc->write_buf, stream_id, H2_ERR_STREAM_CLOSED);
        return 0;
    }

    /* Strip padding                                                       */
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

    /* Flow control: send WINDOW_UPDATE to keep stream alive               */
    if (dlen > 0) {
        hc->recv_window += (int32_t)dlen;   /* restore before WINDOW_UPDATE */
        write_window_update(&hc->write_buf, stream_id, dlen);
        write_window_update(&hc->write_buf, 0, dlen);
    }

    if (flags & H2_FLAG_END_STREAM) {
        s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        dispatch_stream(hc, s, stream_id, router, chain);
        s->body.data = NULL; s->body.len = 0; s->body.cap = 0;
        if (s->pending_data.len == 0) {
            s->state = H2_STREAM_CLOSED;
            stream_remove(hc, stream_id);
        } else {
            s->state = H2_STREAM_HALF_CLOSED_REMOTE;
        }
    }
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
    /* ── Client preface check (first call only) ── */
    if (!hc->preface_done) {
        if (rb->len < H2_CLIENT_PREFACE_LEN) return 0;
        if (memcmp(rb->data, H2_CLIENT_PREFACE,
                   H2_CLIENT_PREFACE_LEN) != 0) {
            LOG_WARN("h2: bad client preface");
            return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
                   }
        buf_consume(rb, H2_CLIENT_PREFACE_LEN);
        hc->preface_done = 1;
    }
    /* ── Frame loop ── */
    while (rb->len >= H2_FRAME_HDR_SZ) {
        const uint8_t *hdr     = (const uint8_t *)rb->data;
        uint32_t       pay_len = frame_length(hdr);
        uint8_t        type    = frame_type(hdr);
        uint8_t        flags   = frame_flags(hdr);
        uint32_t       sid     = frame_stream(hdr);

        /* Wait until full frame is buffered                               */
        if (rb->len < H2_FRAME_HDR_SZ + pay_len) break;

        const uint8_t *payload = (const uint8_t *)rb->data + H2_FRAME_HDR_SZ;

        /* CONTINUATION interlock — only CONTINUATION allowed mid-block   */
        if (hc->continuation_stream_id != 0 &&
            type != H2_FRAME_CONTINUATION)
            return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
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
            rc = handle_goaway(hc,payload,pay_len);
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
            /* Ignore — deprecated in RFC 9113, no-op here                */
            break;
        case H2_FRAME_PUSH_PROMISE:
            /* Client must not send PUSH_PROMISE                          */
            return conn_error(hc, H2_ERR_PROTOCOL_ERROR);
        default:
            /* Unknown frame types MUST be ignored (RFC 7540 §4.1)        */
            break;
        }
        buf_consume(rb, H2_FRAME_HDR_SZ + pay_len);
        if (rc < 0) return -1;
    }
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