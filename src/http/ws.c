#define _GNU_SOURCE
#include "http/ws.h"
#include "http/request.h"
#include "core/conn.h"
#include "util/buf.h"
#include "util/logger.h"
#include "core/event_loop.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <errno.h>
#include <unistd.h>

/* ── Constants ──────────────────────────────────────────────────────────── */
#define WS_GUID         "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_GUID_LEN     36
#define WS_KEY_MAX      64
#define WS_ACCEPT_LEN   29      /* base64(sha1) = 28 chars + NUL           */
#define WS_FRAME_HDR_MAX 14

/* ── Config defaults ────────────────────────────────────────────────────── */
void ws_config_init(ws_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled                = 0;
    cfg->max_connections        = 10000;
    cfg->handshake_timeout_ms   = 5000;
    cfg->idle_timeout_ms        = 0;
    cfg->max_frame_size         = 16 * 1024 * 1024;   /* 16 MB             */
    cfg->max_message_size       = 64 * 1024 * 1024;   /* 64 MB             */
    cfg->ping_interval_ms       = 30000;
    cfg->ping_timeout_ms        = 10000;
    cfg->max_ping_misses        = 3;
    cfg->read_buf_size          = 65536;
    cfg->write_buf_size         = 65536;
    cfg->write_queue_max        = 128;
    cfg->permessage_deflate     = 0;
    cfg->compression_level      = 6;
    cfg->compression_threshold  = 512;
    cfg->require_masking        = 1;
}

/* ── Frame state ────────────────────────────────────────────────────────── */
void ws_frame_state_init(ws_frame_state_t *fs) {
    if (!fs) return;
    memset(fs, 0, sizeof(*fs));
    fs->phase = WS_PARSE_HEADER;
    buf_init(&fs->frag_buf);
}

void ws_frame_state_free(ws_frame_state_t *fs) {
    if (!fs) return;
    buf_free(&fs->frag_buf);
    memset(fs, 0, sizeof(*fs));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handshake
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Check whether an HTTP request is a WebSocket upgrade request. */
int ws_is_upgrade_request(const http_request_t *req) {
    if (!req) return 0;
    const char *upgrade    = http_request_get_header(req, "Upgrade");
    const char *connection = http_request_get_header(req, "Connection");
    if (!upgrade || !connection) return 0;
    /* Case-insensitive match per RFC 6455 §4.1 */
    return (strcasecmp(upgrade, "websocket") == 0 &&
            strcasestr(connection, "Upgrade") != NULL);
}

/* Compute Sec-WebSocket-Accept from Sec-WebSocket-Key.
 * out must be at least WS_ACCEPT_LEN bytes.                               */
static int compute_accept(const char *key, char *out) {
    char  buf[WS_KEY_MAX + WS_GUID_LEN + 1];
    size_t key_len = strlen(key);
    if (key_len == 0 || key_len >= WS_KEY_MAX) return -1;

    memcpy(buf, key, key_len);
    memcpy(buf + key_len, WS_GUID, WS_GUID_LEN);
    buf[key_len + WS_GUID_LEN] = '\0';

    /* SHA-1 */
    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)buf, key_len + WS_GUID_LEN, digest);

    /* Base64 encode */
    EVP_EncodeBlock((unsigned char *)out, digest, SHA_DIGEST_LENGTH);
    return 0;
}

int ws_handshake(conn_t *conn, const http_request_t *req,
                 buf_t *out, const ws_config_t *cfg) {
    (void)cfg;   /* reserved for future origin/subprotocol checks          */

    if (!conn || !req || !out) return -1;

    const char *key = http_request_get_header(req, "Sec-WebSocket-Key");
    if (!key || strlen(key) == 0) {
        LOG_WARN("ws: missing Sec-WebSocket-Key from %s", conn->remote_ip);
        return -1;
    }

    /* RFC 6455 §4.1: version must be 13 */
    const char *ver = http_request_get_header(req, "Sec-WebSocket-Version");
    if (!ver || strcmp(ver, "13") != 0) {
        LOG_WARN("ws: unsupported version '%s' from %s",
                 ver ? ver : "(null)", conn->remote_ip);
        return -1;
    }

    char accept[WS_ACCEPT_LEN + 1];
    memset(accept, 0, sizeof(accept));
    if (compute_accept(key, accept) < 0) {
        LOG_WARN("ws: failed to compute accept key for %s", conn->remote_ip);
        return -1;
    }

    /* Write 101 Switching Protocols response */
    buf_append_str(out, "HTTP/1.1 101 Switching Protocols\r\n");
    buf_append_str(out, "Upgrade: websocket\r\n");
    buf_append_str(out, "Connection: Upgrade\r\n");
    buf_append_str(out, "Sec-WebSocket-Accept: ");
    buf_append_str(out, accept);
    buf_append_str(out, "\r\n\r\n");

    conn->ws_state = WS_STATE_OPEN;
    ws_frame_state_init(&conn->ws_fs);

    LOG_DEBUG("ws: handshake complete for %s", conn->remote_ip);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Frame serialization (send path)
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Build a WebSocket frame header into hdr[].
 * Returns the number of header bytes written.
 * Server-to-client frames are never masked (RFC 6455 §5.1).              */
static int build_frame_header(uint8_t *hdr, ws_opcode_t opcode,
                               int fin, uint64_t payload_len) {
    int idx = 0;
    hdr[idx++] = (uint8_t)(((fin ? 1 : 0) << 7) | (opcode & 0x0F));

    if (payload_len < 126) {
        hdr[idx++] = (uint8_t)payload_len;
    } else if (payload_len <= 0xFFFF) {
        hdr[idx++] = 126;
        hdr[idx++] = (uint8_t)(payload_len >> 8);
        hdr[idx++] = (uint8_t)(payload_len & 0xFF);
    } else {
        hdr[idx++] = 127;
        for (int i = 7; i >= 0; i--)
            hdr[idx++] = (uint8_t)(payload_len >> (8 * i));
    }
    return idx;
}

int ws_send(conn_t *conn, const uint8_t *data, size_t len,
            ws_opcode_t opcode) {
    if (!conn || (!data && len > 0)) return -1;
    if (conn->ws_state != WS_STATE_OPEN &&
        conn->ws_state != WS_STATE_CLOSING) return -1;

    uint8_t hdr[WS_FRAME_HDR_MAX];
    int hdr_len = build_frame_header(hdr, opcode, /*fin=*/1, (uint64_t)len);

    if (buf_append(&conn->write_buf, hdr, (size_t)hdr_len) < 0) return -1;
    if (len > 0 && buf_append(&conn->write_buf, data, len) < 0) return -1;
    return 0;
}

int ws_ping(conn_t *conn, const uint8_t *payload, size_t len) {
    /* Control frames must not exceed 125 bytes (RFC 6455 §5.5) */
    if (len > 125) return -1;
    return ws_send(conn, payload, len, WS_OP_PING);
}

int ws_pong(conn_t *conn, const uint8_t *payload, size_t len) {
    if (len > 125) return -1;
    return ws_send(conn, payload, len, WS_OP_PONG);
}

int ws_close(conn_t *conn, ws_close_code_t code, const char *reason) {
    if (!conn) return -1;
    if (conn->ws_state == WS_STATE_CLOSED) return 0;

    size_t reason_len = reason ? strlen(reason) : 0;
    /* Close payload: 2-byte code + optional reason (max 123 bytes) */
    if (reason_len > 123) reason_len = 123;

    size_t payload_len = 2 + reason_len;
    uint8_t payload[125];
    payload[0] = (uint8_t)((code >> 8) & 0xFF);
    payload[1] = (uint8_t)(code & 0xFF);
    if (reason_len > 0)
        memcpy(payload + 2, reason, reason_len);

    conn->ws_state = WS_STATE_CLOSING;
    return ws_send(conn, payload, payload_len, WS_OP_CLOSE);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Frame parsing (recv path)
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Unmask payload in-place. */
static void unmask_payload(uint8_t *data, size_t len, const uint8_t mask[4]) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= mask[i & 3];
}

/* Parse as many frames as possible from conn->read_buf.
 * Calls handler callbacks for complete messages.
 * Returns 0 to continue, -1 to close the connection.                     */
int ws_recv(conn_t *conn, const ws_handler_t *handler,
            const ws_config_t *cfg) {
    if (!conn || !handler || !cfg) return -1;
    if (conn->ws_state != WS_STATE_OPEN &&
        conn->ws_state != WS_STATE_CLOSING) return -1;

    ws_frame_state_t *fs  = &conn->ws_fs;
    buf_t            *rb  = &conn->read_buf;

    while (rb->len > 0) {
        switch (fs->phase) {

        /* ── Phase 1: parse the first 2 header bytes ─────────────────── */
        case WS_PARSE_HEADER: {
            /* Need at least 2 bytes to determine extended length size */
            if (rb->len < 2) return 0;

            uint8_t b0 = ((uint8_t *)rb->data)[0];
            uint8_t b1 = ((uint8_t *)rb->data)[1];

            fs->fin    = (b0 >> 7) & 1;
            fs->rsv1   = (b0 >> 6) & 1;
            fs->opcode = (ws_opcode_t)(b0 & 0x0F);
            fs->masked = (b1 >> 7) & 1;

            if (cfg->require_masking && !fs->masked) {
                LOG_WARN("ws: unmasked frame from client %s", conn->remote_ip);
                ws_close(conn, WS_CLOSE_PROTOCOL, "masking required");
                return -1;
            }

            uint8_t raw_len = b1 & 0x7F;

            /* Determine how many more header bytes we need */
            int extra = fs->masked ? 4 : 0;
            if      (raw_len == 126) extra += 2;
            else if (raw_len == 127) extra += 8;

            if (rb->len < (size_t)(2 + extra)) return 0; /* wait for more  */

            /* Read extended length */
            const uint8_t *p = (uint8_t *)rb->data + 2;
            if (raw_len < 126) {
                fs->payload_len = raw_len;
            } else if (raw_len == 126) {
                fs->payload_len = ((uint64_t)p[0] << 8) | p[1];
                p += 2;
            } else {
                fs->payload_len = 0;
                for (int i = 0; i < 8; i++)
                    fs->payload_len = (fs->payload_len << 8) | p[i];
                p += 8;
            }

            /* Enforce size limits */
            if (fs->payload_len > cfg->max_frame_size) {
                LOG_WARN("ws: frame too large (%llu) from %s",
                         (unsigned long long)fs->payload_len, conn->remote_ip);
                ws_close(conn, WS_CLOSE_TOO_LARGE, "frame too large");
                return -1;
            }

            /* Read masking key */
            if (fs->masked) {
                memcpy(fs->mask, p, 4);
                p += 4;
            }

            /* Consume header bytes */
            size_t hdr_consumed = (size_t)(p - (uint8_t *)rb->data);
            buf_consume(rb, hdr_consumed);

            fs->payload_read = 0;
            fs->phase        = WS_PARSE_PAYLOAD;
            break;
        }

        /* ── Phase 2: read payload bytes ─────────────────────────────── */
        case WS_PARSE_PAYLOAD: {
            uint64_t remaining = fs->payload_len - fs->payload_read;
            size_t   available = rb->len;
            size_t   to_read   = (available < (size_t)remaining)
                                 ? available : (size_t)remaining;

            if (to_read == 0) return 0;   /* wait for more data           */

            uint8_t *payload_ptr = (uint8_t *)rb->data;

            /* Unmask in-place before processing */
            if (fs->masked)
                unmask_payload(payload_ptr, to_read, fs->mask);

            /* ── Control frames (must not be fragmented, max 125 bytes) */
            int is_control = (fs->opcode == WS_OP_PING  ||
                              fs->opcode == WS_OP_PONG  ||
                              fs->opcode == WS_OP_CLOSE);

            if (is_control) {
                /* Control frames must fit in a single frame */
                if (!fs->fin || fs->payload_len > 125) {
                    ws_close(conn, WS_CLOSE_PROTOCOL,
                             "fragmented or oversized control frame");
                    return -1;
                }
                /* Must have full payload before dispatching */
                if (to_read < (size_t)fs->payload_len) return 0;

                if (fs->opcode == WS_OP_PING) {
                    ws_pong(conn, payload_ptr, (size_t)fs->payload_len);

                } else if (fs->opcode == WS_OP_PONG) {
                    conn->ws_ping_misses = 0;   /* reset miss counter      */

                } else if (fs->opcode == WS_OP_CLOSE) {
                    ws_close_code_t code = WS_CLOSE_NORMAL;
                    const char     *reason = NULL;
                    if (fs->payload_len >= 2) {
                        code = (ws_close_code_t)(
                            ((uint16_t)payload_ptr[0] << 8) | payload_ptr[1]);
                        if (fs->payload_len > 2)
                            reason = (char *)payload_ptr + 2;
                    }
                    if (handler->on_close)
                        handler->on_close(conn, code, reason, handler->ctx);
                    /* Echo close frame and mark closed */
                    ws_close(conn, WS_CLOSE_NORMAL, NULL);
                    conn->ws_state = WS_STATE_CLOSED;
                    buf_consume(rb, (size_t)fs->payload_len);
                    return -1;   /* signal caller to tear down              */
                }

                buf_consume(rb, (size_t)fs->payload_len);
                fs->phase = WS_PARSE_HEADER;
                break;
            }

            /* ── Data frames: accumulate into frag_buf ──────────────── */
            if (fs->opcode != WS_OP_CONTINUATION) {
                /* New message — record opcode for fragmented sequence     */
                if (fs->in_fragment) {
                    /* Protocol error: new data frame before previous ended*/
                    ws_close(conn, WS_CLOSE_PROTOCOL,
                             "new message before fragment complete");
                    return -1;
                }
                fs->frag_opcode = fs->opcode;
                if (!fs->fin) fs->in_fragment = 1;
            }

            /* Check total message size limit */
            if (fs->frag_buf.len + to_read > cfg->max_message_size) {
                ws_close(conn, WS_CLOSE_TOO_LARGE, "message too large");
                return -1;
            }

            buf_append(&fs->frag_buf, payload_ptr, to_read);
            buf_consume(rb, to_read);
            fs->payload_read += to_read;

            if (fs->payload_read < fs->payload_len)
                return 0;   /* frame not yet complete, wait for more        */

            /* Full frame received */
            if (fs->fin) {
                /* Complete message ready — dispatch to handler */
                if (handler->on_message) {
                    handler->on_message(conn,
                                        (const uint8_t *)fs->frag_buf.data,
                                        fs->frag_buf.len,
                                        fs->frag_opcode,
                                        handler->ctx);
                }
                /* Reset fragment state */
                fs->frag_buf.len = 0;
                fs->in_fragment  = 0;
            }

            fs->phase = WS_PARSE_HEADER;
            break;
        }

        /* These phases are resolved inline in HEADER, kept for completeness */
        case WS_PARSE_LENGTH_EXT:
        case WS_PARSE_MASK:
            break;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Broadcast
 * ═══════════════════════════════════════════════════════════════════════════*/

int ws_broadcast(worker_t **workers, int worker_count,
                 const uint8_t *data, size_t len, ws_opcode_t opcode) {
    if (!workers || worker_count <= 0 || !data || len == 0) return -1;

    for (int i = 0; i < worker_count; i++) {
        worker_t *w = workers[i];
        if (!w || w->ws_notify_fd < 0) continue;

        /* Allocate message (freed by the worker after delivery) */
        ws_msg_t *msg = malloc(sizeof(ws_msg_t));
        if (!msg) continue;

        msg->data = malloc(len);
        if (!msg->data) { free(msg); continue; }

        memcpy(msg->data, data, len);
        msg->len    = len;
        msg->opcode = opcode;
        msg->next   = NULL;

        /* Enqueue under lock */
        pthread_mutex_lock(&w->ws_broadcast_queue.lock);
        if (w->ws_broadcast_queue.tail)
            w->ws_broadcast_queue.tail->next = msg;
        else
            w->ws_broadcast_queue.head = msg;
        w->ws_broadcast_queue.tail = msg;
        w->ws_broadcast_queue.count++;
        pthread_mutex_unlock(&w->ws_broadcast_queue.lock);

        /* Wake up the worker via eventfd */
        uint64_t val = 1;
        if (write(w->ws_notify_fd, &val, sizeof(val)) < 0 && errno != EAGAIN)
            LOG_WARN("ws: eventfd write failed for worker %d: %s",
                     i, strerror(errno));
    }

    return 0;
}