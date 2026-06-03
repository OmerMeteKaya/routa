#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/ws.h"
#include "http/request.h"
#include "core/conn.h"
#include "util/buf.h"
#include "util/logger.h"
#include "core/event_loop.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#if defined(__linux__)
#include <sys/eventfd.h>
#endif
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>

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
    cfg->max_frame_size         = (size_t)16 * 1024 * 1024;   /* 16 MB             */
    cfg->max_message_size       = (size_t)64 * 1024 * 1024;   /* 64 MB             */
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

/* ── permessage-deflate negotiation helpers ─────────────────────────────── */

/* Parse "permessage-deflate" extension from Sec-WebSocket-Extensions header.
 * Returns 1 if found and negotiated, 0 otherwise.
 * Fills server_no_ctx and client_no_ctx flags.                             */
static int pmd_negotiate(const char *ext_header,
                          int *server_no_ctx, int *client_no_ctx) {
    if (!ext_header) return 0;
    *server_no_ctx = 0;
    *client_no_ctx = 0;

    /* Look for "permessage-deflate" token */
    const char *p = strcasestr(ext_header, "permessage-deflate");
    if (!p) return 0;

    /* Scan params after the token on the same extension entry */
    const char *end = strchr(p, ',');   /* next extension */
    char entry[256];
    if (end) {
        size_t len = (size_t)(end - p);
        if (len >= sizeof(entry)) len = sizeof(entry) - 1;
        memcpy(entry, p, len);
        entry[len] = '\0';
    } else {
        strncpy(entry, p, sizeof(entry) - 1);
        entry[sizeof(entry) - 1] = '\0';
    }

    if (strcasestr(entry, "server_no_context_takeover")) *server_no_ctx = 1;
    if (strcasestr(entry, "client_no_context_takeover")) *client_no_ctx = 1;

    return 1;
}

/* Build the response extension header value for permessage-deflate.       */
static void pmd_response_header(char *out, size_t cap,
                                 int server_no_ctx, int client_no_ctx) {
    (void)snprintf(out, cap, "permessage-deflate%s%s",
             server_no_ctx ? "; server_no_context_takeover" : "",
             client_no_ctx ? "; client_no_context_takeover" : "");
}

/* Compress src into dst using raw deflate (no zlib header).
 * Returns compressed byte count, -1 on error.
 * Caller must free *dst_out.                                               */
static int pmd_compress(const uint8_t *src, size_t src_len,
                         uint8_t **dst_out, size_t *dst_len_out) {
    if (!src || src_len == 0) return -1;

    /* Worst case: src_len + 10% + 12 bytes */
    size_t   cap = src_len + src_len / 10 + 64;
    uint8_t *dst = malloc(cap);
    if (!dst) return -1;

    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    /* Raw deflate: windowBits = -15 */
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(dst); return -1;
    }

    zs.next_in   = (Bytef *)src;
    zs.avail_in  = (uInt)src_len;
    zs.next_out  = dst;
    zs.avail_out = (uInt)cap;

    int rc = deflate(&zs, Z_SYNC_FLUSH);
    size_t out_len = cap - zs.avail_out;
    deflateEnd(&zs);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        free(dst); return -1;
    }

    /* RFC 7692 §7.2.1: remove trailing 0x00 0x00 0xff 0xff */
    if (out_len >= 4 &&
        dst[out_len-4] == 0x00 && dst[out_len-3] == 0x00 &&
        dst[out_len-2] == 0xff && dst[out_len-1] == 0xff) {
        out_len -= 4;
    }

    *dst_out     = dst;
    *dst_len_out = out_len;
    return (int)out_len;
}

/* Decompress raw deflate stream (permessage-deflate recv path).
 * RFC 7692 §7.2.2: append 0x00 0x00 0xff 0xff before inflate.
 * Returns decompressed byte count, -1 on error.
 * Caller must free *dst_out.                                               */
static int pmd_decompress(const uint8_t *src, size_t src_len,
                            uint8_t **dst_out, size_t *dst_len_out) {
    if (!src || src_len == 0) return -1;

    /* Append RFC 7692 tail */
    size_t   padded_len = src_len + 4;
    uint8_t *padded     = malloc(padded_len);
    if (!padded) return -1;
    memcpy(padded, src, src_len);
    padded[src_len+0] = 0x00;
    padded[src_len+1] = 0x00;
    padded[src_len+2] = 0xff;
    padded[src_len+3] = 0xff;

    /* Initial output buffer — grow if needed */
    size_t   cap = src_len * 4 + 256;
    uint8_t *dst = malloc(cap);
    if (!dst) { free(padded); return -1; }

    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, -15) != Z_OK) {
        free(padded); free(dst); return -1;
    }

    zs.next_in  = padded;
    zs.avail_in = (uInt)padded_len;

    size_t out_len = 0;
    int    rc;
    do {
        zs.next_out  = dst + out_len;
        zs.avail_out = (uInt)(cap - out_len);

        rc = inflate(&zs, Z_SYNC_FLUSH);
        out_len = cap - zs.avail_out;

        if (rc == Z_BUF_ERROR || (rc == Z_OK && zs.avail_out == 0)) {
            /* Grow buffer */
            cap *= 2;
            uint8_t *tmp = realloc(dst, cap);
            if (!tmp) { inflateEnd(&zs); free(padded); free(dst); return -1; }
            dst = tmp;
        }
    } while (rc == Z_OK || rc == Z_BUF_ERROR);

    inflateEnd(&zs);
    free(padded);

    if (rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        free(dst); return -1;
    }

    *dst_out     = dst;
    *dst_len_out = out_len;
    return (int)out_len;
}

int ws_handshake(conn_t *conn, const http_request_t *req,
                 buf_t *out, const ws_config_t *cfg) {
    (void)cfg;   /* reserved for future origin/subprotocol checks          */

    if (!conn || !req || !out) return -1;
    int pmd_ok = 0, srv_no_ctx = 0, cli_no_ctx = 0;
    if (cfg && cfg->permessage_deflate) {
        const char *ext = http_request_get_header(req, "Sec-WebSocket-Extensions");
        pmd_ok = pmd_negotiate(ext, &srv_no_ctx, &cli_no_ctx);
    }
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
    if (pmd_ok) {
        char pmd_hdr[256];
        pmd_response_header(pmd_hdr, sizeof(pmd_hdr), srv_no_ctx, cli_no_ctx);
        buf_append_str(out, "Sec-WebSocket-Extensions: ");
        buf_append_str(out, pmd_hdr);
        buf_append_str(out, "\r\n");
        conn->ws_pmd_enabled = 1;
    }
    buf_append_str(out, "\r\n");

    conn->ws_state = WS_STATE_OPEN;
    ws_frame_state_init(&conn->ws_fs);
    
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
    hdr[idx++] = (uint8_t)(((unsigned)(fin ? 1 : 0) << 7) | ((uint8_t)opcode & 0x0Fu));

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
    if (!conn) return -1;
    if (!data && len > 0) return -1;
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

int ws_send_pmd(conn_t *conn, const uint8_t *data, size_t len,
                ws_opcode_t opcode, const ws_config_t *cfg) {
    if (!conn || !cfg) return -1;

    /* Only compress text/binary, not control frames */
    int should_compress = conn->ws_pmd_enabled &&
                          cfg->permessage_deflate &&
                          len >= cfg->compression_threshold &&
                          (opcode == WS_OP_TEXT || opcode == WS_OP_BINARY);

    if (!should_compress)
        return ws_send(conn, data, len, opcode);

    uint8_t *compressed = NULL;
    size_t   comp_len   = 0;
    if (pmd_compress(data, len, &compressed, &comp_len) < 0)
        return ws_send(conn, data, len, opcode);  /* fallback to uncompressed */

    /* RSV1 bit set — byte 0 of frame header */
    uint8_t hdr[14];
    int hdr_len = build_frame_header(hdr, opcode, 1, (uint64_t)comp_len);
    hdr[0] |= 0x40;   /* RSV1 = 1 */

    int rc = 0;
    if (buf_append(&conn->write_buf, hdr, (size_t)hdr_len) < 0) rc = -1;
    if (rc == 0 && buf_append(&conn->write_buf, compressed, comp_len) < 0) rc = -1;

    free(compressed);
    return rc;
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
        memcpy(payload + 2, reason, reason_len);  // NOLINT(bugprone-not-null-terminated-result)

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

            uint8_t b0 = ((uint8_t *)buf_data(rb))[0];
            uint8_t b1 = ((uint8_t *)buf_data(rb))[1];

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

            if (rb->len < (size_t)2 + (size_t)extra) return 0; /* wait for more  */

            /* Read extended length */
            const uint8_t *p = (uint8_t *)buf_data(rb) + 2;
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
            size_t hdr_consumed = (size_t)(p - (uint8_t *)buf_data(rb));
            buf_consume(rb, hdr_consumed);

            fs->payload_read = 0;
            if (fs->payload_len == 0) {
                int is_ctrl = (fs->opcode == WS_OP_PING ||
                               fs->opcode == WS_OP_PONG ||
                               fs->opcode == WS_OP_CLOSE);
                if (is_ctrl) {
                    if (fs->opcode == WS_OP_PING) {
                        (void)ws_pong(conn, NULL, 0);
                    } else if (fs->opcode == WS_OP_PONG) {
                        conn->ws_ping_misses = 0;
                    } else if (fs->opcode == WS_OP_CLOSE) {
                        if (handler->on_close)
                            handler->on_close(conn, WS_CLOSE_NORMAL,
                                              NULL, handler->ctx);
                        ws_close(conn, WS_CLOSE_NORMAL, NULL);
                        conn->ws_state = WS_STATE_CLOSED;
                        return -1;
                    }
                    fs->phase = WS_PARSE_HEADER;
                    break;
                }
            }
            fs->phase        = WS_PARSE_PAYLOAD;

            break;
        }

        /* ── Phase 2: read payload bytes ─────────────────────────────── */
        case WS_PARSE_PAYLOAD: {

            uint64_t remaining = fs->payload_len - fs->payload_read;
            size_t   available = rb->len;
            size_t   to_read   = (available < (size_t)remaining)
                                 ? available : (size_t)remaining;

            if (to_read == 0 && remaining > 0) return 0;   /* wait for more data           */

            uint8_t *payload_ptr = (uint8_t *)buf_data(rb);

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
                    (void)ws_pong(conn, payload_ptr, (size_t)fs->payload_len);
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
            /* Reject reserved/unknown opcodes (RFC 6455 §5.2)            */
            if (fs->opcode != WS_OP_TEXT     &&
                fs->opcode != WS_OP_BINARY   &&
                fs->opcode != WS_OP_CONTINUATION) {
                ws_close(conn, WS_CLOSE_PROTOCOL, "unknown opcode");
                return -1;
                }

            /* Reject orphan CONTINUATION (no preceding TEXT/BINARY)      */
            if (fs->opcode == WS_OP_CONTINUATION && !fs->in_fragment) {
                ws_close(conn, WS_CLOSE_PROTOCOL, "unexpected continuation");
                return -1;
            }
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
                const uint8_t *msg_data = (const uint8_t *)fs->frag_buf.data;
                size_t         msg_len  = fs->frag_buf.len;
                uint8_t       *decomp   = NULL;
                size_t         decomp_len = 0;
                int            used_pmd  = 0;

                /* Decompress if RSV1 was set on the first frame */
                if (conn->ws_pmd_enabled && fs->rsv1) {
                    if (pmd_decompress(msg_data, msg_len,
                                       &decomp, &decomp_len) >= 0) {
                        msg_data  = decomp;
                        msg_len   = decomp_len;
                        used_pmd  = 1;
                                       }
                    /* If decompression fails, pass raw data — handler decides */
                }

                if (handler->on_message) {
                    handler->on_message(conn, msg_data, msg_len,
                                        fs->frag_opcode, handler->ctx);
                }

                if (used_pmd) free(decomp);
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

        /* Wake up the worker via eventfd (Linux) or pipe (macOS/BSD) */
#if defined(__linux__)
        uint64_t val = 1;
        if (write(w->ws_notify_write_fd, &val, sizeof(val)) < 0 && errno != EAGAIN)
#else
        if (write(w->ws_notify_write_fd, "x", 1) < 0 && errno != EAGAIN)
#endif
            LOG_WARN("ws: write notify failed for worker %d: %s",
                     i, strerror(errno));
    }

    return 0;
}
