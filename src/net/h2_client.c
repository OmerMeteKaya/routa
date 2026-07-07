#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "net/h2_client.h"
#include "net/poller.h"
#include "net/socket.h"
#include "core/event_loop.h"
#include "core/proxy.h"
#include "core/conn.h"
#include "http/h2.h"
#include "lb/upstream.h"
#include "util/logger.h"
#include "http/cookie.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ── H2 frame constants (RFC 7540) ──────────────────────────────────────── */
#define FRM_DATA          0x0
#define FRM_HEADERS       0x1
#define FRM_PRIORITY      0x2
#define FRM_RST_STREAM    0x3
#define FRM_SETTINGS      0x4
#define FRM_PUSH_PROMISE  0x5
#define FRM_PING          0x6
#define FRM_GOAWAY        0x7
#define FRM_WINDOW_UPDATE 0x8
#define FRM_CONTINUATION  0x9

#define FL_END_STREAM    0x1
#define FL_END_HEADERS   0x4
#define FL_PADDED        0x8
#define FL_PRIORITY      0x20
#define FL_ACK           0x1

#define SETTINGS_HEADER_TABLE_SIZE      0x1
#define SETTINGS_ENABLE_PUSH            0x2
#define SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define SETTINGS_INITIAL_WINDOW_SIZE    0x4
#define SETTINGS_MAX_FRAME_SIZE         0x5
#define SETTINGS_MAX_HEADER_LIST_SIZE   0x6

#define H2_DEFAULT_WINDOW 65535
#define H2_FRAME_HDR_SZ   9

static const char *h2_client_preface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN 24

/* ── Frame header write helper ───────────────────────────────────────────── */
static int write_fhdr(buf_t *b, uint32_t len, uint8_t type,
                       uint8_t flags, uint32_t sid)
{
    uint8_t h[H2_FRAME_HDR_SZ];
    h[0] = (len >> 16) & 0xff;
    h[1] = (len >>  8) & 0xff;
    h[2] =  len        & 0xff;
    h[3] = type;
    h[4] = flags;
    h[5] = (sid >> 24) & 0x7f;
    h[6] = (sid >> 16) & 0xff;
    h[7] = (sid >>  8) & 0xff;
    h[8] =  sid        & 0xff;
    return buf_append(b, h, H2_FRAME_HDR_SZ);
}

static int write_window_update(buf_t *b, uint32_t sid, uint32_t inc)
{
    if (write_fhdr(b, 4, FRM_WINDOW_UPDATE, 0, sid) < 0) return -1;
    uint8_t p[4];
    p[0] = (inc >> 24) & 0x7f;
    p[1] = (inc >> 16) & 0xff;
    p[2] = (inc >>  8) & 0xff;
    p[3] =  inc        & 0xff;
    return buf_append(b, p, 4);
}

/* ── Blocking SSL helpers used only during h2up_conn_create ─────────────── */

static int ssl_write_all(SSL *ssl, const void *data, int len)
{
    const unsigned char *p = (const unsigned char *)data;
    int remaining = len;
    while (remaining > 0) {
        int n = SSL_write(ssl, p, remaining);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

static int ssl_read_exactly(SSL *ssl, uint8_t *dst, int count)
{
    int got = 0;
    while (got < count) {
        int n = SSL_read(ssl, dst + got, count - got);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return -1;
        }
        got += n;
    }
    return 0;
}

/* Read the upstream's initial SETTINGS and update h2up's peer limits.
 * Sends SETTINGS ACK.  Returns 0 on success, -1 on error.                  */
static int h2up_exchange_settings(h2up_conn_t *h2up)
{
    SSL *ssl = h2up->tls->ssl;

    /* We loop over frames until we see the server's initial SETTINGS.
     * RFC 7540 §3.5: the server sends its SETTINGS as the first frame.      */
    for (int attempts = 0; attempts < 20; attempts++) {
        uint8_t fhdr[H2_FRAME_HDR_SZ];
        if (ssl_read_exactly(ssl, fhdr, H2_FRAME_HDR_SZ) < 0) return -1;

        uint32_t flen  = ((uint32_t)fhdr[0] << 16)
                       | ((uint32_t)fhdr[1] <<  8)
                       |  (uint32_t)fhdr[2];
        uint8_t  ftype = fhdr[3];
        uint8_t  fflags= fhdr[4];

        if (flen > 65536) {
            LOG_WARN("h2up: server sent oversized frame type=%u len=%u",
                     ftype, flen);
            return -1;
        }

        uint8_t payload[65536];
        if (flen > 0 && ssl_read_exactly(ssl, payload, (int)flen) < 0) return -1;

        if (ftype == FRM_SETTINGS && !(fflags & FL_ACK)) {
            /* Parse settings */
            const uint8_t *p = payload;
            for (uint32_t i = 0; i + 6 <= flen; i += 6, p += 6) {
                uint16_t id  = (uint16_t)(((uint32_t)p[0] << 8) | p[1]);
                uint32_t val = ((uint32_t)p[2] << 24) | ((uint32_t)p[3] << 16)
                             | ((uint32_t)p[4] <<  8) |  (uint32_t)p[5];
                switch (id) {
                case SETTINGS_MAX_CONCURRENT_STREAMS:
                    h2up->peer_max_concurrent_streams = val;
                    break;
                case SETTINGS_INITIAL_WINDOW_SIZE:
                    if (val > 0x7fffffffu) return -1;
                    h2up->stream_init_window = (int32_t)val;
                    for (int s = 0; s < H2UP_MAX_STREAMS; s++)
                        h2up->streams[s].send_window = (int32_t)val;
                    break;
                case SETTINGS_MAX_FRAME_SIZE:
                    if (val >= 16384 && val <= 16777215)
                        h2up->peer_max_frame_size = val;
                    break;
                }
            }

            /* Send SETTINGS ACK */
            uint8_t ack[H2_FRAME_HDR_SZ] = {0, 0, 0, FRM_SETTINGS, FL_ACK,
                                              0, 0, 0, 0};
            if (ssl_write_all(ssl, ack, H2_FRAME_HDR_SZ) < 0) return -1;
            return 0;
        }
        /* Skip any other frames (e.g. WINDOW_UPDATE on stream 0) */
    }
    return -1;   /* didn't see SETTINGS in time */
}

/* ── h2up_conn_create ────────────────────────────────────────────────────── */

h2up_conn_t *h2up_conn_create(upstream_node_t *node)
{
    /* ── 1. Blocking TCP connect ──────────────────────────────────────────*/
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(node->port);
    if (inet_pton(AF_INET, node->host, &addr.sin_addr) != 1) {
        LOG_ERROR("h2up: bad upstream IP '%s'", node->host);
        return NULL;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        LOG_WARN("h2up: connect to %s:%d failed: %s",
                 node->host, node->port, strerror(errno));
        close(fd);
        return NULL;
    }
    if (ret < 0) {   /* EINPROGRESS */
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
            close(fd);
            return NULL;
        }
        int serr = 0;
        socklen_t slen = sizeof(serr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &serr, &slen);
        if (serr) { close(fd); return NULL; }
    }

    /* ── 2. Blocking TLS handshake with ALPN="h2" ────────────────────────*/
    SSL_CTX *sctx = SSL_CTX_new(TLS_client_method());
    if (!sctx) { close(fd); return NULL; }
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(sctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                           SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* Offer h2 then http/1.1 (wire format: length-prefixed) */
    static const unsigned char alpn_protos[] = "\x02h2\x08http/1.1";
    SSL_CTX_set_alpn_protos(sctx, alpn_protos, sizeof(alpn_protos) - 1);

    SSL *ssl = SSL_new(sctx);
    SSL_CTX_free(sctx);
    if (!ssl) { close(fd); return NULL; }

    SSL_set_fd(ssl, fd);
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, node->host);  /* SNI */

    /* Handshake on the (still-blocking) fd */
    while (1) {
        int hret = SSL_do_handshake(ssl);
        if (hret == 1) break;
        int err = SSL_get_error(ssl, hret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            char ebuf[256];
            ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
            LOG_WARN("h2up: TLS handshake to %s:%d failed: %s",
                     node->host, node->port, ebuf);
            SSL_free(ssl);
            close(fd);
            return NULL;
        }
    }

    /* Check ALPN */
    const unsigned char *proto = NULL;
    unsigned int         plen  = 0;
    SSL_get0_alpn_selected(ssl, &proto, &plen);
    if (plen != 2 || memcmp(proto, "h2", 2) != 0) {
        LOG_INFO("h2up: upstream %s:%d did not negotiate h2 (alpn len=%u)",
                 node->host, node->port, plen);
        SSL_free(ssl);
        close(fd);
        return NULL;
    }

    /* ── 3. Allocate h2up_conn_t ─────────────────────────────────────────*/
    h2up_conn_t *h2up = calloc(1, sizeof(h2up_conn_t));
    if (!h2up) { SSL_free(ssl); close(fd); return NULL; }

    h2up->magic = H2UP_MAGIC;
    h2up->fd    = fd;
    h2up->node  = node;

    /* Wrap SSL in a tls_conn_t so we can reuse tls_read/tls_write */
    tls_conn_t *tc = calloc(1, sizeof(tls_conn_t));
    if (!tc) { SSL_free(ssl); close(fd); free(h2up); return NULL; }
    tc->ssl            = ssl;
    tc->fd             = fd;
    tc->handshake_done = 1;
    h2up->tls = tc;

    h2up->next_stream_id             = 1;
    h2up->conn_send_window           = H2_DEFAULT_WINDOW;
    h2up->stream_init_window         = H2_DEFAULT_WINDOW;
    h2up->peer_max_concurrent_streams= 100;   /* safe default before SETTINGS */
    h2up->peer_max_frame_size        = 16384;

    buf_init(&h2up->write_buf);
    buf_init(&h2up->read_buf);

    if (hpack_ctx_init(&h2up->hpack_tx, 4096, 1, 1, 0) < 0 ||
        hpack_ctx_init(&h2up->hpack_rx, 4096, 0, 0, 0) < 0) {
        hpack_ctx_free(&h2up->hpack_tx);
        hpack_ctx_free(&h2up->hpack_rx);
        buf_free(&h2up->write_buf);
        buf_free(&h2up->read_buf);
        tls_conn_free(tc);
        close(fd);
        free(h2up);
        return NULL;
    }

    /* ── 4. H2 client preface + initial SETTINGS ─────────────────────────*/
    /* Client preface */
    if (ssl_write_all(ssl, h2_client_preface, H2_PREFACE_LEN) < 0) goto fail;

    /* Our SETTINGS: empty (accept upstream defaults) */
    {
        uint8_t s[H2_FRAME_HDR_SZ] = {0, 0, 0, FRM_SETTINGS, 0, 0, 0, 0, 0};
        if (ssl_write_all(ssl, s, H2_FRAME_HDR_SZ) < 0) goto fail;
    }

    /* Connection-level WINDOW_UPDATE: expand to 1 GiB */
    {
        buf_t tmp;
        buf_init(&tmp);
        write_window_update(&tmp, 0, 0x3fffffff);
        ssl_write_all(ssl, buf_data(&tmp), (int)tmp.len);
        buf_free(&tmp);
    }

    /* ── 5. Read upstream SETTINGS, send ACK ─────────────────────────────*/
    if (h2up_exchange_settings(h2up) < 0) goto fail;

    /* ── 6. Set fd non-blocking for async I/O ────────────────────────────*/
    net_set_nonblocking(fd);

    LOG_INFO("h2up: established H2 connection to %s:%d", node->host, node->port);
    return h2up;

fail:
    hpack_ctx_free(&h2up->hpack_tx);
    hpack_ctx_free(&h2up->hpack_rx);
    buf_free(&h2up->write_buf);
    buf_free(&h2up->read_buf);
    tls_conn_free(tc);
    close(fd);
    free(h2up);
    return NULL;
}

/* ── h2up_conn_free ──────────────────────────────────────────────────────── */

void h2up_conn_free(h2up_conn_t *h2up)
{
    if (!h2up) return;

    /* Free any stream buffers (ctx pointers are already cleared by callers) */
    for (int i = 0; i < H2UP_MAX_STREAMS; i++) {
        if (h2up->streams[i].stream_id) {
            http_response_destroy(&h2up->streams[i].resp);
            buf_free(&h2up->streams[i].hdr_block);
            buf_free(&h2up->streams[i].body_buf);
        }
    }

    hpack_ctx_free(&h2up->hpack_tx);
    hpack_ctx_free(&h2up->hpack_rx);
    buf_free(&h2up->write_buf);
    buf_free(&h2up->read_buf);

    if (h2up->tls) {
        SSL_shutdown(h2up->tls->ssl);
        tls_conn_free(h2up->tls);
    }
    close(h2up->fd);
    free(h2up);
}

/* ── h2up_has_capacity ───────────────────────────────────────────────────── */

int h2up_has_capacity(const h2up_conn_t *h2up)
{
    if (!h2up || h2up->closed || h2up->goaway_received) return 0;
    if (h2up->stream_count >= H2UP_MAX_STREAMS) return 0;
    if ((uint32_t)h2up->stream_count >= h2up->peer_max_concurrent_streams)
        return 0;
    return 1;
}

/* ── h2up_stream_find ────────────────────────────────────────────────────── */

static h2up_stream_t *h2up_stream_find(h2up_conn_t *h2up, uint32_t stream_id)
{
    for (int i = 0; i < H2UP_MAX_STREAMS; i++)
        if (h2up->streams[i].stream_id == stream_id && h2up->streams[i].ctx)
            return &h2up->streams[i];
    return NULL;
}

/* ── h2up_stream_remove ──────────────────────────────────────────────────── */

void h2up_stream_remove(h2up_conn_t *h2up, uint32_t stream_id)
{
    for (int i = 0; i < H2UP_MAX_STREAMS; i++) {
        if (h2up->streams[i].stream_id == stream_id) {
            http_response_destroy(&h2up->streams[i].resp);
            buf_free(&h2up->streams[i].hdr_block);
            buf_free(&h2up->streams[i].body_buf);
            h2up->streams[i].stream_id = 0;
            h2up->streams[i].ctx       = NULL;
            if (h2up->stream_count > 0) h2up->stream_count--;
            return;
        }
    }
}

/* ── Method string ───────────────────────────────────────────────────────── */

static const char *method_name(http_method_t m)
{
    switch (m) {
    case HTTP_GET:     return "GET";
    case HTTP_POST:    return "POST";
    case HTTP_PUT:     return "PUT";
    case HTTP_DELETE:  return "DELETE";
    case HTTP_HEAD:    return "HEAD";
    case HTTP_PATCH:   return "PATCH";
    case HTTP_OPTIONS: return "OPTIONS";
    case HTTP_TRACE:   return "TRACE";
    case HTTP_CONNECT: return "CONNECT";
    default:           return "GET";
    }
}

/* ── Hop-by-hop header check ─────────────────────────────────────────────── */

static int is_hop_by_hop(const char *name)
{
    static const char *hbh[] = {
        "connection", "keep-alive", "transfer-encoding",
        "proxy-connection", "upgrade", "te", "trailer", NULL
    };
    for (int i = 0; hbh[i]; i++)
        if (strcasecmp(name, hbh[i]) == 0) return 1;
    return 0;
}

/* ── h2up_begin_stream ───────────────────────────────────────────────────── */

int h2up_begin_stream(h2up_conn_t *h2up, proxy_ctx_t *ctx,
                      const http_request_t *req,
                      const char *client_ip, const char *proto)
{
    if (!h2up_has_capacity(h2up)) return -1;

    /* Find a free stream slot */
    h2up_stream_t *s = NULL;
    for (int i = 0; i < H2UP_MAX_STREAMS; i++) {
        if (!h2up->streams[i].stream_id) {
            s = &h2up->streams[i];
            break;
        }
    }
    if (!s) return -1;

    uint32_t stream_id = h2up->next_stream_id;
    h2up->next_stream_id += 2;

    /* Init stream slot */
    memset(s, 0, sizeof(*s));
    s->stream_id  = stream_id;
    s->ctx        = ctx;
    s->send_window= h2up->stream_init_window;
    s->hdr_done   = 0;
    s->end_stream  = 0;
    buf_init(&s->hdr_block);
    buf_init(&s->body_buf);
    http_response_init(&s->resp);

    h2up->stream_count++;

    /* ── Build request headers for HPACK encoding ────────────────────────*/
    /* Stack-allocated header array */
    hpack_header_t hdrs[72];
    char key_bufs[64][80];  /* for lowercased request header names */
    char path_buf[2048];
    char auth_buf[320];
    char xff_buf[512];
    char via_buf[256];
    int  n = 0, kb = 0;

    /* Pseudo-headers (RFC 7540 §8.1.2.3) */
    hdrs[n++] = (hpack_header_t){(char *)":method",
                                  (char *)method_name(req->method)};

    if (req->query && req->query[0])
        snprintf(path_buf, sizeof(path_buf), "%s?%s", req->path, req->query);
    else
        snprintf(path_buf, sizeof(path_buf), "%s", req->path ? req->path : "/");
    hdrs[n++] = (hpack_header_t){(char *)":path", path_buf};

    hdrs[n++] = (hpack_header_t){(char *)":scheme",
                                  (char *)(proto ? proto : "https")};

    snprintf(auth_buf, sizeof(auth_buf), "%s:%d",
             h2up->node->host, h2up->node->port);
    hdrs[n++] = (hpack_header_t){(char *)":authority", auth_buf};

    /* Scan existing forwarding chains */
    const char *prev_xff = NULL;
    const char *prev_via = NULL;

    /* Forward end-to-end headers */
    for (int i = 0; i < req->header_count && n < 68; i++) {
        const char *k = req->headers[i].key;
        const char *v = req->headers[i].value ? req->headers[i].value : "";
        if (!k) continue;
        if (is_hop_by_hop(k))                            continue;
        if (strcasecmp(k, "host") == 0)                  continue;
        if (strcasecmp(k, "x-forwarded-proto") == 0)     continue;
        if (k[0] == ':')                                  continue;
        if (strcasecmp(k, "content-length") == 0)        continue; /* re-emitted */
        if (strcasecmp(k, "x-forwarded-for") == 0) { prev_xff = v; continue; }
        if (strcasecmp(k, "via") == 0)             { prev_via = v; continue; }

        /* Lowercase the key (H2 pseudo-spec requires lowercase) */
        int klen = (int)strlen(k);
        if (klen >= 80) klen = 79;
        for (int j = 0; j < klen; j++)
            key_bufs[kb][j] = (char)tolower((unsigned char)k[j]);
        key_bufs[kb][klen] = '\0';
        hdrs[n++] = (hpack_header_t){key_bufs[kb++], (char *)v};
    }

    /* X-Forwarded-For */
    if (prev_xff && prev_xff[0])
        snprintf(xff_buf, sizeof(xff_buf), "%s, %s", prev_xff,
                 client_ip && client_ip[0] ? client_ip : "unknown");
    else
        snprintf(xff_buf, sizeof(xff_buf), "%s",
                 client_ip && client_ip[0] ? client_ip : "unknown");
    hdrs[n++] = (hpack_header_t){(char *)"x-forwarded-for", xff_buf};

    if (proto) {
        hdrs[n++] = (hpack_header_t){(char *)"x-forwarded-proto",
                                      (char *)proto};
    }

    /* Via */
    if (prev_via && prev_via[0])
        snprintf(via_buf, sizeof(via_buf), "%s, 1.1 routa", prev_via);
    else
        snprintf(via_buf, sizeof(via_buf), "1.1 routa");
    hdrs[n++] = (hpack_header_t){(char *)"via", via_buf};

    /* Content-Length for bodies */
    char cl_buf[32];
    if (req->body_len > 0) {
        snprintf(cl_buf, sizeof(cl_buf), "%zu", req->body_len);
        hdrs[n++] = (hpack_header_t){(char *)"content-length", cl_buf};
    }

    /* ── HPACK encode ────────────────────────────────────────────────────*/
    uint8_t hdr_block[65536];
    int hdr_len = hpack_encode(&h2up->hpack_tx, hdrs, n,
                               hdr_block, sizeof(hdr_block));
    if (hdr_len < 0) {
        h2up_stream_remove(h2up, stream_id);
        return -1;
    }

    /* ── Write HEADERS frame ─────────────────────────────────────────────*/
    int has_body = (req->body && req->body_len > 0);
    uint8_t hflags = FL_END_HEADERS | (has_body ? 0 : FL_END_STREAM);
    if (write_fhdr(&h2up->write_buf, (uint32_t)hdr_len,
                   FRM_HEADERS, hflags, stream_id) < 0 ||
        buf_append(&h2up->write_buf, hdr_block, (size_t)hdr_len) < 0) {
        h2up_stream_remove(h2up, stream_id);
        return -1;
    }

    /* ── Write DATA frame (if body) ──────────────────────────────────────*/
    if (has_body) {
        if (write_fhdr(&h2up->write_buf, (uint32_t)req->body_len,
                       FRM_DATA, FL_END_STREAM, stream_id) < 0 ||
            buf_append(&h2up->write_buf, req->body, req->body_len) < 0) {
            h2up_stream_remove(h2up, stream_id);
            return -1;
        }
    }

    return (int)stream_id;
}

/* ── Response delivery helper ────────────────────────────────────────────── */

static const char *status_reason(int status)
{
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

/* Deliver a completed stream response to the frontend and clean up the slot.
 * MUST clear ctx->up_h2up / ctx->upstream_fd / stream->ctx BEFORE calling
 * proxy_stream_remove so proxy_drop_upstream does not double-close.          */
static void deliver_response(h2up_conn_t *h2up, h2up_stream_t *s, worker_t *w)
{
    proxy_ctx_t *ctx = s->ctx;
    if (!ctx) return;

    conn_t     *conn      = ctx->conn;
    uint32_t    front_sid = ctx->front_stream_id;
    struct h2_conn *fh2   = ctx->front_h2;
    upstream_node_t *node = ctx->node;
    upstream_pool_t *pool = ctx->pool;

    int is_h2_front = (conn->h2 && fh2);

    /* Set body from accumulated DATA */
    if (s->body_buf.len > 0) {
        http_response_set_body(&s->resp,
                               (char *)buf_data(&s->body_buf), s->body_buf.len);
    }
    /* Ensure a status is set */
    if (s->resp.status == 0) {
        http_response_set_status(&s->resp, 200, "OK");
    } else {
        /* reason may have been set as a literal; refresh with our static copy */
        s->resp.reason = (char *)status_reason(s->resp.status);
    }

    /* Sticky session: same rationale as the H1 upstream path in proxy.c --
     * set on every response while enabled, not just the first. */
    if (ctx->sticky_node_for_cookie && ctx->lb) {
        char idx_buf[16];
        lb_sticky_cookie_value_for_node(ctx->lb, ctx->sticky_node_for_cookie,
                                        idx_buf, sizeof(idx_buf));
        cookie_opts_t sticky_opts = {
            .name      = lb_sticky_cookie_name(ctx->lb),
            .value     = idx_buf,
            .path      = "/",
            .domain    = NULL,
            .max_age   = -1,
            .http_only = 1,
            .secure    = 0,
            .same_site = "Lax",
        };
        cookie_set(&s->resp, &sticky_opts);
    }

    /* Detach ctx from this h2up stream BEFORE proxy_stream_remove so that
     * proxy_drop_upstream sees up_h2up==NULL and does not call
     * h2up_stream_remove again or close the shared fd.                      */
    ctx->up_h2up      = NULL;
    ctx->up_stream_id = 0;
    ctx->upstream_fd  = -1;

    /* Clear the stream slot */
    s->ctx       = NULL;
    s->stream_id = 0;
    if (h2up->stream_count > 0) h2up->stream_count--;

    /* Forward response to frontend */
    if (is_h2_front) {
        h2_proxy_send_response(fh2, front_sid, &s->resp);
        http_response_destroy(&s->resp);
        proxy_stream_remove(conn, front_sid);   /* frees ctx */
        h2_conn_flush(fh2);
    } else {
        http_response_set_header(&s->resp, "Connection",
            conn->keep_alive ? "keep-alive" : "close");
        conn_prepare_writev(conn, &s->resp);
        http_response_destroy(&s->resp);
        proxy_stream_remove(conn, front_sid);   /* frees ctx */
        conn->state = CONN_WRITING;
    }

    /* Cleanup stream slot buffers */
    buf_free(&s->hdr_block);
    buf_free(&s->body_buf);
    http_response_init(&s->resp);

    /* Record upstream success */
    if (node && pool) upstream_node_record_success(node, pool);

    /* Arm the frontend conn for write if needed */
    worker_conn_flush(w, conn);
}

/* ── Frame processors ────────────────────────────────────────────────────── */

static void proc_settings(h2up_conn_t *h2up, uint8_t flags,
                           const uint8_t *pay, uint32_t plen)
{
    if (flags & FL_ACK) return;   /* our SETTINGS was ACKed, nothing to do */

    const uint8_t *p = pay;
    for (uint32_t i = 0; i + 6 <= plen; i += 6, p += 6) {
        uint16_t id  = (uint16_t)(((uint32_t)p[0] << 8) | p[1]);
        uint32_t val = ((uint32_t)p[2] << 24) | ((uint32_t)p[3] << 16)
                     | ((uint32_t)p[4] <<  8) |  (uint32_t)p[5];
        switch (id) {
        case SETTINGS_MAX_CONCURRENT_STREAMS:
            h2up->peer_max_concurrent_streams = val;
            break;
        case SETTINGS_INITIAL_WINDOW_SIZE:
            if (val > 0x7fffffffu) { h2up->closed = 1; return; }
            h2up->stream_init_window = (int32_t)val;
            for (int s = 0; s < H2UP_MAX_STREAMS; s++)
                if (h2up->streams[s].stream_id)
                    h2up->streams[s].send_window = (int32_t)val;
            break;
        case SETTINGS_MAX_FRAME_SIZE:
            if (val >= 16384 && val <= 16777215)
                h2up->peer_max_frame_size = val;
            break;
        }
    }
    /* Queue SETTINGS ACK */
    uint8_t ack[H2_FRAME_HDR_SZ] = {0, 0, 0, FRM_SETTINGS, FL_ACK,
                                      0, 0, 0, 0};
    buf_append(&h2up->write_buf, ack, H2_FRAME_HDR_SZ);
}

static void proc_headers(h2up_conn_t *h2up, uint32_t stream_id,
                          uint8_t flags, const uint8_t *pay, uint32_t plen,
                          worker_t *w)
{
    h2up_stream_t *s = h2up_stream_find(h2up, stream_id);
    if (!s) return;

    const uint8_t *block = pay;
    uint32_t blen = plen;

    if (flags & FL_PADDED) {
        if (blen == 0) return;
        uint8_t pad = block[0]; block++; blen--;
        if (pad >= blen) return;
        blen -= pad;
    }
    if (flags & FL_PRIORITY) {
        if (blen < 5) return;
        block += 5; blen -= 5;
    }

    if (buf_append(&s->hdr_block, block, blen) < 0) return;

    if (flags & FL_END_HEADERS) {
        hpack_header_t hdrs[64];
        int n = hpack_decode(&h2up->hpack_rx,
                              buf_data(&s->hdr_block), s->hdr_block.len,
                              hdrs, 64);
        buf_reset(&s->hdr_block);

        if (n >= 0) {
            for (int i = 0; i < n; i++) {
                const char *name = hdrs[i].name  ? hdrs[i].name  : "";
                const char *val  = hdrs[i].value ? hdrs[i].value : "";
                if (strcmp(name, ":status") == 0) {
                    int st = (int)strtol(val, NULL, 10);
                    http_response_set_status(&s->resp, st, status_reason(st));
                } else if (name[0] != ':') {
                    if (strcasecmp(name, "content-length") != 0)
                        http_response_set_header(&s->resp, name, val);
                }
            }
            hpack_headers_free(hdrs, n);
        } else {
            LOG_WARN("h2up: HPACK decode error on stream %u", stream_id);
            h2up->closed = 1;
            return;
        }
        s->hdr_done = 1;
    }

    if (flags & FL_END_STREAM) {
        s->end_stream = 1;
        if (s->hdr_done) deliver_response(h2up, s, w);
    }
}

static void proc_data(h2up_conn_t *h2up, uint32_t stream_id,
                       uint8_t flags, const uint8_t *pay, uint32_t plen,
                       worker_t *w)
{
    h2up_stream_t *s = h2up_stream_find(h2up, stream_id);
    const uint8_t *data = pay;
    uint32_t dlen = plen;

    if (flags & FL_PADDED) {
        if (dlen == 0) return;
        uint8_t pad = data[0]; data++; dlen--;
        if (pad >= dlen) return;
        dlen -= pad;
    }

    /* Send connection + stream WINDOW_UPDATE so upstream doesn't stall */
    if (plen > 0) {
        write_window_update(&h2up->write_buf, 0, plen);
        if (s) write_window_update(&h2up->write_buf, stream_id, plen);
    }

    if (!s) return;

    if (dlen > 0)
        buf_append(&s->body_buf, data, dlen);

    if (flags & FL_END_STREAM) {
        s->end_stream = 1;
        if (s->hdr_done) deliver_response(h2up, s, w);
    }
}

static void proc_window_update(h2up_conn_t *h2up, uint32_t stream_id,
                                const uint8_t *pay)
{
    uint32_t inc = (((uint32_t)pay[0] & 0x7f) << 24) |
                   ((uint32_t)pay[1] << 16) |
                   ((uint32_t)pay[2] <<  8) |
                    (uint32_t)pay[3];
    if (stream_id == 0) {
        h2up->conn_send_window += (int32_t)inc;
    } else {
        h2up_stream_t *s = h2up_stream_find(h2up, stream_id);
        if (s) s->send_window += (int32_t)inc;
    }
}

static void proc_rst_stream(h2up_conn_t *h2up, uint32_t stream_id, worker_t *w)
{
    h2up_stream_t *s = h2up_stream_find(h2up, stream_id);
    if (!s) return;

    proxy_ctx_t *ctx = s->ctx;
    if (!ctx) return;

    conn_t *conn     = ctx->conn;
    uint32_t fsid    = ctx->front_stream_id;

    /* Detach before any cleanup */
    ctx->up_h2up      = NULL;
    ctx->up_stream_id = 0;
    ctx->upstream_fd  = -1;
    s->ctx = NULL;
    s->stream_id = 0;
    if (h2up->stream_count > 0) h2up->stream_count--;
    buf_free(&s->hdr_block);
    buf_free(&s->body_buf);
    http_response_destroy(&s->resp);
    http_response_init(&s->resp);

    if (ctx->node && ctx->pool)
        upstream_node_record_failure(ctx->node, ctx->pool);

    /* Send 502 to frontend */
    if (conn->h2 && ctx->front_h2) {
        http_response_t err;
        http_response_init(&err);
        http_response_set_status(&err, 502, "Bad Gateway");
        http_response_set_body(&err, "Bad Gateway\n", 12);
        h2_proxy_send_response(ctx->front_h2, fsid, &err);
        http_response_destroy(&err);
        proxy_stream_remove(conn, fsid);
        h2_conn_flush(ctx->front_h2);
    } else if (!conn->h2) {
        http_response_simple(&conn->write_buf, 502, "Bad Gateway",
                             "text/plain", "Bad Gateway\n");
        conn_reset_write_state(conn);
        conn->state = CONN_WRITING;
    }
    worker_conn_flush(w, conn);
}

/* ── h2up_conn_close ─────────────────────────────────────────────────────── */

void h2up_conn_close(h2up_conn_t *h2up, worker_t *w)
{
    if (!h2up || h2up->closed) return;
    h2up->closed = 1;

    for (int i = 0; i < H2UP_MAX_STREAMS; i++) {
        if (!h2up->streams[i].stream_id || !h2up->streams[i].ctx) continue;
        proc_rst_stream(h2up, h2up->streams[i].stream_id, w);
    }
}

/* ── h2up_on_readable ────────────────────────────────────────────────────── */

int h2up_on_readable(h2up_conn_t *h2up, worker_t *w)
{
    if (h2up->closed) return -1;

    /* Read from upstream TLS into read_buf */
    char tmp[65536];
    for (;;) {
        ssize_t n = tls_read(h2up->tls, tmp, sizeof(tmp));
        if (n > 0) {
            if (buf_append(&h2up->read_buf, tmp, (size_t)n) < 0) break;
        } else {
            if (n == 0) {
                /* EOF */
                h2up_conn_close(h2up, w);
                return -1;
            }
            if (n == -2) {
                /* Permanent TLS error — connection is broken, must not
                 * be left in the pool for a future request to pick up
                 * and hang against. See the matching fix in
                 * h2up_on_writable() for the full rationale. */
                h2up_conn_close(h2up, w);
                return -1;
            }
            break;  /* EAGAIN (n == -1) */
        }
    }

    /* Parse H2 frames from read_buf */
    while (!h2up->closed && h2up->read_buf.len >= (size_t)H2_FRAME_HDR_SZ) {
        const uint8_t *p    = buf_data(&h2up->read_buf);
        uint32_t frame_len  = ((uint32_t)p[0] << 16)
                            | ((uint32_t)p[1] <<  8)
                            |  (uint32_t)p[2];
        uint8_t  frame_type = p[3];
        uint8_t  frame_flags= p[4];
        uint32_t stream_id  = (((uint32_t)p[5] & 0x7f) << 24)
                            | ((uint32_t)p[6] << 16)
                            | ((uint32_t)p[7] <<  8)
                            |  (uint32_t)p[8];

        if (h2up->read_buf.len < (size_t)(H2_FRAME_HDR_SZ + frame_len))
            break;   /* wait for more data */

        const uint8_t *payload = p + H2_FRAME_HDR_SZ;

        switch (frame_type) {
        case FRM_SETTINGS:
            proc_settings(h2up, frame_flags, payload, frame_len);
            break;
        case FRM_HEADERS:
            proc_headers(h2up, stream_id, frame_flags, payload, frame_len, w);
            break;
        case FRM_DATA:
            proc_data(h2up, stream_id, frame_flags, payload, frame_len, w);
            break;
        case FRM_WINDOW_UPDATE:
            if (frame_len >= 4)
                proc_window_update(h2up, stream_id, payload);
            break;
        case FRM_RST_STREAM:
            if (frame_len >= 4)
                proc_rst_stream(h2up, stream_id, w);
            break;
        case FRM_GOAWAY:
            h2up->goaway_received = 1;
            break;
        case FRM_PING:
            if (!(frame_flags & FL_ACK) && frame_len == 8) {
                /* Send PING ACK */
                write_fhdr(&h2up->write_buf, 8, FRM_PING, FL_ACK, 0);
                buf_append(&h2up->write_buf, payload, 8);
            }
            break;
        case FRM_CONTINUATION:
            /* Append to the most recent stream's hdr_block.
             * For simplicity, find the stream with hdr_done==0. */
            {
                h2up_stream_t *s = h2up_stream_find(h2up, stream_id);
                if (s && !s->hdr_done) {
                    buf_append(&s->hdr_block, payload, frame_len);
                    if (frame_flags & FL_END_HEADERS) {
                        hpack_header_t hdrs[64];
                        int n = hpack_decode(&h2up->hpack_rx,
                                              buf_data(&s->hdr_block),
                                              s->hdr_block.len, hdrs, 64);
                        buf_reset(&s->hdr_block);
                        if (n >= 0) {
                            for (int i = 0; i < n; i++) {
                                const char *nm = hdrs[i].name  ? hdrs[i].name  : "";
                                const char *vl = hdrs[i].value ? hdrs[i].value : "";
                                if (strcmp(nm, ":status") == 0) {
                                    int st = (int)strtol(vl, NULL, 10);
                                    http_response_set_status(&s->resp, st,
                                                              status_reason(st));
                                } else if (nm[0] != ':' &&
                                           strcasecmp(nm, "content-length") != 0) {
                                    http_response_set_header(&s->resp, nm, vl);
                                }
                            }
                            hpack_headers_free(hdrs, n);
                        }
                        s->hdr_done = 1;
                        if (s->end_stream)
                            deliver_response(h2up, s, w);
                    }
                }
            }
            break;
        default:
            break;
        }

        buf_consume(&h2up->read_buf, (size_t)(H2_FRAME_HDR_SZ + frame_len));
    }

    /* NOTE: any SETTINGS ACK / PING ACK / WINDOW_UPDATE frames queued into
     * write_buf during frame processing above are intentionally NOT flushed
     * here via a nested h2up_on_writable() call. See h2up_service() in
     * event_loop.c, which drains read+write in a flat loop after this
     * function returns — nested read/write calls between these two
     * functions previously created an ET-mode edge-timing hazard where a
     * response arriving during the nested call window could be missed
     * until the connection was force-closed. Just re-arm for both
     * directions if we still have data to send. */
    if (h2up->write_buf.len > 0 && !h2up->closed) {
        poller_mod(w->poller, h2up->fd,
                   POLLER_READ | POLLER_WRITE, h2up);
    }

    if (h2up->closed) return -1;
    return 0;
}

/* ── h2up_on_writable ────────────────────────────────────────────────────── */

int h2up_on_writable(h2up_conn_t *h2up, worker_t *w)
{
    if (h2up->closed || h2up->write_buf.len == 0) return 0;

    buf_t *wb = &h2up->write_buf;
    size_t  off = 0;
    size_t  rem = wb->len;

    while (rem > 0) {
        ssize_t n = tls_write(h2up->tls, buf_data(wb) + off, rem);
        if (n > 0) {
            off += (size_t)n;
            rem -= (size_t)n;
        } else if (n == -2) {
            /* Permanent error (or clean EOF via n==0 handled by the
             * n > 0 branch above not matching) — this connection is
             * broken and must not be reused. Without this check, a
             * dead h2up connection stays in the pool forever: every
             * future request that picks it calls tls_write() again,
             * gets the same permanent error, and is silently treated
             * as "try again later" — the request hangs and the
             * connection is never retired. */
            if (off > 0) buf_consume(wb, off);
            h2up_conn_close(h2up, w);
            return -1;
        } else {
            /* EAGAIN / WANT_WRITE (n == -1) */
            break;
        }
    }

    if (off > 0) buf_consume(wb, off);

    /* Re-arm poller. NOTE: we deliberately do NOT nest-call
     * h2up_on_readable() here anymore (see h2up_service() in
     * event_loop.c) — nesting read/write calls between these two
     * functions created an ET-mode edge-timing hazard where a response
     * arriving during the nested call window could be silently missed
     * until the connection was force-closed by the caller. The caller
     * (h2up_service) drains both directions in a flat loop right after
     * this function returns, on the same epoll_wait turn. */
    if (wb->len > 0) {
        poller_mod(w->poller, h2up->fd,
                   POLLER_READ | POLLER_WRITE, h2up);
    } else {
        poller_mod(w->poller, h2up->fd,
                   POLLER_READ, h2up);
    }
    return 0;
}
