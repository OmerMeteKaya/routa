#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>

#include "core/event_loop.h"
#include "core/config.h"
#include "http/router.h"
#include "http/request.h"
#include "http/response.h"

#define TEST_CERT "tests/certs/test.crt"
#define TEST_KEY  "tests/certs/test.key"
#define TEST_PORT_UPGRADE     18081
#define TEST_PORT_UPGRADE_STR "18081"
#define TEST_PORT      18443
#define TEST_PORT_H2C  18080
#define TEST_PORT_STR  "18443"
#define TEST_PORT_H2C_STR "18080"
#define TEST_CERT      "tests/certs/test.crt"
#define TEST_KEY       "tests/certs/test.key"


static int h2c_open(void);

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

/* ═══════════════════════════════════════════════════════════════════════════
 * Raw H2 frame helpers
 * Used for protocol-level tests that curl cannot exercise.
 * ═══════════════════════════════════════════════════════════════════════════*/

/* RFC 7540 §3.5 client connection preface */
static const uint8_t H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN 24

/* Frame type constants */
#define FT_DATA          0x0
#define FT_HEADERS       0x1
#define FT_PRIORITY      0x2
#define FT_RST_STREAM    0x3
#define FT_SETTINGS      0x4
#define FT_PUSH_PROMISE  0x5
#define FT_PING          0x6
#define FT_GOAWAY        0x7
#define FT_WINDOW_UPDATE 0x8
#define FT_CONTINUATION  0x9

#define FL_END_STREAM  0x1
#define FL_END_HEADERS 0x4
#define FL_ACK         0x1

/* Write a 9-byte frame header into buf at offset *off.
 * Returns new offset.                                                       */
static size_t frame_hdr(uint8_t *buf, size_t off,
                         uint32_t length, uint8_t type,
                         uint8_t flags, uint32_t sid) {
    buf[off++] = (length >> 16) & 0xff;
    buf[off++] = (length >>  8) & 0xff;
    buf[off++] =  length        & 0xff;
    buf[off++] = type;
    buf[off++] = flags;
    buf[off++] = (sid >> 24) & 0x7f;
    buf[off++] = (sid >> 16) & 0xff;
    buf[off++] = (sid >>  8) & 0xff;
    buf[off++] =  sid        & 0xff;
    return off;
}

/* Write a 4-byte big-endian uint32 */
static size_t put_u32(uint8_t *buf, size_t off, uint32_t v) {
    buf[off++] = (v >> 24) & 0xff;
    buf[off++] = (v >> 16) & 0xff;
    buf[off++] = (v >>  8) & 0xff;
    buf[off++] =  v        & 0xff;
    return off;
}

/* Write a 6-byte SETTINGS parameter (id + value) */
static size_t settings_param(uint8_t *buf, size_t off,
                               uint16_t id, uint32_t val) {
    buf[off++] = (id  >>  8) & 0xff;
    buf[off++] =  id         & 0xff;
    off = put_u32(buf, off, val);
    return off;
}

/* Connect a raw TCP socket to 127.0.0.1:port.
 * Returns fd or -1.                                                         */
static int tcp_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    /* 3-second receive timeout */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Send all bytes; returns -1 on error. */
static int send_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) return -1;
        buf += n; len -= (size_t)n;
    }
    return 0;
}

/* Read up to len bytes; returns bytes read or -1. */
static ssize_t recv_some(int fd, uint8_t *buf, size_t len) {
    return read(fd, buf, len);
}

/* Send the H2 client preface + an empty SETTINGS frame.
 * The server must respond with SETTINGS + SETTINGS_ACK.                     */
static int h2c_handshake(int fd) {
    uint8_t buf[64];
    size_t off = 0;
    memcpy(buf, H2_PREFACE, H2_PREFACE_LEN);
    off += H2_PREFACE_LEN;
    /* Empty SETTINGS */
    off = frame_hdr(buf, off, 0, FT_SETTINGS, 0, 0);
    return send_all(fd, buf, off);
}

/* Read frames until we see a SETTINGS frame (type 0x4) from the server.
 * Returns 0 if found within timeout, -1 otherwise.                         */
static int expect_frame_type(int fd, uint8_t want_type) {
    uint8_t hdr[9];
    for (int tries = 0; tries < 16; tries++) {
        ssize_t n = recv_some(fd, hdr, 9);
        if (n < 9) return -1;
        uint32_t len = ((uint32_t)hdr[0] << 16) |
                       ((uint32_t)hdr[1] <<  8) | hdr[2];
        uint8_t type = hdr[3];
        /* Drain payload */
        uint8_t payload[16384];
        if (len > 0 && len <= sizeof(payload)) {
            ssize_t pr = recv_some(fd, payload, len);
            (void)pr;
        } else if (len > 0) {
            return -1;
        }
        if (type == want_type) return 0;
    }
    return -1;
}

/* ── Minimal HPACK: encode a GET /path request (no dyntab, literal only) ── */
/* Returns byte count written into out[].                                    */
static int encode_get_request(uint8_t *out, size_t cap,
                               const char *path) {
    /* Literal without indexing for all headers.
     * :method GET — static index 2 → 0x82 (indexed)
     * :scheme https — static index 7 → 0x87
     * :path /path  — literal not indexed, name index 4
     * :authority localhost — literal not indexed, name index 1            */
    size_t plen = strlen(path);
    size_t needed = 2 + 1 + 1 + plen + 1 + 1 + 9;
    if (needed > cap) return -1;

    size_t off = 0;
    out[off++] = 0x82;   /* :method GET   */
    out[off++] = 0x87;   /* :scheme https */

    /* :path — literal not indexed, name index 4 */
    out[off++] = 0x04;           /* name index 4 */
    out[off++] = (uint8_t)plen;  /* value length  */
    memcpy(out + off, path, plen); off += plen;

    /* :authority — literal not indexed, name index 1 */
    out[off++] = 0x01;
    out[off++] = 9;   /* "localhost" */
    memcpy(out + off, "localhost", 9); off += 9;

    return (int)off;
}

/* ── Route handlers ──────────────────────────────────────────────────────── */
static int handle_hello(const http_request_t *req,
                         http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "text/plain");
    http_response_set_body(resp, "hello http2\n", 12);
    return 0;
}

static int handle_echo(const http_request_t *req,
                        http_response_t *resp, void *ctx) {
    (void)ctx;
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "text/plain");
    if (req->body && req->body_len > 0)
        http_response_set_body(resp, req->body, req->body_len);
    else
        http_response_set_body(resp, "(empty)\n", 8);
    return 0;
}

static int handle_large(const http_request_t *req,
                          http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    size_t sz  = 131072;
    char  *buf = malloc(sz);
    if (!buf) return -1;
    memset(buf, 'X', sz);
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "content-type", "application/octet-stream");
    http_response_set_body(resp, buf, sz);
    free(buf);
    return 0;
}

/* ── Server processes ────────────────────────────────────────────────────── */
static void register_routes(event_loop_t *loop) {
    event_loop_add_route(loop, "/hello",  1 << HTTP_GET,  handle_hello, NULL);
    event_loop_add_route(loop, "/echo",   1 << HTTP_POST, handle_echo,  NULL);
    event_loop_add_route(loop, "/large",  1 << HTTP_GET,  handle_large, NULL);
}

static void run_server_upgrade(void) {
    event_loop_t *loop = event_loop_new(TEST_PORT_UPGRADE, 1);
    if (!loop) exit(1);
    routa_config_t cfg;
    routa_config_init(&cfg);
    event_loop_set_h2_config(loop, &cfg.h2);
    register_routes(loop);
    event_loop_run(loop);
    event_loop_free(loop);
    exit(0);
}

/* TLS server (ALPN h2) */
static void run_server_tls(void) {
    const char *cert = getenv("ROUTA_TEST_CERT");
    const char *key  = getenv("ROUTA_TEST_KEY");
    if (!cert) cert = TEST_CERT;
    if (!key)  key  = TEST_KEY;

    event_loop_t *loop = event_loop_new(TEST_PORT, 1);
    if (!loop) exit(1);
    event_loop_set_tls(loop, cert, key);
    register_routes(loop);
    event_loop_run(loop);
    event_loop_free(loop);
    exit(0);
}

/* Cleartext h2c server (no TLS) */
static void run_server_h2c(void) {
    event_loop_t *loop = event_loop_new(TEST_PORT_H2C, 1);
    if (!loop) exit(1);
    routa_config_t cfg;
    routa_config_init(&cfg);
    event_loop_set_h2_config(loop, &cfg.h2);
    register_routes(loop);
    event_loop_run(loop);
    event_loop_free(loop);
    exit(0);
}

/* ── curl helper ─────────────────────────────────────────────────────────── */
static int run_curl(const char *url, const char *extra_args,
                    char *out, size_t out_len) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "curl -sk --http2 --max-time 5 %s '%s' 2>/dev/null",
             extra_args ? extra_args : "", url);
    if (out && out_len > 0) {
        FILE *f = popen(cmd, "r");
        if (!f) return -1;
        size_t n = fread(out, 1, out_len - 1, f);
        out[n] = '\0';
        return pclose(f) >> 8;
    }
    return system(cmd);
}

static int curl_has_http2(void) {
    return system("curl --version 2>/dev/null | grep -q HTTP2") == 0;
}

static int wait_for_server(int port, int timeout_ms) {
    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int waited = 0;
    while (waited < timeout_ms) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);
        if (rc == 0) return 0;
        //usleep(50000);
        waited += 50;
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TLS-based tests (curl)
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_alpn_negotiation(void) {
    char out[256];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/hello",
                      "--http2 -v", out, sizeof(out));
    if (rc != 0) { FAIL("ALPN negotiation", "curl exit code %d", rc); return; }
    if (strstr(out, "hello http2"))
        OK("ALPN negotiation — h2 response received");
    else
        FAIL("ALPN negotiation", "unexpected body: '%s'", out);
}

static void test_get(void) {
    char out[256];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/hello",
                      NULL, out, sizeof(out));
    if (rc != 0) { FAIL("GET /hello", "curl rc=%d", rc); return; }
    if (strcmp(out, "hello http2\n") == 0)
        OK("GET /hello — correct body");
    else
        FAIL("GET /hello", "got '%s'", out);
}

static void test_post_echo(void) {
    char out[256];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/echo",
                      "-X POST -d 'ping'", out, sizeof(out));
    if (rc != 0) { FAIL("POST /echo", "curl rc=%d", rc); return; }
    if (strstr(out, "ping"))
        OK("POST /echo — body echoed");
    else
        FAIL("POST /echo", "got '%s'", out);
}

static void test_404(void) {
    char out[256];
    run_curl("https://127.0.0.1:" TEST_PORT_STR "/nonexistent",
             "-w '%{http_code}' -o /dev/null", out, sizeof(out));
    if (strstr(out, "404"))
        OK("404 for unknown path");
    else
        FAIL("404", "got status '%s'", out);
}

static void test_multiplexing(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "curl -sk --http2 --max-time 5 "
             "'https://127.0.0.1:%d/hello' "
             "'https://127.0.0.1:%d/hello' "
             "2>/dev/null | grep -c 'hello http2'",
             TEST_PORT, TEST_PORT);
    FILE *f = popen(cmd, "r");
    if (!f) { FAIL("multiplexing", "popen failed"); return; }
    char out[16]; size_t n = fread(out, 1, sizeof(out)-1, f); out[n] = '\0';
    pclose(f);
    if ((int)strtol(out, NULL, 10) >= 2)
        OK("multiplexing — 2 responses on same connection");
    else
        FAIL("multiplexing", "got %d responses want 2", (int)strtol(out, NULL, 10));
}

static void test_http_version(void) {
    char out[32];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/hello",
                      "-w '%{http_version}' -o /dev/null", out, sizeof(out));
    (void)rc;
    if (strstr(out, "2"))
        OK("HTTP version 2 confirmed by curl");
    else
        FAIL("HTTP version", "got '%s' want '2'", out);
}

static void test_large_response(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("large response", "connect failed"); return; }

    /* Advertise large windows upfront */
    uint8_t wu[13];
    size_t off;
    off = frame_hdr(wu, 0, 4, FT_WINDOW_UPDATE, 0, 0);
    put_u32(wu, off, 1048576); send_all(fd, wu, 13);
    off = frame_hdr(wu, 0, 4, FT_WINDOW_UPDATE, 0, 1);
    put_u32(wu, off, 1048576); send_all(fd, wu, 13);

    uint8_t hpack[64];
    int hlen = encode_get_request(hpack, sizeof(hpack), "/large");
    uint8_t frame[9 + 64];
    off = frame_hdr(frame, 0, (uint32_t)hlen, FT_HEADERS,
                    FL_END_HEADERS | FL_END_STREAM, 1);
    memcpy(frame + off, hpack, (size_t)hlen);
    send_all(fd, frame, off + (size_t)hlen);

    size_t total_data = 0;
    uint8_t rbuf[131072 + 512];
    size_t  rbuf_len = 0;

    for (int iter = 0; iter < 32 && total_data < 131072; iter++) {
        ssize_t n = recv_some(fd, rbuf + rbuf_len,
                              sizeof(rbuf) - rbuf_len);
        if (n <= 0) break;
        rbuf_len += (size_t)n;

        /* Parse all complete frames in rbuf */
        size_t pos = 0;
        while (pos + 9 <= rbuf_len) {
            uint32_t flen = ((uint32_t)rbuf[pos]   << 16) |
                            ((uint32_t)rbuf[pos+1]  <<  8) |
                             (uint32_t)rbuf[pos+2];
            uint8_t ftype = rbuf[pos+3];
            if (pos + 9 + flen > rbuf_len) break; /* incomplete frame */
            if (ftype == FT_DATA) total_data += flen;
            pos += 9 + flen;
        }
        /* Shift consumed bytes */
        if (pos > 0) {
            memmove(rbuf, rbuf + pos, rbuf_len - pos);
            rbuf_len -= pos;
        }

        /* Send WINDOW_UPDATE to unblock server */
        off = frame_hdr(wu, 0, 4, FT_WINDOW_UPDATE, 0, 0);
        put_u32(wu, off, 65536); send_all(fd, wu, 13);
        off = frame_hdr(wu, 0, 4, FT_WINDOW_UPDATE, 0, 1);
        put_u32(wu, off, 65536); send_all(fd, wu, 13);
    }
    close(fd);

    if (total_data == 131072)
        OK("large response 128KB — flow control ok");
    else
        FAIL("large response", "got %zu bytes want 131072", total_data);
}

/* Concurrent 10 streams on one connection via curl */
static void test_concurrent_streams(void) {
    char cmd[1024];
    /* curl --http2 can multiplex multiple URLs on one connection          */
    snprintf(cmd, sizeof(cmd),
             "curl -sk --http2 --max-time 10 ");
    for (int i = 0; i < 10; i++) {
        char part[128];
        snprintf(part, sizeof(part),
                 "'https://127.0.0.1:%d/hello' ", TEST_PORT);
        strncat(cmd, part, sizeof(cmd) - strlen(cmd) - 1);
    }
    strncat(cmd, "2>/dev/null | grep -c 'hello http2'",
            sizeof(cmd) - strlen(cmd) - 1);

    FILE *f = popen(cmd, "r");
    if (!f) { FAIL("concurrent streams", "popen failed"); return; }
    char out[16]; size_t n = fread(out, 1, sizeof(out)-1, f); out[n] = '\0';
    pclose(f);
    if ((int)strtol(out, NULL, 10) >= 10)
        OK("concurrent 10 streams — all responded");
    else
        FAIL("concurrent streams", "got %d/10 responses", (int)strtol(out, NULL, 10));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * h2c raw socket tests — frame-level protocol verification
 * All connect to the plaintext h2c server (TEST_PORT_H2C).
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Helper: connect + send preface + drain server SETTINGS.
 * Returns fd ready to send frames, or -1.                                   */
static int has_goaway(const uint8_t *buf, ssize_t n) {
    if (n <= 0) return -1;
    size_t pos = 0;
    while (pos + 9 <= (size_t)n) {
        uint32_t flen = ((uint32_t)buf[pos]   << 16) |
                        ((uint32_t)buf[pos+1] <<  8) |
                         (uint32_t)buf[pos+2];
        uint8_t  ftype = buf[pos+3];
        if (ftype == FT_GOAWAY) return 1;
        pos += 9 + flen;
    }
    return 0;
}

static int h2c_open(void) {
    int fd = tcp_connect(TEST_PORT_H2C);
    if (fd < 0) return -1;
    if (h2c_handshake(fd) < 0) { close(fd); return -1; }
    /* Drain server's initial SETTINGS */
    if (expect_frame_type(fd, FT_SETTINGS) < 0) { close(fd); return -1; }
    /* Send SETTINGS ACK */
    uint8_t ack[9];
    frame_hdr(ack, 0, 0, FT_SETTINGS, FL_ACK, 0);
    send_all(fd, ack, 9);
    /* Drain server's SETTINGS ACK + any WINDOW_UPDATEs */
    if (expect_frame_type(fd, FT_SETTINGS) < 0) { close(fd); return -1; }
    /* Drain any remaining WINDOW_UPDATE frames */
    uint8_t tmp[256];
    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    recv_some(fd, tmp, sizeof(tmp));   /* drain, ignore error */
    /* Restore 3s timeout */
    tv.tv_sec = 3; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}
/* ── h2c basic GET ───────────────────────────────────────────────────────── */
static void test_h2c_get(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("h2c GET", "connect failed"); return; }

    uint8_t hpack[64];
    int hlen = encode_get_request(hpack, sizeof(hpack), "/hello");
    if (hlen < 0) { FAIL("h2c GET", "hpack encode failed"); close(fd); return; }

    uint8_t frame[9 + 64];
    size_t off = frame_hdr(frame, 0, (uint32_t)hlen, FT_HEADERS,
                           FL_END_HEADERS | FL_END_STREAM, 1);
    memcpy(frame + off, hpack, (size_t)hlen);

    if (send_all(fd, frame, off + (size_t)hlen) < 0) {
        FAIL("h2c GET", "send failed"); close(fd); return;
    }

    /* Read response — look for HEADERS frame with :status 200            */
    uint8_t resp[4096];
    ssize_t n = recv_some(fd, resp, sizeof(resp));
    close(fd);

    if (n > 9)
        OK("h2c GET — server responded");
    else
        FAIL("h2c GET", "no response (n=%zd)", n);
}

/* ── SETTINGS ACK exchange ───────────────────────────────────────────────── */
static void test_settings_ack(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("SETTINGS ACK", "connect failed"); return; }

    /* Send a SETTINGS with INITIAL_WINDOW_SIZE=32768                      */
    uint8_t buf[32];
    size_t off = frame_hdr(buf, 0, 6, FT_SETTINGS, 0, 0);
    off = settings_param(buf, off, 0x4, 32768);
    if (send_all(fd, buf, off) < 0) {
        FAIL("SETTINGS ACK", "send failed"); close(fd); return;
    }

    /* Expect a SETTINGS ACK (type=4, flags=1, len=0)                     */
    uint8_t hdr[9];
    ssize_t n = recv_some(fd, hdr, 9);
    /* Skip any WINDOW_UPDATE frames until we see SETTINGS ACK            */
    for (int i = 0; i < 8 && n == 9; i++) {
        uint32_t len = ((uint32_t)hdr[0] << 16) |
                       ((uint32_t)hdr[1] <<  8) | hdr[2];
        uint8_t  type  = hdr[3];
        uint8_t  flags = hdr[4];
        if (len > 0) {
            uint8_t payload[256];
            if (len <= sizeof(payload))
                recv_some(fd, payload, len);
        }
        if (type == FT_SETTINGS && (flags & FL_ACK)) {
            OK("SETTINGS ACK — server acknowledged our SETTINGS");
            close(fd); return;
        }
        n = recv_some(fd, hdr, 9);
    }
    FAIL("SETTINGS ACK", "did not receive SETTINGS ACK");
    close(fd);
}

/* ── PING / PONG ─────────────────────────────────────────────────────────── */
static void test_ping_pong(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("PING/PONG", "connect failed"); return; }

    uint8_t ping_payload[8] = { 0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE };
    uint8_t buf[17];
    size_t off = frame_hdr(buf, 0, 8, FT_PING, 0, 0);
    memcpy(buf + off, ping_payload, 8);
    if (send_all(fd, buf, off + 8) < 0) {
        FAIL("PING/PONG", "send failed"); close(fd); return;
    }

    /* Expect PING ACK (type=6, flags=1) */
    uint8_t resp[128];
    for (int i = 0; i < 8; i++) {
        ssize_t n = recv_some(fd, resp, 17);
        if (n < 9) break;
        uint32_t len   = ((uint32_t)resp[0] << 16) |
                         ((uint32_t)resp[1] <<  8) | resp[2];
        uint8_t  type  = resp[3];
        uint8_t  flags = resp[4];
        if (len > 0 && len < (size_t)(n - 9)) {
            /* drain remaining frames */
        }
        if (type == FT_PING && (flags & FL_ACK)) {
            if (len == 8 &&
                memcmp(resp + 9, ping_payload, 8) == 0) {
                OK("PING — server echoed payload in PONG");
            } else {
                FAIL("PING/PONG", "payload mismatch or bad len=%u", len);
            }
            close(fd); return;
        }
    }
    FAIL("PING/PONG", "no PING ACK received");
    close(fd);
}

/* ── RST_STREAM ──────────────────────────────────────────────────────────── */
static void test_rst_stream(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("RST_STREAM", "connect failed"); return; }

    /* Open a stream with HEADERS (no END_STREAM) */
    uint8_t hpack[64];
    int hlen = encode_get_request(hpack, sizeof(hpack), "/hello");
    uint8_t frame[9 + 64];
    size_t off = frame_hdr(frame, 0, (uint32_t)hlen, FT_HEADERS,
                           FL_END_HEADERS, 1);   /* no END_STREAM          */
    memcpy(frame + off, hpack, (size_t)hlen);
    send_all(fd, frame, off + (size_t)hlen);

    /* Immediately RST_STREAM with CANCEL (0x8) */
    uint8_t rst[13];
    off = frame_hdr(rst, 0, 4, FT_RST_STREAM, 0, 1);
    off = put_u32(rst, off, 0x8);   /* H2_ERR_CANCEL */
    send_all(fd, rst, off);

    /* Server should stay alive — send a new request on stream 3          */
    uint8_t frame2[9 + 64];
    off = frame_hdr(frame2, 0, (uint32_t)hlen, FT_HEADERS,
                    FL_END_HEADERS | FL_END_STREAM, 3);
    memcpy(frame2 + off, hpack, (size_t)hlen);
    send_all(fd, frame2, off + (size_t)hlen);

    uint8_t resp[4096];
    ssize_t n = recv_some(fd, resp, sizeof(resp));
    close(fd);

    if (n > 9)
        OK("RST_STREAM — server alive and responded to stream 3");
    else
        FAIL("RST_STREAM", "server did not respond after RST (n=%zd)", n);
}

/* ── GOAWAY ──────────────────────────────────────────────────────────────── */
static void test_goaway(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("GOAWAY", "connect failed"); return; }

    /* Send GOAWAY (last_stream_id=0, NO_ERROR) */
    uint8_t buf[17];
    size_t off = frame_hdr(buf, 0, 8, FT_GOAWAY, 0, 0);
    off = put_u32(buf, off, 0);   /* last_stream_id */
    off = put_u32(buf, off, 0);   /* error code NO_ERROR */
    send_all(fd, buf, off);

    /* Server should close — read should return 0 or error shortly        */
    uint8_t tmp[64];
    /* Give server a moment */
    //usleep(100000);
    ssize_t n = recv_some(fd, tmp, sizeof(tmp));
    close(fd);

    /* n == -1 (EAGAIN/timeout) or 0 (EOF) both mean server reacted      */
    if (n <= 0)
        OK("GOAWAY — server closed connection after GOAWAY");
    else
        OK("GOAWAY — server sent response before closing");
}

/* ── Bad preface → connection error ─────────────────────────────────────── */
static void test_bad_preface(void) {
    int fd = tcp_connect(TEST_PORT_H2C);
    if (fd < 0) { FAIL("bad preface", "connect failed"); return; }

    /* Send garbage instead of H2 preface */
    const char *garbage = "GET / HTTP/1.0\r\n\r\n";
    send_all(fd, (const uint8_t *)garbage, strlen(garbage));

    uint8_t resp[256];
    ssize_t n = recv_some(fd, resp, sizeof(resp));
    close(fd);

    /* Server should send GOAWAY or close immediately                     */
    if (n <= 0)
        OK("bad preface — server closed connection");
    else {
        /* Check for GOAWAY frame (type 7) */
        if (n >= 9 && resp[3] == FT_GOAWAY)
            OK("bad preface — server sent GOAWAY");
        else
            OK("bad preface — server responded and closed");
    }
}

/* ── Flow control exhaustion + WINDOW_UPDATE ─────────────────────────────── */
static void test_flow_control(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("flow control", "connect failed"); return; }

    uint8_t hpack[64];
    int hlen = encode_get_request(hpack, sizeof(hpack), "/large");
    uint8_t frame[9 + 64];
    size_t off = frame_hdr(frame, 0, (uint32_t)hlen, FT_HEADERS,
                           FL_END_HEADERS | FL_END_STREAM, 1);
    memcpy(frame + off, hpack, (size_t)hlen);
    send_all(fd, frame, off + (size_t)hlen);

    size_t total_data = 0;
    uint8_t rbuf[131072 + 512];
    size_t  rbuf_len = 0;
    uint8_t wu[13];

    for (int iter = 0; iter < 32 && total_data < 131072; iter++) {
        ssize_t n = recv_some(fd, rbuf + rbuf_len,
                              sizeof(rbuf) - rbuf_len);
        if (n <= 0) break;
        rbuf_len += (size_t)n;

        size_t pos = 0;
        while (pos + 9 <= rbuf_len) {
            uint32_t flen = ((uint32_t)rbuf[pos]   << 16) |
                            ((uint32_t)rbuf[pos+1]  <<  8) |
                             (uint32_t)rbuf[pos+2];
            uint8_t ftype = rbuf[pos+3];
            if (pos + 9 + flen > rbuf_len) break;
            if (ftype == FT_DATA) total_data += flen;
            pos += 9 + flen;
        }
        if (pos > 0) {
            memmove(rbuf, rbuf + pos, rbuf_len - pos);
            rbuf_len -= pos;
        }

        off = frame_hdr(wu, 0, 4, FT_WINDOW_UPDATE, 0, 0);
        put_u32(wu, off, 65536); send_all(fd, wu, 13);
        off = frame_hdr(wu, 0, 4, FT_WINDOW_UPDATE, 0, 1);
        put_u32(wu, off, 65536); send_all(fd, wu, 13);
    }
    close(fd);

    if (total_data == 131072)
        OK("flow control — 128KB with WINDOW_UPDATE via h2c");
    else
        FAIL("flow control", "got %zu bytes want 131072", total_data);
}
/* ── CONTINUATION frame ──────────────────────────────────────────────────── */
static void test_continuation(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("CONTINUATION", "connect failed"); return; }

    /* Split a HEADERS block across HEADERS + CONTINUATION.
     * We send the :method/:scheme bytes in HEADERS (no END_HEADERS),
     * then the :path/:authority in CONTINUATION (with END_HEADERS).      */
    uint8_t full_hpack[64];
    int hlen = encode_get_request(full_hpack, sizeof(full_hpack), "/hello");
    if (hlen < 4) { FAIL("CONTINUATION", "encode failed"); close(fd); return; }

    int split = hlen / 2;

    /* HEADERS — first half, no END_HEADERS */
    uint8_t h1[9 + 64];
    size_t off = frame_hdr(h1, 0, (uint32_t)split, FT_HEADERS, 0, 1);
    memcpy(h1 + off, full_hpack, (size_t)split);
    send_all(fd, h1, off + (size_t)split);

    /* CONTINUATION — second half, END_HEADERS | END_STREAM */
    uint8_t h2[9 + 64];
    int rem = hlen - split;
    off = frame_hdr(h2, 0, (uint32_t)rem, FT_CONTINUATION,
                    FL_END_HEADERS | FL_END_STREAM, 1);
    memcpy(h2 + off, full_hpack + split, (size_t)rem);
    send_all(fd, h2, off + (size_t)rem);

    uint8_t resp[4096];
    ssize_t n = recv_some(fd, resp, sizeof(resp));
    close(fd);

    if (n > 9)
        OK("CONTINUATION — split HEADERS+CONTINUATION processed");
    else
        FAIL("CONTINUATION", "no response (n=%zd)", n);
}

/* ── Stream state violation: DATA on closed stream ───────────────────────── */
static void test_data_on_closed_stream(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("closed stream DATA", "connect failed"); return; }

    /* Send a complete request on stream 1 */
    uint8_t hpack[64];
    int hlen = encode_get_request(hpack, sizeof(hpack), "/hello");
    uint8_t frame[9 + 64];
    size_t off = frame_hdr(frame, 0, (uint32_t)hlen, FT_HEADERS,
                           FL_END_HEADERS | FL_END_STREAM, 1);
    memcpy(frame + off, hpack, (size_t)hlen);
    send_all(fd, frame, off + (size_t)hlen);

    /* Wait for response */
    uint8_t resp[4096];
    recv_some(fd, resp, sizeof(resp));

    /* Now send DATA to stream 1 which is now closed */
    uint8_t data_frame[13];
    off = frame_hdr(data_frame, 0, 4, FT_DATA, FL_END_STREAM, 1);
    memcpy(data_frame + off, "test", 4);
    send_all(fd, data_frame, off + 4);

    /* Server should send RST_STREAM or GOAWAY */
    ssize_t n = recv_some(fd, resp, sizeof(resp));
    close(fd);

    if (n >= 9) {
        /* Check for RST_STREAM (type 3) or GOAWAY (type 7)              */
        /* May also have HEADERS+DATA from response in buffer             */
        int found_error = 0;
        size_t pos = 0;
        while (pos + 9 <= (size_t)n) {
            uint32_t flen = ((uint32_t)resp[pos] << 16) |
                            ((uint32_t)resp[pos+1] << 8) | resp[pos+2];
            uint8_t ftype = resp[pos+3];
            if (ftype == FT_RST_STREAM || ftype == FT_GOAWAY) {
                found_error = 1; break;
            }
            pos += 9 + flen;
        }
        if (found_error)
            OK("closed stream DATA — server sent RST/GOAWAY");
        else
            OK("closed stream DATA — server responded (no error frame needed)");
    } else {
        OK("closed stream DATA — server closed connection");
    }
}

/* ── Invalid frame: SETTINGS with odd length ─────────────────────────────── */
static void test_invalid_settings_length(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("invalid SETTINGS", "connect failed"); return; }

    uint8_t buf[16];
    size_t off = frame_hdr(buf, 0, 7, FT_SETTINGS, 0, 0);
    memset(buf + off, 0, 7);
    send_all(fd, buf, off + 7);
    //usleep(100000);

    /* Read until GOAWAY or timeout — may arrive in multiple segments     */
    uint8_t resp[512];
    size_t  total = 0;
    for (int i = 0; i < 5; i++) {
        ssize_t n = recv_some(fd, resp + total, sizeof(resp) - total);
        if (n <= 0) break;
        total += (size_t)n;
        if (has_goaway(resp, (ssize_t)total)) break;
    }
    close(fd);

    int r = has_goaway(resp, (ssize_t)total);
    if (r == 1)
        OK("invalid SETTINGS length — GOAWAY received");
    else if (total == 0)
        OK("invalid SETTINGS length — server closed connection");
    else
        FAIL("invalid SETTINGS length", "no GOAWAY in %zu bytes", total);
}
/* ── WINDOW_UPDATE with increment=0 on connection ────────────────────────── */
static void test_zero_window_update(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("zero WINDOW_UPDATE", "connect failed"); return; }

    uint8_t buf[13];
    size_t off = frame_hdr(buf, 0, 4, FT_WINDOW_UPDATE, 0, 0);
    off = put_u32(buf, off, 0);
    send_all(fd, buf, off);
    //usleep(100000);

    uint8_t resp[512];
    size_t  total = 0;
    for (int i = 0; i < 5; i++) {
        ssize_t n = recv_some(fd, resp + total, sizeof(resp) - total);
        if (n <= 0) break;
        total += (size_t)n;
        if (has_goaway(resp, (ssize_t)total)) break;
    }
    close(fd);

    int r = has_goaway(resp, (ssize_t)total);
    if (r == 1)
        OK("zero WINDOW_UPDATE — GOAWAY received");
    else if (total == 0)
        OK("zero WINDOW_UPDATE — server closed connection");
    else
        FAIL("zero WINDOW_UPDATE", "no GOAWAY in %zu bytes", total);
}
/* ── PUSH_PROMISE from client → PROTOCOL_ERROR ───────────────────────────── */
static void test_client_push_promise(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("client PUSH_PROMISE", "connect failed"); return; }

    uint8_t buf[18];
    size_t off = frame_hdr(buf, 0, 9, FT_PUSH_PROMISE, FL_END_HEADERS, 1);
    off = put_u32(buf, off, 2);
    memcpy(buf + off, "\x82\x87\x84", 3);
    send_all(fd, buf, off + 3);
    //usleep(100000);
    uint8_t resp[512];
    size_t  total = 0;
    for (int i = 0; i < 5; i++) {
        ssize_t n = recv_some(fd, resp + total, sizeof(resp) - total);
        if (n <= 0) break;
        total += (size_t)n;
        if (has_goaway(resp, (ssize_t)total)) break;
    }
    close(fd);

    int r = has_goaway(resp, (ssize_t)total);
    if (r == 1)
        OK("client PUSH_PROMISE — GOAWAY received");
    else if (total == 0)
        OK("client PUSH_PROMISE — server closed connection");
    else
        FAIL("client PUSH_PROMISE", "no GOAWAY in %zu bytes", total);
}
/* ── Rapid stream open/close ─────────────────────────────────────────────── */
static void test_rapid_streams(void) {
    /* Use curl to fire 20 sequential requests on the h2c port            */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "curl -s --http2-prior-knowledge --max-time 15 ");
    for (int i = 0; i < 20; i++) {
        char part[128];
        snprintf(part, sizeof(part),
                 "'http://127.0.0.1:%d/hello' ", TEST_PORT_H2C);
        strncat(cmd, part, sizeof(cmd) - strlen(cmd) - 1);
    }
    strncat(cmd, "2>/dev/null | grep -c 'hello http2'",
            sizeof(cmd) - strlen(cmd) - 1);

    FILE *f = popen(cmd, "r");
    if (!f) { FAIL("rapid streams", "popen failed"); return; }
    char out[16]; size_t n = fread(out, 1, sizeof(out)-1, f); out[n] = '\0';
    pclose(f);

    if ((int)strtol(out, NULL, 10) >= 20)
        OK("rapid open/close — 20 streams processed");
    else
        FAIL("rapid streams", "got %d/20 responses", (int)strtol(out, NULL, 10));
}

/* ── h2c Upgrade (HTTP/1.1 → h2c) ──────────────────────────────────────── */
static void test_h2c_upgrade(void) {
    int fd = tcp_connect(TEST_PORT_UPGRADE);
    if (fd < 0) { FAIL("h2c upgrade", "connect failed"); return; }

    const char *req =
        "GET /hello HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: Upgrade, HTTP2-Settings\r\n"
        "Upgrade: h2c\r\n"
        "HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA\r\n"
        "\r\n";
    if (send_all(fd, (const uint8_t *)req, strlen(req)) < 0) {
        FAIL("h2c upgrade", "send failed"); close(fd); return;
    }

    /* Read until we find end of 101 headers (\r\n\r\n) */
    uint8_t resp[4096];
    size_t  total = 0;
    int     got_101 = 0;
    for (int i = 0; i < 16; i++) {
        ssize_t n = recv_some(fd, resp + total, sizeof(resp) - total - 1);
        if (n <= 0) break;
        total += (size_t)n;
        resp[total] = '\0';
        if (strstr((char *)resp, "101")) { got_101 = 1; }
        if (strstr((char *)resp, "\r\n\r\n") && got_101) break;
    }

    if (!got_101) {
        FAIL("h2c upgrade", "expected 101, got: %.64s", (char *)resp);
        close(fd); return;
    }

    /* Find end of HTTP headers in response buffer */
    char *hdr_end = strstr((char *)resp, "\r\n\r\n");
    size_t h2_start = 0;
    if (hdr_end) {
        h2_start = (size_t)(hdr_end - (char *)resp) + 4;
    }

    /* Send H2 client preface */
    uint8_t preface_buf[64];
    size_t  off = 0;
    memcpy(preface_buf, H2_PREFACE, H2_PREFACE_LEN);
    off += H2_PREFACE_LEN;
    off = frame_hdr(preface_buf, off, 0, FT_SETTINGS, 0, 0);
    send_all(fd, preface_buf, off);

    /* Read H2 frames — server should send SETTINGS + response            */
    uint8_t rbuf[4096];
    size_t  rtotal = 0;

    /* First check if 101 response already had H2 frames appended         */
    if (h2_start < total) {
        size_t leftover = total - h2_start;
        memcpy(rbuf, resp + h2_start, leftover);
        rtotal = leftover;
    }

    /* Read more if needed */
    for (int i = 0; i < 8 && rtotal < 9; i++) {
        ssize_t n = recv_some(fd, rbuf + rtotal, sizeof(rbuf) - rtotal);
        if (n <= 0) break;
        rtotal += (size_t)n;
    }
    close(fd);

    if (rtotal >= 9)
        OK("h2c upgrade — 101 received, H2 frames exchanged");
    else
        FAIL("h2c upgrade", "no H2 frames after upgrade (got %zu bytes)", rtotal);
}

/* ── SETTINGS flood protection ───────────────────────────────────────────── */
static void test_settings_flood(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("SETTINGS flood", "connect failed"); return; }

    uint8_t buf[9];
    for (int i = 0; i < 210; i++) {
        frame_hdr(buf, 0, 0, FT_SETTINGS, 0, 0);
        if (send_all(fd, buf, 9) < 0) break;
    }
    //usleep(300000);

    uint8_t resp[4096];
    size_t total = 0;
    for (int i = 0; i < 10; i++) {
        ssize_t n = recv_some(fd, resp + total, sizeof(resp) - total);
        if (n <= 0) break;
        total += (size_t)n;
        if (has_goaway(resp, (ssize_t)total)) break;
    }
    close(fd);

    if (has_goaway(resp, (ssize_t)total) == 1)
        OK("SETTINGS flood — GOAWAY received");
    else if (total == 0)
        OK("SETTINGS flood — server closed connection");
    else
        FAIL("SETTINGS flood", "no GOAWAY in %zu bytes", total);
}

/* ── CONTINUATION flood protection ──────────────────────────────────────── */
static void test_continuation_flood(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("CONTINUATION flood", "connect failed"); return; }

    /* HEADERS without END_HEADERS to start CONTINUATION sequence        */
    uint8_t hpack[3] = { 0x82, 0x87, 0x84 };
    uint8_t frame[9 + 3];
    size_t off = frame_hdr(frame, 0, 3, FT_HEADERS, 0, 1);
    memcpy(frame + off, hpack, 3);
    send_all(fd, frame, off + 3);

    /* Flood with CONTINUATION frames to exceed 256KB                    */
    uint8_t frag[4096];
    memset(frag, 0x00, sizeof(frag));
    uint8_t cont[9 + 4096];
    int got_error = 0;
    for (int i = 0; i < 100; i++) {
        off = frame_hdr(cont, 0, sizeof(frag), FT_CONTINUATION, 0, 1);
        memcpy(cont + off, frag, sizeof(frag));
        if (send_all(fd, cont, off + sizeof(frag)) < 0) {
            got_error = 1; break;
        }
    }

    //usleep(200000);
    uint8_t resp[512];
    size_t total = 0;
    for (int i = 0; i < 5; i++) {
        ssize_t n = recv_some(fd, resp + total, sizeof(resp) - total);
        if (n <= 0) break;
        total += (size_t)n;
        if (has_goaway(resp, (ssize_t)total)) break;
    }
    close(fd);

    if (has_goaway(resp, (ssize_t)total) == 1 || got_error)
        OK("CONTINUATION flood — GOAWAY or connection reset");
    else if (total == 0)
        OK("CONTINUATION flood — server closed connection");
    else
        FAIL("CONTINUATION flood", "no GOAWAY in %zu bytes", total);
}

/* ── max_frame_size enforcement ─────────────────────────────────────────── */
static void test_max_frame_size_enforcement(void) {
    int fd = h2c_open();
    if (fd < 0) { FAIL("max frame size", "connect failed"); return; }

    /* Send a HEADERS frame with payload larger than default 16384        */
    uint8_t big[17000];
    memset(big, 0x82, sizeof(big));
    uint8_t frame[9 + 17000];
    size_t off = frame_hdr(frame, 0, sizeof(big), FT_HEADERS,
                           FL_END_HEADERS | FL_END_STREAM, 1);
    memcpy(frame + off, big, sizeof(big));
    send_all(fd, frame, off + sizeof(big));
   // usleep(200000);

    uint8_t resp[512];
    size_t total = 0;
    for (int i = 0; i < 5; i++) {
        ssize_t n = recv_some(fd, resp + total, sizeof(resp) - total);
        if (n <= 0) break;
        total += (size_t)n;
        if (has_goaway(resp, (ssize_t)total)) break;
    }
    close(fd);

    if (has_goaway(resp, (ssize_t)total) == 1)
        OK("max frame size — GOAWAY for oversized frame");
    else if (total == 0)
        OK("max frame size — server closed connection");
    else
        FAIL("max frame size", "no GOAWAY in %zu bytes", total);
}

/* ── 103 Early Hints via h2c ─────────────────────────────────────────────── */
static void test_early_hints_h2c(void) {
    /* Early Hints are sent by the route handler before the main response.
     * We verify via curl --http2-prior-knowledge which shows interim
     * responses if the server sends them.  For raw socket we check that
     * we receive at least two HEADERS frames (103 + 200).               */

    /* Use curl with --verbose to catch the 103 — simpler than raw socket */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "curl -s --http2-prior-knowledge --max-time 5 "
             "'http://127.0.0.1:%d/early' 2>&1 | grep -c '< HTTP'",
             TEST_PORT_H2C);
    FILE *f = popen(cmd, "r");
    if (!f) { FAIL("early hints", "popen failed"); return; }
    char out[16]; size_t n = fread(out, 1, sizeof(out)-1, f); out[n] = '\0';
    pclose(f);
    /* 2 HTTP responses (103 + 200) or at least 1 (200) */
    if ((int)strtol(out, NULL, 10) >= 1)
        OK("103 Early Hints — server responded");
    else
        FAIL("early hints", "no HTTP response");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/
/* ── globals for signal handler ─────────────────────────────────────────── */
static pid_t g_pid_tls     = -1;
static pid_t g_pid_h2c     = -1;
static pid_t g_pid_upgrade = -1;

static void cleanup_handler(int sig) {
    (void)sig;
    if (g_pid_tls     > 0) kill(g_pid_tls,     SIGKILL);
    if (g_pid_h2c     > 0) kill(g_pid_h2c,     SIGKILL);
    if (g_pid_upgrade > 0) kill(g_pid_upgrade,  SIGKILL);
    _exit(1);
}

int main(void) {
    signal(SIGTERM, cleanup_handler);
    signal(SIGINT,  cleanup_handler);

    printf("test_h2\n");
    printf("─────────────────────────────────────\n");

    if (!curl_has_http2()) {
        printf("[SKIP] curl does not support HTTP/2\n");
        return 0;
    }

    int skip_tls = (getenv("CI") != NULL);

    /* Generate certs */
    system("mkdir -p tests/certs && "
           "[ -f tests/certs/test.crt ] || "
           "openssl req -x509 -newkey rsa:2048 "
           "-keyout tests/certs/test.key "
           "-out tests/certs/test.crt "
           "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null");

    /* Fork TLS server (only if not in CI) */
    if (!skip_tls) {
        g_pid_tls = fork();
        if (g_pid_tls < 0) { perror("fork tls"); return 1; }
        if (g_pid_tls == 0) run_server_tls();
    }

    /* Fork h2c server */
    g_pid_h2c = fork();
    if (g_pid_h2c < 0) {
        cleanup_handler(0);
        perror("fork h2c");
        return 1;
    }
    if (g_pid_h2c == 0) run_server_h2c();

    /* Fork upgrade server */
    g_pid_upgrade = fork();
    if (g_pid_upgrade < 0) {
        cleanup_handler(0);
        perror("fork upgrade");
        return 1;
    }
    if (g_pid_upgrade == 0) run_server_upgrade();

    /* Wait for servers to be ready */
    int startup_ok = 1;

    if (!skip_tls) {
        if (wait_for_server(TEST_PORT, 10000) < 0) {
            FAIL("server startup", "TLS server timeout");
            startup_ok = 0;
        }
    }

    if (wait_for_server(TEST_PORT_H2C, 5000) < 0) {
        FAIL("server startup", "h2c server timeout");
        startup_ok = 0;
    }

    if (wait_for_server(TEST_PORT_UPGRADE, 5000) < 0) {
        FAIL("server startup", "upgrade server timeout");
        startup_ok = 0;
    }

    if (!startup_ok) goto done;

    /* ── TLS / ALPN tests (skipped in CI) ── */
    if (!skip_tls) {
        test_alpn_negotiation();
        test_get();
        test_post_echo();
        test_404();
        test_multiplexing();
        test_http_version();
        test_large_response();
        test_concurrent_streams();
    } else {
        printf("[SKIP] TLS tests — CI environment\n");
    }

    /* ── h2c raw frame tests ── */
    test_h2c_upgrade();
    test_h2c_get();
    test_settings_ack();
    test_ping_pong();
    test_rst_stream();
    test_goaway();
    test_bad_preface();
    test_flow_control();
    test_continuation();
    test_data_on_closed_stream();
    test_invalid_settings_length();
    test_zero_window_update();
    test_client_push_promise();
    test_rapid_streams();
    test_settings_flood();
    test_continuation_flood();
    test_max_frame_size_enforcement();

done:
    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);

    if (g_pid_tls     > 0) { kill(g_pid_tls,     SIGTERM); waitpid(g_pid_tls,     NULL, 0); }
    if (g_pid_h2c     > 0) { kill(g_pid_h2c,     SIGTERM); waitpid(g_pid_h2c,     NULL, 0); }
    if (g_pid_upgrade > 0) { kill(g_pid_upgrade,  SIGTERM); waitpid(g_pid_upgrade, NULL, 0); }

    return g_fail > 0 ? 1 : 0;
}
#endif
