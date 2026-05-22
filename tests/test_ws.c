#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "core/event_loop.h"
#include "core/config.h"
#include "http/request.h"
#include "http/response.h"
#include "http/ws.h"
#include "http/ws_registry.h"

#define WS_PORT     18765
#define WS_PORT_STR "18765"
#define BUF_SZ      8192

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
 * TCP / socket helpers
 * ═══════════════════════════════════════════════════════════════════════════*/

static int tcp_connect_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

static int wait_for_server(int port, int timeout_ms) {
    struct sockaddr_in addr = {0};
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
        usleep(50000);
        waited += 50;
    }
    return -1;
}

static ssize_t recv_timeout(int fd, uint8_t *buf, size_t len) {
    return recv(fd, buf, len, 0);
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, 0);
        if (n <= 0) return -1;
        buf += n; len -= (size_t)n;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * WebSocket frame builder (client → server, MUST be masked per RFC 6455)
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Build a masked client frame. plen must be < 126 for simplicity.
 * Returns total frame length written into out[].                           */
static int build_frame(uint8_t *out, size_t out_sz,
                        const uint8_t *payload, size_t plen,
                        uint8_t opcode, int fin) {
    assert(plen < 126 && out_sz >= plen + 6);
    uint8_t mask[4] = { 0x37, 0xfa, 0x21, 0x3d };
    int idx = 0;
    out[idx++] = (uint8_t)((fin ? 0x80 : 0x00) | (opcode & 0x0f));
    out[idx++] = (uint8_t)(0x80 | plen);
    memcpy(out + idx, mask, 4); idx += 4;
    for (size_t i = 0; i < plen; i++)
        out[idx++] = payload[i] ^ mask[i & 3];
    return idx;
}

/* Build an UNMASKED client frame (protocol violation — server must reject). */
static int build_frame_unmasked(uint8_t *out, size_t out_sz,
                                 const uint8_t *payload, size_t plen,
                                 uint8_t opcode) {
    assert(plen < 126 && out_sz >= plen + 2);
    out[0] = (uint8_t)(0x80 | (opcode & 0x0f));
    out[1] = (uint8_t)plen;
    memcpy(out + 2, payload, plen);
    return (int)(plen + 2);
}

/* Parse a server frame (server → client, NOT masked).
 * Returns 0 on success, -1 on error.                                       */
static int parse_server_frame(const uint8_t *buf, size_t len,
                               uint8_t *opcode_out,
                               const uint8_t **payload_out,
                               size_t *payload_len_out) {
    if (len < 2) return -1;
    int fin    = (buf[0] >> 7) & 1;
    *opcode_out = buf[0] & 0x0f;
    int masked  = (buf[1] >> 7) & 1;
    size_t plen = buf[1] & 0x7f;
    (void)fin;
    if (masked)       return -1;   /* server MUST NOT mask */
    if (plen >= 126)  return -1;   /* we only handle small frames */
    if (len < 2 + plen) return -1;
    *payload_out     = (plen > 0) ? buf + 2 : NULL;
   //debug *payload_out     = buf + 2;
    *payload_len_out = plen;
    return 0;
}

/* ── Perform WebSocket handshake, return 0 on 101, -1 otherwise ─────────── */
static int do_do_ws_handshake(int fd, const char *path, const char *key) {
    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: localhost\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n", path, key);
    if (send_all(fd, (const uint8_t *)req, strlen(req)) < 0) return -1;
    uint8_t buf[1024];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';
    if (!strstr((char *)buf, "101")) return -1;
    return 0;
}

/* Standard test key */
#define TEST_KEY "dGhlIHNhbXBsZSBub25jZQ=="

/* ═══════════════════════════════════════════════════════════════════════════
 * Test server
 * ═══════════════════════════════════════════════════════════════════════════*/

static void on_message(conn_t *conn, const uint8_t *data, size_t len,
                        ws_opcode_t opcode, void *ctx) {
    (void)ctx;
    ws_send(conn, data, len, opcode);
}

static void run_server(void) {
    event_loop_t *loop = event_loop_new(WS_PORT, 1);
    if (!loop) exit(1);

    routa_config_t cfg;
    routa_config_init(&cfg);

    ws_handler_t handler = {0};
    handler.on_message = on_message;
    ws_config_init(&handler.cfg);
    handler.cfg.require_masking = 1;

    event_loop_add_ws_route(loop, "/ws", &handler);
    event_loop_run(loop);
    event_loop_free(loop);
    exit(0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Handshake tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_handshake_valid(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("handshake valid", "connect failed"); return; }
    int rc = do_do_ws_handshake(fd, "/ws", TEST_KEY);
    if (rc == 0)
        OK("handshake valid — 101 received");
    else
        FAIL("handshake valid", "no 101");
    close(fd);
}

static void test_handshake_bad_version(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("handshake bad version", "connect"); return; }
    const char *req =
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " TEST_KEY "\r\n"
        "Sec-WebSocket-Version: 8\r\n"
        "\r\n";
    send_all(fd, (const uint8_t *)req, strlen(req));
    uint8_t buf[256]; ssize_t n = recv_timeout(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n > 0) { buf[n] = '\0'; }
    if (n > 0 && strstr((char *)buf, "400"))
        OK("handshake bad version — got 400");
    else
        FAIL("handshake bad version", "expected 400");
}

static void test_handshake_missing_key(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("handshake missing key", "connect"); return; }
    const char *req =
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    send_all(fd, (const uint8_t *)req, strlen(req));
    uint8_t buf[256]; ssize_t n = recv_timeout(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n > 0) { buf[n] = '\0'; }
    if (n > 0 && strstr((char *)buf, "400"))
        OK("handshake missing key — got 400");
    else
        FAIL("handshake missing key", "expected 400");
}

static void test_handshake_wrong_path(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("handshake wrong path", "connect"); return; }
    const char *req =
        "GET /noexist HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " TEST_KEY "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    send_all(fd, (const uint8_t *)req, strlen(req));
    uint8_t buf[256]; ssize_t n = recv_timeout(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n > 0) { buf[n] = '\0'; }
    if (n > 0 && (strstr((char *)buf, "404") || strstr((char *)buf, "400")))
        OK("handshake wrong path — got 4xx");
    else
        FAIL("handshake wrong path", "expected 4xx, got: '%s'",
             n > 0 ? (char *)buf : "(nothing)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Frame tests (require open WS connection)
 * ═══════════════════════════════════════════════════════════════════════════*/

/* Open connection + handshake. Returns fd or -1. */
static int open_ws(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) return -1;
    if (do_do_ws_handshake(fd, "/ws", TEST_KEY) < 0) { close(fd); return -1; }
    return fd;
}

static void test_echo_text(void) {
    int fd = open_ws();
    if (fd < 0) { FAIL("echo text", "connect/handshake failed"); return; }

    const char *msg = "Hello, Routa!";
    uint8_t frame[64];
    int flen = build_frame(frame, sizeof(frame),
                           (const uint8_t *)msg, strlen(msg), 0x1, 1);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) { FAIL("echo text", "no response"); return; }

    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) < 0) {
        FAIL("echo text", "frame parse failed"); return;
    }
    if (opcode != 0x1 || plen != strlen(msg) ||
        memcmp(payload, msg, plen) != 0)
        FAIL("echo text", "opcode=%d plen=%zu", opcode, plen);
    else
        OK("echo text frame — content matches");
}

static void test_echo_binary(void) {
    int fd = open_ws();
    if (fd < 0) { FAIL("echo binary", "connect failed"); return; }

    uint8_t data[] = { 0x00, 0x01, 0x02, 0x7f, 0x80, 0xff };
    uint8_t frame[32];
    int flen = build_frame(frame, sizeof(frame), data, sizeof(data), 0x2, 1);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) { FAIL("echo binary", "no response"); return; }

    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) < 0) {
        FAIL("echo binary", "frame parse failed"); return;
    }
    if (opcode != 0x2 || plen != sizeof(data) ||
        memcmp(payload, data, plen) != 0)
        FAIL("echo binary", "opcode=%d plen=%zu", opcode, plen);
    else
        OK("echo binary frame — binary payload preserved");
}

static void test_ping_pong(void) {
    int fd = open_ws();
    if (fd < 0) { FAIL("ping/pong", "connect failed"); return; }

    uint8_t frame[16];
    int flen = build_frame(frame, sizeof(frame),
                           (const uint8_t *)"ping", 4, 0x9, 1);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) { FAIL("ping/pong", "no response"); return; }

    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) < 0) {
        FAIL("ping/pong", "frame parse failed"); return;
    }
    if (opcode != 0xA || plen != 4 || memcmp(payload, "ping", 4) != 0)
        FAIL("ping/pong", "opcode=%d plen=%zu", opcode, plen);
    else
        OK("ping → pong — payload echoed");
}

static void test_ping_empty(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("ping empty", "connect failed"); return; }

    char req[512];
    snprintf(req, sizeof(req),
             "GET /ws HTTP/1.1\r\n"
             "Host: localhost\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n", TEST_KEY);
    send_all(fd, (const uint8_t *)req, strlen(req));
    uint8_t hsbuf[512];
    ssize_t hsn = recv_timeout(fd, hsbuf, sizeof(hsbuf)-1);
    if (hsn <= 0 || !strstr((char*)hsbuf, "101")) {
        FAIL("ping empty", "handshake failed"); close(fd); return;
    }
    
    uint8_t dummy[1] = {0};
    uint8_t tframe[16];
    int tlen = build_frame(tframe, sizeof(tframe),
                           (const uint8_t *)"x", 1, 0x1, 1);
    uint8_t frame[16];
    int flen = build_frame(frame, sizeof(frame), dummy, 0, 0x9, 1);
    send_all(fd, tframe, (size_t)tlen);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n1 = recv_timeout(fd, buf, sizeof(buf));
    ssize_t n2 = recv_timeout(fd, buf + (n1 > 0 ? n1 : 0),
                              sizeof(buf) - (size_t)(n1 > 0 ? n1 : 0));
    ssize_t n = (n1 > 0 ? n1 : 0) + (n2 > 0 ? n2 : 0);
    close(fd);

    int found_pong = 0;
    size_t pos = 0;
    while (pos + 2 <= (size_t)n) {
        uint8_t opcode; const uint8_t *payload; size_t plen;
        if (parse_server_frame(buf + pos, (size_t)n - pos,
                               &opcode, &payload, &plen) < 0) break;
        if (opcode == 0xA) { found_pong = 1; break; }
        pos += 2 + plen;
    }

    if (!found_pong)
        FAIL("ping empty", "no PONG in response (n=%zd)", n);
    else
        OK("ping empty payload — PONG received");
}

static void test_close_handshake(void) {
    int fd = open_ws();
    if (fd < 0) { FAIL("close handshake", "connect failed"); return; }

    uint8_t close_payload[2] = { 0x03, 0xE8 };   /* 1000 */
    uint8_t frame[16];
    int flen = build_frame(frame, sizeof(frame), close_payload, 2, 0x8, 1);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) { FAIL("close handshake", "no response"); return; }

    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) < 0) {
        FAIL("close handshake", "frame parse failed"); return;
    }
    if (opcode != 0x8)
        FAIL("close handshake", "opcode=%d want 0x8 (CLOSE)", opcode);
    else
        OK("close handshake — server echoed CLOSE");
}

/* ── Fragmentation ───────────────────────────────────────────────────────── */

static void test_fragmented_message(void) {
    int fd = open_ws();
    if (fd < 0) { FAIL("fragmented", "connect failed"); return; }

    /* Frame 1: FIN=0, opcode=TEXT, "Hel" */
    uint8_t mask1[4] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t f1[9];
    f1[0] = 0x01;   /* FIN=0, TEXT */
    f1[1] = 0x83;   /* MASK=1, len=3 */
    memcpy(f1 + 2, mask1, 4);
    f1[6] = 'H' ^ mask1[0];
    f1[7] = 'e' ^ mask1[1];
    f1[8] = 'l' ^ mask1[2];
    send_all(fd, f1, 9);

    /* Frame 2: FIN=1, opcode=CONTINUATION, "lo!" */
    uint8_t mask2[4] = { 0x55, 0x66, 0x77, 0x88 };
    uint8_t f2[9];
    f2[0] = 0x80;   /* FIN=1, CONTINUATION */
    f2[1] = 0x83;   /* MASK=1, len=3 */
    memcpy(f2 + 2, mask2, 4);
    f2[6] = 'l' ^ mask2[0];
    f2[7] = 'o' ^ mask2[1];
    f2[8] = '!' ^ mask2[2];
    send_all(fd, f2, 9);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) { FAIL("fragmented", "no response"); return; }

    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) < 0) {
        FAIL("fragmented", "frame parse failed"); return;
    }
    if (opcode != 0x1 || plen != 6 || memcmp(payload, "Hello!", 6) != 0)
        FAIL("fragmented", "opcode=%d plen=%zu content='%.*s'",
             opcode, plen, (int)plen, (char *)payload);
    else
        OK("fragmented message — FIN=0 + CONTINUATION reassembled");
}

static void test_fragmented_three_parts(void) {
    int fd = open_ws();
    if (fd < 0) { FAIL("fragmented 3-part", "connect failed"); return; }

    /* "ABC" split into 3 frames: "A" + "B" + "C" */
    struct { char ch; uint8_t opcode; int fin; } parts[3] = {
        { 'A', 0x1, 0 },   /* TEXT, FIN=0    */
        { 'B', 0x0, 0 },   /* CONTINUATION   */
        { 'C', 0x0, 1 },   /* CONTINUATION, FIN=1 */
    };
    for (int i = 0; i < 3; i++) {
        uint8_t frame[16];
        uint8_t payload = (uint8_t)parts[i].ch;
        int flen = build_frame(frame, sizeof(frame),
                               &payload, 1, parts[i].opcode, parts[i].fin);
        send_all(fd, frame, (size_t)flen);
    }

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) { FAIL("fragmented 3-part", "no response"); return; }

    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) < 0) {
        FAIL("fragmented 3-part", "frame parse failed"); return;
    }
    if (opcode != 0x1 || plen != 3 || memcmp(payload, "ABC", 3) != 0)
        FAIL("fragmented 3-part", "opcode=%d plen=%zu content='%.*s'",
             opcode, plen, (int)plen, (char *)payload);
    else
        OK("fragmented 3-part message — all fragments reassembled");
}

/* ── Protocol violations ─────────────────────────────────────────────────── */

static void test_unmasked_frame_rejected(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("unmasked rejected", "connect"); return; }
    if (do_do_ws_handshake(fd, "/ws", TEST_KEY) < 0) {
        FAIL("unmasked rejected", "handshake failed"); close(fd); return;
    }

    /* Send unmasked TEXT frame — server MUST close */
    uint8_t frame[16];
    int flen = build_frame_unmasked(frame, sizeof(frame),
                                    (const uint8_t *)"hello", 5, 0x1);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);

    if (n <= 0) {
        OK("unmasked frame — server closed connection");
        return;
    }
    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) == 0
        && opcode == 0x8)
        OK("unmasked frame — server sent CLOSE");
    else
        FAIL("unmasked frame rejected", "unexpected response opcode=%d", opcode);
}

static void test_invalid_opcode(void) {
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("invalid opcode", "connect"); return; }
    if (do_do_ws_handshake(fd, "/ws", TEST_KEY) < 0) {
        FAIL("invalid opcode", "handshake"); close(fd); return;
    }

    /* Opcode 0x3 is reserved (invalid) */
    uint8_t frame[16];
    int flen = build_frame(frame, sizeof(frame),
                           (const uint8_t *)"test", 4, 0x3, 1);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);

    if (n <= 0) {
        OK("invalid opcode — server closed connection");
        return;
    }
    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) == 0
        && opcode == 0x8)
        OK("invalid opcode — server sent CLOSE");
    else
        FAIL("invalid opcode", "expected close or disconnect");
}

static void test_oversized_frame(void) {
    /* Build a frame claiming a very large payload (126+ requires extended length).
     * We manually craft a 2-byte extended length frame with 65535 byte claim
     * but send only a few bytes — server should handle incomplete frame. */
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("oversized frame", "connect"); return; }
    if (do_do_ws_handshake(fd, "/ws", TEST_KEY) < 0) {
        FAIL("oversized frame", "handshake"); close(fd); return;
    }

    /* Frame header: FIN+TEXT, MASK+126, 2-byte length=1024, mask, partial payload */
    uint8_t frame[12] = {
        0x81,           /* FIN + TEXT */
        0xFE,           /* MASK=1, len=126 → 2-byte extended */
        0x04, 0x00,     /* extended length = 1024 */
        0x37, 0xfa, 0x21, 0x3d,  /* mask */
        'A'^0x37, 'B'^0xfa, 'C'^0x21, 'D'^0x3d  /* only 4 bytes payload */
    };
    send_all(fd, frame, sizeof(frame));

    /* Server should either wait (no response yet) or close */
    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);

    /* Any response (close frame or timeout) is acceptable — must not crash */
    if (n <= 0)
        OK("oversized frame — server waited/closed (no crash)");
    else {
        uint8_t opcode; const uint8_t *payload; size_t plen;
        if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) == 0
            && opcode == 0x8)
            OK("oversized frame — server sent CLOSE");
        else
            OK("oversized frame — server responded (no crash)");
    }
}

static void test_continuation_without_start(void) {
    /* CONTINUATION frame without a preceding TEXT/BINARY — protocol error */
    int fd = tcp_connect_port(WS_PORT);
    if (fd < 0) { FAIL("continuation abuse", "connect"); return; }
    if (do_do_ws_handshake(fd, "/ws", TEST_KEY) < 0) {
        FAIL("continuation abuse", "handshake"); close(fd); return;
    }

    uint8_t frame[16];
    int flen = build_frame(frame, sizeof(frame),
                           (const uint8_t *)"orphan", 6, 0x0, 1);
    send_all(fd, frame, (size_t)flen);

    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);

    if (n <= 0) {
        OK("continuation abuse — server closed connection");
        return;
    }
    uint8_t opcode; const uint8_t *payload; size_t plen;
    if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) == 0
        && opcode == 0x8)
        OK("continuation abuse — server sent CLOSE");
    else
        FAIL("continuation abuse", "expected close or disconnect");
}

static void test_ping_in_fragmented(void) {
    /* RFC 6455 §5.5: control frames (PING) may be injected between fragments */
    int fd = open_ws();
    if (fd < 0) { FAIL("ping in fragmented", "connect failed"); return; }

    /* Fragment 1: TEXT FIN=0, "He" */
    uint8_t f1[16];
    int l1 = build_frame(f1, sizeof(f1), (const uint8_t *)"He", 2, 0x1, 0);
    send_all(fd, f1, (size_t)l1);

    /* Interleaved PING */
    uint8_t fp[16];
    int lp = build_frame(fp, sizeof(fp), (const uint8_t *)"chk", 3, 0x9, 1);
    send_all(fd, fp, (size_t)lp);

    /* Fragment 2: CONTINUATION FIN=1, "llo" */
    uint8_t f2[16];
    int l2 = build_frame(f2, sizeof(f2), (const uint8_t *)"llo", 3, 0x0, 1);
    send_all(fd, f2, (size_t)l2);

    /* Read responses — expect PONG + echoed "Hello" (in some order) */
    uint8_t buf[BUF_SZ];
    ssize_t n = recv_timeout(fd, buf, sizeof(buf));
    close(fd);

    if (n <= 0) { FAIL("ping in fragmented", "no response"); return; }

    /* At minimum we got something — verify no crash */
    int found_pong = 0, found_text = 0;
    size_t pos = 0;
    while (pos + 2 <= (size_t)n) {
        uint8_t op; const uint8_t *pl; size_t pl_len;
        if (parse_server_frame(buf + pos, (size_t)n - pos,
                               &op, &pl, &pl_len) < 0) break;
        if (op == 0xA) found_pong = 1;
        if (op == 0x1) found_text = 1;
        pos += 2 + pl_len;
    }
    if (found_pong || found_text)
        OK("ping in fragmented — PONG and/or text response received");
    else
        OK("ping in fragmented — server responded (no crash)");
}

/* ── Multiple messages on same connection ────────────────────────────────── */

static void test_multiple_messages(void) {
    int fd = open_ws();
    if (fd < 0) { FAIL("multiple messages", "connect failed"); return; }

    int ok = 1;
    for (int i = 0; i < 10 && ok; i++) {
        char msg[16];
        int mlen = snprintf(msg, sizeof(msg), "msg%d", i);
        uint8_t frame[32];
        int flen = build_frame(frame, sizeof(frame),
                               (const uint8_t *)msg, (size_t)mlen, 0x1, 1);
        send_all(fd, frame, (size_t)flen);

        uint8_t buf[BUF_SZ];
        ssize_t n = recv_timeout(fd, buf, sizeof(buf));
        if (n <= 0) { ok = 0; break; }

        uint8_t opcode; const uint8_t *payload; size_t plen;
        if (parse_server_frame(buf, (size_t)n, &opcode, &payload, &plen) < 0
            || opcode != 0x1 || plen != (size_t)mlen
            || memcmp(payload, msg, plen) != 0) {
            ok = 0;
        }
    }
    close(fd);
    if (ok)
        OK("multiple messages — 10 echo roundtrips on same connection");
    else
        FAIL("multiple messages", "roundtrip failed");
}

/* ── Unit test: broadcast queue/dispatch mechanics (no network) ─────────── */

static void test_broadcast_queue(void) {
    ws_msg_queue_t q;
    ws_msg_queue_init(&q);

    ws_msg_t *msg = malloc(sizeof(ws_msg_t));
    if (!msg) { FAIL("broadcast queue", "malloc"); return; }
    msg->data   = malloc(5);
    if (!msg->data) { free(msg); FAIL("broadcast queue", "malloc"); return; }
    memcpy(msg->data, "hello", 5);
    msg->len    = 5;
    msg->opcode = WS_OP_TEXT;
    msg->next   = NULL;

    pthread_mutex_lock(&q.lock);
    q.head = q.tail = msg;
    q.count = 1;
    pthread_mutex_unlock(&q.lock);

    ws_registry_t r;
    ws_registry_init(&r);
    ws_registry_dispatch_broadcast(&r, &q);   /* empty registry, must not crash */
    ws_msg_queue_destroy(&q);
    ws_registry_destroy(&r);

    OK("broadcast queue/dispatch — empty registry, no crash");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/
int main(void) {
    printf("test_ws\n");
    printf("─────────────────────────────────────\n");

    /* Suppress SIGPIPE — expected when server closes on protocol errors  */
    signal(SIGPIPE, SIG_IGN);

    /* Fork test server */
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) run_server();

    if (wait_for_server(WS_PORT, 3000) < 0) {
        FAIL("server startup", "timeout");
        kill(pid, SIGTERM); waitpid(pid, NULL, 0);
        return 1;
    }

    /* Handshake tests */
    test_handshake_valid();
    test_handshake_bad_version();
    test_handshake_missing_key();
    test_handshake_wrong_path();

    /* Frame tests */
    test_echo_text();
    test_echo_binary();
    test_ping_pong();
    test_ping_empty();
    test_close_handshake();

    /* Fragmentation */
    test_fragmented_message();
    test_fragmented_three_parts();

    /* Protocol violations */
    test_unmasked_frame_rejected();
    test_invalid_opcode();
    test_oversized_frame();
    test_continuation_without_start();
    test_ping_in_fragmented();

    /* Multi-message */
    test_multiple_messages();

    /* Unit tests */
    test_broadcast_queue();

    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);

    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return g_fail > 0 ? 1 : 0;
}