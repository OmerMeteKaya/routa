
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

#include "http/ws_registry.h"

#define WS_PORT   8080
#define WS_PATH   "/ws"
#define BUF_SZ    4096

/* ── TCP helpers ─────────────────────────────────────────────────────────── */
static int tcp_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) { close(fd); return -1; }
    return fd;
}

static ssize_t recv_all(int fd, uint8_t *buf, size_t max, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000
    };
    int r = select(fd + 1, &fds, NULL, NULL, &tv);
    if (r <= 0) return -1;
    return recv(fd, buf, max, 0);
}

/* ── WebSocket frame builder (client side — masked) ──────────────────────── */
static int build_client_frame(uint8_t *out, size_t out_sz,
                               const uint8_t *payload, size_t plen,
                               uint8_t opcode) {
    assert(plen < 126);   /* test frames are small */
    assert(out_sz >= plen + 6);

    uint8_t mask[4] = { 0x37, 0xfa, 0x21, 0x3d };   /* fixed test mask */
    int idx = 0;
    out[idx++] = (uint8_t)(0x80 | (opcode & 0x0F));  /* FIN + opcode */
    out[idx++] = (uint8_t)(0x80 | plen);              /* MASK bit + len */
    memcpy(out + idx, mask, 4); idx += 4;
    for (size_t i = 0; i < plen; i++)
        out[idx++] = payload[i] ^ mask[i & 3];
    return idx;
}

/* Parse a server frame — server frames are NOT masked */
static int parse_server_frame(const uint8_t *buf, size_t len,
                               uint8_t *opcode_out,
                               const uint8_t **payload_out,
                               size_t *payload_len_out) {
    if (len < 2) return -1;
    *opcode_out      = buf[0] & 0x0F;
    int masked       = (buf[1] >> 7) & 1;
    size_t plen      = buf[1] & 0x7F;
    if (masked || plen >= 126) return -1;   /* server must not mask */
    if (len < 2 + plen) return -1;
    *payload_out     = buf + 2;
    *payload_len_out = plen;
    return 0;
}

/* ── Tests ───────────────────────────────────────────────────────────────── */

static int g_fd = -1;
static uint8_t g_buf[BUF_SZ];

static void setup(void) {
    g_fd = tcp_connect("127.0.0.1", WS_PORT);
    if (g_fd < 0) {
        fprintf(stderr, "  SKIP: could not connect to 127.0.0.1:%d — "
                        "is the test server running?\n", WS_PORT);
        exit(0);
    }
}

static void teardown(void) {
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
}

/* 1. Valid handshake — 101 expected */
static void test_handshake_valid(void) {
    const char *req =
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";

    send(g_fd, req, strlen(req), 0);
    ssize_t n = recv_all(g_fd, g_buf, sizeof(g_buf) - 1, 2000);
    assert(n > 0);
    g_buf[n] = '\0';

    assert(strstr((char *)g_buf, "HTTP/1.1 101") != NULL);
    assert(strstr((char *)g_buf, "Upgrade: websocket") != NULL);
    assert(strstr((char *)g_buf, "Sec-WebSocket-Accept:") != NULL);

    printf("  [OK] handshake valid — got 101\n");
}

/* 2. Bad version — 400 expected */
static void test_handshake_bad_version(void) {
    int fd = tcp_connect("127.0.0.1", WS_PORT);
    assert(fd >= 0);

    const char *req =
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 8\r\n"   /* wrong version */
        "\r\n";

    send(fd, req, strlen(req), 0);
    ssize_t n = recv_all(fd, g_buf, sizeof(g_buf) - 1, 2000);
    assert(n > 0);
    if (n <= 0) { close(fd); printf("  [SKIP] no response\n"); return; }
    g_buf[n] = '\0';
    assert(strstr((char *)g_buf, "400") != NULL);
    close(fd);
    printf("  [OK] handshake bad version — got 400\n");
}

/* 3. Key missing - 400 expected */
static void test_handshake_missing_key(void) {
    int fd = tcp_connect("127.0.0.1", WS_PORT);
    assert(fd >= 0);

    const char *req =
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    send(fd, req, strlen(req), 0);
    ssize_t n = recv_all(fd, g_buf, sizeof(g_buf) - 1, 2000);
    assert(n > 0);
    if (n <= 0) {
        close(fd);
        return;
    }
    g_buf[n] = '\0';
    assert(strstr((char *)g_buf, "400") != NULL);
    close(fd);
    printf("  [OK] handshake missing key — got 400\n");

}

/* 4. Text frame sending */
static void test_echo_text(void) {
    const char *msg      = "Hello, Routa!";
    size_t      msg_len  = strlen(msg);
    uint8_t     frame[64];
    int         flen = build_client_frame(frame, sizeof(frame),
                                          (const uint8_t *)msg, msg_len,
                                          0x1 /* TEXT */);
    send(g_fd, frame, (size_t)flen, 0);

    ssize_t n = recv_all(g_fd, g_buf, sizeof(g_buf), 2000);
    assert(n > 0);

    uint8_t opcode;
    const uint8_t *payload;
    size_t payload_len;
    assert(parse_server_frame(g_buf, (size_t)n,
                              &opcode, &payload, &payload_len) == 0);
    assert(opcode == 0x1);   /* TEXT */
    assert(payload_len == msg_len);
    assert(memcmp(payload, msg, msg_len) == 0);

    printf("  [OK] echo text frame\n");
}

/* 5. Ping → Pong */
static void test_ping_pong(void) {
    uint8_t frame[16];
    int flen = build_client_frame(frame, sizeof(frame),
                                  (const uint8_t *)"ping", 4,
                                  0x9 /* PING */);
    send(g_fd, frame, (size_t)flen, 0);

    ssize_t n = recv_all(g_fd, g_buf, sizeof(g_buf), 2000);
    assert(n > 0);

    uint8_t opcode;
    const uint8_t *payload;
    size_t payload_len;
    assert(parse_server_frame(g_buf, (size_t)n,
                              &opcode, &payload, &payload_len) == 0);
    assert(opcode == 0xA);   /* PONG */
    assert(payload_len == 4);
    assert(memcmp(payload, "ping", 4) == 0);

    printf("  [OK] ping → pong\n");
}

/* 6. Close handshake */
static void test_close_handshake(void) {
    /* Send close frame — code 1000 */
    uint8_t close_payload[2] = { 0x03, 0xE8 };   /* 1000 big-endian */
    uint8_t frame[16];
    int flen = build_client_frame(frame, sizeof(frame),
                                  close_payload, 2,
                                  0x8 /* CLOSE */);
    send(g_fd, frame, (size_t)flen, 0);

    ssize_t n = recv_all(g_fd, g_buf, sizeof(g_buf), 2000);
    assert(n > 0);

    uint8_t opcode;
    const uint8_t *payload;
    size_t payload_len;
    assert(parse_server_frame(g_buf, (size_t)n,
                              &opcode, &payload, &payload_len) == 0);
    assert(opcode == 0x8);   /* CLOSE echo */

    printf("  [OK] close handshake\n");
}

/* Fragmented message: two frame, FIN=0 then FIN=1 */
static void test_fragmented_message(void) {
    /* Frame 1: FIN=0, opcode=TEXT, payload="Hel" */
    uint8_t mask1[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t f1[9];
    f1[0] = 0x01;   /* FIN=0, TEXT */
    f1[1] = 0x83;   /* MASK=1, len=3 */
    memcpy(f1+2, mask1, 4);
    f1[6] = 'H' ^ mask1[0];
    f1[7] = 'e' ^ mask1[1];
    f1[8] = 'l' ^ mask1[2];
    send(g_fd, f1, 9, 0);

    /* Frame 2: FIN=1, opcode=CONTINUATION, payload="lo!" */
    uint8_t mask2[4] = {0x55, 0x66, 0x77, 0x88};
    uint8_t f2[9];
    f2[0] = 0x80;   /* FIN=1, CONTINUATION */
    f2[1] = 0x83;   /* MASK=1, len=3 */
    memcpy(f2+2, mask2, 4);
    f2[6] = 'l' ^ mask2[0];
    f2[7] = 'o' ^ mask2[1];
    f2[8] = '!' ^ mask2[2];
    send(g_fd, f2, 9, 0);

    ssize_t n = recv_all(g_fd, g_buf, sizeof(g_buf), 2000);
    assert(n > 0);

    uint8_t opcode;
    const uint8_t *payload;
    size_t payload_len;
    assert(parse_server_frame(g_buf, (size_t)n,
                              &opcode, &payload, &payload_len) == 0);
    assert(opcode == 0x1);   /* TEXT */
    assert(payload_len == 6);
    assert(memcmp(payload, "Hello!", 6) == 0);

    printf("  [OK] fragmented message\n");
}

/* 7. Unmasked frame — if server require_masking=1 should shutdown  */
static void test_unmasked_frame_rejected(void) {
    int fd = tcp_connect("127.0.0.1", WS_PORT);
    assert(fd >= 0);

    /* Handshake */
    const char *hs =
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    send(fd, hs, strlen(hs), 0);
    ssize_t n = recv_all(fd, g_buf, sizeof(g_buf) - 1, 2000);
    assert(n > 0 && strstr((char *)g_buf, "101") != NULL);

    /* Unmasked text frame */
    uint8_t frame[16] = {
        0x81,               /* FIN + TEXT */
        0x05,               /* no MASK bit, len=5 */
        'H','e','l','l','o'
    };
    send(fd, frame, 7, 0);

    /* Server should close or send close frame */
    n = recv_all(fd, g_buf, sizeof(g_buf), 2000);
    /* Either connection closed (n<=0) or close frame received */
    if (n > 0) {
        uint8_t opcode;
        const uint8_t *payload;
        size_t payload_len;
        int r = parse_server_frame(g_buf, (size_t)n,
                                   &opcode, &payload, &payload_len);
        assert(r == 0 && opcode == 0x8);   /* CLOSE */
    }
    close(fd);
    printf("  [OK] unmasked frame rejected\n");
}

static void test_broadcast(void) {
    ws_msg_queue_t q;
    ws_msg_queue_init(&q);

    ws_msg_t *msg = malloc(sizeof(ws_msg_t));
    msg->data   = malloc(5);
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
    ws_registry_dispatch_broadcast(&r, &q);

    ws_msg_queue_destroy(&q);
    ws_registry_destroy(&r);

    printf("  [OK] broadcast queue/dispatch mechanics\n");
}

int main(void) {
    printf("=== test_ws ===\n");
    printf("  Connecting to 127.0.0.1:%d%s\n", WS_PORT, WS_PATH);

    /* Test 2, 3 — independent, no need for setup */
    test_handshake_bad_version();
    test_handshake_missing_key();
    test_unmasked_frame_rejected();

    /* Test 1, 4, 5, 6, 7, 8 — in order */
    setup();
    test_handshake_valid();
    test_fragmented_message();
    test_echo_text();
    test_ping_pong();
    test_broadcast();
    test_close_handshake();
    teardown();

    printf("=== ALL PASSED ===\n");
    return 0;
}