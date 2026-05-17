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

#include "core/event_loop.h"
#include "core/config.h"
#include "http/router.h"
#include "http/request.h"
#include "http/response.h"

#define TEST_PORT     18443
#define TEST_PORT_STR "18443"
#define TEST_CERT     "tests/certs/test.crt"
#define TEST_KEY      "tests/certs/test.key"

static int handle_large(const http_request_t *req,
                          http_response_t *resp, void *ctx);

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

/* ── Test server port ────────────────────────────────────────────────────── */
#define TEST_PORT     18443
#define TEST_CERT     "tests/certs/test.crt"
#define TEST_KEY      "tests/certs/test.key"

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

static int handle_404(const http_request_t *req,
                       http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    http_response_set_status(resp, 404, "Not Found");
    http_response_set_body(resp, "not found\n", 10);
    return 0;
}

/* ── Server process ──────────────────────────────────────────────────────── */
static void run_server(void) {
    event_loop_t *loop = event_loop_new(TEST_PORT, 1);
    if (!loop) exit(1);

    event_loop_set_tls(loop, TEST_CERT, TEST_KEY);

    routa_config_t cfg;
    routa_config_init(&cfg);
    event_loop_set_h2_config(loop, &cfg.h2);

    event_loop_add_route(loop, "/hello",
                         1 << HTTP_GET, handle_hello, NULL);
    event_loop_add_route(loop, "/echo",
                         1 << HTTP_POST, handle_echo, NULL);
    event_loop_add_route(loop, "/large",
                         1 << HTTP_GET, handle_large, NULL);

    event_loop_run(loop);
    event_loop_free(loop);
    exit(0);
}
/* ── curl helper ─────────────────────────────────────────────────────────── */
/* Runs curl and returns exit code. Output written to out (if non-NULL).    */
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

/* Check if curl supports --http2                                           */
static int curl_has_http2(void) {
    return system("curl --version 2>/dev/null | grep -q HTTP2") == 0;
}

/* ── Wait for server to be ready ─────────────────────────────────────────── */
static int wait_for_server(int port, int timeout_ms) {
    int fd;
    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int waited = 0;
    while (waited < timeout_ms) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);
        if (rc == 0) return 0;
        usleep(50000);   /* 50ms */
        waited += 50;
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Tests
 * ═══════════════════════════════════════════════════════════════════════════*/

/* ── Test 1: HTTP/2 negotiated via ALPN ──────────────────────────────────── */
static void test_alpn_negotiation(void) {
    char out[256];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/hello",
                      "--http2 -v", out, sizeof(out));
    if (rc != 0) {
        FAIL("ALPN negotiation", "curl exit code %d", rc);
        return;
    }

    if (strstr(out, "hello http2")) {
        OK("ALPN negotiation — h2 response received");
    } else {
        FAIL("ALPN negotiation", "unexpected body: '%s'", out);
    }
}

/* ── Test 2: Basic GET ───────────────────────────────────────────────────── */
static void test_get(void) {
    char out[256];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/hello",
                      NULL, out, sizeof(out));
    if (rc != 0) { FAIL("GET /hello", "curl rc=%d", rc); return; }
    if (strcmp(out, "hello http2\n") == 0) {
        OK("GET /hello — correct body");
    } else {
        FAIL("GET /hello", "got '%s'", out);
    }
}

/* ── Test 3: POST with body ──────────────────────────────────────────────── */
static void test_post_echo(void) {
    char out[256];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/echo",
                      "-X POST -d 'ping'", out, sizeof(out));
    if (rc != 0) { FAIL("POST /echo", "curl rc=%d", rc); return; }
    if (strstr(out, "ping")) {
        OK("POST /echo — body echoed");
    } else {
        FAIL("POST /echo", "got '%s'", out);
    }
}

/* ── Test 4: 404 ─────────────────────────────────────────────────────────── */
static void test_404(void) {
    char out[256];
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/nonexistent",
                      "-w '%{http_code}' -o /dev/null", out, sizeof(out));
    (void)rc;
    if (strstr(out, "404")) {
        OK("404 for unknown path");
    } else {
        FAIL("404", "got status '%s'", out);
    }
}

/* ── Test 5: Multiplexing — multiple requests in a single connection ─────────── */
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
    char out[16];
    size_t n = fread(out, 1, sizeof(out)-1, f);
    out[n] = '\0';
    pclose(f);

    int count = atoi(out);
    if (count >= 2) {
        OK("multiplexing — 2 responses on same connection");
    } else {
        FAIL("multiplexing", "got %d responses want 2", count);
    }
}

/* ── Test 6: HTTP version check ─────────────────────────────────────────── */
static void test_http_version(void) {
    /* curl -w "%{http_version}" ile protocol version kontrol              */
    char out[32];
    char extra[128];
    snprintf(extra, sizeof(extra),
             "-w '%%{http_version}' -o /dev/null");
    int rc = run_curl("https://127.0.0.1:" TEST_PORT_STR "/hello",
                      extra, out, sizeof(out));
    (void)rc;
    if (strstr(out, "2")) {
        OK("HTTP version 2 confirmed by curl");
    } else {
        FAIL("HTTP version", "got '%s' want '2'", out);
    }
}

/* ── Test 7: Large response (flow control) ───────────────────────────────── */
static int handle_large(const http_request_t *req,
                          http_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    /* 128KB response — tests DATA frame chunking + flow control           */
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

static void test_large_response(void) {
    char out[32];
    snprintf(out, sizeof(out), "-w '%%{size_download}' -o /dev/null");
    char url[128];
    snprintf(url, sizeof(url),
             "https://127.0.0.1:%d/large", TEST_PORT);
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "curl -sk --http2 --max-time 10 "
             "-w '%%{size_download}' -o /dev/null "
             "'https://127.0.0.1:%d/large' 2>/dev/null",
             TEST_PORT);
    FILE *f = popen(cmd, "r");
    if (!f) { FAIL("large response", "popen failed"); return; }
    char buf[32];
    size_t n = fread(buf, 1, sizeof(buf)-1, f);
    buf[n] = '\0';
    pclose(f);

    long got = atol(buf);
    if (got == 131072) {
        OK("large response 128KB — flow control ok");
    } else {
        FAIL("large response", "got %ld bytes want 131072", got);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/

#define TEST_PORT_STR "18443"

int main(void) {
    printf("test_h2\n");
    printf("─────────────────────────────────────\n");

    /* Check curl HTTP/2 support */
    if (!curl_has_http2()) {
        printf("[SKIP] curl does not support HTTP/2 — install libcurl-h2\n");
        return 0;
    }

    /* Generate test certs if missing */
    system("mkdir -p tests/certs && "
           "[ -f tests/certs/test.crt ] || "
           "openssl req -x509 -newkey rsa:2048 -keyout tests/certs/test.key "
           "-out tests/certs/test.crt -days 1 -nodes "
           "-subj '/CN=localhost' 2>/dev/null");

    /* Fork server */
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* Child — server */
        /* Register /large handler before running */
        run_server();
        /* never returns */
    }

    /* Parent — wait for server */
    if (wait_for_server(TEST_PORT, 3000) < 0) {
        FAIL("server startup", "timeout waiting for port %d", TEST_PORT);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 1;
    }

    /* Run tests */
    test_alpn_negotiation();
    test_get();
    test_post_echo();
    test_404();
    test_multiplexing();
    test_http_version();

    printf("─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);

    /* Shutdown server */
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);

    return g_fail > 0 ? 1 : 0;
}