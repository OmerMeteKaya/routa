#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "http/cookie.h"
#include "http/mw_auth.h"
#include "http/request.h"
#include "http/response.h"
#include "http/middleware.h"

/* ── Test harness ────────────────────────────────────────────────────────── */
static int g_pass = 0;
static int g_fail = 0;

#define OK(label)   do { printf("[OK] %s\n",   label); g_pass++; } while(0)
#define FAIL(label, ...) do { \
    printf("[FAIL] %s: ", label); \
    printf(__VA_ARGS__); printf("\n"); g_fail++; \
} while(0)

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static http_request_t *make_request(const char *method, const char *path) {
    http_request_t *req = calloc(1, sizeof(http_request_t));
    if (!req) return NULL;
    if      (strcmp(method, "GET")  == 0) req->method = HTTP_GET;
    else if (strcmp(method, "POST") == 0) req->method = HTTP_POST;
    req->path           = strdup(path);
    req->version_major  = 1;
    req->version_minor  = 1;
    req->keep_alive     = 1;
    return req;
}

static void request_add_header(http_request_t *req,
                                const char *key, const char *val) {
    if (req->header_count >= 64) return;
    req->headers[req->header_count].key   = strdup(key);
    req->headers[req->header_count].value = strdup(val);
    req->header_count++;
}

static void request_free(http_request_t *req) {
    if (!req) return;
    free(req->path);
    free(req->query);
    for (int i = 0; i < req->header_count; i++) {
        free(req->headers[i].key);
        free(req->headers[i].value);
    }
    free(req->body);
    free(req);
}

/* Base64 encode helper for building test tokens */
static void b64url_encode(const uint8_t *src, size_t len, char *out) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    while (i < len) {
        uint32_t v  = (uint32_t)src[i++] << 16;
        int      b2 = (i < len);
        int      b3 = 0;
        if (b2) v |= (uint32_t)src[i++] << 8;
        if (i < len) { v |= src[i++]; b3 = 1; }

        out[o++] = tbl[(v >> 18) & 0x3f];
        out[o++] = tbl[(v >> 12) & 0x3f];
        if (b2) out[o++] = tbl[(v >>  6) & 0x3f];
        if (b3) out[o++] = tbl[ v        & 0x3f];
    }
    out[o] = '\0';
    /* Convert to URL-safe */
    for (size_t j = 0; j < o; j++) {
        if      (out[j] == '+') out[j] = '-';
        else if (out[j] == '/') out[j] = '_';
    }
}

/* Build a minimal HS256 JWT for testing.
 * Uses the same HMAC logic as mw_auth.c — OpenSSL HMAC-SHA256.           */
#include <openssl/hmac.h>
#include <openssl/evp.h>

static void build_hs256_token(const char *secret, long long exp,
                               const char *iss, char *out, size_t cap) {

    /* Header */
    const char *hdr_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char hdr_b64[256];
    b64url_encode((const uint8_t *)hdr_json, strlen(hdr_json), hdr_b64);

    /* Payload */
    char pay_json[512];
    if (iss && iss[0])
        snprintf(pay_json, sizeof(pay_json),
                 "{\"sub\":\"testuser\",\"iss\":\"%s\",\"exp\":%lld}",
                 iss, exp);
    else
        snprintf(pay_json, sizeof(pay_json),
                 "{\"sub\":\"testuser\",\"exp\":%lld}", exp);

    char pay_b64[512];
    b64url_encode((const uint8_t *)pay_json, strlen(pay_json), pay_b64);

    /* header.payload */
    char hp[1024];
    snprintf(hp, sizeof(hp), "%s.%s", hdr_b64, pay_b64);

    /* HMAC-SHA256 signature */
    uint8_t      mac[32];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(),
         secret, (int)strlen(secret),
         (const unsigned char *)hp, strlen(hp),
         mac, &mac_len);

    char sig_b64[256];
    b64url_encode(mac, mac_len, sig_b64);
    snprintf(out, cap, "%s.%s", hp, sig_b64);
}

/* ── Middleware test shim ────────────────────────────────────────────────── */

typedef struct {
    int called;
} next_state_t;

static void test_next(middleware_chain_t *chain, const http_request_t *req,
                       http_response_t *resp, int current) {
    (void)chain; (void)req; (void)current;
    http_response_set_status(resp, 200, "OK");
    http_response_set_body(resp, "authorized\n", 11);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Cookie tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_cookie_parse_simple(void) {
    http_request_t *req = make_request("GET", "/");
    request_add_header(req, "cookie", "session=abc123; user=alice");

    cookie_jar_t *jar = cookie_jar_parse(req);
    if (!jar) { FAIL("cookie parse simple", "jar is NULL"); request_free(req); return; }

    const char *session = cookie_jar_get(jar, "session");
    const char *user    = cookie_jar_get(jar, "user");
    const char *missing = cookie_jar_get(jar, "notexist");

    if (session && strcmp(session, "abc123") == 0)
        OK("cookie parse — session=abc123");
    else
        FAIL("cookie parse session", "got '%s'", session ? session : "(null)");

    if (user && strcmp(user, "alice") == 0)
        OK("cookie parse — user=alice");
    else
        FAIL("cookie parse user", "got '%s'", user ? user : "(null)");

    if (!missing)
        OK("cookie parse — missing key returns NULL");
    else
        FAIL("cookie parse missing", "expected NULL got '%s'", missing);

    cookie_jar_free(jar);
    request_free(req);
}

static void test_cookie_parse_empty(void) {
    http_request_t *req = make_request("GET", "/");
    /* No cookie header */
    cookie_jar_t *jar = cookie_jar_parse(req);
    if (jar && jar->count == 0)
        OK("cookie parse — empty jar for no cookie header");
    else
        FAIL("cookie parse empty", "unexpected jar state");
    cookie_jar_free(jar);
    request_free(req);
}

static void test_cookie_parse_whitespace(void) {
    http_request_t *req = make_request("GET", "/");
    request_add_header(req, "cookie", "  a = 1 ;  b = 2 ");

    cookie_jar_t *jar = cookie_jar_parse(req);
    const char *a = cookie_jar_get(jar, "a");
    if (a && strcmp(a, "1") == 0)
        OK("cookie parse — whitespace trimmed in name");
    else
        FAIL("cookie parse whitespace", "a='%s'", a ? a : "(null)");
    cookie_jar_free(jar);
    request_free(req);
}

static void test_cookie_set_simple(void) {
    http_response_t resp;
    http_response_init(&resp);

    int rc = cookie_set_simple(&resp, "session", "tok123");
    if (rc != 0) { FAIL("cookie set simple", "returned %d", rc); goto done; }

    /* Find set-cookie header */
    int found = 0;
    for (int i = 0; i < resp.header_count; i++) {
        if (strcasecmp(resp.headers[i][0], "set-cookie") == 0) {
            if (strstr(resp.headers[i][1], "session=tok123") &&
                strstr(resp.headers[i][1], "HttpOnly"))
                found = 1;
        }
    }
    if (found)
        OK("cookie set simple — Set-Cookie header with HttpOnly");
    else
        FAIL("cookie set simple", "header not found or missing HttpOnly");

done:
    http_response_destroy(&resp);
}

static void test_cookie_set_full(void) {
    http_response_t resp;
    http_response_init(&resp);

    cookie_opts_t opts = {0};
    opts.name      = "prefs";
    opts.value     = "dark-mode";
    opts.path      = "/app";
    opts.domain    = "example.com";
    opts.max_age   = 3600;
    opts.secure    = 1;
    opts.http_only = 1;
    opts.same_site = "Strict";

    int rc = cookie_set(&resp, &opts);
    if (rc != 0) { FAIL("cookie set full", "returned %d", rc); goto done; }

    int found = 0;
    for (int i = 0; i < resp.header_count; i++) {
        if (strcasecmp(resp.headers[i][0], "set-cookie") == 0) {
            const char *v = resp.headers[i][1];
            if (strstr(v, "prefs=dark-mode") &&
                strstr(v, "Path=/app")       &&
                strstr(v, "Domain=example.com") &&
                strstr(v, "Max-Age=3600")    &&
                strstr(v, "SameSite=Strict") &&
                strstr(v, "Secure")          &&
                strstr(v, "HttpOnly"))
                found = 1;
        }
    }
    if (found)
        OK("cookie set full — all attributes present");
    else
        FAIL("cookie set full", "missing attributes in Set-Cookie");

done:
    http_response_destroy(&resp);
}

static void test_cookie_expire(void) {
    http_response_t resp;
    http_response_init(&resp);

    int rc = cookie_expire(&resp, "session", "/");
    if (rc != 0) { FAIL("cookie expire", "returned %d", rc); goto done; }

    int found = 0;
    for (int i = 0; i < resp.header_count; i++) {
        if (strcasecmp(resp.headers[i][0], "set-cookie") == 0) {
            if (strstr(resp.headers[i][1], "Max-Age=0"))
                found = 1;
        }
    }
    if (found)
        OK("cookie expire — Max-Age=0 present");
    else
        FAIL("cookie expire", "Max-Age=0 not found");

done:
    http_response_destroy(&resp);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Basic Auth tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_basic_auth_valid(void) {
    basic_auth_config_t *cfg = basic_auth_config_new("TestRealm");
    basic_auth_config_add_user(cfg, "alice", "secret123");

    http_request_t *req = make_request("GET", "/protected");
    /* "alice:secret123" in base64 = "YWxpY2U6c2VjcmV0MTIz" */
    request_add_header(req, "authorization", "Basic YWxpY2U6c2VjcmV0MTIz");

    http_response_t resp;
    http_response_init(&resp);
    middleware_chain_t *chain = middleware_chain_new();
    middleware_chain_set_handler(chain, NULL, NULL);

    mw_basic_auth(chain, req, &resp,
                  (next_fn_t)test_next, cfg, 0);

    if (resp.status == 200)
        OK("basic auth — valid credentials accepted");
    else
        FAIL("basic auth valid", "status=%d", resp.status);

    http_response_destroy(&resp);
    middleware_chain_free(chain);
    request_free(req);
    basic_auth_config_free(cfg);
}

static void test_basic_auth_invalid(void) {
    basic_auth_config_t *cfg = basic_auth_config_new("TestRealm");
    basic_auth_config_add_user(cfg, "alice", "secret123");

    http_request_t *req = make_request("GET", "/protected");
    /* "alice:wrongpassword" */
    request_add_header(req, "authorization", "Basic YWxpY2U6d3JvbmdwYXNzd29yZA==");

    http_response_t resp;
    http_response_init(&resp);
    middleware_chain_t *chain = middleware_chain_new();

    mw_basic_auth(chain, req, &resp,
                  (next_fn_t)test_next, cfg, 0);

    if (resp.status == 401)
        OK("basic auth — invalid credentials rejected (401)");
    else
        FAIL("basic auth invalid", "status=%d expected 401", resp.status);

    http_response_destroy(&resp);
    middleware_chain_free(chain);
    request_free(req);
    basic_auth_config_free(cfg);
}

static void test_basic_auth_missing_header(void) {
    basic_auth_config_t *cfg = basic_auth_config_new("TestRealm");
    basic_auth_config_add_user(cfg, "alice", "secret123");

    http_request_t *req = make_request("GET", "/protected");
    /* No Authorization header */

    http_response_t resp;
    http_response_init(&resp);
    middleware_chain_t *chain = middleware_chain_new();

    mw_basic_auth(chain, req, &resp,
                  (next_fn_t)test_next, cfg, 0);

    if (resp.status == 401)
        OK("basic auth — missing header returns 401");
    else
        FAIL("basic auth missing", "status=%d expected 401", resp.status);

    /* WWW-Authenticate header must be present */
    int has_www_auth = 0;
    for (int i = 0; i < resp.header_count; i++)
        if (strcasecmp(resp.headers[i][0], "www-authenticate") == 0)
            has_www_auth = 1;
    if (has_www_auth)
        OK("basic auth — WWW-Authenticate header present");
    else
        FAIL("basic auth WWW-Authenticate", "header missing");

    http_response_destroy(&resp);
    middleware_chain_free(chain);
    request_free(req);
    basic_auth_config_free(cfg);
}

static void test_basic_auth_multiple_users(void) {
    basic_auth_config_t *cfg = basic_auth_config_new("Multi");
    basic_auth_config_add_user(cfg, "alice", "pass1");
    basic_auth_config_add_user(cfg, "bob",   "pass2");
    basic_auth_config_add_user(cfg, "carol", "pass3");

    /* Test bob — "bob:pass2" = "Ym9iOnBhc3My" */
    http_request_t *req = make_request("GET", "/");
    request_add_header(req, "authorization", "Basic Ym9iOnBhc3My");

    http_response_t resp;
    http_response_init(&resp);
    middleware_chain_t *chain = middleware_chain_new();

    mw_basic_auth(chain, req, &resp,
                  (next_fn_t)test_next, cfg, 0);

    if (resp.status == 200)
        OK("basic auth — second user in list accepted");
    else
        FAIL("basic auth multi", "status=%d", resp.status);

    http_response_destroy(&resp);
    middleware_chain_free(chain);
    request_free(req);
    basic_auth_config_free(cfg);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * JWT tests
 * ═══════════════════════════════════════════════════════════════════════════*/

static void test_jwt_hs256_valid(void) {
    const char *secret = "supersecretkey";
    jwt_config_t *cfg  = jwt_config_new_hs256(secret);

    /* Build a valid token expiring far in future */
    char token[1024];
    build_hs256_token(secret, (long long)time(NULL) + 3600,
                      NULL, token, sizeof(token));

    jwt_claims_t *claims = jwt_verify(cfg, token);
    if (claims) {
        const char *sub = jwt_claims_get(claims, "sub");
        if (sub && strcmp(sub, "testuser") == 0)
            OK("JWT HS256 — valid token verified, sub claim correct");
        else
            FAIL("JWT HS256 sub", "sub='%s'", sub ? sub : "(null)");
        jwt_claims_free(claims);
    } else {
        FAIL("JWT HS256 valid", "verification returned NULL");
    }

    jwt_config_free(cfg);
}

static void test_jwt_hs256_expired(void) {
    const char *secret = "supersecretkey";
    jwt_config_t *cfg  = jwt_config_new_hs256(secret);

    /* Build a token that expired 1 hour ago */
    char token[1024];
    build_hs256_token(secret, (long long)time(NULL) - 3600,
                      NULL, token, sizeof(token));

    jwt_claims_t *claims = jwt_verify(cfg, token);
    if (!claims)
        OK("JWT HS256 — expired token rejected");
    else {
        FAIL("JWT HS256 expired", "expected NULL for expired token");
        jwt_claims_free(claims);
    }

    jwt_config_free(cfg);
}

static void test_jwt_hs256_wrong_secret(void) {
    jwt_config_t *cfg = jwt_config_new_hs256("correctsecret");

    /* Token signed with different secret */
    char token[1024];
    build_hs256_token("wrongsecret", (long long)time(NULL) + 3600,
                      NULL, token, sizeof(token));

    jwt_claims_t *claims = jwt_verify(cfg, token);
    if (!claims)
        OK("JWT HS256 — wrong secret rejected");
    else {
        FAIL("JWT HS256 wrong secret", "expected NULL");
        jwt_claims_free(claims);
    }

    jwt_config_free(cfg);
}

static void test_jwt_hs256_tampered(void) {
    const char *secret = "supersecretkey";
    jwt_config_t *cfg  = jwt_config_new_hs256(secret);

    char token[1024];
    build_hs256_token(secret, (long long)time(NULL) + 3600,
                      NULL, token, sizeof(token));

    /* Tamper with payload — change last char of payload segment */
    char *dot1 = strchr(token, '.');
    char *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
    if (dot2 && dot2 > dot1 + 1) {
        char *last = dot2 - 1;
        *last = (*last == 'A') ? 'B' : 'A';
    }

    jwt_claims_t *claims = jwt_verify(cfg, token);
    if (!claims)
        OK("JWT HS256 — tampered payload rejected");
    else {
        FAIL("JWT HS256 tampered", "expected NULL for tampered token");
        jwt_claims_free(claims);
    }

    jwt_config_free(cfg);
}

static void test_jwt_issuer_check(void) {
    const char *secret = "supersecretkey";
    jwt_config_t *cfg  = jwt_config_new_hs256(secret);
    strncpy(cfg->issuer, "routa.io", sizeof(cfg->issuer) - 1);

    /* Token with correct issuer */
    char token[1024];
    build_hs256_token(secret, (long long)time(NULL) + 3600,
                      "routa.io", token, sizeof(token));

    jwt_claims_t *claims = jwt_verify(cfg, token);
    if (claims)
        OK("JWT — correct issuer accepted");
    else
        FAIL("JWT issuer correct", "verification failed");
    if (claims) jwt_claims_free(claims);

    /* Token with wrong issuer */
    build_hs256_token(secret, (long long)time(NULL) + 3600,
                      "evil.io", token, sizeof(token));
    claims = jwt_verify(cfg, token);
    if (!claims)
        OK("JWT — wrong issuer rejected");
    else {
        FAIL("JWT issuer wrong", "expected NULL");
        jwt_claims_free(claims);
    }

    jwt_config_free(cfg);
}

static void test_jwt_middleware(void) {
    const char *secret = "mw-secret";
    jwt_config_t *cfg  = jwt_config_new_hs256(secret);

    char token[1024];
    build_hs256_token(secret, (long long)time(NULL) + 3600,
                      NULL, token, sizeof(token));

    char auth_hdr[1100];
    snprintf(auth_hdr, sizeof(auth_hdr), "Bearer %s", token);

    http_request_t *req = make_request("GET", "/api/data");
    request_add_header(req, "authorization", auth_hdr);

    http_response_t resp;
    http_response_init(&resp);
    middleware_chain_t *chain = middleware_chain_new();

    mw_jwt_auth(chain, req, &resp,
                (next_fn_t)test_next, cfg, 0);

    if (resp.status == 200)
        OK("JWT middleware — valid token passes through");
    else
        FAIL("JWT middleware valid", "status=%d", resp.status);

    http_response_destroy(&resp);

    /* Invalid token */
    http_response_init(&resp);
    http_request_t *req2 = make_request("GET", "/api/data");
    request_add_header(req2, "authorization", "Bearer invalid.token.here");

    mw_jwt_auth(chain, req2, &resp,
                (next_fn_t)test_next, cfg, 0);

    if (resp.status == 401)
        OK("JWT middleware — invalid token returns 401");
    else
        FAIL("JWT middleware invalid", "status=%d", resp.status);

    http_response_destroy(&resp);
    middleware_chain_free(chain);
    request_free(req);
    request_free(req2);
    jwt_config_free(cfg);
}

static void test_jwt_no_bearer_prefix(void) {
    jwt_config_t *cfg = jwt_config_new_hs256("secret");

    http_request_t *req = make_request("GET", "/");
    request_add_header(req, "authorization", "Token sometoken");

    http_response_t resp;
    http_response_init(&resp);
    middleware_chain_t *chain = middleware_chain_new();

    mw_jwt_auth(chain, req, &resp,
                (next_fn_t)test_next, cfg, 0);

    if (resp.status == 401)
        OK("JWT — non-Bearer scheme returns 401");
    else
        FAIL("JWT no bearer", "status=%d", resp.status);

    http_response_destroy(&resp);
    middleware_chain_free(chain);
    request_free(req);
    jwt_config_free(cfg);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════*/

int main(void) {
    printf("test_auth\n");
    printf("─────────────────────────────────────\n");

    printf("\n[Cookie]\n");
    test_cookie_parse_simple();
    test_cookie_parse_empty();
    test_cookie_parse_whitespace();
    test_cookie_set_simple();
    test_cookie_set_full();
    test_cookie_expire();

    printf("\n[Basic Auth]\n");
    test_basic_auth_valid();
    test_basic_auth_invalid();
    test_basic_auth_missing_header();
    test_basic_auth_multiple_users();

    printf("\n[JWT]\n");
    test_jwt_hs256_valid();
    test_jwt_hs256_expired();
    test_jwt_hs256_wrong_secret();
    test_jwt_hs256_tampered();
    test_jwt_issuer_check();
    test_jwt_middleware();
    test_jwt_no_bearer_prefix();

    printf("\n─────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
#endif
