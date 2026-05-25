#define _GNU_SOURCE
#include "http/mw_auth.h"
#include "http/cookie.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Basic Auth
 * ═══════════════════════════════════════════════════════════════════════════*/

basic_auth_config_t *basic_auth_config_new(const char *realm) {
    basic_auth_config_t *cfg = calloc(1, sizeof(basic_auth_config_t));
    if (!cfg) return NULL;
    strncpy(cfg->realm, realm ? realm : "Restricted",
            sizeof(cfg->realm) - 1);
    return cfg;
}

int basic_auth_config_add_user(basic_auth_config_t *cfg,
                                const char *username,
                                const char *password) {
    if (!cfg || !username || !password) return -1;

    basic_auth_user_t *tmp = realloc(cfg->users,
        (size_t)(cfg->count + 1) * sizeof(basic_auth_user_t));
    if (!tmp) return -1;
    cfg->users = tmp;

    strncpy(cfg->users[cfg->count].username, username,
            sizeof(cfg->users[0].username) - 1);
    strncpy(cfg->users[cfg->count].password, password,
            sizeof(cfg->users[0].password) - 1);
    cfg->count++;
    return 0;
}

void basic_auth_config_free(basic_auth_config_t *cfg) {
    if (!cfg) return;
    free(cfg->users);
    free(cfg);
}

/* Base64 decode — returns heap buffer, caller frees. Sets *out_len.        */
static uint8_t *b64_decode(const char *src, size_t *out_len) {
    size_t src_len = strlen(src);
    size_t max_out = (src_len / 4) * 3 + 4;
    uint8_t *out   = malloc(max_out);
    if (!out) return NULL;

    int n = EVP_DecodeBlock(out, (const unsigned char *)src, (int)src_len);
    if (n < 0) { free(out); return NULL; }

    /* EVP_DecodeBlock counts padding as output — adjust */
    if (src_len >= 1 && src[src_len - 1] == '=') n--;
    if (src_len >= 2 && src[src_len - 2] == '=') n--;

    *out_len = (size_t)n;
    out[n]   = '\0';
    return out;
}

static void send_401_basic(http_response_t *resp, const char *realm) {
    char www_auth[512];
    snprintf(www_auth, sizeof(www_auth),
             "Basic realm=\"%s\", charset=\"UTF-8\"", realm);
    http_response_set_status(resp, 401, "Unauthorized");
    http_response_set_header(resp, "www-authenticate", www_auth);
    http_response_set_body(resp, "Unauthorized\n", 13);
}

void mw_basic_auth(middleware_chain_t *chain,
                   const http_request_t *req,
                   http_response_t *resp,
                   next_fn_t next, void *ctx, int current) {
    basic_auth_config_t *cfg = (basic_auth_config_t *)ctx;
    if (!cfg) { send_401_basic(resp, "Restricted"); return; }

    const char *auth = http_request_get_header(req, "authorization");
    if (!auth || strncasecmp(auth, "Basic ", 6) != 0) {
        send_401_basic(resp, cfg->realm); return;
    }

    const char *encoded = auth + 6;
    while (*encoded == ' ') encoded++;

    size_t   dec_len = 0;
    uint8_t *decoded = b64_decode(encoded, &dec_len);
    if (!decoded) { send_401_basic(resp, cfg->realm); return; }

    /* decoded = "username:password" */
    char *colon = memchr(decoded, ':', dec_len);
    if (!colon) { free(decoded); send_401_basic(resp, cfg->realm); return; }

    *colon = '\0';
    const char *username = (char *)decoded;
    const char *password = colon + 1;

    int authenticated = 0;
    for (int i = 0; i < cfg->count; i++) {
        if (strcmp(cfg->users[i].username, username) == 0 &&
            strcmp(cfg->users[i].password, password) == 0) {
            authenticated = 1;
            break;
        }
    }
    free(decoded);

    if (!authenticated) { send_401_basic(resp, cfg->realm); return; }

    next(chain, req, resp, current);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * JWT — HS256 + RS256, verify only
 * ═══════════════════════════════════════════════════════════════════════════*/

jwt_config_t *jwt_config_new_hs256(const char *secret) {
    if (!secret) return NULL;
    jwt_config_t *cfg = calloc(1, sizeof(jwt_config_t));
    if (!cfg) return NULL;
    cfg->alg        = JWT_ALG_HS256;
    cfg->secret     = strdup(secret);
    cfg->verify_exp = 1;
    if (!cfg->secret) { free(cfg); return NULL; }
    return cfg;
}

jwt_config_t *jwt_config_new_rs256(const char *pubkey_pem) {
    if (!pubkey_pem) return NULL;
    jwt_config_t *cfg = calloc(1, sizeof(jwt_config_t));
    if (!cfg) return NULL;
    cfg->alg        = JWT_ALG_RS256;
    cfg->pubkey_pem = strdup(pubkey_pem);
    cfg->verify_exp = 1;
    if (!cfg->pubkey_pem) { free(cfg); return NULL; }
    return cfg;
}

void jwt_config_free(jwt_config_t *cfg) {
    if (!cfg) return;
    free(cfg->secret);
    free(cfg->pubkey_pem);
    free(cfg);
}

void jwt_claims_free(jwt_claims_t *claims) {
    if (!claims) return;
    for (int i = 0; i < claims->count; i++) {
        free(claims->keys[i]);
        free(claims->values[i]);
    }
    free(claims->keys);
    free(claims->values);
    free(claims);
}

const char *jwt_claims_get(const jwt_claims_t *claims, const char *key) {
    if (!claims || !key) return NULL;
    for (int i = 0; i < claims->count; i++)
        if (strcmp(claims->keys[i], key) == 0)
            return claims->values[i];
    return NULL;
}

/* URL-safe base64 decode (JWT uses - and _ instead of + and /)            */
static uint8_t *jwt_b64url_decode(const char *src, size_t src_len,
                                   size_t *out_len) {
    /* Convert URL-safe to standard base64 */
    char *tmp = malloc(src_len + 4);
    if (!tmp) return NULL;

    for (size_t i = 0; i < src_len; i++) {
        if      (src[i] == '-') tmp[i] = '+';
        else if (src[i] == '_') tmp[i] = '/';
        else                    tmp[i] = src[i];
    }
    /* Pad to multiple of 4 */
    size_t padded = src_len;
    while (padded % 4) tmp[padded++] = '=';
    tmp[padded] = '\0';

    size_t max_out = (padded / 4) * 3 + 4;
    uint8_t *out   = malloc(max_out + 1);
    if (!out) { free(tmp); return NULL; }

    int n = EVP_DecodeBlock(out, (const unsigned char *)tmp, (int)padded);
    free(tmp);
    if (n < 0) { free(out); return NULL; }

    size_t pad_count = padded - src_len;
    *out_len  = (size_t)n - pad_count;
    out[*out_len] = '\0';
    return out;
}

/* Minimal JSON claim parser — extracts string and number values.
 * Does NOT handle nested objects or arrays.                                */
static jwt_claims_t *parse_claims(const char *json, size_t len) {
    jwt_claims_t *claims = calloc(1, sizeof(jwt_claims_t));
    if (!claims) return NULL;

    /* Count quote pairs to pre-allocate */
    int cap = 8;
    claims->keys   = calloc((size_t)cap, sizeof(char *));
    claims->values = calloc((size_t)cap, sizeof(char *));
    if (!claims->keys || !claims->values) {
        jwt_claims_free(claims); return NULL;
    }

    const char *p   = json;
    const char *end = json + len;

    while (p < end) {
        /* Find next key (quoted string) */
        const char *ks = memchr(p, '"', (size_t)(end - p));
        if (!ks) break;
        ks++;
        const char *ke = memchr(ks, '"', (size_t)(end - ks));
        if (!ke) break;

        size_t key_len = (size_t)(ke - ks);
        char  *key     = strndup(ks, key_len);
        if (!key) break;

        p = ke + 1;
        /* Skip whitespace and colon */
        while (p < end && (*p == ' ' || *p == ':' || *p == '\t')) p++;
        if (p >= end) { free(key); break; }

        char *value = NULL;
        if (*p == '"') {
            /* String value */
            const char *vs = p + 1;
            const char *ve = memchr(vs, '"', (size_t)(end - vs));
            if (!ve) { free(key); break; }
            value = strndup(vs, (size_t)(ve - vs));
            p     = ve + 1;
        } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
            /* Numeric value */
            const char *ns = p;
            while (p < end && (*p == '-' || (*p >= '0' && *p <= '9'))) p++;
            value = strndup(ns, (size_t)(p - ns));
        } else {
            /* Boolean or null — skip */
            free(key);
            while (p < end && *p != ',' && *p != '}') p++;
            continue;
        }

        if (!value) { free(key); break; }

        /* Grow if needed */
        if (claims->count >= cap) {
            cap *= 2;
            char **tk = realloc(claims->keys,   (size_t)cap * sizeof(char *));
            char **tv = realloc(claims->values, (size_t)cap * sizeof(char *));
            if (!tk || !tv) { free(key); free(value); break; }
            claims->keys   = tk;
            claims->values = tv;
        }

        claims->keys[claims->count]   = key;
        claims->values[claims->count] = value;
        claims->count++;
    }

    return claims;
}

/* ── HS256 signature verify ──────────────────────────────────────────────── */
static int verify_hs256(const char *secret,
                          const char *header_payload,  /* "hdr.pay" */
                          const uint8_t *sig, size_t sig_len) {
    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;

    HMAC(EVP_sha256(),
         secret, (int)strlen(secret),
         (const unsigned char *)header_payload, strlen(header_payload),
         mac, &mac_len);

    if (mac_len != sig_len) return 0;

    /* Constant-time compare */
    int diff = 0;
    for (size_t i = 0; i < mac_len; i++)
        diff |= mac[i] ^ sig[i];
    return diff == 0;
}

/* ── RS256 signature verify ──────────────────────────────────────────────── */
static int verify_rs256(const char *pubkey_pem,
                          const char *header_payload,
                          const uint8_t *sig, size_t sig_len) {
    BIO *bio = BIO_new_mem_buf(pubkey_pem, -1);
    if (!bio) return 0;

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return 0; }

    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx,
            (const unsigned char *)header_payload,
            strlen(header_payload)) == 1 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        ok = 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* ── jwt_verify ──────────────────────────────────────────────────────────── */

jwt_claims_t *jwt_verify(const jwt_config_t *cfg, const char *token) {
    if (!cfg || !token) return NULL;

    /* Split into header.payload.signature */
    const char *dot1 = strchr(token, '.');
    if (!dot1) return NULL;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return NULL;

    size_t hdr_len = (size_t)(dot1 - token);
    size_t pay_len = (size_t)(dot2 - dot1 - 1);
    const char *sig_b64 = dot2 + 1;
    size_t sig_b64_len  = strlen(sig_b64);

    /* header.payload as signed string */
    size_t hp_len = (size_t)(dot2 - token);
    char  *header_payload = strndup(token, hp_len);
    if (!header_payload) return NULL;

    /* Decode signature */
    size_t   sig_len = 0;
    uint8_t *sig     = jwt_b64url_decode(sig_b64, sig_b64_len, &sig_len);
    if (!sig) { free(header_payload); return NULL; }

    /* Verify signature */
    int valid = 0;
    if (cfg->alg == JWT_ALG_HS256 && cfg->secret)
        valid = verify_hs256(cfg->secret, header_payload, sig, sig_len);
    else if (cfg->alg == JWT_ALG_RS256 && cfg->pubkey_pem)
        valid = verify_rs256(cfg->pubkey_pem, header_payload, sig, sig_len);
    free(sig);
    free(header_payload);
    if (!valid) return NULL;

    /* Decode payload */
    size_t   pay_dec_len = 0;
    uint8_t *payload     = jwt_b64url_decode(dot1 + 1, pay_len, &pay_dec_len);
    if (!payload) return NULL;

    jwt_claims_t *claims = parse_claims((char *)payload, pay_dec_len);
    free(payload);
    if (!claims) return NULL;

    /* Verify expiry */
    if (cfg->verify_exp) {
        const char *exp_str = jwt_claims_get(claims, "exp");
        if (exp_str) {
            long long exp = atoll(exp_str);
            if (exp > 0 && (long long)time(NULL) > exp) {
                jwt_claims_free(claims);
                return NULL;   /* token expired */
            }
        }
    }

    /* Verify issuer */
    if (cfg->issuer[0]) {
        const char *iss = jwt_claims_get(claims, "iss");
        if (!iss || strcmp(iss, cfg->issuer) != 0) {
            jwt_claims_free(claims); return NULL;
        }
    }

    /* Verify audience */
    if (cfg->audience[0]) {
        const char *aud = jwt_claims_get(claims, "aud");
        if (!aud || strcmp(aud, cfg->audience) != 0) {
            jwt_claims_free(claims); return NULL;
        }
    }

    return claims;
}

/* ── mw_jwt_auth ─────────────────────────────────────────────────────────── */

static void send_401_bearer(http_response_t *resp, const char *msg) {
    http_response_set_status(resp, 401, "Unauthorized");
    http_response_set_header(resp, "www-authenticate", "Bearer");
    http_response_set_body(resp, msg ? msg : "Unauthorized\n",
                           msg ? strlen(msg) : 13);
}

void mw_jwt_auth(middleware_chain_t *chain,
                 const http_request_t *req,
                 http_response_t *resp,
                 next_fn_t next, void *ctx, int current) {
    jwt_config_t *cfg = (jwt_config_t *)ctx;
    if (!cfg) { send_401_bearer(resp, "No JWT config\n"); return; }

    const char *auth = http_request_get_header(req, "authorization");
    if (!auth || strncasecmp(auth, "Bearer ", 7) != 0) {
        send_401_bearer(resp, "Missing token\n"); return;
    }

    const char *token = auth + 7;
    while (*token == ' ') token++;

    jwt_claims_t *claims = jwt_verify(cfg, token);
    if (!claims) {
        send_401_bearer(resp, "Invalid token\n"); return;
    }

    /* Claims verified — proceed */
    jwt_claims_free(claims);
    next(chain, req, resp, current);
}