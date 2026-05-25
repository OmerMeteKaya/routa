#ifndef ROUTA_HTTP_MW_AUTH_H
#define ROUTA_HTTP_MW_AUTH_H

#include "http/middleware.h"
#include "http/request.h"
#include "http/response.h"

/* ── Basic Auth ──────────────────────────────────────────────────────────── */

typedef struct {
    char username[256];
    char password[256];
} basic_auth_user_t;

typedef struct {
    basic_auth_user_t *users;
    int                count;
    char               realm[256];
} basic_auth_config_t;

/* Create a basic auth config with given realm.
 * Returns heap-allocated config, caller must call basic_auth_config_free(). */
basic_auth_config_t *basic_auth_config_new(const char *realm);

/* Add a user to the config. Returns 0 on success, -1 on error. */
int basic_auth_config_add_user(basic_auth_config_t *cfg,
                                const char *username,
                                const char *password);

void basic_auth_config_free(basic_auth_config_t *cfg);

/* Middleware function — use with middleware_chain_use().
 * ctx: basic_auth_config_t *                                               */
void mw_basic_auth(middleware_chain_t *chain,
                   const http_request_t *req,
                   http_response_t *resp,
                   next_fn_t next, void *ctx, int current);

/* ── JWT Auth ────────────────────────────────────────────────────────────── */

typedef enum {
    JWT_ALG_HS256 = 0,
    JWT_ALG_RS256 = 1,
} jwt_alg_t;

typedef struct {
    jwt_alg_t   alg;
    char       *secret;        /* HS256: shared secret (heap)              */
    char       *pubkey_pem;    /* RS256: PEM public key (heap)             */
    int         verify_exp;    /* default: 1 — verify expiry               */
    char        issuer[256];   /* optional — verify iss claim if set       */
    char        audience[256]; /* optional — verify aud claim if set       */
} jwt_config_t;

/* Decoded JWT claims (simple key-value, heap allocated) */
typedef struct {
    char **keys;
    char **values;
    int    count;
} jwt_claims_t;

jwt_config_t *jwt_config_new_hs256(const char *secret);
jwt_config_t *jwt_config_new_rs256(const char *pubkey_pem);
void          jwt_config_free(jwt_config_t *cfg);

/* Verify a JWT token string.
 * Returns heap-allocated claims on success, NULL on failure.
 * Caller must call jwt_claims_free().                                       */
jwt_claims_t *jwt_verify(const jwt_config_t *cfg, const char *token);

/* Get a claim value by key. Returns NULL if not found. */
const char   *jwt_claims_get(const jwt_claims_t *claims, const char *key);

void          jwt_claims_free(jwt_claims_t *claims);

/* Middleware function — reads Bearer token from Authorization header.
 * On success: calls next(), claims available via req context (future).
 * On failure: returns 401.
 * ctx: jwt_config_t *                                                      */
void mw_jwt_auth(middleware_chain_t *chain,
                 const http_request_t *req,
                 http_response_t *resp,
                 next_fn_t next, void *ctx, int current);

#endif /* ROUTA_HTTP_MW_AUTH_H */