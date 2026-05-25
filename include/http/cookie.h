#ifndef ROUTA_HTTP_COOKIE_H
#define ROUTA_HTTP_COOKIE_H

#include "http/request.h"
#include "http/response.h"
#include <stddef.h>
#include <time.h>

/* ── Single cookie ───────────────────────────────────────────────────────── */
typedef struct {
    char  name[256];
    char  value[4096];
} routa_cookie_t;

/* ── Cookie jar (parsed from request) ───────────────────────────────────── */
typedef struct {
    routa_cookie_t *cookies;
    int             count;
} cookie_jar_t;

/* ── Set-Cookie attributes ───────────────────────────────────────────────── */
typedef struct {
    const char *name;
    const char *value;
    const char *path;       /* default: "/"          */
    const char *domain;     /* default: NULL          */
    int         max_age;    /* seconds, -1 = not set  */
    int         http_only;  /* default: 0             */
    int         secure;     /* default: 0             */
    const char *same_site;  /* "Strict","Lax","None"  */
} cookie_opts_t;

/* ── Request: parse Cookie header ───────────────────────────────────────── */

/* Parse "Cookie: name=value; name2=value2" from request.
 * Returns heap-allocated jar, caller must call cookie_jar_free().          */
cookie_jar_t *cookie_jar_parse(const http_request_t *req);

/* Get a cookie value by name. Returns NULL if not found.
 * Pointer is valid until cookie_jar_free() is called.                      */
const char   *cookie_jar_get(const cookie_jar_t *jar, const char *name);

void          cookie_jar_free(cookie_jar_t *jar);

/* ── Response: set Set-Cookie header ────────────────────────────────────── */

/* Append a Set-Cookie header to the response.
 * opts->name and opts->value are required.
 * Returns 0 on success, -1 on error.                                       */
int cookie_set(http_response_t *resp, const cookie_opts_t *opts);

/* Convenience: set a simple session cookie (no expiry, http_only=1).       */
int cookie_set_simple(http_response_t *resp,
                       const char *name, const char *value);

/* Convenience: expire a cookie (max_age=0).                                */
int cookie_expire(http_response_t *resp,
                   const char *name, const char *path);

#endif /* ROUTA_HTTP_COOKIE_H */