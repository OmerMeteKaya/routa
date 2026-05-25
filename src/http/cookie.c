#define _GNU_SOURCE
#include "http/cookie.h"
#include "http/request.h"
#include "http/response.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── cookie_jar_parse ────────────────────────────────────────────────────── */

cookie_jar_t *cookie_jar_parse(const http_request_t *req) {
    cookie_jar_t *jar = calloc(1, sizeof(cookie_jar_t));
    if (!jar) return NULL;

    const char *hdr = http_request_get_header(req, "cookie");
    if (!hdr || !*hdr) return jar;   /* empty jar */

    /* Count semicolons to pre-allocate */
    int count = 1;
    for (const char *p = hdr; *p; p++)
        if (*p == ';') count++;

    jar->cookies = calloc((size_t)count, sizeof(routa_cookie_t));
    if (!jar->cookies) { free(jar); return NULL; }

    /* Parse "name=value; name2=value2; ..." */
    char *buf = strdup(hdr);
    if (!buf) { free(jar->cookies); free(jar); return NULL; }

    char *saveptr = NULL;
    char *token   = strtok_r(buf, ";", &saveptr);
    while (token && jar->count < count) {
        /* Trim leading whitespace */
        while (*token == ' ' || *token == '\t') token++;

        char *eq = strchr(token, '=');
        if (!eq) { token = strtok_r(NULL, ";", &saveptr); continue; }

        size_t name_len = (size_t)(eq - token);
        /* Trim trailing whitespace from name */
        while (name_len > 0 &&
               (token[name_len-1] == ' ' || token[name_len-1] == '\t'))
            name_len--;

        if (name_len == 0 || name_len >= sizeof(jar->cookies[0].name)) {
            token = strtok_r(NULL, ";", &saveptr); continue;
        }

        const char *val = eq + 1;
        /* Trim leading whitespace from value */
        while (*val == ' ' || *val == '\t') val++;

        routa_cookie_t *c = &jar->cookies[jar->count];
        memcpy(c->name, token, name_len);
        c->name[name_len] = '\0';
        /* Trim trailing whitespace from value */
        size_t val_len = strlen(val);
        while (val_len > 0 &&
               (val[val_len-1] == ' ' || val[val_len-1] == '\t'))
            val_len--;

        
        memcpy(c->value, val, val_len < sizeof(c->value) - 1
                               ? val_len : sizeof(c->value) - 1);
        c->value[val_len < sizeof(c->value) - 1
                 ? val_len : sizeof(c->value) - 1] = '\0';
        c->value[sizeof(c->value) - 1] = '\0';
        jar->count++;

        token = strtok_r(NULL, ";", &saveptr);
    }

    free(buf);
    return jar;
}

/* ── cookie_jar_get ──────────────────────────────────────────────────────── */

const char *cookie_jar_get(const cookie_jar_t *jar, const char *name) {
    if (!jar || !name) return NULL;
    for (int i = 0; i < jar->count; i++) {
        if (strcmp(jar->cookies[i].name, name) == 0)
            return jar->cookies[i].value;
    }
    return NULL;
}

/* ── cookie_jar_free ─────────────────────────────────────────────────────── */

void cookie_jar_free(cookie_jar_t *jar) {
    if (!jar) return;
    free(jar->cookies);
    free(jar);
}

/* ── cookie_set ──────────────────────────────────────────────────────────── */

int cookie_set(http_response_t *resp, const cookie_opts_t *opts) {
    if (!resp || !opts || !opts->name || !opts->value) return -1;

    /* Build Set-Cookie value */
    char buf[8192];
    int  pos = 0;

    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "%s=%s", opts->name, opts->value);

    if (opts->path && opts->path[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "; Path=%s", opts->path);
    else
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "; Path=/");

    if (opts->domain && opts->domain[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "; Domain=%s", opts->domain);

    if (opts->max_age >= 0)
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "; Max-Age=%d", opts->max_age);

    if (opts->same_site && opts->same_site[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "; SameSite=%s", opts->same_site);

    if (opts->secure)
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "; Secure");

    if (opts->http_only)
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "; HttpOnly");

    if (pos >= (int)sizeof(buf)) return -1;

    http_response_set_header(resp, "set-cookie", buf);
    return 0;
}

/* ── cookie_set_simple ───────────────────────────────────────────────────── */

int cookie_set_simple(http_response_t *resp,
                       const char *name, const char *value) {
    cookie_opts_t opts = {0};
    opts.name      = name;
    opts.value     = value;
    opts.path      = "/";
    opts.http_only = 1;
    opts.max_age   = -1;
    return cookie_set(resp, &opts);
}

/* ── cookie_expire ───────────────────────────────────────────────────────── */

int cookie_expire(http_response_t *resp,
                   const char *name, const char *path) {
    cookie_opts_t opts = {0};
    opts.name    = name;
    opts.value   = "";
    opts.path    = path ? path : "/";
    opts.max_age = 0;
    return cookie_set(resp, &opts);
}