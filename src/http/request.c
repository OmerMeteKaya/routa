#define _GNU_SOURCE
#include "http/request.h"
#include "util/logger.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static http_method_t parse_method(const char *s, size_t len) {
    if (len == 3 && memcmp(s, "GET",     3) == 0) return HTTP_GET;
    if (len == 4 && memcmp(s, "POST",    4) == 0) return HTTP_POST;
    if (len == 3 && memcmp(s, "PUT",     3) == 0) return HTTP_PUT;
    if (len == 6 && memcmp(s, "DELETE",  6) == 0) return HTTP_DELETE;
    if (len == 4 && memcmp(s, "HEAD",    4) == 0) return HTTP_HEAD;
    if (len == 5 && memcmp(s, "PATCH",   5) == 0) return HTTP_PATCH;
    if (len == 7 && memcmp(s, "OPTIONS", 7) == 0) return HTTP_OPTIONS;
    if (len == 5 && memcmp(s, "TRACE",   5) == 0) return HTTP_TRACE;
    if (len == 7 && memcmp(s, "CONNECT", 7) == 0) return HTTP_CONNECT;
    return HTTP_METHOD_UNKNOWN;
}

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return c - 'a' + 10;
}

static char *url_decode(const char *src, size_t len) {
    char *out = malloc(len + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        if (src[i] == '%' && i + 2 < len && is_hex(src[i+1]) && is_hex(src[i+2])) {
            out[j++] = (char)((hex_val(src[i+1]) << 4) | hex_val(src[i+2]));
            i += 3;
        } else if (src[i] == '+') {
            out[j++] = ' ';
            i++;
        } else {
            out[j++] = src[i++];
        }
    }
    out[j] = '\0';
    return out;
}

static char *normalize_path(const char *path) {
    size_t len = strlen(path);
    char *out = malloc(len + 2);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    if (path[0] != '/') out[j++] = '/';
    while (i < len) {
        if (path[i] == '/') {
            while (i < len && path[i] == '/') i++;
            out[j++] = '/';
        } else if (path[i] == '.' && (i + 1 >= len || path[i+1] == '/')) {
            i++;
        } else if (path[i] == '.' && i + 1 < len && path[i+1] == '.'
                   && (i + 2 >= len || path[i+2] == '/')) {
            i += 2;
            if (j > 1) {
                j--;
                while (j > 1 && out[j-1] != '/') j--;
            }
        } else {
            out[j++] = path[i++];
        }
    }
    if (j > 1 && out[j-1] == '/') j--;
    out[j] = '\0';
    return out;
}

/* Find next \r\n-terminated line inside [start, end). */
static char *find_next_line(char *start, char *end, char **line_end) {
    for (char *p = start; p + 1 <= end; p++) {
        if (p[0] == '\r' && p[1] == '\n') {
            *line_end = p;
            return start;
        }
    }
    return NULL;
}

int http_request_parse(http_request_t *req, const buf_t *buf, size_t *consumed) {
    if (!req || !buf || !consumed) return -1;

    memset(req, 0, sizeof(*req));

    if (buf->len == 0) return 1;

    /* Single null-terminated working copy — ALL pointer arithmetic uses this. */
    char *data = malloc(buf->len + 1);
    if (!data) return -1;
    memcpy(data, buf->data, buf->len);
    data[buf->len] = '\0';
    char *data_end = data + buf->len;

    int ret = 1; /* default: incomplete */

    /* ---- find end of headers ---- */
    char *hdr_end = memmem(data, buf->len, "\r\n\r\n", 4);
    if (!hdr_end) goto done; /* incomplete */

    size_t headers_len = (size_t)(hdr_end - data) + 4;

    /* ---- request line ---- */
    char *rl_end = NULL;
    char *rl     = find_next_line(data, data_end, &rl_end);
    if (!rl || !rl_end) { ret = -1; goto done; }
    size_t rl_len = (size_t)(rl_end - rl);

    /* method */
    size_t i = 0;
    while (i < rl_len && rl[i] != ' ') i++;
    if (i >= rl_len) { ret = -1; goto done; }

    req->method = parse_method(rl, i);
    if (req->method == HTTP_METHOD_UNKNOWN) { ret = -1; goto done; }

    /* path+query */
    size_t path_start = i + 1;
    i = path_start;
    while (i < rl_len && rl[i] != ' ') i++;
    if (i >= rl_len) { ret = -1; goto done; }

    size_t path_len = i - path_start;
    /* path_len is bounded by rl_len which is bounded by buf->len — safe */
    char *raw_path = strndup(rl + path_start, path_len);
    if (!raw_path) { ret = -1; goto done; }

    char *q = memchr(raw_path, '?', path_len);
    if (q) {
        *q = '\0';
        req->query = strdup(q + 1);
        if (!req->query) { free(raw_path); ret = -1; goto done; }
    }

    char *decoded = url_decode(raw_path, strlen(raw_path));
    free(raw_path);
    if (!decoded) { ret = -1; goto done; }

    /* reject path traversal before normalization */
    if (strstr(decoded, "..")) { free(decoded); ret = -1; goto done; }

    req->path = normalize_path(decoded);
    free(decoded);
    if (!req->path) { ret = -1; goto done; }

    /* HTTP version */
    size_t vs = i + 1;
    if (vs + 5 > rl_len) { ret = -1; goto done; }
    if (memcmp(rl + vs, "HTTP/", 5) != 0) { ret = -1; goto done; }
    vs += 5;

    /* version string is null-terminated because data is null-terminated */
    char *dot = strchr(rl + vs, '.');
    if (!dot || dot >= rl_end) { ret = -1; goto done; }
    req->version_major = atoi(rl + vs);
    req->version_minor = atoi(dot + 1);

    /* ---- headers ---- */
    char *hp = rl_end + 2; /* skip first \r\n */
    while (hp < hdr_end) {
        char *le = NULL;
        char *hl = find_next_line(hp, hdr_end + 2, &le);
        if (!hl || !le || le == hl) break;

        if (req->header_count >= 64) { ret = -1; goto done; }

        size_t hl_len = (size_t)(le - hl);
        char *colon   = memchr(hl, ':', hl_len);
        if (colon) {
            size_t klen = (size_t)(colon - hl);
            size_t vi   = klen + 1;
            while (vi < hl_len && (hl[vi] == ' ' || hl[vi] == '\t')) vi++;
            size_t vlen = hl_len - vi;

            req->headers[req->header_count].key   = strndup(hl, klen);
            req->headers[req->header_count].value = strndup(hl + vi, vlen);
            if (!req->headers[req->header_count].key ||
                !req->headers[req->header_count].value) {
                ret = -1; goto done;
            }
            req->header_count++;
        }
        hp = le + 2;
    }

    /* ---- keep-alive ---- */
    const char *conn = http_request_get_header(req, "Connection");
    if (req->version_major == 1 && req->version_minor == 1) {
        req->keep_alive = !(conn && strcasecmp(conn, "close") == 0);
    } else {
        req->keep_alive = (conn && strcasecmp(conn, "keep-alive") == 0);
    }

    /* ---- body ---- */
    const char *cl_str = http_request_get_header(req, "Content-Length");
    size_t content_length = cl_str ? (size_t)strtoull(cl_str, NULL, 10) : 0;
    size_t body_start     = headers_len;
    size_t available      = buf->len > body_start ? buf->len - body_start : 0;

    if (content_length > 0) {
        if (available < content_length) goto done; /* incomplete */
        req->body = malloc(content_length);
        if (!req->body) { ret = -1; goto done; }
        memcpy(req->body, buf->data + body_start, content_length);
        req->body_len = content_length;
    }

    *consumed = body_start + content_length;
    ret = 0;

done:
    free(data);
    if (ret != 0) http_request_free(req);
    return ret;
}

void http_request_free(http_request_t *req) {
    if (!req) return;
    free(req->path);
    free(req->query);
    free(req->body);
    for (int i = 0; i < req->header_count; i++) {
        free(req->headers[i].key);
        free(req->headers[i].value);
    }
    memset(req, 0, sizeof(*req));
}

const char *http_request_get_header(const http_request_t *req, const char *key) {
    if (!req || !key) return NULL;
    for (int i = 0; i < req->header_count; i++)
        if (req->headers[i].key && strcasecmp(req->headers[i].key, key) == 0)
            return req->headers[i].value;
    return NULL;
}