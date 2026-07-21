#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/request.h"
#include "util/logger.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "util/metrics.h"

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

/* RFC 9110 5.6.2 token characters — header field names are tokens: no
 * spaces, no separators, no control characters. */
static int is_tchar(char c) {
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
        return 1;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~':
            return 1;
        default:
            return 0;
    }
}

/* Decode an RFC 9112 6.1 chunked message body from [data, data+avail).
 * Returns 0 on success (*out_body/*out_len/*out_consumed set, *out_consumed
 * is the number of bytes from `data` consumed including the terminating
 * chunk and any (discarded) trailer section), 1 if more data is needed,
 * -1 on malformed chunked syntax. On 1 or -1, *out_body is freed/NULL. */
static int decode_chunked_body(const char *data, size_t avail,
                                char **out_body, size_t *out_len,
                                size_t *out_consumed) {
    char  *body     = NULL;
    size_t body_len = 0;
    size_t pos      = 0;

    *out_body = NULL;
    *out_len  = 0;

    for (;;) {
        /* find CRLF terminating the chunk-size line */
        const char *line_end = NULL;
        for (size_t k = pos; k + 1 < avail; k++) {
            if (data[k] == '\r' && data[k+1] == '\n') { line_end = data + k; break; }
        }
        if (!line_end) { free(body); return 1; }

        size_t line_len = (size_t)(line_end - (data + pos));
        size_t sz = 0, hexlen = 0;
        for (size_t k = 0; k < line_len; k++) {
            char c = data[pos + k];
            if (c == ';') break;               /* chunk-extension — ignored */
            if (!is_hex(c)) { free(body); return -1; }
            if (hexlen >= 16) { free(body); return -1; }  /* would overflow */
            sz = (sz << 4) | (size_t)hex_val(c);
            hexlen++;
        }
        if (hexlen == 0) { free(body); return -1; }  /* empty chunk-size token */

        pos = (size_t)(line_end - data) + 2;

        if (sz == 0) {
            /* last-chunk: consume (and discard) the trailer section up to
             * the terminating blank line */
            for (;;) {
                const char *t_end = NULL;
                for (size_t k = pos; k + 1 < avail; k++) {
                    if (data[k] == '\r' && data[k+1] == '\n') { t_end = data + k; break; }
                }
                if (!t_end) { free(body); return 1; }
                size_t t_len = (size_t)(t_end - (data + pos));
                pos = (size_t)(t_end - data) + 2;
                if (t_len == 0) break;  /* empty line — end of trailers */
            }
            *out_body     = body;
            *out_len      = body_len;
            *out_consumed = pos;
            return 0;
        }

        if (avail - pos < sz + 2) { free(body); return 1; }        /* incomplete */
        if (data[pos + sz] != '\r' || data[pos + sz + 1] != '\n') { /* RFC 9112 6.1: chunk-data must be followed by CRLF */
            free(body); return -1;
        }

        char *nb = realloc(body, body_len + sz);
        if (!nb) { free(body); return -1; }
        body = nb;
        memcpy(body + body_len, data + pos, sz);
        body_len += sz;
        pos += sz + 2;
    }
}

static char *url_decode(const char *src, size_t len) {
    char *out = malloc(len + 1);
    if (!out) return NULL;
    out[len] = '\0';
    size_t i = 0, j = 0;
    while (i < len) {
        if (src[i] == '%' && i + 2 < len && is_hex(src[i+1]) && is_hex(src[i+2])) {
            char c = (char)((hex_val(src[i+1]) << 4) | hex_val(src[i+2]));
            if (c == '\0') { free(out); return NULL; }  /* reject %00 */
            out[j++] = c;
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
    out[0] = '\0';
    size_t i = 0, j = 0;
    if (path[0] != '/') out[j++] = '/';
    while (i < len) {
        if (path[i] == '/') {
            while (i < len && path[i] == '/') i++;
            out[j++] = '/';
        } else if (path[i] == '.' && (i + 1 >= len || path[i+1] == '/')) {
            /* BUG FIX: previously this only skipped the '.' character
             * itself (i++), leaving a following '/' (if any) for the
             * NEXT loop iteration -- which then emitted it as its own
             * redundant '/' segment via the slash-collapsing branch
             * above, turning e.g. "/a/./b" into "/a//b" (a stray double
             * slash) instead of the correctly-normalized "/a/b". Now
             * consumes the trailing '/' along with the '.' when present
             * (i += 2), matching how the ".." branch just below already
             * consumes its own trailing '/'. At end-of-string (i+1 >=
             * len) there's no '/' to consume, so i++ alone is correct
             * there (unchanged). */
            i += (i + 1 < len && path[i+1] == '/') ? 2 : 1;
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
static char *find_next_line(char *start,const char *end, char **line_end) {
    for (char *p = start; p + 1 <= end; p++) {
        if (p[0] == '\r' && p[1] == '\n') {
            *line_end = p;
            return start;
        }
    }
    return NULL;
}

const char *http_request_get_query(const http_request_t *req, const char *key) {
    if (!req || !key) return NULL;
    for (int i = 0; i < req->query_param_count; i++)
        if (req->query_params[i].key &&
            strcmp(req->query_params[i].key, key) == 0)
            return req->query_params[i].value;
    return NULL;
}

int http_request_parse(http_request_t *req, const buf_t *buf, size_t *consumed,
                        size_t max_body_size) {
    if (!req || !buf || !consumed) return -1;

    memset(req, 0, sizeof(*req));
    req->headers_owned = 1;
    if (buf->len == 0) return 1;

    /* Single null-terminated working copy — ALL pointer arithmetic uses this. */
    char *data = malloc(buf->len + 1);
    if (!data) return -1;
    memcpy(data, buf_data(buf), buf->len);
    data[buf->len] = '\0';
    char *data_end = data + buf->len;

    int ret = 1; /* default: incomplete */

    /* ---- find end of headers ---- */
    char *hdr_end = memmem(data, buf->len, "\r\n\r\n", 4);
    if (!hdr_end) {
        /* Bare LF terminator — reject as malformed                       */
        if (memmem(data, buf->len, "\n\n", 2)) { ret = -1; goto done; }
        goto done; /* genuinely incomplete */
    }

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
    /* Reject null bytes in raw path */
    if (memchr(raw_path, '\0', path_len) != NULL) {
        free(raw_path); ret = -1; goto done;
    }

    char *q = memchr(raw_path, '?', path_len);
    if (q) {
        *q = '\0';
        req->query = strdup(q + 1);
        if (!req->query) { free(raw_path); ret = -1; goto done; }
    }

    /* Parse query params from req->query */
    if (req->query) {
        char *qs = strdup(req->query);
        if (qs) {
            char *pair = qs;
            char *amp;
            do {
                amp = strchr(pair, '&');
                if (amp) *amp = '\0';
                char *eq = strchr(pair, '=');
                if (eq && req->query_param_count < 32) {
                    *eq = '\0';
                    char *k = url_decode(pair, strlen(pair));
                    char *v = url_decode(eq + 1, strlen(eq + 1));
                    if (k && v) {
                        req->query_params[req->query_param_count].key   = k;
                        req->query_params[req->query_param_count].value = v;
                        req->query_param_count++;
                    } else {
                        free(k);
                        free(v);
                    }
                }
                pair = amp ? amp + 1 : NULL;
            } while (pair);
            free(qs);
        }
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
    req->version_major = (int)strtol(rl + vs, NULL, 10);
    req->version_minor = (int)strtol(dot + 1, NULL, 10);

    /* Only HTTP/1.0 and HTTP/1.1 are handled on this parser (HTTP/2.0
     * arrives via the h2c preface / Upgrade path, never here as a
     * regular request line). */
    if (req->version_major != 1 ||
        (req->version_minor != 0 && req->version_minor != 1)) {
        ret = -1; goto done;
    }

    /* ---- headers ---- */
    char *hp = rl_end + 2; /* skip first \r\n */
    while (hp < hdr_end) {
        char *le = NULL;
        char *hl = find_next_line(hp, hdr_end + 2, &le);
        if (!hl || !le || le == hl) break;

        if (req->header_count >= 64) { ret = -1; goto done; }

        size_t hl_len = (size_t)(le - hl);

        /* Obsolete line folding (RFC 9112 5.2): a continuation line begins
         * with SP/HTAB. This is a request-smuggling vector — reject it
         * rather than silently treating it as a fold or dropping it. */
        if (hl_len > 0 && (hl[0] == ' ' || hl[0] == '\t')) { ret = -1; goto done; }

        /* NUL byte anywhere in the header line is never valid. */
        if (memchr(hl, '\0', hl_len) != NULL) { ret = -1; goto done; }

        char *colon = memchr(hl, ':', hl_len);
        if (!colon) { ret = -1; goto done; } /* malformed header line */

        size_t klen = (size_t)(colon - hl);
        /* Header field names are tokens (RFC 9110 5.6.2) — no whitespace,
         * no separators. This also rejects "Foo : bar" (space before the
         * colon becomes part of the "name"). */
        if (klen == 0) { ret = -1; goto done; }
        for (size_t k = 0; k < klen; k++) {
            if (!is_tchar(hl[k])) { ret = -1; goto done; }
        }

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
        hp = le + 2;

    }

    /* ---- keep-alive ---- */
    const char *conn = http_request_get_header(req, "Connection");
    if (req->version_major == 1 && req->version_minor == 1) {
        req->keep_alive = !(conn && strcasecmp(conn, "close") == 0);
    } else {
        req->keep_alive = (conn && strcasecmp(conn, "keep-alive") == 0);
    }

    /* ---- Host header (RFC 9112 3.2): mandatory on HTTP/1.1, duplicates
     * and invalid values (embedded whitespace) are request-smuggling
     * adjacent — some intermediaries pick the first, some the last. ---- */
    {
        int host_count = 0;
        const char *host_val = NULL;
        for (int hi = 0; hi < req->header_count; hi++) {
            if (strcasecmp(req->headers[hi].key, "Host") == 0) {
                host_count++;
                if (!host_val) host_val = req->headers[hi].value;
            }
        }
        if (req->version_major == 1 && req->version_minor == 1 && host_count == 0) {
            ret = -1; goto done;
        }
        if (host_count > 1) { ret = -1; goto done; }
        if (host_val) {
            for (const unsigned char *p = (const unsigned char *)host_val; *p; p++) {
                if (*p <= 0x20 || *p == 0x7f) { ret = -1; goto done; }
            }
        }
    }

    /* ---- Transfer-Encoding / Content-Length (RFC 9112 6.1, 6.3) ----
     * Both present together, or an unrecognized/non-final transfer-coding,
     * are request-smuggling vectors — reject outright rather than guess
     * which framing an intermediary would have honored. */
    const char *te_str = http_request_get_header(req, "Transfer-Encoding");
    const char *cl_str = http_request_get_header(req, "Content-Length");
    int te_chunked = 0;

    if (te_str) {
        const char *v = te_str;
        while (*v == ' ' || *v == '\t') v++;
        size_t vlen = strlen(v);
        while (vlen > 0 && (v[vlen-1] == ' ' || v[vlen-1] == '\t')) vlen--;
        if (vlen == 7 && strncasecmp(v, "chunked", 7) == 0) {
            te_chunked = 1;
        } else {
            /* Unknown coding, or "chunked" isn't the final (and only)
             * coding (e.g. "chunked, gzip") — RFC 9112 6.1 requires
             * chunked be the final transfer-coding when present. */
            ret = -1; goto done;
        }
    }

    if (te_chunked && cl_str) { ret = -1; goto done; } /* smuggling vector */

    if (te_chunked && !(req->version_major == 1 && req->version_minor == 1)) {
        ret = -1; goto done; /* chunked is undefined for HTTP/1.0 */
    }

    /* Reject conflicting duplicate Content-Length headers (RFC 9112 6.1) —
     * all instances must agree, or the request must be rejected. */
    if (cl_str) {
        const char *first_cl = NULL;
        for (int hi = 0; hi < req->header_count; hi++) {
            if (strcasecmp(req->headers[hi].key, "Content-Length") == 0) {
                if (!first_cl) first_cl = req->headers[hi].value;
                else if (strcmp(first_cl, req->headers[hi].value) != 0) {
                    ret = -1; goto done;
                }
            }
        }
    }

    size_t content_length = 0;
    if (cl_str && !te_chunked) {
        /* Reject negative or non-numeric Content-Length                  */
        const char *p = cl_str;
        while (*p == ' ') p++;
        if (*p == '-') { ret = -1; goto done; }
        char *endptr = NULL;
        unsigned long long val = strtoull(p, &endptr, 10);
        if (endptr == p) { ret = -1; goto done; }   /* no digits */
        content_length = (size_t)val;
        /* Reject an oversized DECLARED length immediately -- before
         * waiting for the body to actually arrive. Without this, a
         * client can send a huge Content-Length and either (a) actually
         * send that much data, exhausting memory once buffered, or (b)
         * send the header and nothing else, tying up the connection
         * (and its read_buf) indefinitely since http_request_parse()
         * would otherwise just keep returning "incomplete" (1) forever
         * waiting for bytes that may never come. */
        if (max_body_size > 0 && content_length > max_body_size) {
            ret = -1; goto done;
        }
    }
    size_t body_start     = headers_len;
    size_t available      = buf->len > body_start ? buf->len - body_start : 0;

    if (te_chunked) {
        char *dec_body = NULL;
        size_t dec_len = 0, dec_consumed = 0;
        int dc = decode_chunked_body(data + body_start, available,
                                      &dec_body, &dec_len, &dec_consumed);
        if (dc == 1) goto done;          /* incomplete — need more data */
        if (dc == -1) { ret = -1; goto done; } /* malformed chunked body */
        /* Same oversized-body rejection as the Content-Length path above
         * -- chunked bodies have no declared total length to check
         * up front, so this can only be caught once decoding finishes,
         * but it still prevents an oversized body from ever reaching
         * the application/route handlers. */
        if (max_body_size > 0 && dec_len > max_body_size) {
            free(dec_body);
            ret = -1; goto done;
        }
        req->body     = dec_body;
        req->body_len = dec_len;
        if (dec_len > 0) routa_metrics_record_bytes_received(dec_len);
        *consumed = body_start + dec_consumed;
    } else {
        if (content_length > 0) {
            if (available < content_length) goto done; /* incomplete */
            req->body = malloc(content_length);
            if (!req->body) { ret = -1; goto done; }
            memcpy(req->body, buf_data(buf) + body_start, content_length);
            req->body_len = content_length;
            routa_metrics_record_bytes_received(content_length);
        }
        *consumed = body_start + content_length;
    }
    req->headers_owned = 1;

    /* ── Observability: trace ID + request start timestamp ── */
    {
        static uint64_t s_trace_ctr = 0;
        const uint64_t tid = ++s_trace_ctr;
        snprintf(req->trace_id, sizeof(req->trace_id),
                 "%016llx", (unsigned long long)tid);
        req->start_us = routa_now_us();
    }

    ret = 0;

done:
    free(data);
    if (ret != 0) http_request_free(req);
    return ret;
}

/* Deep-copies everything build_forward_request() reads (method, path,
 * query, headers, body) so a proxy_ctx_t can retry a request against a
 * different upstream node after the original req has already been freed
 * by the caller (see proxy.c's async connect-retry path). Does NOT copy
 * query_params[] (unused by the forwarding path) or remote_ip/trace_id
 * (retry keeps using the values already stored elsewhere in proxy_ctx_t).
 * Returns 0 on success, -1 on allocation failure (partial state is safe
 * to pass to http_request_free()). */
int http_request_clone(const http_request_t *src, http_request_t *dst) {
    if (!src || !dst) return -1;
    memset(dst, 0, sizeof(*dst));

    dst->method         = src->method;
    dst->version_major  = src->version_major;
    dst->version_minor  = src->version_minor;
    dst->keep_alive     = src->keep_alive;
    dst->body_len       = src->body_len;
    dst->headers_owned  = 1;   /* clone always owns its own header strings */
    memcpy(dst->remote_ip, src->remote_ip, sizeof(dst->remote_ip));
    memcpy(dst->trace_id,  src->trace_id,  sizeof(dst->trace_id));
    dst->start_us       = src->start_us;

    if (src->path) {
        dst->path = strdup(src->path);
        if (!dst->path) return -1;
    }
    if (src->query) {
        dst->query = strdup(src->query);
        if (!dst->query) return -1;
    }
    if (src->body && src->body_len > 0) {
        dst->body = malloc(src->body_len);
        if (!dst->body) return -1;
        memcpy(dst->body, src->body, src->body_len);
    }

    dst->header_count = src->header_count;
    for (int i = 0; i < src->header_count; i++) {
        dst->headers[i].key = src->headers[i].key ? strdup(src->headers[i].key) : NULL;
        dst->headers[i].value = src->headers[i].value ? strdup(src->headers[i].value) : NULL;
        if (src->headers[i].key && !dst->headers[i].key) return -1;
        if (src->headers[i].value && !dst->headers[i].value) return -1;
    }
    return 0;
}

void http_request_free(http_request_t *req) {
    if (!req) return;
    free(req->path);
    free(req->query);
    for (int i = 0; i < req->query_param_count; i++) {
        free(req->query_params[i].key);
        free(req->query_params[i].value);
    }
    free(req->body);
    if (req->headers_owned) {
        for (int i = 0; i < req->header_count; i++) {
            free(req->headers[i].key);
            free(req->headers[i].value);
        }
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
