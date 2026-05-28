#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/response.h"
#include "util/logger.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

void http_response_init(http_response_t *r) {
    if (!r) return;
    memset(r, 0, sizeof(http_response_t)); // NOLINT(clang-analyzer-unix.Malloc)
    r->body_fd = -1;
}

int http_chunk_append(buf_t *out, const void *data, size_t len) {
    if (!out) return -1;

    if (len == 0) {
        return buf_append(out, "0\r\n\r\n", 5);
    }
    char prefix[24];
    int plen = snprintf(prefix, sizeof(prefix), "%zx\r\n", len);
    if (buf_append(out, prefix, (size_t)plen) < 0) return -1;
    if (buf_append(out, data, len) < 0) return -1;
    return buf_append(out, "\r\n", 2);
}

void http_response_set_status(http_response_t *r, int status, const char *reason) {
    if (!r) return;
    r->status = status;
    r->reason = (char *)reason;
}

void http_response_set_header(http_response_t *r, const char *key, const char *val) {
    if (!r || !key || !val) return;
    if (r->header_count >= 32) return;

    strncpy(r->headers[r->header_count][0], key, sizeof(r->headers[0][0]) - 1);
    r->headers[r->header_count][0][sizeof(r->headers[0][0]) - 1] = '\0';

    strncpy(r->headers[r->header_count][1], val, sizeof(r->headers[0][1]) - 1);
    r->headers[r->header_count][1][sizeof(r->headers[0][1]) - 1] = '\0';  // NOLINT(clang-analyzer-unix.Malloc)

    r->header_count++;
}

void http_response_set_body(http_response_t *r, const char *data, size_t len) {
    if (!r) return;

    if (r->body_fd >= 0) {
        close(r->body_fd);
        r->body_fd = -1;
    }
    free(r->body);
    r->body = NULL;
    r->body_len = 0;

    if (!data || len == 0) return;

    r->body = malloc(len);
    if (!r->body) return;

    memcpy(r->body, data, len);
    r->body_len = len;

    // Only set Content-Length if not using chunked encoding
    if (!r->chunked) {
        char cl[32];
        (void)snprintf(cl, sizeof(cl), "%zu", len);
        http_response_set_header(r, "Content-Length", cl);
    }
}

void http_response_set_body_fd(http_response_t *r, int fd, off_t offset, size_t len) {
    if (!r) return;

    if (r->body_fd >= 0) close(r->body_fd);
    free(r->body);
    r->body = NULL;
    r->body_len = 0;

    r->body_fd = fd;
    r->body_fd_off = offset;
    r->body_fd_len = len;

    char cl[32];
    (void)snprintf(cl, sizeof(cl), "%zu", len);
    http_response_set_header(r, "Content-Length", cl);
}

int http_response_serialize(const http_response_t *r, buf_t *out) {
    if (!r || !out) return -1;

    /* Date header */
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char date_str[64];
    (void)strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);

    /* Check which required headers already set */
    int has_date = 0, has_server = 0, has_connection = 0;
    int has_transfer_encoding = 0;
    for (int i = 0; i < r->header_count; i++) {
        if (strcasecmp(r->headers[i][0], "Date") == 0)              has_date = 1;
        if (strcasecmp(r->headers[i][0], "Server") == 0)            has_server = 1;
        if (strcasecmp(r->headers[i][0], "Connection") == 0)        has_connection = 1;
        if (strcasecmp(r->headers[i][0], "Transfer-Encoding") == 0) has_transfer_encoding = 1;
    }

    /* Status line */
    char status_line[256];
    int status_len = snprintf(status_line, sizeof(status_line),
                              "HTTP/1.1 %d %s\r\n",
                              r->status, r->reason ? r->reason : "Unknown");
    if (buf_append(out, status_line, (size_t)status_len) < 0) return -1;

    /* Required headers first */
    if (!has_date) {
        char dh[128];
        int dl = snprintf(dh, sizeof(dh), "Date: %s\r\n", date_str);
        if (buf_append(out, dh, (size_t)dl) < 0) return -1;
    }
    if (!has_server) {
        if (buf_append(out, "Server: routa/0.1\r\n", 19) < 0) return -1;
    }
    if (!has_connection) {
        if (buf_append(out, "Connection: close\r\n", 19) < 0) return -1;
    }

    /* Handle chunked encoding */
    if (r->chunked) {
        if (!has_transfer_encoding) {
            if (buf_append(out, "Transfer-Encoding: chunked\r\n", 28) < 0) return -1;
        }
    }

    /* All headers set by caller */
    for (int i = 0; i < r->header_count; i++) {
        // Skip Content-Length header when using chunked encoding
        if (r->chunked && strcasecmp(r->headers[i][0], "Content-Length") == 0) {
            continue;
        }
        
        char hl[512];
        int hl_len = snprintf(hl, sizeof(hl), "%s: %s\r\n",
                              r->headers[i][0], r->headers[i][1]);
        if (buf_append(out, hl, (size_t)hl_len) < 0) return -1;
    }

    /* End of headers */
    if (buf_append(out, "\r\n", 2) < 0) return -1;

    /* Body */
    if (r->chunked) {
        // For chunked encoding with body data
        if (r->body && r->body_len > 0) {
            if (http_chunk_append(out, r->body, r->body_len) < 0) return -1;
        }
        // Always add terminating chunk for chunked encoding
        if (http_chunk_append(out, NULL, 0) < 0) return -1;
    } else {
        // Non-chunked encoding
        if (r->body && r->body_len > 0) {
            if (buf_append(out, r->body, r->body_len) < 0) return -1;
        }
    }
    /* If body_fd >= 0: headers only, caller uses sendfile() for body */

    return 0;
}

void http_response_destroy(http_response_t *r) {
    if (!r) return;
    free(r->body);
    if (r->body_fd >= 0) {
        close(r->body_fd);
        r->body_fd = -1;
    }
    memset(r, 0, sizeof(http_response_t));
    r->body_fd = -1;
}

int http_response_simple(buf_t *out, int status, const char *reason,
                         const char *content_type, const char *body) {
    if (!out) return -1;

    http_response_t resp;
    http_response_init(&resp);
    http_response_set_status(&resp, status, reason);

    if (content_type)
        http_response_set_header(&resp, "Content-Type", content_type);

    if (body)
        http_response_set_body(&resp, body, strlen(body));

    int result = http_response_serialize(&resp, out);
    http_response_destroy(&resp);
    return result;
}

int http_response_send(const http_response_t *r, int client_fd, tls_conn_t *tls) {
    (void)tls;
    buf_t tmp;
    buf_init(&tmp);
    if (http_response_serialize(r, &tmp) < 0) {
        buf_free(&tmp);
        return -1;
    }
    ssize_t written = 0;
    while ((size_t)written < tmp.len) {
        ssize_t n = write(client_fd, tmp.data + written, tmp.len - (size_t)written);
        if (n < 0) { buf_free(&tmp); return -1; }
        written += n;
    }
    buf_free(&tmp);
    return 0;
}
