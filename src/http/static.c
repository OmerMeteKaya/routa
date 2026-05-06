#define _GNU_SOURCE
#include "http/static.h"
#include "http/response.h"
#include "util/logger.h"
#include "http/file_cache.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

static const struct {
    const char *ext;
    const char *mime;
} mime_types[] = {
    {".html", "text/html"},
    {".htm",  "text/html"},
    {".css",  "text/css"},
    {".js",   "application/javascript"},
    {".json", "application/json"},
    {".png",  "image/png"},
    {".jpg",  "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif",  "image/gif"},
    {".svg",  "image/svg+xml"},
    {".ico",  "image/x-icon"},
    {".txt",  "text/plain"},
    {".pdf",  "application/pdf"},
    {NULL,    "application/octet-stream"}
};

static const char *get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "application/octet-stream";
    for (int i = 0; mime_types[i].ext; i++)
        if (strcasecmp(dot, mime_types[i].ext) == 0)
            return mime_types[i].mime;
    return "application/octet-stream";
}

int static_serve(const http_request_t *req, http_response_t *resp,
                 const static_config_t *cfg) {
    if (!req || !resp || !cfg) return -1;

    if (req->method != HTTP_GET && req->method != HTTP_HEAD) {
        http_response_set_status(resp, 405, "Method Not Allowed");
        return 0;
    }

    size_t prefix_len = strlen(cfg->url_prefix);
    const char *req_path = req->path;

    if (prefix_len == 1 && cfg->url_prefix[0] == '/') {
        req_path = req->path + 1;
    } else if (strncmp(req->path, cfg->url_prefix, prefix_len) == 0) {
        if (req->path[prefix_len] == '\0' || req->path[prefix_len] == '/') {
            req_path = req->path + prefix_len;
            if (*req_path == '/') req_path++;
        } else {
            http_response_set_status(resp, 404, "Not Found");
            http_response_set_body(resp, "Not Found\n", 10);
            return 0;
        }
    } else {
        http_response_set_status(resp, 404, "Not Found");
        http_response_set_body(resp, "Not Found\n", 10);
        return 0;
    }

    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s/%s", cfg->doc_root, req_path);

    char resolved[1024];
    char etag[64];
    char last_modified[64];
    struct stat st;

    /* Try cache first */
    file_cache_entry_t cached;
    if (file_cache_get(req->path, &cached)) {
        memcpy(resolved,      cached.resolved,      sizeof(resolved));
        memcpy(etag,          cached.etag,          sizeof(etag));
        memcpy(last_modified, cached.last_modified, sizeof(last_modified));
        resolved[sizeof(resolved) - 1]           = '\0';
        etag[sizeof(etag) - 1]                   = '\0';
        last_modified[sizeof(last_modified) - 1] = '\0';
        st.st_size  = cached.size;
        st.st_mtime = cached.mtime;
    } else {
        /* Cache miss — full resolution */
        if (!realpath(full_path, resolved)) {
            http_response_set_status(resp, 404, "Not Found");
            http_response_set_body(resp, "Not Found\n", 10);
            return 0;
        }

        if (strncmp(resolved, cfg->doc_root, strlen(cfg->doc_root)) != 0 ||
            (resolved[strlen(cfg->doc_root)] != '/' &&
             resolved[strlen(cfg->doc_root)] != '\0')) {
            http_response_set_status(resp, 403, "Forbidden");
            http_response_set_body(resp, "Forbidden\n", 10);
            return 0;
        }

        if (stat(resolved, &st) < 0) {
            http_response_set_status(resp, 404, "Not Found");
            http_response_set_body(resp, "Not Found\n", 10);
            return 0;
        }

        if (S_ISDIR(st.st_mode)) {
            if (cfg->enable_index) {
                char index_path[1024];
                snprintf(index_path, sizeof(index_path) - 1,
                         "%.1000s/index.html", resolved);
                index_path[sizeof(index_path) - 1] = '\0';
                if (stat(index_path, &st) == 0 && S_ISREG(st.st_mode)) {
                    memcpy(resolved, index_path, sizeof(resolved));
                    resolved[sizeof(resolved) - 1] = '\0';
                } else {
                    http_response_set_status(resp, 403, "Forbidden");
                    http_response_set_body(resp, "Forbidden\n", 10);
                    return 0;
                }
            } else {
                http_response_set_status(resp, 403, "Forbidden");
                http_response_set_body(resp, "Forbidden\n", 10);
                return 0;
            }
        }

        if (!S_ISREG(st.st_mode)) {
            http_response_set_status(resp, 404, "Not Found");
            http_response_set_body(resp, "Not Found\n", 10);
            return 0;
        }

        /* Build ETag and Last-Modified */
        snprintf(etag, sizeof(etag), "\"%lx-%lx\"",
                 (unsigned long)st.st_mtime, (unsigned long)st.st_size);

        struct tm tm_buf;
        gmtime_r(&st.st_mtime, &tm_buf);
        strftime(last_modified, sizeof(last_modified),
                 "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);

        /* Store in cache */
        file_cache_entry_t new_entry;
        memset(&new_entry, 0, sizeof(new_entry));
        memcpy(new_entry.resolved,      resolved,      sizeof(new_entry.resolved));
        memcpy(new_entry.etag,          etag,          sizeof(new_entry.etag));
        memcpy(new_entry.last_modified, last_modified, sizeof(new_entry.last_modified));
        new_entry.resolved[sizeof(new_entry.resolved) - 1]           = '\0';
        new_entry.etag[sizeof(new_entry.etag) - 1]                   = '\0';
        new_entry.last_modified[sizeof(new_entry.last_modified) - 1] = '\0';
        strncpy(new_entry.mime_type,     get_mime_type(resolved),
                sizeof(new_entry.mime_type) - 1);
        new_entry.size  = st.st_size;
        new_entry.mtime = st.st_mtime;
        new_entry.valid = 1;
        file_cache_put(req->path, &new_entry);
    }

    /* Range request */
    off_t  range_start = 0;
    size_t range_len   = (size_t)st.st_size;
    int    is_range    = 0;

    const char *range_hdr = http_request_get_header(req, "Range");
    if (range_hdr && strncmp(range_hdr, "bytes=", 6) == 0) {
        const char *spec = range_hdr + 6;
        const char *dash = strchr(spec, '-');
        if (dash) {
            long long first = -1, last = -1;
            if (dash != spec)        first = atoll(spec);
            if (*(dash + 1) != '\0') last  = atoll(dash + 1);

            if (first < 0 && last > 0) {
                first = (long long)st.st_size - last;
                last  = (long long)st.st_size - 1;
            } else {
                if (first < 0) first = 0;
                if (last < 0 || last >= (long long)st.st_size)
                    last = (long long)st.st_size - 1;
            }

            if (first <= last && first < (long long)st.st_size) {
                range_start = (off_t)first;
                range_len   = (size_t)(last - first + 1);
                is_range    = 1;
            } else {
                char cr[64];
                snprintf(cr, sizeof(cr), "bytes */%lld", (long long)st.st_size);
                http_response_set_status(resp, 416, "Range Not Satisfiable");
                http_response_set_header(resp, "Content-Range", cr);
                return 0;
            }
        }
    }

    int fd = open(resolved, O_RDONLY);
    if (fd < 0) {
        http_response_set_status(resp, 500, "Internal Server Error");
        return 0;
    }

    http_response_set_header(resp, "Content-Type",   get_mime_type(resolved));
    http_response_set_header(resp, "Last-Modified",  last_modified);
    http_response_set_header(resp, "ETag",           etag);
    http_response_set_header(resp, "Accept-Ranges",  "bytes");

    if (is_range) {
        http_response_set_status(resp, 206, "Partial Content");
        char cr[128];
        snprintf(cr, sizeof(cr), "bytes %lld-%lld/%lld",
                 (long long)range_start,
                 (long long)((off_t)range_start + (off_t)range_len - 1),
                 (long long)st.st_size);
        http_response_set_header(resp, "Content-Range", cr);
    } else {
        http_response_set_status(resp, 200, "OK");
    }

    if (req->method == HTTP_HEAD) {
        char len_str[32];
        snprintf(len_str, sizeof(len_str), "%zu", range_len);
        http_response_set_header(resp, "Content-Length", len_str);
        close(fd);
    } else {
        http_response_set_body_fd(resp, fd, range_start, range_len);
    }

    return 0;
}
