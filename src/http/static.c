#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "http/static.h"
#include "http/response.h"
#include "util/logger.h"
#include "http/file_cache.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

/* ── MIME types ─────────────────────────────────────────────────────────── */
static const struct { const char *ext, *mime; } mime_types[] = {
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

/* ── Path resolution helpers ────────────────────────────────────────────── */
static int resolve_path(const http_request_t *req,
                        const static_config_t *cfg,
                        char *resolved, size_t resolved_sz,
                        struct stat *st)
{
    size_t      prefix_len = strlen(cfg->url_prefix);
    const char *req_path;

    if (prefix_len == 1 && cfg->url_prefix[0] == '/') {
        req_path = req->path + 1;
    } else if (strncmp(req->path, cfg->url_prefix, prefix_len) == 0) {
        if (req->path[prefix_len] == '\0' || req->path[prefix_len] == '/') {
            req_path = req->path + prefix_len;
            if (*req_path == '/') req_path++;
        } else {
            return 404;
        }
    } else {
        return 404;
    }

    char full_path[1024];
    (void)snprintf(full_path, sizeof(full_path), "%s/%s", cfg->doc_root, req_path);

    if (!realpath(full_path, resolved)) return 404;

    /* Path traversal guard */
    size_t root_len = strlen(cfg->doc_root);
    if (strncmp(resolved, cfg->doc_root, root_len) != 0 ||
        (resolved[root_len] != '/' && resolved[root_len] != '\0'))
        return 403;

    if (stat(resolved, st) < 0) return 404;

    if (S_ISDIR(st->st_mode)) {
        if (!cfg->enable_index) return 403;
        char idx[1024];
        (void)snprintf(idx, sizeof(idx), "%.1000s/index.html", resolved);
        if (stat(idx, st) != 0 || !S_ISREG(st->st_mode)) return 403;
        strncpy(resolved, idx, resolved_sz - 1);
        resolved[resolved_sz - 1] = '\0';
    }

    if (!S_ISREG(st->st_mode)) return 404;
    return 200;
}

/* ── Main handler ───────────────────────────────────────────────────────── */
int static_serve(const http_request_t *req, http_response_t *resp,
                 const static_config_t *cfg)
{
    if (!req || !resp || !cfg) return -1;

    if (req->method != HTTP_GET && req->method != HTTP_HEAD) {
        http_response_set_status(resp, 405, "Method Not Allowed");
        return 0;
    }

    char            resolved[1024];
    char            etag[64];
    char            last_modified[64];
    struct stat     st;
    const char     *mime     = NULL;
    int             from_cache = 0;
    void           *mmap_ptr  = NULL;   /* non-NULL = small file from cache */

    /* ── Cache lookup ── */
    file_cache_entry_t cached;
    if (file_cache_get(req->path, &cached)) {
        memcpy(resolved,      cached.resolved,      sizeof(resolved));
        memcpy(etag,          cached.etag,          sizeof(etag));
        memcpy(last_modified, cached.last_modified, sizeof(last_modified));
        resolved[sizeof(resolved)-1]           = '\0';
        etag[sizeof(etag)-1]                   = '\0';
        last_modified[sizeof(last_modified)-1] = '\0';
        st.st_size  = cached.size;
        st.st_mtime = cached.mtime;
        mime        = cached.mime_type[0] ? cached.mime_type
                                          : get_mime_type(resolved);
        mmap_ptr    = cached.data;   /* may be NULL for large files */
        from_cache  = 1;
    } else {
        /* ── Cache miss: resolve path ── */
        int code = resolve_path(req, cfg, resolved, sizeof(resolved), &st);
        if (code != 200) {
            const char *msg = (code == 403) ? "Forbidden\n" : "Not Found\n";
            const char *txt = (code == 403) ? "Forbidden"   : "Not Found";
            http_response_set_status(resp, code, txt);
            http_response_set_body(resp, msg, strlen(msg));
            return 0;
        }

        /* Build ETag and Last-Modified */
        (void)snprintf(etag, sizeof(etag), "\"%lx-%lx\"",
                 (unsigned long)st.st_mtime, (unsigned long)st.st_size);
        struct tm tm_buf;
        gmtime_r(&st.st_mtime, &tm_buf);
        (void)strftime(last_modified, sizeof(last_modified),
                 "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);

        mime = get_mime_type(resolved);

        /* ── mmap small files and cache the pointer ── */
        if ((size_t)st.st_size > 0 &&
            (size_t)st.st_size < (size_t)FILE_CACHE_MMAP_THRESHOLD) {

            int fd = open(resolved, O_RDONLY);
            if (fd >= 0) {
                void *ptr = mmap(NULL, (size_t)st.st_size,
                                 PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
                close(fd);   /* fd no longer needed after mmap */
                if (ptr != MAP_FAILED) {
                    mmap_ptr = ptr;
                    /* Advise sequential access for the page prefetcher */
                    madvise(ptr, (size_t)st.st_size, MADV_SEQUENTIAL);
                }
            }
        }

        /* Store in cache (with or without mmap ptr) */
        file_cache_entry_t new_entry;
        memset(&new_entry, 0, sizeof(new_entry));
        memcpy(new_entry.resolved,      resolved,      sizeof(new_entry.resolved));
        memcpy(new_entry.etag,          etag,          sizeof(new_entry.etag));
        memcpy(new_entry.last_modified, last_modified, sizeof(new_entry.last_modified));
        strncpy(new_entry.mime_type, mime, sizeof(new_entry.mime_type) - 1);
        new_entry.size     = st.st_size;
        new_entry.mtime    = st.st_mtime;
        new_entry.valid    = 1;
        new_entry.data     = mmap_ptr;
        new_entry.data_len = mmap_ptr ? (size_t)st.st_size : 0;
        file_cache_put(req->path, &new_entry);
    }

    /* ── Conditional request: ETag / If-None-Match ── */
    const char *inm = http_request_get_header(req, "If-None-Match");
    if (inm && strcmp(inm, etag) == 0) {
        http_response_set_status(resp, 304, "Not Modified");
        http_response_set_header(resp, "ETag",          etag);
        http_response_set_header(resp, "Last-Modified", last_modified);
        return 0;
    }

    /* ── Range parsing ── */
    off_t  range_start = 0;
    size_t range_len   = (size_t)st.st_size;
    int    is_range    = 0;

    const char *range_hdr = http_request_get_header(req, "Range");
    if (range_hdr && strncmp(range_hdr, "bytes=", 6) == 0) {
        const char *spec = range_hdr + 6;
        const char *dash = strchr(spec, '-');
        if (dash) {
            long long first = -1, last = -1;
            if (dash != spec)        first = strtoll(spec, NULL, 10);
            if (*(dash + 1) != '\0') last  = strtoll(dash + 1, NULL, 10);

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
                (void)snprintf(cr, sizeof(cr), "bytes */%lld", (long long)st.st_size);
                http_response_set_status(resp, 416, "Range Not Satisfiable");
                http_response_set_header(resp, "Content-Range", cr);
                return 0;
            }
        }
    }

    /* ── Common response headers ── */
    http_response_set_header(resp, "Content-Type",  mime);
    http_response_set_header(resp, "Last-Modified", last_modified);
    http_response_set_header(resp, "ETag",          etag);
    http_response_set_header(resp, "Accept-Ranges", "bytes");

    if (is_range) {
        http_response_set_status(resp, 206, "Partial Content");
        char cr[128];
        (void)snprintf(cr, sizeof(cr), "bytes %lld-%lld/%lld",
                 (long long)range_start,
                 (long long)(range_start + (off_t)range_len - 1),
                 (long long)st.st_size);
        http_response_set_header(resp, "Content-Range", cr);
    } else {
        http_response_set_status(resp, 200, "OK");
    }

    /* ── HEAD: no body ── */
    if (req->method == HTTP_HEAD) {
        char len_str[32];
        (void)snprintf(len_str, sizeof(len_str), "%zu", range_len);
        http_response_set_header(resp, "Content-Length", len_str);
        /* mmap_ptr stays owned by cache — do not munmap here */
        return 0;
    }

    /* ── Body: mmap path (small files) ── */
    if (mmap_ptr) {
        /* Serve directly from the mmap'd region.
         * The cache owns the pointer — we pass a slice into it.
         * http_response_set_body does a memcpy, so the cache pointer
         * remains valid after the response is serialized.              */
        const char *body_start = (const char *)mmap_ptr + range_start;
        http_response_set_body(resp, body_start, range_len);
        return 0;
    }

    /* ── Body: sendfile path (large files ≥ 64 KB) ── */
    int fd = open(resolved, O_RDONLY);
    if (fd < 0) {
        http_response_set_status(resp, 500, "Internal Server Error");
        return 0;
    }

    /* Cache miss for large file — store metadata only (data=NULL) */
    if (!from_cache) {
        /* already stored above; nothing extra needed */
    }

    http_response_set_body_fd(resp, fd, range_start, range_len);
    return 0;
}
