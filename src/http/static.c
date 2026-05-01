#define _GNU_SOURCE
#include "http/static.h"
#include "http/response.h"
#include "util/logger.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

// MIME type mapping
static const struct {
    const char *ext;
    const char *mime;
} mime_types[] = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},
    {".txt", "text/plain"},
    {".pdf", "application/pdf"},
    {NULL, "application/octet-stream"}
};

static const char *get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "application/octet-stream";
    
    for (int i = 0; mime_types[i].ext; i++) {
        if (strcasecmp(dot, mime_types[i].ext) == 0) {
            return mime_types[i].mime;
        }
    }
    return "application/octet-stream";
}

static char *format_time(time_t t) {
    static char buf[100];
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
    return buf;
}

int static_serve(const http_request_t *req, http_response_t *resp,
                 const static_config_t *cfg) {
    if (!req || !resp || !cfg) return -1;
    
    // Only handle GET and HEAD methods
    if (req->method != HTTP_GET && req->method != HTTP_HEAD) {
        http_response_set_status(resp, 405, "Method Not Allowed");
        return 0;
    }
    
    // Strip url_prefix from req->path to get relative path
    size_t prefix_len = strlen(cfg->url_prefix);
    const char *req_path = req->path;
    
    // Handle root prefix case
    if (prefix_len == 1 && cfg->url_prefix[0] == '/') {
        // For root prefix, use path as-is (skip leading slash)
        req_path = req->path + 1;
    } else if (strncmp(req->path, cfg->url_prefix, prefix_len) == 0) {
        // Check if prefix matches exactly or is followed by /
        if (req->path[prefix_len] == '\0' || req->path[prefix_len] == '/') {
            // Skip the prefix and any leading slash
            req_path = req->path + prefix_len;
            if (*req_path == '/') req_path++;
        } else {
            // Prefix doesn't match properly
            http_response_set_status(resp, 404, "Not Found");
            http_response_set_body(resp, "Not Found\n", 10);
            return 0;
        }
    } else {
        // Path doesn't start with prefix
        http_response_set_status(resp, 404, "Not Found");
        http_response_set_body(resp, "Not Found\n", 10);
        return 0;
    }
    
    // Build full path
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s/%s", cfg->doc_root, req_path);
    
    // Resolve real path
    char resolved[1024];
    if (!realpath(full_path, resolved)) {
        http_response_set_status(resp, 404, "Not Found");
        http_response_set_body(resp, "Not Found\n", 10);
        return 0;
    }
    
    // Security check: ensure path is under doc_root
    if (strncmp(resolved, cfg->doc_root, strlen(cfg->doc_root)) != 0 ||
        (resolved[strlen(cfg->doc_root)] != '/' && resolved[strlen(cfg->doc_root)] != '\0')) {
        http_response_set_status(resp, 403, "Forbidden");
        http_response_set_body(resp, "Forbidden\n", 10);
        return 0;
    }
    
    // Stat the file
    struct stat st;
    if (stat(resolved, &st) < 0) {
        http_response_set_status(resp, 404, "Not Found");
        http_response_set_body(resp, "Not Found\n", 10);
        return 0;
    }
    
    // Handle directories
    if (S_ISDIR(st.st_mode)) {
        if (cfg->enable_index) {
            // Try index.html
            char index_path[1024];
            snprintf(index_path, sizeof(index_path), "%s/index.html", resolved);
            
            if (stat(index_path, &st) == 0 && S_ISREG(st.st_mode)) {
                strcpy(resolved, index_path);
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
    
    // Ensure we have a regular file now
    if (!S_ISREG(st.st_mode)) {
        http_response_set_status(resp, 404, "Not Found");
        http_response_set_body(resp, "Not Found\n", 10);
        return 0;
    }
    
    // Open file
    FILE *file = fopen(resolved, "rb");
    if (!file) {
        http_response_set_status(resp, 404, "Not Found");
        http_response_set_body(resp, "Not Found\n", 10);
        return 0;
    }
    
    // Read file content
    char *content = malloc(st.st_size);
    if (!content) {
        fclose(file);
        http_response_set_status(resp, 500, "Internal Server Error");
        return -1;
    }
    
    size_t bytes_read = fread(content, 1, st.st_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)st.st_size) {
        free(content);
        http_response_set_status(resp, 500, "Internal Server Error");
        return -1;
    }
    
    // Set response
    http_response_set_status(resp, 200, "OK");
    http_response_set_header(resp, "Content-Type", get_mime_type(resolved));
    http_response_set_header(resp, "Last-Modified", format_time(st.st_mtime));
    
    // For HEAD requests, just set content length but don't send body
    if (req->method == HTTP_HEAD) {
        char len_str[32];
        snprintf(len_str, sizeof(len_str), "%zu", st.st_size);
        http_response_set_header(resp, "Content-Length", len_str);
        free(content);
    } else {
        http_response_set_body(resp, content, st.st_size);
        // http_response_set_body copies the data, so we can free our buffer
        free(content);
    }
    
    return 0;
}
