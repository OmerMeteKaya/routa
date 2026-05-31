#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../include/core/config.h"
#include "util/logger.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#define H2_INITIAL_WINDOW_SIZE   (1 * 1024 * 1024)
#define H2_CONNECTION_WINDOW_SIZE (4 * 1024 * 1024)

/* Get CPU count for default n_workers */
#ifdef __linux__
#include <unistd.h>
#define GET_CPU_COUNT() (int)sysconf(_SC_NPROCESSORS_ONLN)
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
static int get_cpu_count(void) {
    int n = 1;
    size_t len = sizeof(n);
    sysctlbyname("hw.ncpu", &n, &len, NULL, 0);
    return n;
}
#define GET_CPU_COUNT() get_cpu_count()
#else
#define GET_CPU_COUNT() 4
#endif

void routa_config_init(routa_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->port                = 8080;
    cfg->n_workers           = GET_CPU_COUNT();
    cfg->backlog             = 128;
    cfg->tls_session_timeout = 3600;
    cfg->log_level           = 1; /* INFO */
    cfg->keepalive_timeout_ms = 30000;
    cfg->request_timeout_ms  = 10000;
    cfg->max_connections     = 10000;
    cfg->max_request_size    = 1048576; /* 1MB */
    cfg->cache_memory_mb     = 64;
    cfg->file_cache_enabled     = 1;
    cfg->file_cache_max_entries = 512;
    cfg->file_cache_ttl         = 5;
    cfg->file_cache_strategy    = 1; /* stat_ttl */
    cfg->h2.enabled                = 1;
    cfg->h2.header_table_size      = 4096;
    cfg->h2.huffman_encoding       = 1;
    cfg->h2.dynamic_table_update   = 1;
    cfg->h2.initial_window_size    = 1048576;
    cfg->h2.max_frame_size         = 65536;
    cfg->h2.max_header_list_size   = 0;
    cfg->h2.max_concurrent_streams = 128;
    cfg->h2.stream_timeout_ms      = 30000;
    cfg->h2.keepalive_timeout_ms   = 120000;
    cfg->h2.stream_lookup = H2_STREAM_LOOKUP_LINEAR;
    cfg->h2.max_concurrent_streams_hard_cap = 256;
    cfg->h2.server_push_enabled  = 1;
    cfg->h2.h2c_upgrade_enabled  = 1;
    cfg->shutdown_timeout_ms     = 30000;
}

/* ---- Simple line-based parser ---- */
/* Format:
     key = value
     # comment
   Sections not needed — flat key=value is enough for now.
   String values are unquoted or quoted with "".
   Example:
     port = 8443
     workers = 8
     tls_cert = /etc/routa/cert.pem
     tls_key  = /etc/routa/key.pem
     log_level = info
     keepalive_timeout = 30
     static_dir = / -> /var/www/html
     cache_memory_mb = 128
*/

static char *trim(char *s) {
    size_t slen = strlen(s);
    if (slen == 0) return s;
    char *end = s + slen - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static void strip_quotes(char *s) {
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len-1] == '"') {
        memmove(s, s+1, len-2);
        s[len-2] = '\0';
    }
}

static int cfg_atoi(const char *val, int default_val) {
    if (!val || !*val) return default_val;
    char *end;
    errno = 0;
    long n = strtol(val, &end, 10);
    if (errno != 0 || end == val || *end != '\0') return default_val;
    return (int)n;
}

static int parse_log_level(const char *val) {
    if (strcasecmp(val, "debug") == 0) return 0;
    if (strcasecmp(val, "info")  == 0) return 1;
    if (strcasecmp(val, "warn")  == 0) return 2;
    if (strcasecmp(val, "error") == 0) return 3;
    return cfg_atoi(val, 0);
}

int routa_config_load(routa_config_t *cfg, const char *path) {
    if (!path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open config file: %s", path);
        return -1;
    }

    char line[1024];
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = trim(line);
        if (*s == '#' || *s == '\0') continue;

        char *eq = strchr(s, '=');
        if (!eq) {
            LOG_WARN("config:%d: missing '=' in line: %s", lineno, s);
            continue;
        }
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        strip_quotes(val);

        if (strcmp(key, "port") == 0) {
            cfg->port =cfg_atoi(val, 8080);
        } else if (strcmp(key, "workers") == 0) {
            cfg->n_workers = cfg_atoi(val, 12);
        } else if (strcmp(key, "backlog") == 0) {
            cfg->backlog = cfg_atoi(val, 128);
        } else if (strcmp(key, "tls_cert") == 0) {
            strncpy(cfg->tls_cert, val, sizeof(cfg->tls_cert) - 1);
            cfg->tls_enabled = 1;
        } else if (strcmp(key, "tls_key") == 0) {
            strncpy(cfg->tls_key, val, sizeof(cfg->tls_key) - 1);
            cfg->tls_enabled = 1;
        } else if (strcmp(key, "log_level") == 0) {
            cfg->log_level = parse_log_level(val);
        } else if (strcmp(key, "log_file") == 0) {
            strncpy(cfg->log_file, val, sizeof(cfg->log_file) - 1);
        } else if (strcmp(key, "keepalive_timeout") == 0) {
            cfg->keepalive_timeout_ms = cfg_atoi(val, 30) * 1000;
        } else if (strcmp(key, "request_timeout") == 0) {
            cfg->request_timeout_ms = cfg_atoi(val, 10) * 1000;
        } else if (strcmp(key, "max_connections") == 0) {
            cfg->max_connections = cfg_atoi(val, 10000);
        } else if (strcmp(key, "cache_memory_mb") == 0) {
            cfg->cache_memory_mb = (size_t)cfg_atoi(val, 64);
        } else if (strcmp(key, "cache_dir") == 0) {
            strncpy(cfg->cache_dir, val, sizeof(cfg->cache_dir) - 1);
            cfg->cache_enabled = 1;
        } else if (strcmp(key, "static_dir") == 0) {
            /* Format: url_prefix -> doc_root */
            /* Example: / -> /var/www/html */
            if (cfg->static_count < ROUTA_MAX_STATIC) {
                char *arrow = strstr(val, "->");
                if (arrow) {
                    *arrow = '\0';
                    char *prefix  = trim(val);
                    char *docroot = trim(arrow + 2);
                    strncpy(cfg->static_dirs[cfg->static_count].url_prefix,
                          prefix,
                          sizeof(cfg->static_dirs[cfg->static_count].url_prefix) - 1);
                    strncpy(cfg->static_dirs[cfg->static_count].doc_root,
                            docroot,
                            sizeof(cfg->static_dirs[cfg->static_count].doc_root) - 1);
                    cfg->static_dirs[cfg->static_count].enable_index = 1;
                    cfg->static_count++;
                } else {
                    LOG_WARN("config:%d: static_dir missing '->': %s",
                             lineno, val);
                }
            }
        } else if (strcmp(key, "file_cache_enabled") == 0) {
            cfg->file_cache_enabled = cfg_atoi(val, 1);
        } else if (strcmp(key, "file_cache_entries") == 0) {
            cfg->file_cache_max_entries = cfg_atoi(val, 512);
        } else if (strcmp(key, "file_cache_ttl") == 0) {
            cfg->file_cache_ttl = cfg_atoi(val, 5);
        } else if (strcmp(key, "file_cache_strategy") == 0) {
            if (strcasecmp(val, "ttl") == 0)          cfg->file_cache_strategy = 0;
            else if (strcasecmp(val, "stat_ttl") == 0) cfg->file_cache_strategy = 1;
            else if (strcasecmp(val, "inotify") == 0)  cfg->file_cache_strategy = 2;
            else cfg->file_cache_strategy = cfg_atoi(val, 1);
        } else if (strcmp(key, "tls_session_timeout") == 0) {
            cfg->tls_session_timeout = cfg_atoi(val, 3600);
        } else if (strcmp(key, "tls_ocsp_response") == 0) {
            strncpy(cfg->tls_ocsp_response, val, sizeof(cfg->tls_ocsp_response) - 1);
        } else {
            LOG_WARN("config:%d: unknown key '%s'", lineno, key);
        }
    }

    (void)fclose(f);
    LOG_INFO("Config loaded from %s", path);
    return 0;
}

int routa_config_validate(const routa_config_t *cfg) {
    if (cfg->port < 1 || cfg->port > 65535) {
        LOG_ERROR("Invalid port: %d", cfg->port);
        return -1;
    }
    if (cfg->n_workers < 1 || cfg->n_workers > 256) {
        LOG_ERROR("Invalid workers: %d", cfg->n_workers);
        return -1;
    }
    if (cfg->tls_enabled) {
        if (cfg->tls_cert[0] == '\0' || cfg->tls_key[0] == '\0') {
            LOG_ERROR("TLS enabled but cert/key not set");
            return -1;
        }
    }
    return 0;
}

void routa_config_dump(const routa_config_t *cfg) {
    (void)fprintf(stderr, "=== routa config ===\n");
    (void)fprintf(stderr, "port            = %d\n", cfg->port);
    (void)fprintf(stderr, "workers         = %d\n", cfg->n_workers);
    (void)fprintf(stderr, "tls_enabled     = %d\n", cfg->tls_enabled);
    (void)fprintf(stderr, "log_level       = %d\n", cfg->log_level);
    (void)fprintf(stderr, "keepalive_ms    = %d\n", cfg->keepalive_timeout_ms);
    (void)fprintf(stderr, "max_connections = %d\n", cfg->max_connections);
    (void)fprintf(stderr, "cache_mb        = %zu\n", (size_t)cfg->cache_memory_mb);
    for (int i = 0; i < cfg->static_count; i++) {
        (void)fprintf(stderr, "static_dir[%d]  = %s -> %s\n", i,
                cfg->static_dirs[i].url_prefix,
                cfg->static_dirs[i].doc_root);
    }
    (void)fprintf(stderr, "====================\n");
}

int routa_config_reload(const char *path,
                        const routa_config_t *current,
                        routa_config_t *out) {
    routa_config_init(out);
    if (routa_config_load(out, path) < 0) return -1;
    if (routa_config_validate(out) < 0)   return -1;

    /* Enforce restart-only fields: silently preserve current values */
    if (out->port != current->port) {
        LOG_WARN("hot reload: port change requires restart, keeping %d", current->port);
        out->port = current->port;
    }
    if (out->n_workers != current->n_workers) {
        LOG_WARN("hot reload: worker count change requires restart, keeping %d",
                 current->n_workers);
        out->n_workers = current->n_workers;
    }
    return 0;
}
