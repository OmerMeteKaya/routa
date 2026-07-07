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

    /* pools[0] starts pre-initialized so a config with no [pool ...]
     * sections at all (just a bare `upstream` line, legacy style) still
     * gets sane pool defaults without the parser needing to call
     * lb_pool_config_init() explicitly before seeing the first upstream
     * line -- see routa_config_load(). */
    lb_pool_config_init(&cfg->pools[0]);
    cfg->pool_count = 0;   /* becomes 1 as soon as anything targets pools[0] */

    /* ── Middleware defaults ── */
    cfg->logger_enabled   = 1;
    cfg->compress_enabled = 1;
    cfg->compress_min_size = 256;
    cfg->compress_level    = 6;

    cfg->cors_enabled = 0;
    strncpy(cfg->cors_origin,  "*", sizeof(cfg->cors_origin) - 1);
    strncpy(cfg->cors_methods, "GET,POST,PUT,DELETE,OPTIONS", sizeof(cfg->cors_methods) - 1);
    strncpy(cfg->cors_headers, "Content-Type,Authorization", sizeof(cfg->cors_headers) - 1);

    cfg->auth_basic_enabled = 0;
    strncpy(cfg->auth_basic_realm, "Restricted", sizeof(cfg->auth_basic_realm) - 1);
    cfg->auth_basic_user_count = 0;

    cfg->auth_jwt_enabled     = 0;
    cfg->auth_jwt_verify_exp  = 1;

    cfg->rate_limit_enabled            = 0;
    cfg->rate_limit_requests_per_second = 100;
    cfg->rate_limit_burst              = 200;

    cfg->metrics_enabled = 1;
    strncpy(cfg->metrics_path, "/metrics", sizeof(cfg->metrics_path) - 1);
}

void lb_pool_config_init(lb_pool_config_t *pool) {
    memset(pool, 0, sizeof(*pool));
    pool->lb_algo                     = CFG_LB_ROUND_ROBIN;
    strncpy(pool->route, "/*", sizeof(pool->route) - 1);
    pool->lb_pool_max_per_node        = 64;
    pool->lb_pool_connect_timeout_ms  = 2000;
    pool->lb_upstream_read_timeout_ms  = 30000;
    pool->lb_upstream_write_timeout_ms = 30000;
    pool->lb_pool_idle_timeout_s      = 60;
    pool->lb_passive_fail_threshold   = 3;
    pool->lb_passive_recover_threshold = 2;
    pool->lb_max_retries              = 1;
    pool->lb_retry_on_5xx             = 0;
    pool->lb_consistent_hash_vnodes   = 150;
    pool->lb_hc_type                  = CFG_HC_NONE;
    strncpy(pool->lb_hc_path, "/health", sizeof(pool->lb_hc_path) - 1);
    pool->lb_hc_interval_ms           = 5000;
    pool->lb_hc_timeout_ms            = 2000;
    pool->lb_hc_threshold_up          = 2;
    pool->lb_hc_threshold_down        = 3;
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
    /* Trim leading whitespace by advancing the pointer... */
    while (*s && isspace((unsigned char)*s)) s++;
    size_t slen = strlen(s);
    if (slen == 0) return s;
    /* ...then trim trailing whitespace in place. */
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
    int active_pool = -1;   /* index into cfg->pools[], -1 = none yet */

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = trim(line);
        if (*s == '#' || *s == '\0') continue;

        /* [pool NAME] section header: starts a new pool. Every subsequent
         * lb_* / upstream line applies to this pool until the next
         * [pool ...] line or EOF. */
        if (*s == '[') {
            char *close = strchr(s, ']');
            if (!close) {
                LOG_WARN("config:%d: unterminated section header: %s", lineno, s);
                continue;
            }
            *close = '\0';
            char *inner = trim(s + 1);
            if (strncmp(inner, "pool", 4) == 0 &&
                (inner[4] == '\0' || isspace((unsigned char)inner[4]))) {
                char *name = trim(inner + 4);
                if (cfg->pool_count >= ROUTA_MAX_LB_POOLS) {
                    LOG_ERROR("config:%d: max %d [pool] sections exceeded, ignoring '%s'",
                              lineno, ROUTA_MAX_LB_POOLS, name);
                    active_pool = -1;
                    continue;
                }
                active_pool = cfg->pool_count++;
                lb_pool_config_init(&cfg->pools[active_pool]);
                strncpy(cfg->pools[active_pool].name, name,
                       sizeof(cfg->pools[active_pool].name) - 1);
                cfg->pools[active_pool].lb_enabled = 1;
            } else {
                LOG_WARN("config:%d: unknown section '[%s]'", lineno, inner);
                active_pool = -1;
            }
            continue;
        }

        /* upstream HOST:PORT [weight=N] -- not key=value, handle before
         * the generic '=' split. https:// prefix marks a TLS/H2 upstream. */
        if (strncmp(s, "upstream", 8) == 0 &&
            (s[8] == '\0' || isspace((unsigned char)s[8]))) {
            int pool_idx = (active_pool >= 0) ? active_pool : 0;
            if (active_pool < 0 && cfg->pool_count == 0) {
                cfg->pools[0].lb_enabled = 1;
                cfg->pool_count = 1;
            }
            lb_pool_config_t *pool = &cfg->pools[pool_idx];

            char *rest = s + 8;
            while (*rest && isspace((unsigned char)*rest)) rest++;  /* trim() only trims the right side */
            rest = trim(rest);
            int use_tls = 0;
            if (strncmp(rest, "https://", 8) == 0) {
                use_tls = 1;
                rest += 8;
            } else if (strncmp(rest, "http://", 7) == 0) {
                rest += 7;
            }

            char *space = rest;
            while (*space && !isspace((unsigned char)*space)) space++;
            int had_space = (*space != '\0');
            if (had_space) *space = '\0';
            char *hostport = rest;
            char *weight_part = had_space ? trim(space + 1) : NULL;

            char *colon = strrchr(hostport, ':');
            if (!colon) {
                LOG_WARN("config:%d: upstream missing ':port': %s", lineno, hostport);
                continue;
            }
            *colon = '\0';
            char *host = hostport;
            int   port = cfg_atoi(colon + 1, 0);
            if (port <= 0 || port > 65535) {
                LOG_WARN("config:%d: upstream invalid port: %s", lineno, colon + 1);
                continue;
            }

            int weight = 1;
            if (weight_part && strncmp(weight_part, "weight=", 7) == 0) {
                weight = cfg_atoi(weight_part + 7, 1);
            }

            if (pool->upstream_count >= ROUTA_MAX_UPSTREAMS) {
                LOG_ERROR("config:%d: max %d upstreams per pool exceeded",
                          lineno, ROUTA_MAX_UPSTREAMS);
                continue;
            }
            int ui = pool->upstream_count++;
            strncpy(pool->upstreams[ui].host, host,
                   sizeof(pool->upstreams[ui].host) - 1);
            pool->upstreams[ui].port    = port;
            pool->upstreams[ui].weight  = weight;
            pool->upstreams[ui].use_tls = use_tls;
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) {
            LOG_WARN("config:%d: missing '=' in line: %s", lineno, s);
            continue;
        }
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        strip_quotes(val);

        /* lb_* keys apply to the active pool, or the implicit legacy pool
         * (pools[0]) if no [pool ...] section has been seen yet. */
        if (strncmp(key, "lb_", 3) == 0) {
            int pool_idx = (active_pool >= 0) ? active_pool : 0;
            if (active_pool < 0 && cfg->pool_count == 0) {
                cfg->pools[0].lb_enabled = 1;
                cfg->pool_count = 1;
            }
            lb_pool_config_t *pool = &cfg->pools[pool_idx];

            if (strcmp(key, "lb_route") == 0) {
                strncpy(pool->route, val, sizeof(pool->route) - 1);
            } else if (strcmp(key, "lb_algo") == 0) {
                if (strcasecmp(val, "round_robin") == 0)       pool->lb_algo = CFG_LB_ROUND_ROBIN;
                else if (strcasecmp(val, "weighted_rr") == 0)  pool->lb_algo = CFG_LB_WEIGHTED_RR;
                else if (strcasecmp(val, "least_conn") == 0)   pool->lb_algo = CFG_LB_LEAST_CONN;
                else if (strcasecmp(val, "ip_hash") == 0)      pool->lb_algo = CFG_LB_IP_HASH;
                else if (strcasecmp(val, "random") == 0)       pool->lb_algo = CFG_LB_RANDOM;
                else if (strcasecmp(val, "p2c") == 0)          pool->lb_algo = CFG_LB_P2C;
                else if (strcasecmp(val, "consistent_hash") == 0) pool->lb_algo = CFG_LB_CONSISTENT_HASH;
                else pool->lb_algo = (cfg_lb_algo_t)cfg_atoi(val, CFG_LB_ROUND_ROBIN);
            } else if (strcmp(key, "lb_pool_max_per_node") == 0) {
                pool->lb_pool_max_per_node = cfg_atoi(val, 64);
            } else if (strcmp(key, "lb_pool_connect_timeout_ms") == 0) {
                pool->lb_pool_connect_timeout_ms = cfg_atoi(val, 2000);
            } else if (strcmp(key, "lb_upstream_read_timeout_ms") == 0) {
                pool->lb_upstream_read_timeout_ms = cfg_atoi(val, 30000);
            } else if (strcmp(key, "lb_upstream_write_timeout_ms") == 0) {
                pool->lb_upstream_write_timeout_ms = cfg_atoi(val, 30000);
            } else if (strcmp(key, "lb_pool_idle_timeout_s") == 0) {
                pool->lb_pool_idle_timeout_s = cfg_atoi(val, 60);
            } else if (strcmp(key, "lb_passive_fail_threshold") == 0) {
                pool->lb_passive_fail_threshold = cfg_atoi(val, 3);
            } else if (strcmp(key, "lb_passive_recover_threshold") == 0) {
                pool->lb_passive_recover_threshold = cfg_atoi(val, 2);
            } else if (strcmp(key, "lb_hc_type") == 0) {
                if (strcasecmp(val, "none") == 0)        pool->lb_hc_type = CFG_HC_NONE;
                else if (strcasecmp(val, "tcp") == 0)    pool->lb_hc_type = CFG_HC_TCP;
                else if (strcasecmp(val, "http") == 0)   pool->lb_hc_type = CFG_HC_HTTP;
                else if (strcasecmp(val, "custom") == 0) pool->lb_hc_type = CFG_HC_CUSTOM;
                else pool->lb_hc_type = (cfg_hc_type_t)cfg_atoi(val, CFG_HC_NONE);
            } else if (strcmp(key, "lb_hc_path") == 0) {
                strncpy(pool->lb_hc_path, val, sizeof(pool->lb_hc_path) - 1);
            } else if (strcmp(key, "lb_hc_interval_ms") == 0) {
                pool->lb_hc_interval_ms = cfg_atoi(val, 5000);
            } else if (strcmp(key, "lb_hc_timeout_ms") == 0) {
                pool->lb_hc_timeout_ms = cfg_atoi(val, 2000);
            } else if (strcmp(key, "lb_hc_threshold_up") == 0) {
                pool->lb_hc_threshold_up = cfg_atoi(val, 2);
            } else if (strcmp(key, "lb_hc_threshold_down") == 0) {
                pool->lb_hc_threshold_down = cfg_atoi(val, 3);
            } else if (strcmp(key, "lb_max_retries") == 0) {
                pool->lb_max_retries = cfg_atoi(val, 1);
            } else if (strcmp(key, "lb_retry_on_5xx") == 0) {
                pool->lb_retry_on_5xx = cfg_atoi(val, 0);
            } else if (strcmp(key, "lb_consistent_hash_vnodes") == 0) {
                pool->lb_consistent_hash_vnodes = cfg_atoi(val, 150);
            } else {
                LOG_WARN("config:%d: unknown lb_* key '%s'", lineno, key);
            }
            continue;
        }

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
        } else if (strcmp(key, "max_request_size") == 0) {
            cfg->max_request_size = cfg_atoi(val, 1048576);
        } else if (strcmp(key, "shutdown_timeout_ms") == 0) {
            cfg->shutdown_timeout_ms = cfg_atoi(val, 30000);
        } else if (strcmp(key, "h2_enabled") == 0) {
            cfg->h2.enabled = cfg_atoi(val, 1);
        } else if (strcmp(key, "h2_header_table_size") == 0) {
            cfg->h2.header_table_size = (uint32_t)cfg_atoi(val, 4096);
        } else if (strcmp(key, "h2_huffman_encoding") == 0) {
            cfg->h2.huffman_encoding = cfg_atoi(val, 1);
        } else if (strcmp(key, "h2_dynamic_table_update") == 0) {
            cfg->h2.dynamic_table_update = cfg_atoi(val, 1);
        } else if (strcmp(key, "h2_initial_window_size") == 0) {
            cfg->h2.initial_window_size = (uint32_t)cfg_atoi(val, 65535);
        } else if (strcmp(key, "h2_max_frame_size") == 0) {
            cfg->h2.max_frame_size = (uint32_t)cfg_atoi(val, 16384);
        } else if (strcmp(key, "h2_max_header_list_size") == 0) {
            cfg->h2.max_header_list_size = (uint32_t)cfg_atoi(val, 0);
        } else if (strcmp(key, "h2_max_concurrent_streams") == 0) {
            cfg->h2.max_concurrent_streams = (uint32_t)cfg_atoi(val, 128);
        } else if (strcmp(key, "h2_max_concurrent_streams_hard_cap") == 0) {
            cfg->h2.max_concurrent_streams_hard_cap = (uint32_t)cfg_atoi(val, 256);
        } else if (strcmp(key, "h2_stream_timeout_ms") == 0) {
            cfg->h2.stream_timeout_ms = cfg_atoi(val, 30000);
        } else if (strcmp(key, "h2_keepalive_timeout_ms") == 0) {
            cfg->h2.keepalive_timeout_ms = cfg_atoi(val, 120000);
        } else if (strcmp(key, "h2_server_push_enabled") == 0) {
            cfg->h2.server_push_enabled = cfg_atoi(val, 1);
        } else if (strcmp(key, "h2_c_upgrade_enabled") == 0) {
            cfg->h2.h2c_upgrade_enabled = cfg_atoi(val, 1);
        } else if (strcmp(key, "h2_stream_lookup") == 0) {
            if (strcasecmp(val, "linear") == 0)       cfg->h2.stream_lookup = H2_STREAM_LOOKUP_LINEAR;
            else if (strcasecmp(val, "hashmap") == 0) cfg->h2.stream_lookup = H2_STREAM_LOOKUP_HASHMAP;
            else cfg->h2.stream_lookup = (h2_stream_lookup_t)cfg_atoi(val, H2_STREAM_LOOKUP_LINEAR);

        /* ── Middleware ── */
        } else if (strcmp(key, "logger_enabled") == 0) {
            cfg->logger_enabled = cfg_atoi(val, 1);
        } else if (strcmp(key, "compress_enabled") == 0) {
            cfg->compress_enabled = cfg_atoi(val, 1);
        } else if (strcmp(key, "compress_min_size") == 0) {
            cfg->compress_min_size = (size_t)cfg_atoi(val, 256);
        } else if (strcmp(key, "compress_level") == 0) {
            cfg->compress_level = cfg_atoi(val, 6);
        } else if (strcmp(key, "cors_enabled") == 0) {
            cfg->cors_enabled = cfg_atoi(val, 0);
        } else if (strcmp(key, "cors_origin") == 0) {
            strncpy(cfg->cors_origin, val, sizeof(cfg->cors_origin) - 1);
        } else if (strcmp(key, "cors_methods") == 0) {
            strncpy(cfg->cors_methods, val, sizeof(cfg->cors_methods) - 1);
        } else if (strcmp(key, "cors_headers") == 0) {
            strncpy(cfg->cors_headers, val, sizeof(cfg->cors_headers) - 1);
        } else if (strcmp(key, "auth_basic_enabled") == 0) {
            cfg->auth_basic_enabled = cfg_atoi(val, 0);
        } else if (strcmp(key, "auth_basic_realm") == 0) {
            strncpy(cfg->auth_basic_realm, val, sizeof(cfg->auth_basic_realm) - 1);
        } else if (strcmp(key, "auth_basic_user") == 0) {
            /* Format: username:password */
            char *colon = strchr(val, ':');
            if (!colon) {
                LOG_WARN("config:%d: auth_basic_user missing ':password': %s", lineno, val);
            } else if (cfg->auth_basic_user_count >= 32) {
                LOG_ERROR("config:%d: max 32 auth_basic_user entries exceeded", lineno);
            } else {
                *colon = '\0';
                int ui = cfg->auth_basic_user_count++;
                strncpy(cfg->auth_basic_users[ui].username, val,
                       sizeof(cfg->auth_basic_users[ui].username) - 1);
                strncpy(cfg->auth_basic_users[ui].password, colon + 1,
                       sizeof(cfg->auth_basic_users[ui].password) - 1);
            }
        } else if (strcmp(key, "auth_jwt_enabled") == 0) {
            cfg->auth_jwt_enabled = cfg_atoi(val, 0);
        } else if (strcmp(key, "auth_jwt_secret") == 0) {
            strncpy(cfg->auth_jwt_secret, val, sizeof(cfg->auth_jwt_secret) - 1);
        } else if (strcmp(key, "auth_jwt_pubkey_path") == 0) {
            strncpy(cfg->auth_jwt_pubkey_path, val, sizeof(cfg->auth_jwt_pubkey_path) - 1);
        } else if (strcmp(key, "auth_jwt_verify_exp") == 0) {
            cfg->auth_jwt_verify_exp = cfg_atoi(val, 1);
        } else if (strcmp(key, "auth_jwt_issuer") == 0) {
            strncpy(cfg->auth_jwt_issuer, val, sizeof(cfg->auth_jwt_issuer) - 1);
        } else if (strcmp(key, "auth_jwt_audience") == 0) {
            strncpy(cfg->auth_jwt_audience, val, sizeof(cfg->auth_jwt_audience) - 1);
        } else if (strcmp(key, "rate_limit_enabled") == 0) {
            cfg->rate_limit_enabled = cfg_atoi(val, 0);
        } else if (strcmp(key, "rate_limit_requests_per_second") == 0) {
            cfg->rate_limit_requests_per_second = cfg_atoi(val, 100);
        } else if (strcmp(key, "rate_limit_burst") == 0) {
            cfg->rate_limit_burst = cfg_atoi(val, 200);
        } else if (strcmp(key, "metrics_enabled") == 0) {
            cfg->metrics_enabled = cfg_atoi(val, 1);
        } else if (strcmp(key, "metrics_path") == 0) {
            strncpy(cfg->metrics_path, val, sizeof(cfg->metrics_path) - 1);
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
