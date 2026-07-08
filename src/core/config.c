#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../include/core/config.h"
#include "util/logger.h"
#include "http/ws.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <glob.h>
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

    ws_config_init(&cfg->ws);

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

    cfg->acl_enabled       = 0;
    cfg->acl_default_allow = 1;
    cfg->acl_rule_count    = 0;
}

void apply_resource_profile(routa_config_t *cfg, resource_profile_t profile) {
    cfg->resource_profile = profile;

    if (profile == RESOURCE_PROFILE_BALANCED) {
        /* No-op: routa_config_init()'s hardcoded defaults already ARE
         * the balanced profile -- nothing to override. */
        return;
    }

    int cpu_count = GET_CPU_COUNT();
    if (cpu_count < 1) cpu_count = 1;

    if (profile == RESOURCE_PROFILE_LIGHT) {
        /* Weak/resource-constrained machines (e.g. laptops): fewer
         * workers, smaller caches, tighter connection limits, and
         * memory guard-rails enabled by default since such machines are
         * the most likely to actually run out of memory under load. */
        int workers = cpu_count / 2;
        if (workers < 1) workers = 1;
        cfg->n_workers                    = workers;
        cfg->cache_memory_mb              = 16;
        cfg->max_connections              = 1000;
        cfg->file_cache_max_entries       = 128;
        cfg->socket_recv_buf_size         = 0;   /* OS default */
        cfg->socket_send_buf_size         = 0;   /* OS default */
        cfg->cpu_affinity_enabled         = 0;   /* not worth it on few cores */
        cfg->numa_aware_enabled           = 0;
        cfg->memory_soft_limit_mb         = 512;
        cfg->memory_hard_limit_mb         = 1024;
        cfg->compress_level               = 3;   /* less CPU per request */
        cfg->keepalive_timeout_ms         = 15000;
    } else if (profile == RESOURCE_PROFILE_PERFORMANCE) {
        /* Large multi-core servers: many workers, big caches, high
         * connection ceiling, CPU/NUMA pinning on, memory limits left
         * disabled (operators at this scale typically already have
         * cgroups/systemd limits in place -- see the roadmap note on
         * per-worker memory limits being deferred for the same reason). */
        int workers = cpu_count * 2;
        cfg->n_workers                    = workers;
        cfg->cache_memory_mb              = 512;
        cfg->max_connections              = 100000;
        cfg->file_cache_max_entries       = 4096;
        cfg->socket_recv_buf_size         = 262144;
        cfg->socket_send_buf_size         = 262144;
        cfg->cpu_affinity_enabled         = 1;
        cfg->numa_aware_enabled           = 1;
        cfg->memory_soft_limit_mb         = 0;    /* disabled */
        cfg->memory_hard_limit_mb         = 0;    /* disabled */
        cfg->compress_level               = 9;    /* more CPU available, better ratio */
        cfg->keepalive_timeout_ms         = 60000;
    }
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
    pool->lb_half_open_retry_after_ms  = 30000;
    pool->lb_max_retries              = 1;
    pool->lb_retry_on_5xx             = 0;
    pool->lb_consistent_hash_vnodes   = 150;
    pool->lb_hc_type                  = CFG_HC_NONE;
    strncpy(pool->lb_hc_path, "/health", sizeof(pool->lb_hc_path) - 1);
    pool->lb_hc_interval_ms           = 5000;
    pool->lb_hc_timeout_ms            = 2000;
    pool->lb_hc_threshold_up          = 2;
    pool->lb_hc_threshold_down        = 3;

    pool->acl_enabled       = 0;
    pool->acl_default_allow = 1;
    pool->acl_rule_count    = 0;

    pool->sticky_session_enabled = 0;
    strncpy(pool->sticky_cookie_name, "routa_sticky", sizeof(pool->sticky_cookie_name) - 1);
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

/* Strips a trailing inline comment (a '#' not inside a quoted string) by
 * truncating the line there. Must run after trim()'s leading-whitespace
 * skip but before the "whole line is a comment" check, so lines like
 * `key = value   # comment` and section headers like `[pool NAME] # note`
 * both work -- previously only a comment as the FIRST non-whitespace
 * character on a line was recognized; anything after a real value was
 * parsed as part of that value (e.g. "1   # some note" failed cfg_atoi's
 * strict end-of-string check and silently fell back to the key's
 * default, with no warning). Quote-aware so a '#' inside a quoted value
 * (e.g. auth_basic_realm = "Team #1") is not mistaken for a comment. */
static void strip_inline_comment(char *s) {
    int in_quotes = 0;
    for (char *p = s; *p; p++) {
        if (*p == '"') { in_quotes = !in_quotes; continue; }
        if (*p == '#' && !in_quotes) {
            *p = '\0';
            break;
        }
    }
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

/* Accepts 0/1/true/false/yes/no/on/off (case-insensitive). Anything else
 * falls back to default_val, same "fail closed to a sane value" policy
 * as cfg_atoi(). This is the parser used for every boolean config key
 * (foo_enabled = ...) -- a single flexible parser rather than requiring
 * operators to remember that this project only accepts "1"/"0". */
static int cfg_atob(const char *val, int default_val) {
    if (!val || !*val) return default_val;
    if (strcasecmp(val, "1") == 0 || strcasecmp(val, "true") == 0 ||
        strcasecmp(val, "yes") == 0 || strcasecmp(val, "on") == 0)
        return 1;
    if (strcasecmp(val, "0") == 0 || strcasecmp(val, "false") == 0 ||
        strcasecmp(val, "no") == 0 || strcasecmp(val, "off") == 0)
        return 0;
    LOG_WARN("config: invalid boolean value '%s', using default", val);
    return default_val;
}

/* Parses a duration string with a MANDATORY unit suffix into
 * milliseconds: "ms" (milliseconds), "s" (seconds), "m" (minutes), "h"
 * (hours). A bare number with no suffix is rejected (returns
 * default_val with a warning) -- this is intentional: routa's config
 * used to silently mix "value is already ms" and "value is seconds,
 * multiply by 1000" conventions across different keys (operators had to
 * remember which), which is exactly the ambiguity requiring an explicit
 * unit on every duration eliminates. Examples: "500ms", "45s", "2m",
 * "1h". Whitespace between the number and unit is not allowed (matches
 * common config-format conventions, e.g. nginx). */
static int cfg_duration_ms(const char *val, int default_val) {
    if (!val || !*val) return default_val;

    char *end;
    errno = 0;
    double n = strtod(val, &end);
    if (errno != 0 || end == val || n < 0) {
        LOG_WARN("config: invalid duration '%s' (expected e.g. \"45s\", \"500ms\", \"2m\"), using default", val);
        return default_val;
    }

    double multiplier;
    if (strcmp(end, "ms") == 0)      multiplier = 1.0;
    else if (strcmp(end, "s") == 0)  multiplier = 1000.0;
    else if (strcmp(end, "m") == 0)  multiplier = 60.0 * 1000.0;
    else if (strcmp(end, "h") == 0)  multiplier = 60.0 * 60.0 * 1000.0;
    else {
        LOG_WARN("config: duration '%s' missing/unknown unit (expected ms/s/m/h), using default", val);
        return default_val;
    }

    return (int)(n * multiplier);
}

/* Same as cfg_duration_ms() but returns whole seconds (for the handful
 * of existing fields, like lb_pool_idle_timeout_s, whose runtime type
 * is already "seconds" rather than "milliseconds" -- this just divides
 * by 1000 rather than requiring every such call site to do that itself). */
static int cfg_duration_s(const char *val, int default_val) {
    int ms = cfg_duration_ms(val, default_val * 1000);
    return ms / 1000;
}

/* Parses a size string with a MANDATORY unit suffix into bytes: "B"
 * (bytes), "KB"/"K" (1024), "MB"/"M" (1024*1024), "GB"/"G"
 * (1024*1024*1024). Binary (1024-based) units, matching how these
 * values are actually used (buffer sizes, memory limits) rather than
 * decimal (1000-based) "marketing" units. A bare number with no suffix
 * is rejected, same rationale as cfg_duration_ms(). Examples: "256KB",
 * "64MB", "1GB", "512B". Case-insensitive suffix. */
static long long cfg_size_bytes(const char *val, long long default_val) {
    if (!val || !*val) return default_val;

    char *end;
    errno = 0;
    double n = strtod(val, &end);
    if (errno != 0 || end == val || n < 0) {
        LOG_WARN("config: invalid size '%s' (expected e.g. \"64MB\", \"256KB\"), using default", val);
        return default_val;
    }

    double multiplier;
    if (strcasecmp(end, "B") == 0)        multiplier = 1.0;
    else if (strcasecmp(end, "KB") == 0 || strcasecmp(end, "K") == 0)
        multiplier = 1024.0;
    else if (strcasecmp(end, "MB") == 0 || strcasecmp(end, "M") == 0)
        multiplier = 1024.0 * 1024.0;
    else if (strcasecmp(end, "GB") == 0 || strcasecmp(end, "G") == 0)
        multiplier = 1024.0 * 1024.0 * 1024.0;
    else {
        LOG_WARN("config: size '%s' missing/unknown unit (expected B/KB/MB/GB), using default", val);
        return default_val;
    }

    return (long long)(n * multiplier);
}

/* Same as cfg_size_bytes() but returns whole megabytes (for fields whose
 * runtime type is already "MB", e.g. cache_memory_mb/memory_*_limit_mb). */
static long long cfg_size_mb(const char *val, long long default_mb) {
    long long bytes = cfg_size_bytes(val, default_mb * 1024 * 1024);
    return bytes / (1024 * 1024);
}

/* Expands every "${VAR_NAME}" occurrence in-place (writing into out,
 * size out_sz) by looking VAR_NAME up via getenv(). An undefined
 * variable expands to an empty string (with a warning) rather than
 * failing the whole line -- consistent with most config-templating
 * tools' "missing var = empty" convention, and it keeps a single unset
 * env var from taking down config parsing entirely. Malformed
 * references (${ with no closing }) are left as literal text from that
 * point on. Truncates silently at out_sz if the expansion would
 * overflow (extremely unlikely for realistic config lines/values). */
static void expand_env_vars(const char *in, char *out, size_t out_sz) {
    size_t oi = 0;
    for (const char *p = in; *p && oi + 1 < out_sz; ) {
        if (p[0] == '$' && p[1] == '{') {
            const char *name_start = p + 2;
            const char *close = strchr(name_start, '}');
            if (close) {
                size_t name_len = (size_t)(close - name_start);
                if (name_len > 0 && name_len < 128) {
                    char name[128];
                    memcpy(name, name_start, name_len);
                    name[name_len] = '\0';
                    const char *val = getenv(name);
                    if (!val) {
                        LOG_WARN("config: environment variable '%s' is not set, expanding to empty string", name);
                        val = "";
                    }
                    size_t vlen = strlen(val);
                    size_t copy = vlen;
                    if (oi + copy + 1 > out_sz) copy = out_sz - oi - 1;
                    memcpy(out + oi, val, copy);
                    oi += copy;
                    p = close + 1;
                    continue;
                }
            }
        }
        out[oi++] = *p++;
    }
    out[oi] = '\0';
}

static int parse_log_level(const char *val) {
    if (strcasecmp(val, "debug") == 0) return 0;
    if (strcasecmp(val, "info")  == 0) return 1;
    if (strcasecmp(val, "warn")  == 0) return 2;
    if (strcasecmp(val, "error") == 0) return 3;
    return cfg_atoi(val, 0);
}

/* First pass: scan the whole file just for a resource_profile line, so
 * its defaults can be applied before the real (second) parsing pass --
 * regardless of where in the file the operator put the resource_profile
 * line, every other line in the file still gets to override whatever the
 * profile pre-filled, since the second pass runs the normal key=value
 * assignment logic same as always. Returns silently (profile left as
 * whatever routa_config_init() already set, i.e. balanced/no-op) if no
 * resource_profile line is found or the file can't be read a second time
 * -- routa_config_load()'s own fopen() call right after this will
 * surface any real file-access error properly. */
static void prescan_resource_profile(routa_config_t *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (*s == '#' || *s == '\0' || *s == '[') continue;
        strip_inline_comment(s);
        s = trim(s);
        if (*s == '\0') continue;

        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        strip_quotes(val);

        if (strcmp(key, "resource_profile") == 0) {
            resource_profile_t profile;
            if (strcasecmp(val, "light") == 0)            profile = RESOURCE_PROFILE_LIGHT;
            else if (strcasecmp(val, "performance") == 0)  profile = RESOURCE_PROFILE_PERFORMANCE;
            else if (strcasecmp(val, "balanced") == 0)     profile = RESOURCE_PROFILE_BALANCED;
            else {
                LOG_WARN("config: unknown resource_profile '%s', ignoring (valid: light|balanced|performance)", val);
                break;
            }
            apply_resource_profile(cfg, profile);
            break; /* only one resource_profile line is meaningful */
        }
    }
    (void)fclose(f);
}

#define ROUTA_MAX_INCLUDE_DEPTH 8

static int routa_config_parse_file(routa_config_t *cfg, const char *path, int depth);

/* Handles an `include glob-pattern` line: expands the glob (relative to
 * the current working directory -- routa doesn't track "the including
 * file's directory" the way some formats do, so patterns are expected
 * relative to wherever routa itself is run from, or given as absolute
 * paths) and recursively parses each match with
 * routa_config_parse_file(), in sorted order (a pattern matching zero
 * files, e.g. an empty conf.d/ directory, is treated as a no-op with a
 * warning, not a hard error). depth guards against include cycles /
 * runaway recursion. */
static void handle_include_line(routa_config_t *cfg, const char *pattern,
                                int lineno, int depth) {
    if (depth >= ROUTA_MAX_INCLUDE_DEPTH) {
        LOG_ERROR("config:%d: include depth exceeded (%d), possible include cycle -- ignoring 'include %s'",
                  lineno, ROUTA_MAX_INCLUDE_DEPTH, pattern);
        return;
    }

    glob_t g;
    memset(&g, 0, sizeof(g));
    int rc = glob(pattern, 0, NULL, &g);
    if (rc != 0 && rc != GLOB_NOMATCH) {
        LOG_ERROR("config:%d: include '%s' failed (glob error %d)", lineno, pattern, rc);
        globfree(&g);
        return;
    }
    if (rc == GLOB_NOMATCH || g.gl_pathc == 0) {
        LOG_WARN("config:%d: include '%s' matched no files", lineno, pattern);
        globfree(&g);
        return;
    }

    for (size_t i = 0; i < g.gl_pathc; i++) {
        LOG_INFO("config: including %s", g.gl_pathv[i]);
        (void)routa_config_parse_file(cfg, g.gl_pathv[i], depth + 1);
    }
    globfree(&g);
}

static int routa_config_parse_file(routa_config_t *cfg, const char *path, int depth) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open config file: %s", path);
        return -1;
    }

    char raw_line[1024];
    char line[1024];
    int lineno = 0;
    int active_pool = -1;   /* index into cfg->pools[], -1 = none yet */
    int active_sni_cert = -1; /* index into cfg->sni_certs[], -1 = none yet */

    while (fgets(raw_line, sizeof(raw_line), f)) {
        lineno++;

        /* Expand ${VAR} references before anything else touches the
         * line -- every subsequent step (comment stripping, quote
         * stripping, key/value split, unit parsing) operates on the
         * already-expanded text. */
        expand_env_vars(raw_line, line, sizeof(line));

        char *s = trim(line);
        if (*s == '#' || *s == '\0') continue;
        strip_inline_comment(s);
        s = trim(s);   /* re-trim: stripping a trailing comment can leave trailing whitespace */
        if (*s == '\0') continue;   /* line was value + inline comment only, now empty -- skip */

        /* `include glob-pattern` -- not key=value, handle before the
         * generic '=' split. */
        if (strncmp(s, "include", 7) == 0 &&
            (s[7] == '\0' || isspace((unsigned char)s[7]))) {
            char *pattern = trim(s + 7);
            if (*pattern == '\0') {
                LOG_WARN("config:%d: include missing a glob pattern", lineno);
                continue;
            }
            strip_quotes(pattern);
            handle_include_line(cfg, pattern, lineno, depth);
            continue;
        }

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
            active_sni_cert = -1; /* any new section header clears this */
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
            } else if (strncmp(inner, "tls_cert", 8) == 0 &&
                       (inner[8] == '\0' || isspace((unsigned char)inner[8]))) {
                active_pool = -1;
                char *hostname = trim(inner + 8);
                if (*hostname == '\0') {
                    LOG_WARN("config:%d: [tls_cert] section missing hostname", lineno);
                    continue;
                }
                if (cfg->sni_cert_count >= ROUTA_MAX_SNI_CERTS) {
                    LOG_ERROR("config:%d: max %d [tls_cert] sections exceeded, ignoring '%s'",
                              lineno, ROUTA_MAX_SNI_CERTS, hostname);
                    continue;
                }
                active_sni_cert = cfg->sni_cert_count++;
                memset(&cfg->sni_certs[active_sni_cert], 0,
                      sizeof(cfg->sni_certs[active_sni_cert]));
                strncpy(cfg->sni_certs[active_sni_cert].hostname, hostname,
                       sizeof(cfg->sni_certs[active_sni_cert].hostname) - 1);
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
            /* IPv6 literal: "[::1]" -- strrchr() above already found the
             * right ':' (the one separating the bracketed address from
             * the port, not one of the address's own colons, since it's
             * the LAST colon in the string and IPv6 literals in this
             * syntax are always bracketed). Strip the brackets here so
             * inet_pton(AF_INET6, ...) receives a bare address. */
            size_t host_len = strlen(host);
            if (host_len >= 2 && host[0] == '[' && host[host_len - 1] == ']') {
                host[host_len - 1] = '\0';
                host++;
            }
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

        /* Inside a [tls_cert HOSTNAME] section: only "cert"/"key" belong to
         * it. Unlike [pool ...] (which spans truly pool-scoped keys only,
         * e.g. lb_*), [tls_cert ...] sits among general top-level keys in
         * a typical config file, so it must implicitly end the moment a
         * non-cert/key line appears -- otherwise every line for the rest
         * of the file would be silently swallowed as "unknown key in
         * [tls_cert] section" until the next [...] header. */
        if (active_sni_cert >= 0) {
            if (strcmp(key, "cert") == 0) {
                strncpy(cfg->sni_certs[active_sni_cert].cert, val,
                       sizeof(cfg->sni_certs[active_sni_cert].cert) - 1);
                continue;
            } else if (strcmp(key, "key") == 0) {
                strncpy(cfg->sni_certs[active_sni_cert].key, val,
                       sizeof(cfg->sni_certs[active_sni_cert].key) - 1);
                continue;
            }
            /* Not a cert/key line: implicitly close the section and fall
             * through to normal top-level key handling below. */
            active_sni_cert = -1;
        }

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
                pool->lb_pool_connect_timeout_ms = cfg_duration_ms(val, 2000);
            } else if (strcmp(key, "lb_upstream_read_timeout_ms") == 0) {
                pool->lb_upstream_read_timeout_ms = cfg_duration_ms(val, 30000);
            } else if (strcmp(key, "lb_upstream_write_timeout_ms") == 0) {
                pool->lb_upstream_write_timeout_ms = cfg_duration_ms(val, 30000);
            } else if (strcmp(key, "lb_pool_idle_timeout_s") == 0) {
                pool->lb_pool_idle_timeout_s = cfg_duration_s(val, 60);
            } else if (strcmp(key, "lb_passive_fail_threshold") == 0) {
                pool->lb_passive_fail_threshold = cfg_atoi(val, 3);
            } else if (strcmp(key, "lb_passive_recover_threshold") == 0) {
                pool->lb_passive_recover_threshold = cfg_atoi(val, 2);
            } else if (strcmp(key, "lb_half_open_retry_after_ms") == 0) {
                pool->lb_half_open_retry_after_ms = cfg_duration_ms(val, 30000);
            } else if (strcmp(key, "lb_hc_type") == 0) {
                if (strcasecmp(val, "none") == 0)        pool->lb_hc_type = CFG_HC_NONE;
                else if (strcasecmp(val, "tcp") == 0)    pool->lb_hc_type = CFG_HC_TCP;
                else if (strcasecmp(val, "http") == 0)   pool->lb_hc_type = CFG_HC_HTTP;
                else if (strcasecmp(val, "custom") == 0) pool->lb_hc_type = CFG_HC_CUSTOM;
                else pool->lb_hc_type = (cfg_hc_type_t)cfg_atoi(val, CFG_HC_NONE);
            } else if (strcmp(key, "lb_hc_path") == 0) {
                strncpy(pool->lb_hc_path, val, sizeof(pool->lb_hc_path) - 1);
            } else if (strcmp(key, "lb_hc_interval_ms") == 0) {
                pool->lb_hc_interval_ms = cfg_duration_ms(val, 5000);
            } else if (strcmp(key, "lb_hc_timeout_ms") == 0) {
                pool->lb_hc_timeout_ms = cfg_duration_ms(val, 2000);
            } else if (strcmp(key, "lb_hc_threshold_up") == 0) {
                pool->lb_hc_threshold_up = cfg_atoi(val, 2);
            } else if (strcmp(key, "lb_hc_threshold_down") == 0) {
                pool->lb_hc_threshold_down = cfg_atoi(val, 3);
            } else if (strcmp(key, "lb_max_retries") == 0) {
                pool->lb_max_retries = cfg_atoi(val, 1);
            } else if (strcmp(key, "lb_retry_on_5xx") == 0) {
                pool->lb_retry_on_5xx = cfg_atob(val, 0);
            } else if (strcmp(key, "lb_consistent_hash_vnodes") == 0) {
                pool->lb_consistent_hash_vnodes = cfg_atoi(val, 150);
            } else if (strcmp(key, "lb_sticky_session_enabled") == 0) {
                pool->sticky_session_enabled = cfg_atob(val, 0);
            } else if (strcmp(key, "lb_sticky_cookie_name") == 0) {
                strncpy(pool->sticky_cookie_name, val, sizeof(pool->sticky_cookie_name) - 1);
            } else {
                LOG_WARN("config:%d: unknown lb_* key '%s'", lineno, key);
            }
            continue;
        }

        /* Pool-scoped ACL. Same active-pool targeting rule as headers. */
        if (strcmp(key, "acl_default") == 0 ||
            strcmp(key, "acl_allow") == 0 ||
            strcmp(key, "acl_deny") == 0) {
            /* Only treat these as pool-scoped when inside a [pool ...]
             * section -- otherwise they were already handled by the
             * global acl_* branch above (which runs earlier in this
             * if/else chain and does NOT continue into this block,
             * since it's a separate top-level if). We only get here at
             * all when active_pool >= 0, guarded below. */
            if (active_pool >= 0) {
                lb_pool_config_t *pool = &cfg->pools[active_pool];
                if (strcmp(key, "acl_default") == 0) {
                    pool->acl_enabled = 1;
                    pool->acl_default_allow = (strcasecmp(val, "allow") == 0) ? 1 : 0;
                } else if (strcmp(key, "acl_allow") == 0) {
                    pool->acl_enabled = 1;
                    if (pool->acl_rule_count < ROUTA_MAX_ACL_RULES) {
                        int ai = pool->acl_rule_count++;
                        strncpy(pool->acl_rules[ai].rule, val, sizeof(pool->acl_rules[ai].rule) - 1);
                        pool->acl_rules[ai].action = 0;
                    } else {
                        LOG_ERROR("config:%d: max %d acl rules exceeded for pool",
                                  lineno, ROUTA_MAX_ACL_RULES);
                    }
                } else { /* acl_deny */
                    pool->acl_enabled = 1;
                    if (pool->acl_rule_count < ROUTA_MAX_ACL_RULES) {
                        int ai = pool->acl_rule_count++;
                        strncpy(pool->acl_rules[ai].rule, val, sizeof(pool->acl_rules[ai].rule) - 1);
                        pool->acl_rules[ai].action = 1;
                    } else {
                        LOG_ERROR("config:%d: max %d acl rules exceeded for pool",
                                  lineno, ROUTA_MAX_ACL_RULES);
                    }
                }
                continue;
            }
            /* active_pool < 0: fall through to the global acl_* handling
             * further down in this function (do NOT continue here). */
        }

        /* Pool-scoped header manipulation. Uses the same "applies to the
         * active pool, or pools[0] if none yet" rule as lb_* keys, but
         * these key names don't start with lb_ so they need their own
         * branch here. */
        if (strcmp(key, "request_header_add") == 0 ||
            strcmp(key, "request_header_remove") == 0 ||
            strcmp(key, "response_header_add") == 0 ||
            strcmp(key, "response_header_remove") == 0) {
            int pool_idx = (active_pool >= 0) ? active_pool : 0;
            if (active_pool < 0 && cfg->pool_count == 0) {
                cfg->pools[0].lb_enabled = 1;
                cfg->pool_count = 1;
            }
            lb_pool_config_t *pool = &cfg->pools[pool_idx];

            if (strcmp(key, "request_header_add") == 0) {
                char *colon = strchr(val, ':');
                if (!colon) {
                    LOG_WARN("config:%d: request_header_add missing ':': %s", lineno, val);
                } else if (pool->request_header_add_count >= LB_MAX_HEADER_RULES) {
                    LOG_ERROR("config:%d: max %d request_header_add rules exceeded per pool",
                              lineno, LB_MAX_HEADER_RULES);
                } else {
                    *colon = '\0';
                    int ri = pool->request_header_add_count++;
                    strncpy(pool->request_header_add[ri].name, trim(val),
                           sizeof(pool->request_header_add[ri].name) - 1);
                    strncpy(pool->request_header_add[ri].value, trim(colon + 1),
                           sizeof(pool->request_header_add[ri].value) - 1);
                }
            } else if (strcmp(key, "request_header_remove") == 0) {
                if (pool->request_header_remove_count >= LB_MAX_HEADER_RULES) {
                    LOG_ERROR("config:%d: max %d request_header_remove rules exceeded per pool",
                              lineno, LB_MAX_HEADER_RULES);
                } else {
                    int ri = pool->request_header_remove_count++;
                    strncpy(pool->request_header_remove[ri], val,
                           sizeof(pool->request_header_remove[ri]) - 1);
                }
            } else if (strcmp(key, "response_header_add") == 0) {
                char *colon = strchr(val, ':');
                if (!colon) {
                    LOG_WARN("config:%d: response_header_add missing ':': %s", lineno, val);
                } else if (pool->response_header_add_count >= LB_MAX_HEADER_RULES) {
                    LOG_ERROR("config:%d: max %d response_header_add rules exceeded per pool",
                              lineno, LB_MAX_HEADER_RULES);
                } else {
                    *colon = '\0';
                    int ri = pool->response_header_add_count++;
                    strncpy(pool->response_header_add[ri].name, trim(val),
                           sizeof(pool->response_header_add[ri].name) - 1);
                    strncpy(pool->response_header_add[ri].value, trim(colon + 1),
                           sizeof(pool->response_header_add[ri].value) - 1);
                }
            } else { /* response_header_remove */
                if (pool->response_header_remove_count >= LB_MAX_HEADER_RULES) {
                    LOG_ERROR("config:%d: max %d response_header_remove rules exceeded per pool",
                              lineno, LB_MAX_HEADER_RULES);
                } else {
                    int ri = pool->response_header_remove_count++;
                    strncpy(pool->response_header_remove[ri], val,
                           sizeof(pool->response_header_remove[ri]) - 1);
                }
            }
            continue;
        }

        if (strcmp(key, "resource_profile") == 0) {
            /* Already applied by prescan_resource_profile() before this
             * loop started -- this branch exists only so the second pass
             * doesn't log a spurious "unknown key" warning for the same
             * line it already consumed in the first pass. */
        } else if (strcmp(key, "port") == 0) {
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
            cfg->keepalive_timeout_ms = cfg_duration_ms(val, 30000);
        } else if (strcmp(key, "request_timeout") == 0) {
            cfg->request_timeout_ms = cfg_duration_ms(val, 10000);
        } else if (strcmp(key, "max_connections") == 0) {
            cfg->max_connections = cfg_atoi(val, 10000);
        } else if (strcmp(key, "cache_memory_mb") == 0) {
            cfg->cache_memory_mb = (size_t)cfg_size_mb(val, 64);
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
            cfg->file_cache_enabled = cfg_atob(val, 1);
        } else if (strcmp(key, "file_cache_entries") == 0) {
            cfg->file_cache_max_entries = cfg_atoi(val, 512);
        } else if (strcmp(key, "file_cache_ttl") == 0) {
            cfg->file_cache_ttl = cfg_duration_s(val, 5);
        } else if (strcmp(key, "file_cache_strategy") == 0) {
            if (strcasecmp(val, "ttl") == 0)          cfg->file_cache_strategy = 0;
            else if (strcasecmp(val, "stat_ttl") == 0) cfg->file_cache_strategy = 1;
            else if (strcasecmp(val, "inotify") == 0)  cfg->file_cache_strategy = 2;
            else cfg->file_cache_strategy = cfg_atoi(val, 1);
        } else if (strcmp(key, "tls_session_timeout") == 0) {
            cfg->tls_session_timeout = cfg_duration_s(val, 3600);
        } else if (strcmp(key, "tls_ocsp_response") == 0) {
            strncpy(cfg->tls_ocsp_response, val, sizeof(cfg->tls_ocsp_response) - 1);
        } else if (strcmp(key, "max_request_size") == 0) {
            cfg->max_request_size = (int)cfg_size_bytes(val, 1048576);
        } else if (strcmp(key, "shutdown_timeout_ms") == 0) {
            cfg->shutdown_timeout_ms = cfg_duration_ms(val, 30000);
        } else if (strcmp(key, "h2_enabled") == 0) {
            cfg->h2.enabled = cfg_atob(val, 1);
        } else if (strcmp(key, "h2_header_table_size") == 0) {
            cfg->h2.header_table_size = (uint32_t)cfg_size_bytes(val, 4096);
        } else if (strcmp(key, "h2_huffman_encoding") == 0) {
            cfg->h2.huffman_encoding = cfg_atob(val, 1);
        } else if (strcmp(key, "h2_dynamic_table_update") == 0) {
            cfg->h2.dynamic_table_update = cfg_atob(val, 1);
        } else if (strcmp(key, "h2_initial_window_size") == 0) {
            cfg->h2.initial_window_size = (uint32_t)cfg_size_bytes(val, 65535);
        } else if (strcmp(key, "h2_max_frame_size") == 0) {
            cfg->h2.max_frame_size = (uint32_t)cfg_size_bytes(val, 16384);
        } else if (strcmp(key, "h2_max_header_list_size") == 0) {
            cfg->h2.max_header_list_size = (uint32_t)cfg_size_bytes(val, 0);
        } else if (strcmp(key, "h2_max_concurrent_streams") == 0) {
            cfg->h2.max_concurrent_streams = (uint32_t)cfg_atoi(val, 128);
        } else if (strcmp(key, "h2_max_concurrent_streams_hard_cap") == 0) {
            cfg->h2.max_concurrent_streams_hard_cap = (uint32_t)cfg_atoi(val, 256);
        } else if (strcmp(key, "h2_stream_timeout_ms") == 0) {
            cfg->h2.stream_timeout_ms = cfg_duration_ms(val, 30000);
        } else if (strcmp(key, "h2_keepalive_timeout_ms") == 0) {
            cfg->h2.keepalive_timeout_ms = cfg_duration_ms(val, 120000);
        } else if (strcmp(key, "h2_server_push_enabled") == 0) {
            cfg->h2.server_push_enabled = cfg_atob(val, 1);
        } else if (strcmp(key, "h2_c_upgrade_enabled") == 0) {
            cfg->h2.h2c_upgrade_enabled = cfg_atob(val, 1);
        } else if (strcmp(key, "h2_stream_lookup") == 0) {
            if (strcasecmp(val, "linear") == 0)       cfg->h2.stream_lookup = H2_STREAM_LOOKUP_LINEAR;
            else if (strcasecmp(val, "hashmap") == 0) cfg->h2.stream_lookup = H2_STREAM_LOOKUP_HASHMAP;
            else cfg->h2.stream_lookup = (h2_stream_lookup_t)cfg_atoi(val, H2_STREAM_LOOKUP_LINEAR);

        /* ── Middleware ── */
        } else if (strcmp(key, "logger_enabled") == 0) {
            cfg->logger_enabled = cfg_atob(val, 1);
        } else if (strcmp(key, "compress_enabled") == 0) {
            cfg->compress_enabled = cfg_atob(val, 1);
        } else if (strcmp(key, "compress_min_size") == 0) {
            cfg->compress_min_size = (size_t)cfg_size_bytes(val, 256);
        } else if (strcmp(key, "compress_level") == 0) {
            cfg->compress_level = cfg_atoi(val, 6);
        } else if (strcmp(key, "cors_enabled") == 0) {
            cfg->cors_enabled = cfg_atob(val, 0);
        } else if (strcmp(key, "cors_origin") == 0) {
            strncpy(cfg->cors_origin, val, sizeof(cfg->cors_origin) - 1);
        } else if (strcmp(key, "cors_methods") == 0) {
            strncpy(cfg->cors_methods, val, sizeof(cfg->cors_methods) - 1);
        } else if (strcmp(key, "cors_headers") == 0) {
            strncpy(cfg->cors_headers, val, sizeof(cfg->cors_headers) - 1);
        } else if (strcmp(key, "auth_basic_enabled") == 0) {
            cfg->auth_basic_enabled = cfg_atob(val, 0);
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
            cfg->auth_jwt_enabled = cfg_atob(val, 0);
        } else if (strcmp(key, "auth_jwt_secret") == 0) {
            strncpy(cfg->auth_jwt_secret, val, sizeof(cfg->auth_jwt_secret) - 1);
        } else if (strcmp(key, "auth_jwt_pubkey_path") == 0) {
            strncpy(cfg->auth_jwt_pubkey_path, val, sizeof(cfg->auth_jwt_pubkey_path) - 1);
        } else if (strcmp(key, "auth_jwt_verify_exp") == 0) {
            cfg->auth_jwt_verify_exp = cfg_atob(val, 1);
        } else if (strcmp(key, "auth_jwt_issuer") == 0) {
            strncpy(cfg->auth_jwt_issuer, val, sizeof(cfg->auth_jwt_issuer) - 1);
        } else if (strcmp(key, "auth_jwt_audience") == 0) {
            strncpy(cfg->auth_jwt_audience, val, sizeof(cfg->auth_jwt_audience) - 1);
        } else if (strcmp(key, "rate_limit_enabled") == 0) {
            cfg->rate_limit_enabled = cfg_atob(val, 0);
        } else if (strcmp(key, "rate_limit_requests_per_second") == 0) {
            cfg->rate_limit_requests_per_second = cfg_atoi(val, 100);
        } else if (strcmp(key, "rate_limit_burst") == 0) {
            cfg->rate_limit_burst = cfg_atoi(val, 200);
        } else if (strcmp(key, "metrics_enabled") == 0) {
            cfg->metrics_enabled = cfg_atob(val, 1);
        } else if (strcmp(key, "metrics_path") == 0) {
            strncpy(cfg->metrics_path, val, sizeof(cfg->metrics_path) - 1);
        } else if (strcmp(key, "global_response_header_add") == 0) {
            /* Format: Header-Name: value */
            char *colon = strchr(val, ':');
            if (!colon) {
                LOG_WARN("config:%d: global_response_header_add missing ':': %s", lineno, val);
            } else if (cfg->response_header_add_count >= ROUTA_MAX_GLOBAL_HEADER_RULES) {
                LOG_ERROR("config:%d: max %d global_response_header_add rules exceeded",
                          lineno, ROUTA_MAX_GLOBAL_HEADER_RULES);
            } else {
                *colon = '\0';
                int ri = cfg->response_header_add_count++;
                strncpy(cfg->response_header_add[ri].name, trim(val),
                       sizeof(cfg->response_header_add[ri].name) - 1);
                strncpy(cfg->response_header_add[ri].value, trim(colon + 1),
                       sizeof(cfg->response_header_add[ri].value) - 1);
            }
        } else if (strcmp(key, "socket_recv_buf_size") == 0) {
            cfg->socket_recv_buf_size = (int)cfg_size_bytes(val, 0);
        } else if (strcmp(key, "socket_send_buf_size") == 0) {
            cfg->socket_send_buf_size = (int)cfg_size_bytes(val, 0);
        } else if (strcmp(key, "cpu_affinity_enabled") == 0) {
            cfg->cpu_affinity_enabled = cfg_atob(val, 0);
        } else if (strcmp(key, "cpu_affinity_start_core") == 0) {
            cfg->cpu_affinity_start_core = cfg_atoi(val, 0);
        } else if (strcmp(key, "memory_soft_limit_mb") == 0) {
            cfg->memory_soft_limit_mb = (int)cfg_size_mb(val, 0);
        } else if (strcmp(key, "memory_hard_limit_mb") == 0) {
            cfg->memory_hard_limit_mb = (int)cfg_size_mb(val, 0);
        } else if (strcmp(key, "numa_aware_enabled") == 0) {
            cfg->numa_aware_enabled = cfg_atob(val, 0);
        } else if (strcmp(key, "ws_enabled") == 0) {
            cfg->ws.enabled = cfg_atob(val, 0);
        } else if (strcmp(key, "ws_max_connections") == 0) {
            cfg->ws.max_connections = cfg_atoi(val, 10000);
        } else if (strcmp(key, "ws_handshake_timeout_ms") == 0) {
            cfg->ws.handshake_timeout_ms = cfg_duration_ms(val, 5000);
        } else if (strcmp(key, "ws_idle_timeout_ms") == 0) {
            cfg->ws.idle_timeout_ms = cfg_duration_ms(val, 0);
        } else if (strcmp(key, "ws_max_frame_size") == 0) {
            cfg->ws.max_frame_size = (size_t)cfg_size_bytes(val, 16 * 1024 * 1024);
        } else if (strcmp(key, "ws_max_message_size") == 0) {
            cfg->ws.max_message_size = (size_t)cfg_size_bytes(val, 64 * 1024 * 1024);
        } else if (strcmp(key, "ws_ping_interval_ms") == 0) {
            cfg->ws.ping_interval_ms = cfg_duration_ms(val, 30000);
        } else if (strcmp(key, "ws_ping_timeout_ms") == 0) {
            cfg->ws.ping_timeout_ms = cfg_duration_ms(val, 10000);
        } else if (strcmp(key, "ws_max_ping_misses") == 0) {
            cfg->ws.max_ping_misses = cfg_atoi(val, 3);
        } else if (strcmp(key, "ws_read_buf_size") == 0) {
            cfg->ws.read_buf_size = (size_t)cfg_size_bytes(val, 65536);
        } else if (strcmp(key, "ws_write_buf_size") == 0) {
            cfg->ws.write_buf_size = (size_t)cfg_size_bytes(val, 65536);
        } else if (strcmp(key, "ws_write_queue_max") == 0) {
            cfg->ws.write_queue_max = cfg_atoi(val, 128);
        } else if (strcmp(key, "ws_permessage_deflate") == 0) {
            cfg->ws.permessage_deflate = cfg_atob(val, 0);
        } else if (strcmp(key, "ws_compression_level") == 0) {
            cfg->ws.compression_level = cfg_atoi(val, 6);
        } else if (strcmp(key, "ws_compression_threshold") == 0) {
            cfg->ws.compression_threshold = (size_t)cfg_size_bytes(val, 512);
        } else if (strcmp(key, "ws_require_masking") == 0) {
            cfg->ws.require_masking = cfg_atob(val, 1);
        } else if (strcmp(key, "acl_default") == 0) {
            cfg->acl_enabled = 1;
            cfg->acl_default_allow = (strcasecmp(val, "allow") == 0) ? 1 : 0;
        } else if (strcmp(key, "acl_allow") == 0) {
            cfg->acl_enabled = 1;
            if (cfg->acl_rule_count < ROUTA_MAX_ACL_RULES) {
                int ai = cfg->acl_rule_count++;
                strncpy(cfg->acl_rules[ai].rule, val, sizeof(cfg->acl_rules[ai].rule) - 1);
                cfg->acl_rules[ai].action = 0;   /* allow */
            } else {
                LOG_ERROR("config:%d: max %d acl_allow/acl_deny rules exceeded",
                          lineno, ROUTA_MAX_ACL_RULES);
            }
        } else if (strcmp(key, "acl_deny") == 0) {
            cfg->acl_enabled = 1;
            if (cfg->acl_rule_count < ROUTA_MAX_ACL_RULES) {
                int ai = cfg->acl_rule_count++;
                strncpy(cfg->acl_rules[ai].rule, val, sizeof(cfg->acl_rules[ai].rule) - 1);
                cfg->acl_rules[ai].action = 1;   /* deny */
            } else {
                LOG_ERROR("config:%d: max %d acl_allow/acl_deny rules exceeded",
                          lineno, ROUTA_MAX_ACL_RULES);
            }
        } else if (strcmp(key, "global_response_header_remove") == 0) {
            if (cfg->response_header_remove_count >= ROUTA_MAX_GLOBAL_HEADER_RULES) {
                LOG_ERROR("config:%d: max %d global_response_header_remove rules exceeded",
                          lineno, ROUTA_MAX_GLOBAL_HEADER_RULES);
            } else {
                int ri = cfg->response_header_remove_count++;
                strncpy(cfg->response_header_remove[ri], val,
                       sizeof(cfg->response_header_remove[ri]) - 1);
            }
        } else {
            LOG_WARN("config:%d: unknown key '%s'", lineno, key);
        }
    }

    (void)fclose(f);
    return 0;
}

int routa_config_load(routa_config_t *cfg, const char *path) {
    if (!path) return -1;

    prescan_resource_profile(cfg, path);

    if (routa_config_parse_file(cfg, path, 0) < 0) return -1;

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
    for (int i = 0; i < cfg->sni_cert_count; i++) {
        if (cfg->sni_certs[i].cert[0] == '\0' || cfg->sni_certs[i].key[0] == '\0') {
            LOG_ERROR("[tls_cert %s] missing cert/key", cfg->sni_certs[i].hostname);
            return -1;
        }
        if (!cfg->tls_enabled) {
            LOG_ERROR("[tls_cert %s] defined but top-level TLS is not enabled",
                      cfg->sni_certs[i].hostname);
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
