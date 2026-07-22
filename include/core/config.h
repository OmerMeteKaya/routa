#ifndef ROUTA_CORE_CONFIG_H
#define ROUTA_CORE_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define ROUTA_MAX_UPSTREAMS   64
#define ROUTA_MAX_STATIC      16
#define ROUTA_MAX_MIDDLEWARES 32

/* ── Resource profile (config file: resource_profile = light|balanced|performance)
 *
 * A profile only supplies DEFAULT values for a curated set of resource-
 * related settings -- it is applied once, right after routa_config_init(),
 * before the rest of the file is parsed. Any explicit key the operator
 * writes anywhere in the file (before or after the resource_profile line)
 * always wins over the profile's value, since normal parsing simply
 * overwrites whatever the profile pre-filled. This means an operator can
 * write `resource_profile = performance` and then override just
 * `workers = 4` without the profile fighting back -- the profile is a
 * starting point, never a hard override. See apply_resource_profile()
 * in config.c for the exact per-field values each profile sets.
 *
 * balanced reproduces routa_config_init()'s pre-existing hardcoded
 * defaults exactly (so a config with no resource_profile line at all, or
 * resource_profile = balanced, behaves identically to before this
 * feature existed). light targets weak/resource-constrained machines
 * (e.g. laptops); performance targets large multi-core servers. */
typedef enum {
    RESOURCE_PROFILE_BALANCED    = 0,   /* default, matches pre-existing hardcoded defaults */
    RESOURCE_PROFILE_LIGHT       = 1,
    RESOURCE_PROFILE_PERFORMANCE = 2,
} resource_profile_t;

/* ── Load balancer algorithm (mirrors lb_algo_t) ───────────────────────────*/
typedef enum {
    CFG_LB_ROUND_ROBIN     = 0,
    CFG_LB_WEIGHTED_RR     = 1,
    CFG_LB_LEAST_CONN      = 2,
    CFG_LB_IP_HASH         = 3,
    CFG_LB_RANDOM          = 4,
    CFG_LB_P2C             = 5,
    CFG_LB_CONSISTENT_HASH = 6,
} cfg_lb_algo_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * WebSocket config
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef struct {
    int    enabled;


    int    max_connections;          /* default: 10000                      */
    int    handshake_timeout_ms;     /* default: 5000                       */
    int    idle_timeout_ms;          /* default: 0                          */

    /* Frame  */
    size_t max_frame_size;           /* default: 16MB                       */
    size_t max_message_size;         /* fragmented, default: 64MB    */

    /* Ping/Pong */
    int    ping_interval_ms;
    int    ping_timeout_ms;
    int    max_ping_misses;

    /* Buffer */
    size_t read_buf_size;            /* default: 65536                      */
    size_t write_buf_size;           /* default: 65536                      */
    int    write_queue_max;          /* backpressure limit, default: 128   */

    /* Compression (RFC 7692 permessage-deflate) */
    int    permessage_deflate;
    int    compression_level;
    size_t compression_threshold;
    int    require_masking;
} ws_config_t;

/* ── Health check type (mirrors health_check_type_t) ───────────────────────*/
typedef enum {
    CFG_HC_NONE   = 0,
    CFG_HC_TCP    = 1,
    CFG_HC_HTTP   = 2,
    CFG_HC_CUSTOM = 3,
} cfg_hc_type_t;

#define ROUTA_MAX_LB_POOLS 16
#define ROUTA_MAX_ACL_RULES 64
#define ROUTA_MAX_SNI_CERTS 32

/* One independently-configured upstream pool: its own upstream list, LB
 * algorithm, health-check settings, retry policy, and the path pattern
 * it's routed to. See routa_config_t.pools[] for the config file syntax. */
typedef struct {
    char name[64];      /* from "[pool NAME]", or "" for the implicit/legacy
                         * single pool when no [pool ...] section is used  */
    char route[256];    /* from lb_route = ..., default "/*"               */

    int            lb_enabled;
    cfg_lb_algo_t  lb_algo;
    struct {
        char host[256];
        int  port;
        int  weight;
        int  use_tls;    /* set when the upstream line used https://       */
    } upstreams[ROUTA_MAX_UPSTREAMS];
    int upstream_count;

    /* Connection pool */
    int lb_pool_max_per_node;
    int lb_pool_connect_timeout_ms;
    int lb_upstream_read_timeout_ms;
    int lb_upstream_write_timeout_ms;
    int lb_pool_idle_timeout_s;

    /* Passive health */
    int lb_passive_fail_threshold;
    int lb_passive_recover_threshold;
    int lb_half_open_retry_after_ms;  /* circuit-breaker half-open, ms.
                                       * 0 = disabled. default: 30000 */

    /* Active health check */
    cfg_hc_type_t lb_hc_type;
    char          lb_hc_path[256];
    int           lb_hc_interval_ms;
    int           lb_hc_timeout_ms;
    int           lb_hc_threshold_up;
    int           lb_hc_threshold_down;

    /* Retry */
    int lb_max_retries;
    int lb_retry_on_5xx;

    /* Consistent hash */
    int lb_consistent_hash_vnodes;
    /* Header manipulation, applied on top of routa's own automatic
     * headers -- see lb_config_t in lb.h for full semantics (mirrored
     * here 1:1 for the file-config layer). */
#define LB_MAX_HEADER_RULES 16
    struct { char name[128]; char value[256]; } request_header_add[LB_MAX_HEADER_RULES];
    int      request_header_add_count;
    char     request_header_remove[LB_MAX_HEADER_RULES][128];
    int      request_header_remove_count;

    struct { char name[128]; char value[256]; } response_header_add[LB_MAX_HEADER_RULES];
    int      response_header_add_count;
    char     response_header_remove[LB_MAX_HEADER_RULES][128];
    int      response_header_remove_count;

    /* Pool-scoped IP-based ACL, applied in addition to (after) any global
     * ACL rules -- a request that passes the global ACL can still be
     * blocked by a pool-specific one. */
    int  acl_enabled;
    int  acl_default_allow;
    struct { char rule[128]; int action; } acl_rules[ROUTA_MAX_ACL_RULES];
    int  acl_rule_count;

    /* Cookie-based sticky sessions -- see lb_config_t in lb.h. */
    int  sticky_session_enabled;
    char sticky_cookie_name[128];
} lb_pool_config_t;

/* ── HTTP/2 ──────────────────────────────────────────────────────────────── */
typedef enum {
    H2_STREAM_LOOKUP_LINEAR  = 0,   /* fixed pool, linear scan, default   */
    H2_STREAM_LOOKUP_HASHMAP = 1,   /* open addressing hashmap            */
} h2_stream_lookup_t;

typedef struct {
    int      enabled;                    /* default: 1                        */

    /* HPACK */
    uint32_t header_table_size;          /* dynamic table per-conn, default: 4096  */
    int      huffman_encoding;           /* outbound Huffman, default: 1      */
    int      dynamic_table_update;       /* server writes to dyn table, default: 1 */

    /* Flow control */
    uint32_t initial_window_size;        /* stream window, default: 65535     */
    uint32_t max_frame_size;             /* default: 16384 (RFC min)          */
    uint32_t max_header_list_size;       /* default: 0 (unlimited)            */

    /* Concurrency */
    uint32_t max_concurrent_streams;     /* per-conn, default: 128            */

    /* Timeouts */
    int      stream_timeout_ms;          /* idle stream, default: 30000       */
    int      keepalive_timeout_ms;       /* h2 conn idle, default: 120000     */

    /* H2 */
    int      server_push_enabled;       /* default: 1                        */
    int      h2c_upgrade_enabled;       /* default: 1                        */
    h2_stream_lookup_t stream_lookup;        /* default: H2_STREAM_LOOKUP_LINEAR  */
    uint32_t           max_concurrent_streams_hard_cap; /* pool hard cap, default: 256 */
} routa_h2_config_t;

typedef struct {
    /* Resource profile: applied once, right after routa_config_init(),
     * before the rest of the file is parsed -- see resource_profile_t's
     * doc comment above. This field just records which profile was
     * requested (for routa_config_dump() and reference); the actual
     * effect already happened by the time parsing finishes. */
    resource_profile_t resource_profile;

    /* Network */
    int   port;           /* default: 8080         */
    int   n_workers;      /* default: CPU count     */
    int   backlog;        /* default: 128           */

    /* TLS */
    int   tls_enabled;
    char  tls_cert[512];
    char  tls_key[512];
    int   tls_session_timeout;      /* seconds, default: 3600          */
    char  tls_ocsp_response[512];   /* path to DER file, empty=disabled */

    /* SNI: additional certificates selected by hostname at handshake time.
     * Config file syntax (one section per extra cert, hostname may be a
     * single-label wildcard like "*.api.example.com"):
     *
     *   [tls_cert example.com]
     *   cert = /etc/routa/certs/example.com.pem
     *   key  = /etc/routa/certs/example.com.key
     *
     * The top-level tls_cert/tls_key above remain the default certificate,
     * used when the client sends no SNI or an unmatched hostname. */
    struct {
        char hostname[256];
        char cert[512];
        char key[512];
    } sni_certs[ROUTA_MAX_SNI_CERTS];
    int sni_cert_count;

    /* Static file serving */
    struct {
        char url_prefix[256];
        char doc_root[512];
        int  enable_index;
    } static_dirs[ROUTA_MAX_STATIC];
    int static_count;

    /* Logging */
    int  log_level;        /* 0=debug 1=info 2=warn 3=error */
    char log_file[512];    /* empty = stderr                 */

    /* Timeouts (ms) */
    int keepalive_timeout_ms;   /* default: 30000 */
    int request_timeout_ms;     /* default: 10000 */

    /* Limits */
    int max_connections;        /* default: 10000 */
    int max_request_size;       /* default: 1MB   */

    /* HTTP response cache */
    int    cache_enabled;
    size_t cache_memory_mb;     /* default: 64    */
    char   cache_dir[512];      /* empty = memory */

    /* File stat/path cache */
    int  file_cache_enabled;
    int  file_cache_max_entries;
    int  file_cache_ttl;
    int  file_cache_strategy;   /* 0=ttl, 1=stat_ttl, 2=inotify */

    /* file_cache_mode: 0=local (thread-local, legacy), 1=shared_metadata
     * (shared hash table for path/etag/mtime/generation, mmap stays
     * per-worker), 2=shared_content (shared refcounted content -- not
     * implemented in this revision, reserved for future work). */
    int  file_cache_mode;
    /* file_cache_lock: 0=global (single lock, n_shards forced to 1),
     * 1=sharded (file_cache_shards independent locks). Only meaningful
     * when file_cache_mode != local. */
    int  file_cache_lock;
    int  file_cache_shards;        /* must be a power of 2 */
    /* file_cache_eviction: 0=lru, 1=lfu, 2=ttl_only (no active eviction
     * ordering, entries just expire/get overwritten oldest-first) */
    int  file_cache_eviction;
    int  file_cache_negative_ttl;  /* seconds; 0 = negative caching off */
    int  file_cache_mmap_threshold; /* bytes; replaces the old hardcoded
                                        FILE_CACHE_MMAP_THRESHOLD constant */
    int  file_cache_max_memory_mb;  /* 0 = off (entry-count limit only) */
    /* file_cache_watch: 0=none (pure TTL/stat_ttl behavior), 1=inotify
     * (Linux only; real inotify-based invalidation) */
    int  file_cache_watch;

    /* ── Load balancer ──────────────────────────────────────────────────── */
    /* ── Load balancer pools ────────────────────────────────────────────────
     * One or more independently configured upstream pools, each bound to
     * its own path pattern (route). Config file syntax:
     *
     *   [pool api]
     *   lb_algo = round_robin
     *   lb_route = /api/*
     *   upstream 10.0.0.1:3000 weight=1
     *   upstream https://10.0.0.2:3443 weight=2
     *   lb_hc_type = http
     *   lb_hc_path = /health
     *
     *   [pool static]
     *   lb_route = /static-proxy/*
     *   upstream 10.0.0.3:4000 weight=1
     *
     * A config with no [pool ...] sections but a bare `upstream` line
     * (legacy single-pool style) is treated as a single implicit pool
     * (pools[0]), routed to "/*" by default -- see routa_config_load(). */
    h2_stream_lookup_t stream_lookup;        /* default: H2_STREAM_LOOKUP_LINEAR  */
    routa_h2_config_t h2;

    /* ── WebSocket (ws_config_t, from ws.h -- included via lb/lb.h's
     * transitive chain isn't guaranteed, so ws_config_t itself is defined
     * earlier in *this* file, see top). Config file syntax: ws_* prefix,
     * e.g. ws_enabled, ws_max_connections, ws_ping_interval_ms, etc. ── */
    ws_config_t ws;

    /* Graceful shutdown */
    int shutdown_timeout_ms;     /* drain timeout before force-close, default: 30000 */

    lb_pool_config_t pools[ROUTA_MAX_LB_POOLS];
    int              pool_count;
    /* ── Middleware ────────────────────────────────────────────────────────
     * Each of these enables and configures a built-in middleware
     * (src/http/mw_*.c). All are opt-in (disabled by default) except
     * logger and compress, which default to enabled since they have no
     * meaningful "off" behavior difference for most deployments; disable
     * them explicitly if not wanted. Order of application (outermost to
     * innermost): logger -> cors -> auth (basic or jwt) -> ratelimit ->
     * compress -> route handler. */

    /* Access logging (mw_logger.c) */
    int logger_enabled;             /* default: 1 */

    /* Response compression (mw_compress.c) */
    int    compress_enabled;        /* default: 1 */
    size_t compress_min_size;       /* bytes, default: 256 */
    int    compress_level;          /* zlib level 1-9, default: 6 */

    /* CORS (mw_cors.c) */
    int  cors_enabled;              /* default: 0 */
    char cors_origin[256];          /* default: "*" */
    char cors_methods[256];         /* default: "GET,POST,PUT,DELETE,OPTIONS" */
    char cors_headers[256];         /* default: "Content-Type,Authorization" */

    /* Basic Auth (mw_auth.c) -- users added via repeatable auth_basic_user lines */
    int  auth_basic_enabled;        /* default: 0 */
    char auth_basic_realm[256];     /* default: "Restricted" */
    struct {
        char username[256];
        char password[256];
    } auth_basic_users[32];
    int auth_basic_user_count;

    /* JWT Auth (mw_auth.c) -- mutually exclusive with basic auth in the
     * default chain (both can technically be enabled, but only makes
     * sense if applied to different routes -- not yet supported by this
     * flat config, see roadmap). */
    int  auth_jwt_enabled;          /* default: 0 */
    char auth_jwt_secret[512];      /* HS256 shared secret */
    char auth_jwt_pubkey_path[512]; /* RS256 public key PEM file path */
    int  auth_jwt_verify_exp;       /* default: 1 */
    char auth_jwt_issuer[256];      /* optional */
    char auth_jwt_audience[256];    /* optional */

    /* Rate limiting (mw_ratelimit.c) */
    int rate_limit_enabled;         /* default: 0 */
    int rate_limit_requests_per_second; /* default: 100 */
    int rate_limit_burst;           /* default: 200 */

    /* Metrics endpoint (mw_metrics.c) */
    int  metrics_enabled;           /* default: 1 */
    char metrics_path[256];         /* default: "/metrics" */

    /* Socket buffer sizes (SO_RCVBUF/SO_SNDBUF on accepted client sockets).
     * 0 = leave at OS default. Tuning these up can meaningfully improve
     * throughput on high-bandwidth-delay-product links (e.g. serving
     * large responses to distant clients); tuning down reduces per-
     * connection memory footprint on memory-constrained deployments. */
    int socket_recv_buf_size;   /* bytes, default: 0 (OS default) */
    int socket_send_buf_size;   /* bytes, default: 0 (OS default) */

    /* CPU affinity: pin worker threads to specific cores (Linux only).
     * Improves cache locality on multi-core machines. */
    int cpu_affinity_enabled;      /* default: 0 (disabled) */
    int cpu_affinity_start_core;   /* worker 0 -> this core, worker N -> this+N, wraps. default: 0 */

    /* Process-wide memory limits (MB, 0 = disabled). Checked periodically
     * (not per-request) against RSS. soft: reject new connections once
     * exceeded, resume once back under it. hard: trigger a graceful
     * shutdown (same path as SIGTERM), expecting a process supervisor to
     * restart routa afterward -- routa does not restart itself in-process.
     * These are process-wide, not truly per-worker, since worker threads
     * share one address space/RSS -- see routa_metrics_update_rss(). */
    int memory_soft_limit_mb;   /* default: 0 (disabled) */
    int memory_hard_limit_mb;   /* default: 0 (disabled) */

    /* NUMA-aware worker placement, layered on top of cpu_affinity_enabled.
     * No effect unless cpu_affinity_enabled is also 1, routa was built
     * with -DROUTA_NUMA (see CMakeLists.txt's ROUTA_NUMA option), and the
     * running system actually has more than one NUMA node -- all three
     * fall back silently to the existing plain round-robin core
     * assignment otherwise. default: 0 (disabled) */
    int numa_aware_enabled;

    /* Global IP-based ACL (mw_acl.c), applied to every request before any
     * pool-specific ACL. If both deny, the request is blocked at whichever
     * layer runs first (global runs first, being registered earlier). */
    int  acl_enabled;
    int  acl_default_allow;   /* default: 1 (allow) */
    struct { char rule[128]; int action; } acl_rules[ROUTA_MAX_ACL_RULES];  /* action: 0=allow,1=deny */
    int  acl_rule_count;

    /* Global header manipulation, applied to EVERY response (proxy,
     * static file, custom route handler alike) in addition to any
     * pool-specific request_header_* / response_header_* rules (which only
     * apply to that pool's proxied requests/responses). */
#define ROUTA_MAX_GLOBAL_HEADER_RULES 16
    struct { char name[128]; char value[256]; } response_header_add[ROUTA_MAX_GLOBAL_HEADER_RULES];
    int  response_header_add_count;
    char response_header_remove[ROUTA_MAX_GLOBAL_HEADER_RULES][128];
    int  response_header_remove_count;
} routa_config_t;

/* Initialize config with sensible defaults */
void routa_config_init(routa_config_t *cfg);

/* Initializes a single lb_pool_config_t with sane defaults, mirroring the
 * defaults lb_config_init() (lb.c) uses for the runtime lb_config_t --
 * kept in sync manually since these are separate structs in separate
 * layers (file-config vs. runtime). */
void lb_pool_config_init(lb_pool_config_t *pool);

/* Applies a resource profile's defaults to cfg. Call after
* routa_config_init() and before parsing the config file (or anywhere
* later, if you want to force a profile's values regardless of what a
* file set -- but routa_config_load() itself only calls this BEFORE
* parsing, preserving the "explicit config always wins" rule described
* on resource_profile_t). balanced is a no-op (routa_config_init()'s
* defaults already match it). */
void apply_resource_profile(routa_config_t *cfg, resource_profile_t profile);

/* Parse routa.conf file. Returns 0 on success, -1 on error. */
int routa_config_load(routa_config_t *cfg, const char *path);

/* Validate config. Returns 0 if valid, -1 with LOG_ERROR if not. */
int routa_config_validate(const routa_config_t *cfg);

/* Print config to stderr (for debugging) */
void routa_config_dump(const routa_config_t *cfg);

/* Reload config from file for hot-reload (SIGHUP).
 * Validates and enforces restart-only constraints (port, workers, bind_addr).
 * Returns 0 on success, -1 on error.                                        */
int routa_config_reload(const char *path,
                        const routa_config_t *current,
                        routa_config_t *out);

#endif /* ROUTA_CORE_CONFIG_H */