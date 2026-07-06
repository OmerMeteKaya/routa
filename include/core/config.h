#ifndef ROUTA_CORE_CONFIG_H
#define ROUTA_CORE_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define ROUTA_MAX_UPSTREAMS   64
#define ROUTA_MAX_STATIC      16
#define ROUTA_MAX_MIDDLEWARES 32

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
    int lb_pool_idle_timeout_s;

    /* Passive health */
    int lb_passive_fail_threshold;
    int lb_passive_recover_threshold;

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
    /* Graceful shutdown */
    int shutdown_timeout_ms;     /* drain timeout before force-close, default: 30000 */

    lb_pool_config_t pools[ROUTA_MAX_LB_POOLS];
    int              pool_count;
} routa_config_t;

/* Initialize config with sensible defaults */
void routa_config_init(routa_config_t *cfg);

/* Initializes a single lb_pool_config_t with sane defaults, mirroring the
 * defaults lb_config_init() (lb.c) uses for the runtime lb_config_t --
 * kept in sync manually since these are separate structs in separate
 * layers (file-config vs. runtime). */
void lb_pool_config_init(lb_pool_config_t *pool);

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