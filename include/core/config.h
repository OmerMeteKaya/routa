#ifndef ROUTA_CORE_CONFIG_H
#define ROUTA_CORE_CONFIG_H

#include <stddef.h>

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
    int            lb_enabled;          /* 0 = disabled (default)           */
    cfg_lb_algo_t  lb_algo;             /* default: CFG_LB_ROUND_ROBIN      */

    struct {
        char host[256];
        int  port;
        int  weight;                    /* default: 1                       */
    } upstreams[ROUTA_MAX_UPSTREAMS];
    int upstream_count;

    /* Connection pool */
    int lb_pool_max_per_node;           /* default: 64                      */
    int lb_pool_connect_timeout_ms;     /* default: 2000                    */
    int lb_pool_idle_timeout_s;         /* default: 60                      */

    /* Passive health */
    int lb_passive_fail_threshold;      /* default: 3                       */
    int lb_passive_recover_threshold;   /* default: 2                       */

    /* Active health check */
    cfg_hc_type_t lb_hc_type;          /* default: CFG_HC_NONE             */
    char          lb_hc_path[256];      /* default: "/health"               */
    int           lb_hc_interval_ms;    /* default: 5000                    */
    int           lb_hc_timeout_ms;     /* default: 2000                    */
    int           lb_hc_threshold_up;   /* default: 2                       */
    int           lb_hc_threshold_down; /* default: 3                       */

    /* Retry */
    int lb_max_retries;                 /* default: 1                       */
    int lb_retry_on_5xx;                /* default: 0                       */

    /* Consistent hash */
    int lb_consistent_hash_vnodes;      /* default: 150                     */
} routa_config_t;

/* Initialize config with sensible defaults */
void routa_config_init(routa_config_t *cfg);

/* Parse routa.conf file. Returns 0 on success, -1 on error. */
int routa_config_load(routa_config_t *cfg, const char *path);

/* Validate config. Returns 0 if valid, -1 with LOG_ERROR if not. */
int routa_config_validate(const routa_config_t *cfg);

/* Print config to stderr (for debugging) */
void routa_config_dump(const routa_config_t *cfg);

#endif /* ROUTA_CORE_CONFIG_H */