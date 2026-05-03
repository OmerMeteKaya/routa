#ifndef ROUTA_CORE_CONFIG_H
#define ROUTA_CORE_CONFIG_H

#include <stddef.h>

#define ROUTA_MAX_UPSTREAMS  64
#define ROUTA_MAX_STATIC     16
#define ROUTA_MAX_MIDDLEWARES 32

typedef struct {
    /* Network */
    int   port;           /* default: 8080 */
    int   n_workers;      /* default: CPU count */
    int   backlog;        /* default: 128 */

    /* TLS */
    int   tls_enabled;
    char  tls_cert[512];
    char  tls_key[512];

    /* Static file serving */
    struct {
        char url_prefix[256];
        char doc_root[512];
        int  enable_index;
    } static_dirs[ROUTA_MAX_STATIC];
    int static_count;

    /* Logging */
    int         log_level;   /* 0=debug 1=info 2=warn 3=error */
    char        log_file[512]; /* empty = stderr */

    /* Timeouts (ms) */
    int keepalive_timeout_ms;   /* default: 30000 */
    int request_timeout_ms;     /* default: 10000 */

    /* Limits */
    int max_connections;        /* default: 10000 */
    int max_request_size;       /* default: 1MB */

    /* Cache */
    int   cache_enabled;
    size_t cache_memory_mb;     /* default: 64 */
    char  cache_dir[512];       /* empty = memory only */
} routa_config_t;

/* Initialize config with sensible defaults */
void routa_config_init(routa_config_t *cfg);

/* Parse routa.conf file. Returns 0 on success, -1 on error.
   Unknown keys are logged as warnings but not fatal. */
int routa_config_load(routa_config_t *cfg, const char *path);

/* Validate config. Returns 0 if valid, -1 with LOG_ERROR if not. */
int routa_config_validate(const routa_config_t *cfg);

/* Print config to stderr (for debugging) */
void routa_config_dump(const routa_config_t *cfg);

#endif /* ROUTA_CORE_CONFIG_H */
