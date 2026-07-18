#ifndef ROUTA_CORE_CONFIG_MULTI_H
#define ROUTA_CORE_CONFIG_MULTI_H

#include "core/config.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Multi-server config: `[server NAME]` blocks
 *
 * routa itself (event_loop.c, server.c, main.c) only ever knows how to load
 * and run ONE routa_config_t / bind ONE port -- that isolation boundary is
 * deliberate (see README) and this file does not change it. What this file
 * adds is a way for a single top-level *authoring* file to describe SEVERAL
 * logical servers at once, each with its own port/workers/static roots/pools/
 * TLS certs/etc, by decomposing it into N independent routa_config_t
 * instances -- one per `[server NAME]` block, each exactly as if it had been
 * written as its own standalone routa.conf. Turning those into N supervised
 * OS processes is routa-orchestrate's job (src/tools/routa_orchestrate.c),
 * not this library's.
 *
 * Config file syntax:
 *
 *   [server web]
 *   port = 8080
 *   static_dir = / -> /var/www/web
 *
 *   [server api]
 *   port = 8443
 *   tls_cert = /etc/routa/certs/api.crt
 *   tls_key  = /etc/routa/certs/api.key
 *   [pool backend]
 *   upstream 10.0.0.1:3000
 *
 * Everything between a `[server NAME]` header and the next top-level
 * `[server ...]` header (or EOF) belongs to that server, using EXACTLY the
 * same syntax as today's single-server config (including its own nested
 * `[pool ...]` / `[tls_cert ...]` sections, `${VAR}` expansion, duration/size
 * units, etc.) -- see routa_multi_config_load() for the parsing approach.
 *
 * A file may have ZERO `[server ...]` blocks (today's behavior, unchanged:
 * a single implicit server, top-level keys apply directly) or ONE OR MORE
 * `[server NAME]` blocks (multi-server mode) -- but never both: any
 * top-level key/section content appearing BEFORE the first `[server ...]`
 * header, in a file that also has `[server ...]` blocks, is a hard error
 * (routa_multi_config_load() returns -1). This is deliberate: silently
 * guessing whether such a line belongs to "the whole file" or "gets
 * dropped" would be far worse than refusing to load.
 *
 * LIMITATION (documented, not a bug): `include` is only meaningful INSIDE a
 * `[server ...]` block (e.g. to pull in a shared set of pool definitions
 * for that one server) -- it cannot be used at the top level to assemble
 * `[server ...]` blocks from separate files, since block-splitting happens
 * on the top-level file's own text before any `include` is expanded. */

#define ROUTA_MAX_SERVERS 32

typedef struct {
    char           name[64];   /* from "[server NAME]" */
    routa_config_t cfg;
} routa_server_entry_t;

/* `servers` is heap-allocated (server_count entries) -- NOT inline, on
 * purpose: routa_config_t is ~750KB on its own (it embeds
 * ROUTA_MAX_LB_POOLS pools, each with its own upstream/header/ACL arrays),
 * so an inline `routa_server_entry_t servers[ROUTA_MAX_SERVERS]` would put
 * a ~24MB struct on the stack -- comfortably over a typical 8MB thread
 * stack, so *any* stack-declared routa_multi_config_t would reliably
 * segfault before a single field is even touched. Always call
 * routa_multi_config_free() when done. */
typedef struct {
    routa_server_entry_t *servers;
    int                    server_count;
} routa_multi_config_t;

/* Loads `path` as a multi-server config file. Returns 0 on success, -1 on
 * error (LOG_ERROR'd): malformed section headers, top-level content mixed
 * with [server] blocks, duplicate server names, more than
 * ROUTA_MAX_SERVERS blocks, or allocation failure. `out` is safe to pass to
 * routa_multi_config_free() even after a failed load (it's left zeroed).
 *
 * If the file has no `[server ...]` blocks at all, `out` ends up with
 * exactly one entry (name == ""), loaded via the ordinary
 * routa_config_init()+routa_config_load() path -- byte-for-byte identical
 * to loading the same file as a single-server config today. */
int routa_multi_config_load(routa_multi_config_t *out, const char *path);

/* Frees `out->servers` and zeroes `out`. Safe to call on a zero-initialized
 * or already-freed routa_multi_config_t. */
void routa_multi_config_free(routa_multi_config_t *out);

#endif /* ROUTA_CORE_CONFIG_MULTI_H */
