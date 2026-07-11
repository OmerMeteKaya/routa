/* routa — main server entry point.
 *
 * Usage: routa [config-file]
 *   config-file defaults to "routa.conf" in the current directory if not
 *   given. See examples/routa.conf for the full reference of every key
 *   this file format understands.
 *
 * This binary is intentionally thin: it does the minimum needed to load a
 * config file, build a server from it, and run it. Anyone embedding routa
 * as a library (rather than running it standalone) would call
 * server_from_config_file()/server_from_config() directly instead of
 * shelling out to this binary -- see server.h.
 */
#include "core/server.h"
#include "core/config.h"
#include "util/logger.h"

#include <stdio.h>

int main(int argc, char *argv[]) {
    const char *config_path = argc > 1 ? argv[1] : "routa.conf";

    /* Fail loudly and refuse to start on a missing/invalid config file --
     * deliberately NOT falling back to hardcoded defaults here. A
     * production server silently running with defaults instead of the
     * operator's actual intended config is a much worse failure mode than
     * refusing to start with a clear error, since the former can look like
     * it's "working" while quietly ignoring everything the operator wrote
     * (wrong port, missing TLS, unintended upstreams, etc). */
    routa_config_t cfg;
    routa_config_init(&cfg);
    if (routa_config_load(&cfg, config_path) < 0) {
        fprintf(stderr, "routa: failed to load config file '%s'\n", config_path);
        fprintf(stderr, "routa: see examples/routa.conf for the full config reference\n");
        return 1;
    }
    if (routa_config_validate(&cfg) < 0) {
        fprintf(stderr, "routa: config file '%s' is invalid -- see the error above for details\n",
                config_path);
        return 1;
    }

    server_t *s = server_from_config(&cfg);
    if (!s) {
        fprintf(stderr, "routa: failed to start server from config '%s'\n", config_path);
        return 1;
    }
    /* Required for SIGHUP hot-reload to work at all -- server_from_config()
     * alone has no way to know which file to re-read on SIGHUP (that's
     * normally server_from_config_file()'s job, but this binary loads
     * config manually via routa_config_load()+routa_config_validate() for
     * better error messages, bypassing that). Without this call, every
     * SIGHUP was silently a no-op in production (confirmed via bench
     * testing under sustained load: 5 consecutive SIGHUPs produced "hot
     * reload: no config path stored, skipping" every time). */
    server_set_config_path(config_path);

    LOG_INFO("routa: starting on port %d (config: %s)", cfg.port, config_path);
    server_run(s);
    server_free(s);
    return 0;
}
