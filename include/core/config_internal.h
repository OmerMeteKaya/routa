#ifndef ROUTA_CORE_CONFIG_INTERNAL_H
#define ROUTA_CORE_CONFIG_INTERNAL_H

#include "core/config.h"
#include <stdio.h>

/* Internal entry points shared between config.c and config_multi.c only --
 * not part of the public config.h API. They let config_multi.c feed an
 * in-memory `[server NAME]` block (via fmemopen()) through EXACTLY the same
 * line-parsing state machine a real standalone file goes through, so a
 * server block's syntax can never drift from single-server routa.conf
 * syntax. See config.c for the implementations. */

/* First-pass scan of an already-open stream for a `resource_profile` line
 * (see prescan_resource_profile() in config.c for why this needs to run
 * before the real parse). Does not close `f`. */
void prescan_resource_profile_stream(routa_config_t *cfg, FILE *f);

/* Parses an already-open stream line-by-line into `cfg`. `path` is used
 * only for log messages. `depth` guards `include` recursion (pass 0 for a
 * fresh top-level unit). Does not close `f`. Returns 0 on success, -1 on
 * error. */
int routa_config_parse_stream(routa_config_t *cfg, FILE *f, const char *path, int depth);

#endif /* ROUTA_CORE_CONFIG_INTERNAL_H */
