#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/config_multi.h"
#include "core/config_internal.h"
#include "util/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Small growable string buffer, used to accumulate one [server NAME]
 * block's raw lines before handing them to routa_config_parse_stream() via
 * fmemopen(). ─────────────────────────────────────────────────────────── */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} strbuf_t;

static void strbuf_init(strbuf_t *b) {
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

static void strbuf_append(strbuf_t *b, const char *s) {
    size_t slen = strlen(s);
    if (b->len + slen + 1 > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 4096;
        while (new_cap < b->len + slen + 1) new_cap *= 2;
        char *grown = realloc(b->data, new_cap);
        if (!grown) return; /* out of memory: block truncated, not crashed */
        b->data = grown;
        b->cap  = new_cap;
    }
    memcpy(b->data + b->len, s, slen);
    b->len += slen;
    b->data[b->len] = '\0';
}

static void strbuf_free(strbuf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* Trims leading/trailing whitespace, returning a pointer into `s` (same
 * convention as config.c's own trim() -- duplicated here rather than
 * shared, since it's a two-line static helper and not worth exposing
 * across the internal header just for this). */
static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t slen = strlen(s);
    if (slen == 0) return s;
    char *end = s + slen - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Recognizes a top-level `[server NAME]` header line (already trimmed).
 * Returns the trimmed NAME (points into `s`), or NULL if `s` isn't a
 * [server ...] header at all. */
static char *match_server_header(char *s) {
    if (*s != '[') return NULL;
    char *close = strchr(s, ']');
    if (!close) return NULL;
    *close = '\0';
    char *inner = trim(s + 1);
    if (strncmp(inner, "server", 6) != 0) return NULL;
    if (inner[6] != '\0' && !isspace((unsigned char)inner[6])) return NULL;
    return trim(inner + 6);
}

/* Loads one already-collected [server NAME] block's text into a fresh
 * routa_config_t, via the exact same two-pass (resource_profile prescan,
 * then full parse) flow routa_config_load() uses for a real file --
 * except both passes read from an in-memory buffer (fmemopen()) rather
 * than a file on disk, since the block's text doesn't exist as its own
 * file anywhere. Returns 0 on success, -1 on error. */
static int load_server_block(routa_config_t *cfg, const char *name,
                             const char *text, size_t text_len) {
    routa_config_init(cfg);

    FILE *f1 = fmemopen((void *)text, text_len, "r");
    if (!f1) {
        LOG_ERROR("config: [server %s]: fmemopen failed for resource_profile prescan", name);
        return -1;
    }
    prescan_resource_profile_stream(cfg, f1);
    (void)fclose(f1);

    FILE *f2 = fmemopen((void *)text, text_len, "r");
    if (!f2) {
        LOG_ERROR("config: [server %s]: fmemopen failed for parse", name);
        return -1;
    }
    char label[96];
    snprintf(label, sizeof(label), "[server %s]", name);
    int rc = routa_config_parse_stream(cfg, f2, label, 0);
    (void)fclose(f2);
    return rc;
}

int routa_multi_config_load(routa_multi_config_t *out, const char *path) {
    memset(out, 0, sizeof(*out));

    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open config file: %s", path);
        return -1;
    }

    strbuf_t   blocks[ROUTA_MAX_SERVERS];
    char       names[ROUTA_MAX_SERVERS][64];
    int        block_count = 0;
    int        have_pre_server_content = 0;
    int        pre_server_lineno = 0;
    int        lineno = 0;

    char raw_line[1024];
    while (fgets(raw_line, sizeof(raw_line), f)) {
        lineno++;

        char check[1024];
        strncpy(check, raw_line, sizeof(check) - 1);
        check[sizeof(check) - 1] = '\0';
        char *trimmed = trim(check);
        int is_comment_or_blank = (*trimmed == '#' || *trimmed == '\0');

        if (!is_comment_or_blank) {
            char *name = match_server_header(trimmed);
            if (name) {
                if (*name == '\0') {
                    LOG_ERROR("config:%d: [server] section missing a name", lineno);
                    (void)fclose(f);
                    for (int i = 0; i < block_count; i++) strbuf_free(&blocks[i]);
                    return -1;
                }
                for (int i = 0; i < block_count; i++) {
                    if (strcmp(names[i], name) == 0) {
                        LOG_ERROR("config:%d: duplicate [server %s] section", lineno, name);
                        (void)fclose(f);
                        for (int j = 0; j < block_count; j++) strbuf_free(&blocks[j]);
                        return -1;
                    }
                }
                if (block_count >= ROUTA_MAX_SERVERS) {
                    LOG_ERROR("config:%d: max %d [server] sections exceeded, ignoring '%s'",
                              lineno, ROUTA_MAX_SERVERS, name);
                    (void)fclose(f);
                    for (int j = 0; j < block_count; j++) strbuf_free(&blocks[j]);
                    return -1;
                }
                strncpy(names[block_count], name, sizeof(names[block_count]) - 1);
                names[block_count][sizeof(names[block_count]) - 1] = '\0';
                strbuf_init(&blocks[block_count]);
                block_count++;
                continue; /* header line itself is not part of the block's body */
            }

            /* Real content (key=value, [pool]/[tls_cert], upstream,
             * include, or anything else) that isn't a [server ...] header. */
            if (block_count == 0 && !have_pre_server_content) {
                have_pre_server_content = 1;
                pre_server_lineno = lineno;
            }
        }

        if (block_count > 0) {
            strbuf_append(&blocks[block_count - 1], raw_line);
        }
        /* block_count == 0: comments/blank lines before the first [server]
         * header are harmless and simply dropped; real content in that
         * position is handled (as an error, once we know whether any
         * [server] block exists at all) below. */
    }
    (void)fclose(f);

    if (block_count == 0) {
        /* No [server ...] blocks at all: today's behavior, unchanged.
         * Load exactly the same way routa_config_load() always has, so
         * this is byte-for-byte identical to single-server parsing. */
        out->servers = calloc(1, sizeof(routa_server_entry_t));
        if (!out->servers) {
            LOG_ERROR("config: out of memory allocating routa_multi_config_t");
            return -1;
        }
        routa_config_init(&out->servers[0].cfg);
        out->servers[0].name[0] = '\0';
        if (routa_config_load(&out->servers[0].cfg, path) < 0) {
            free(out->servers);
            out->servers = NULL;
            return -1;
        }
        out->server_count = 1;
        return 0;
    }

    if (have_pre_server_content) {
        LOG_ERROR("config:%d: cannot mix top-level config keys with [server NAME] blocks -- "
                  "this file has %d [server ...] section(s), so every key/section must live "
                  "inside one of them (see config_multi.h for the exact rule)",
                  pre_server_lineno, block_count);
        for (int i = 0; i < block_count; i++) strbuf_free(&blocks[i]);
        return -1;
    }

    out->servers = calloc((size_t)block_count, sizeof(routa_server_entry_t));
    if (!out->servers) {
        LOG_ERROR("config: out of memory allocating %d server entries", block_count);
        for (int i = 0; i < block_count; i++) strbuf_free(&blocks[i]);
        return -1;
    }

    int rc = 0;
    for (int i = 0; i < block_count; i++) {
        strncpy(out->servers[i].name, names[i], sizeof(out->servers[i].name) - 1);
        if (load_server_block(&out->servers[i].cfg, names[i],
                              blocks[i].data ? blocks[i].data : "",
                              blocks[i].len) < 0) {
            LOG_ERROR("config: failed to parse [server %s] block", names[i]);
            rc = -1;
        }
        strbuf_free(&blocks[i]);
    }
    out->server_count = block_count;
    if (rc < 0) {
        routa_multi_config_free(out);
        return -1;
    }

    /* Duplicate ports across servers can never actually work (each routa
     * process binds unconditionally, there's no per-server bind address to
     * disambiguate them) -- warn loudly so the operator finds out at
     * config-generation time, not "why did only one server come up". Not a
     * hard error: some operators genuinely run these on different hosts
     * from one shared authoring file, so it's a warning, not a rejection. */
    for (int i = 0; i < out->server_count; i++) {
        for (int j = i + 1; j < out->server_count; j++) {
            if (out->servers[i].cfg.port == out->servers[j].cfg.port) {
                LOG_WARN("config: [server %s] and [server %s] both use port %d -- "
                         "they cannot both run on the same host",
                         out->servers[i].name, out->servers[j].name, out->servers[i].cfg.port);
            }
        }
    }

    return 0;
}

void routa_multi_config_free(routa_multi_config_t *out) {
    if (!out) return;
    free(out->servers);
    out->servers = NULL;
    out->server_count = 0;
}
