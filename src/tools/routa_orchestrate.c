/* routa-orchestrate — turns one multi-server authoring config (containing
 * one or more `[server NAME]` blocks, see include/core/config_multi.h) into:
 *
 *   1. a standalone single-server .conf file per [server NAME] block,
 *      written exactly as if that block had been authored as its own
 *      routa.conf (out-dir/<name>.conf)
 *   2. a single systemd TEMPLATE unit, routa@.service, instantiable as
 *      `routa@<name>.service` for any generated server
 *
 * This tool is deliberately separate from the `routa` binary itself --
 * routa's own core (event_loop.c/server.c/main.c) never learns that
 * "multiple servers" is a concept; every routa OS process it supervises
 * still just loads one plain single-server .conf file, same as always.
 *
 * Re-running this tool against the same input is idempotent: the generated
 * files are a pure function of the parsed config (no timestamps or other
 * non-deterministic content), and it NEVER starts/stops/restarts a running
 * routa process itself -- regenerating config after an edit must never have
 * the side effect of bouncing a live production server. Bringing servers up
 * (or restarting them after a config change) is always a systemctl command
 * this tool prints, never one it runs, except behind an explicit --apply
 * flag which only ENABLES+STARTS units (never restarts an already-running
 * one -- systemctl enable --now is a no-op start for units already active).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/config_multi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

/* ── small helpers ────────────────────────────────────────────────────── */

static int mkdir_p(const char *path) {
    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static const char *lb_algo_name(cfg_lb_algo_t a) {
    switch (a) {
        case CFG_LB_ROUND_ROBIN:     return "round_robin";
        case CFG_LB_WEIGHTED_RR:     return "weighted_rr";
        case CFG_LB_LEAST_CONN:      return "least_conn";
        case CFG_LB_IP_HASH:         return "ip_hash";
        case CFG_LB_RANDOM:          return "random";
        case CFG_LB_P2C:             return "p2c";
        case CFG_LB_CONSISTENT_HASH: return "consistent_hash";
        default:                     return "round_robin";
    }
}

static const char *hc_type_name(cfg_hc_type_t t) {
    switch (t) {
        case CFG_HC_NONE:   return "none";
        case CFG_HC_TCP:    return "tcp";
        case CFG_HC_HTTP:   return "http";
        case CFG_HC_CUSTOM: return "custom";
        default:            return "none";
    }
}

static const char *log_level_name(int lvl) {
    switch (lvl) {
        case 0: return "debug";
        case 1: return "info";
        case 2: return "warn";
        case 3: return "error";
        default: return "info";
    }
}

static const char *file_cache_strategy_name(int s) {
    switch (s) {
        case 0: return "ttl";
        case 1: return "stat_ttl";
        case 2: return "inotify";
        default: return "stat_ttl";
    }
}

static const char *stream_lookup_name(h2_stream_lookup_t v) {
    return v == H2_STREAM_LOOKUP_HASHMAP ? "hashmap" : "linear";
}

/* Every string value is written quoted -- harmless for values that don't
 * need it (the parser's strip_quotes() only fires when the WHOLE value is
 * wrapped in ""), and correct for the ones that do (spaces, e.g. an auth
 * realm). Never used for composite values with their own sub-syntax
 * (upstream lines, header rules, static_dir, acl rules). */
static void wq(FILE *out, const char *key, const char *val) {
    fprintf(out, "%s = \"%s\"\n", key, val);
}
static void wb(FILE *out, const char *key, int val) {
    fprintf(out, "%s = %s\n", key, val ? "true" : "false");
}
static void wi(FILE *out, const char *key, long long val) {
    fprintf(out, "%s = %lld\n", key, val);
}
static void wms(FILE *out, const char *key, int ms) {
    fprintf(out, "%s = %dms\n", key, ms);
}
static void ws_(FILE *out, const char *key, int seconds) {
    fprintf(out, "%s = %ds\n", key, seconds);
}
static void wbytes(FILE *out, const char *key, long long bytes) {
    fprintf(out, "%s = %lldB\n", key, bytes);
}
static void wmb(FILE *out, const char *key, long long mb) {
    fprintf(out, "%s = %lldMB\n", key, mb);
}

/* Writes one pool's full [pool NAME] section. */
static void write_pool(FILE *out, const lb_pool_config_t *p) {
    fprintf(out, "\n[pool %s]\n", p->name);
    wq(out, "lb_route", p->route);
    fprintf(out, "lb_algo = %s\n", lb_algo_name(p->lb_algo));

    for (int i = 0; i < p->upstream_count; i++) {
        fprintf(out, "upstream %s%s:%d weight=%d\n",
                p->upstreams[i].use_tls ? "https://" : "",
                p->upstreams[i].host, p->upstreams[i].port,
                p->upstreams[i].weight);
    }

    wi(out, "lb_pool_max_per_node", p->lb_pool_max_per_node);
    wms(out, "lb_pool_connect_timeout_ms", p->lb_pool_connect_timeout_ms);
    wms(out, "lb_upstream_read_timeout_ms", p->lb_upstream_read_timeout_ms);
    wms(out, "lb_upstream_write_timeout_ms", p->lb_upstream_write_timeout_ms);
    ws_(out, "lb_pool_idle_timeout_s", p->lb_pool_idle_timeout_s);

    wi(out, "lb_passive_fail_threshold", p->lb_passive_fail_threshold);
    wi(out, "lb_passive_recover_threshold", p->lb_passive_recover_threshold);
    wms(out, "lb_half_open_retry_after_ms", p->lb_half_open_retry_after_ms);

    fprintf(out, "lb_hc_type = %s\n", hc_type_name(p->lb_hc_type));
    wq(out, "lb_hc_path", p->lb_hc_path);
    wms(out, "lb_hc_interval_ms", p->lb_hc_interval_ms);
    wms(out, "lb_hc_timeout_ms", p->lb_hc_timeout_ms);
    wi(out, "lb_hc_threshold_up", p->lb_hc_threshold_up);
    wi(out, "lb_hc_threshold_down", p->lb_hc_threshold_down);

    wi(out, "lb_max_retries", p->lb_max_retries);
    wb(out, "lb_retry_on_5xx", p->lb_retry_on_5xx);
    wi(out, "lb_consistent_hash_vnodes", p->lb_consistent_hash_vnodes);

    wb(out, "lb_sticky_session_enabled", p->sticky_session_enabled);
    wq(out, "lb_sticky_cookie_name", p->sticky_cookie_name);

    for (int i = 0; i < p->request_header_add_count; i++)
        fprintf(out, "request_header_add = %s: %s\n",
                p->request_header_add[i].name, p->request_header_add[i].value);
    for (int i = 0; i < p->request_header_remove_count; i++)
        fprintf(out, "request_header_remove = %s\n", p->request_header_remove[i]);
    for (int i = 0; i < p->response_header_add_count; i++)
        fprintf(out, "response_header_add = %s: %s\n",
                p->response_header_add[i].name, p->response_header_add[i].value);
    for (int i = 0; i < p->response_header_remove_count; i++)
        fprintf(out, "response_header_remove = %s\n", p->response_header_remove[i]);

    if (p->acl_enabled) {
        fprintf(out, "acl_default = %s\n", p->acl_default_allow ? "allow" : "deny");
        for (int i = 0; i < p->acl_rule_count; i++) {
            fprintf(out, "%s = %s\n", p->acl_rules[i].action == 0 ? "acl_allow" : "acl_deny",
                    p->acl_rules[i].rule);
        }
    }
}

/* Writes the full standalone single-server .conf for one [server NAME]
 * block's parsed routa_config_t -- every field, in the same order they
 * appear in include/core/config.h, so the output is a complete, valid
 * routa.conf a plain `routa` process can load with zero awareness that it
 * came from a multi-server source file. */
static void write_server_conf(FILE *out, const char *server_name, const routa_config_t *c) {
    fprintf(out,
        "# Generated by routa-orchestrate from [server %s] -- do not edit by hand.\n"
        "# Re-run routa-orchestrate against the source multi-server config instead;\n"
        "# this file will be overwritten byte-for-byte identically if nothing changed.\n\n",
        server_name);

    fprintf(out, "# ── Server basics ──\n");
    wi(out, "port", c->port);
    wi(out, "workers", c->n_workers);
    wi(out, "backlog", c->backlog);
    wbytes(out, "max_request_size", c->max_request_size);
    wms(out, "shutdown_timeout_ms", c->shutdown_timeout_ms);

    if (c->tls_enabled) {
        fprintf(out, "\n# ── TLS ──\n");
        wq(out, "tls_cert", c->tls_cert);
        wq(out, "tls_key", c->tls_key);
        ws_(out, "tls_session_timeout", c->tls_session_timeout);
        if (c->tls_ocsp_response[0]) wq(out, "tls_ocsp_response", c->tls_ocsp_response);

        for (int i = 0; i < c->sni_cert_count; i++) {
            fprintf(out, "\n[tls_cert %s]\n", c->sni_certs[i].hostname);
            wq(out, "cert", c->sni_certs[i].cert);
            wq(out, "key", c->sni_certs[i].key);
        }
    }

    fprintf(out, "\n# ── Logging ──\n");
    fprintf(out, "log_level = %s\n", log_level_name(c->log_level));
    if (c->log_file[0]) wq(out, "log_file", c->log_file);

    fprintf(out, "\n# ── Timeouts & connection limits ──\n");
    wms(out, "keepalive_timeout", c->keepalive_timeout_ms);
    wms(out, "request_timeout", c->request_timeout_ms);
    wi(out, "max_connections", c->max_connections);

    if (c->cache_enabled || c->cache_memory_mb) {
        fprintf(out, "\n# ── Response cache ──\n");
        wmb(out, "cache_memory_mb", (long long)c->cache_memory_mb);
        if (c->cache_dir[0]) wq(out, "cache_dir", c->cache_dir);
    }

    if (c->static_count > 0) {
        fprintf(out, "\n# ── Static file serving ──\n");
        for (int i = 0; i < c->static_count; i++)
            fprintf(out, "static_dir = %s -> %s\n",
                    c->static_dirs[i].url_prefix, c->static_dirs[i].doc_root);
    }

    fprintf(out, "\n# ── Static file cache ──\n");
    wb(out, "file_cache_enabled", c->file_cache_enabled);
    wi(out, "file_cache_entries", c->file_cache_max_entries);
    ws_(out, "file_cache_ttl", c->file_cache_ttl);
    fprintf(out, "file_cache_strategy = %s\n", file_cache_strategy_name(c->file_cache_strategy));

    fprintf(out, "\n# ── HTTP/2 ──\n");
    wb(out, "h2_enabled", c->h2.enabled);
    wbytes(out, "h2_header_table_size", c->h2.header_table_size);
    wb(out, "h2_huffman_encoding", c->h2.huffman_encoding);
    wb(out, "h2_dynamic_table_update", c->h2.dynamic_table_update);
    wbytes(out, "h2_initial_window_size", c->h2.initial_window_size);
    wbytes(out, "h2_max_frame_size", c->h2.max_frame_size);
    wbytes(out, "h2_max_header_list_size", c->h2.max_header_list_size);
    wi(out, "h2_max_concurrent_streams", c->h2.max_concurrent_streams);
    wi(out, "h2_max_concurrent_streams_hard_cap", c->h2.max_concurrent_streams_hard_cap);
    wms(out, "h2_stream_timeout_ms", c->h2.stream_timeout_ms);
    wms(out, "h2_keepalive_timeout_ms", c->h2.keepalive_timeout_ms);
    wb(out, "h2_server_push_enabled", c->h2.server_push_enabled);
    wb(out, "h2_c_upgrade_enabled", c->h2.h2c_upgrade_enabled);
    fprintf(out, "h2_stream_lookup = %s\n", stream_lookup_name(c->h2.stream_lookup));

    fprintf(out, "\n# ── WebSocket ──\n");
    wb(out, "ws_enabled", c->ws.enabled);
    wi(out, "ws_max_connections", c->ws.max_connections);
    wms(out, "ws_handshake_timeout_ms", c->ws.handshake_timeout_ms);
    wms(out, "ws_idle_timeout_ms", c->ws.idle_timeout_ms);
    wbytes(out, "ws_max_frame_size", (long long)c->ws.max_frame_size);
    wbytes(out, "ws_max_message_size", (long long)c->ws.max_message_size);
    wms(out, "ws_ping_interval_ms", c->ws.ping_interval_ms);
    wms(out, "ws_ping_timeout_ms", c->ws.ping_timeout_ms);
    wi(out, "ws_max_ping_misses", c->ws.max_ping_misses);
    wbytes(out, "ws_read_buf_size", (long long)c->ws.read_buf_size);
    wbytes(out, "ws_write_buf_size", (long long)c->ws.write_buf_size);
    wi(out, "ws_write_queue_max", c->ws.write_queue_max);
    wb(out, "ws_permessage_deflate", c->ws.permessage_deflate);
    wi(out, "ws_compression_level", c->ws.compression_level);
    wbytes(out, "ws_compression_threshold", (long long)c->ws.compression_threshold);
    wb(out, "ws_require_masking", c->ws.require_masking);

    fprintf(out, "\n# ── System resources ──\n");
    if (c->socket_recv_buf_size) wbytes(out, "socket_recv_buf_size", c->socket_recv_buf_size);
    if (c->socket_send_buf_size) wbytes(out, "socket_send_buf_size", c->socket_send_buf_size);
    wb(out, "cpu_affinity_enabled", c->cpu_affinity_enabled);
    wi(out, "cpu_affinity_start_core", c->cpu_affinity_start_core);
    if (c->memory_soft_limit_mb) wmb(out, "memory_soft_limit_mb", c->memory_soft_limit_mb);
    if (c->memory_hard_limit_mb) wmb(out, "memory_hard_limit_mb", c->memory_hard_limit_mb);
    wb(out, "numa_aware_enabled", c->numa_aware_enabled);

    if (c->acl_enabled) {
        fprintf(out, "\n# ── Global ACL ──\n");
        fprintf(out, "acl_default = %s\n", c->acl_default_allow ? "allow" : "deny");
        for (int i = 0; i < c->acl_rule_count; i++)
            fprintf(out, "%s = %s\n", c->acl_rules[i].action == 0 ? "acl_allow" : "acl_deny",
                    c->acl_rules[i].rule);
    }

    if (c->response_header_add_count || c->response_header_remove_count) {
        fprintf(out, "\n# ── Global header manipulation ──\n");
        for (int i = 0; i < c->response_header_add_count; i++)
            fprintf(out, "global_response_header_add = %s: %s\n",
                    c->response_header_add[i].name, c->response_header_add[i].value);
        for (int i = 0; i < c->response_header_remove_count; i++)
            fprintf(out, "global_response_header_remove = %s\n", c->response_header_remove[i]);
    }

    fprintf(out, "\n# ── Middleware ──\n");
    wb(out, "logger_enabled", c->logger_enabled);
    wb(out, "compress_enabled", c->compress_enabled);
    wbytes(out, "compress_min_size", (long long)c->compress_min_size);
    wi(out, "compress_level", c->compress_level);

    wb(out, "cors_enabled", c->cors_enabled);
    if (c->cors_enabled) {
        wq(out, "cors_origin", c->cors_origin);
        wq(out, "cors_methods", c->cors_methods);
        wq(out, "cors_headers", c->cors_headers);
    }

    wb(out, "auth_basic_enabled", c->auth_basic_enabled);
    if (c->auth_basic_enabled) {
        wq(out, "auth_basic_realm", c->auth_basic_realm);
        for (int i = 0; i < c->auth_basic_user_count; i++)
            fprintf(out, "auth_basic_user = %s:%s\n",
                    c->auth_basic_users[i].username, c->auth_basic_users[i].password);
    }

    wb(out, "auth_jwt_enabled", c->auth_jwt_enabled);
    if (c->auth_jwt_enabled) {
        if (c->auth_jwt_secret[0]) wq(out, "auth_jwt_secret", c->auth_jwt_secret);
        if (c->auth_jwt_pubkey_path[0]) wq(out, "auth_jwt_pubkey_path", c->auth_jwt_pubkey_path);
        wb(out, "auth_jwt_verify_exp", c->auth_jwt_verify_exp);
        if (c->auth_jwt_issuer[0]) wq(out, "auth_jwt_issuer", c->auth_jwt_issuer);
        if (c->auth_jwt_audience[0]) wq(out, "auth_jwt_audience", c->auth_jwt_audience);
    }

    wb(out, "rate_limit_enabled", c->rate_limit_enabled);
    if (c->rate_limit_enabled) {
        wi(out, "rate_limit_requests_per_second", c->rate_limit_requests_per_second);
        wi(out, "rate_limit_burst", c->rate_limit_burst);
    }

    wb(out, "metrics_enabled", c->metrics_enabled);
    if (c->metrics_enabled) wq(out, "metrics_path", c->metrics_path);

    for (int i = 0; i < c->pool_count; i++) write_pool(out, &c->pools[i]);
}

static void write_systemd_template(FILE *out, const char *routa_bin, const char *conf_dir) {
    fprintf(out,
        "# Generated by routa-orchestrate. Instantiable per server: for a server\n"
        "# named \"api\" (from a [server api] block), run:\n"
        "#   systemctl enable --now routa@api.service\n"
        "# %%i expands to the instance name (\"api\"), so this one template covers\n"
        "# every server generated from the source multi-server config.\n"
        "[Unit]\n"
        "Description=routa web server (%%i)\n"
        "Documentation=https://github.com/\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s %s/%%i.conf\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        routa_bin, conf_dir);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <multi-server-config> [options]\n"
        "\n"
        "Parses a routa config file containing one or more [server NAME] blocks\n"
        "(see include/core/config_multi.h) and generates:\n"
        "  - one standalone single-server .conf per [server NAME] block\n"
        "  - a systemd template unit, routa@.service, instantiable per server\n"
        "\n"
        "Options:\n"
        "  --out-dir DIR     directory for generated per-server .conf files\n"
        "                    (default: /etc/routa/servers)\n"
        "  --unit-dir DIR    directory to write routa@.service into\n"
        "                    (default: /etc/systemd/system)\n"
        "  --routa-bin PATH  path to the routa binary baked into ExecStart\n"
        "                    (default: /usr/local/bin/routa)\n"
        "  --apply           after generating, run `systemctl daemon-reload` and\n"
        "                    `systemctl enable --now` for every generated server.\n"
        "                    Prompts for confirmation unless --yes is also given.\n"
        "                    Never stops or restarts an already-running instance.\n"
        "  --yes             skip the --apply confirmation prompt\n"
        "  -h, --help        this message\n"
        "\n"
        "This tool never restarts a server that's already running -- re-run it\n"
        "after every config edit; to pick up changes on an already-running\n"
        "server, apply the printed `systemctl restart routa@<name>.service`\n"
        "yourself (or use ExecReload via `systemctl reload routa@<name>.service`\n"
        "for a SIGHUP hot-reload of settings that support it -- port/workers\n"
        "still require a restart).\n"
        "\n"
        "Observability:\n"
        "  systemctl status routa@<name>.service\n"
        "  journalctl -u routa@<name>.service -f\n",
        prog);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *config_path = NULL;
    const char *out_dir     = "/etc/routa/servers";
    const char *unit_dir    = "/etc/systemd/system";
    const char *routa_bin   = "/usr/local/bin/routa";
    int apply = 0, assume_yes = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        } else if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc) {
            out_dir = argv[++i];
        } else if (strcmp(argv[i], "--unit-dir") == 0 && i + 1 < argc) {
            unit_dir = argv[++i];
        } else if (strcmp(argv[i], "--routa-bin") == 0 && i + 1 < argc) {
            routa_bin = argv[++i];
        } else if (strcmp(argv[i], "--apply") == 0) {
            apply = 1;
        } else if (strcmp(argv[i], "--yes") == 0) {
            assume_yes = 1;
        } else if (argv[i][0] != '-') {
            config_path = argv[i];
        } else {
            fprintf(stderr, "routa-orchestrate: unknown option '%s'\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!config_path) { usage(argv[0]); return 1; }

    routa_multi_config_t multi;
    if (routa_multi_config_load(&multi, config_path) < 0) {
        fprintf(stderr, "routa-orchestrate: failed to load '%s'\n", config_path);
        return 1;
    }

    if (mkdir_p(out_dir) != 0) {
        fprintf(stderr, "routa-orchestrate: cannot create output directory '%s': %s\n",
                out_dir, strerror(errno));
        return 1;
    }
    if (mkdir_p(unit_dir) != 0) {
        fprintf(stderr, "routa-orchestrate: cannot create unit directory '%s': %s\n",
                unit_dir, strerror(errno));
        return 1;
    }

    for (int i = 0; i < multi.server_count; i++) {
        const routa_server_entry_t *srv = &multi.servers[i];
        int invalid = routa_config_validate(&srv->cfg) < 0;
        if (invalid) {
            fprintf(stderr, "routa-orchestrate: [server %s] failed validation, not writing its config\n",
                    srv->name[0] ? srv->name : "(default)");
            continue;
        }

        char path[1200];
        snprintf(path, sizeof(path), "%s/%s.conf", out_dir,
                 srv->name[0] ? srv->name : "default");
        FILE *out = fopen(path, "w");
        if (!out) {
            fprintf(stderr, "routa-orchestrate: cannot write '%s': %s\n", path, strerror(errno));
            continue;
        }
        write_server_conf(out, srv->name[0] ? srv->name : "default", &srv->cfg);
        fclose(out);
        printf("wrote %s\n", path);
    }

    char unit_path[1200];
    snprintf(unit_path, sizeof(unit_path), "%s/routa@.service", unit_dir);
    FILE *unit = fopen(unit_path, "w");
    if (!unit) {
        fprintf(stderr, "routa-orchestrate: cannot write '%s': %s\n", unit_path, strerror(errno));
        return 1;
    }
    write_systemd_template(unit, routa_bin, out_dir);
    fclose(unit);
    printf("wrote %s\n", unit_path);

    printf("\nTo bring every defined server up:\n");
    printf("  systemctl daemon-reload\n");
    for (int i = 0; i < multi.server_count; i++) {
        const char *name = multi.servers[i].name[0] ? multi.servers[i].name : "default";
        printf("  systemctl enable --now routa@%s.service\n", name);
    }
    printf("\nObservability, per server:\n");
    printf("  systemctl status routa@<name>.service\n");
    printf("  journalctl -u routa@<name>.service -f\n");
    printf("\nAfter editing the source config and re-running this tool, apply changes\n");
    printf("to an ALREADY-RUNNING server yourself (this tool never does it for you):\n");
    printf("  systemctl restart routa@<name>.service   # port/workers/TLS changes\n");
    printf("  systemctl reload  routa@<name>.service    # SIGHUP hot-reload (most other settings)\n");

    if (apply) {
        if (!assume_yes) {
            printf("\n--apply requested: this will run `systemctl daemon-reload` and "
                   "`systemctl enable --now` for every server listed above. Continue? [y/N] ");
            fflush(stdout);
            int c = getchar();
            if (c != 'y' && c != 'Y') {
                printf("Aborted -- no systemctl commands were run.\n");
                return 0;
            }
        }
        if (system("systemctl daemon-reload") != 0) {
            fprintf(stderr, "routa-orchestrate: systemctl daemon-reload failed\n");
            return 1;
        }
        for (int i = 0; i < multi.server_count; i++) {
            const char *name = multi.servers[i].name[0] ? multi.servers[i].name : "default";
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "systemctl enable --now routa@%s.service", name);
            printf("+ %s\n", cmd);
            if (system(cmd) != 0)
                fprintf(stderr, "routa-orchestrate: '%s' failed\n", cmd);
        }
    }

    routa_multi_config_free(&multi);
    return 0;
}
