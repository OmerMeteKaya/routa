//! Main parse loop: reads a config source line-by-line, tracks which
//! `[pool NAME]` / `[tls_cert HOSTNAME]` section (if any) is currently
//! active, and dispatches each `key = value` line to the right field on
//! `RoutaConfig` or the active `LbPoolConfig`.

use std::io::BufRead;
use std::path::Path;

use super::parse_helpers::*;
use super::types::*;

/// Parses `source` (already split into lines by the caller) into `cfg`,
/// starting at include-depth `depth`.
pub fn parse_lines(
    cfg: &mut RoutaConfig,
    lines: impl Iterator<Item = String>,
    depth: i32,
    ctx: &mut ParseContext,
) {
    let mut active_pool: Option<usize> = None; // index into cfg.pools
    let mut active_sni_cert: Option<usize> = None; // index into cfg.sni_certs

    for (lineno0, raw_line) in lines.enumerate() {
        let lineno = lineno0 + 1;

        // Skip whole-line comments/blank lines BEFORE ${VAR} expansion,
        // so a line like "# tls_cert = ${TLS_CERT}" explaining the syntax
        // is never expanded (and never warns about an unset var) just
        // because it starts with '#'.
        let raw_trimmed = raw_line.trim();
        if raw_trimmed.starts_with('#') || raw_trimmed.is_empty() {
            continue;
        }

        let expanded = expand_env_vars(&raw_line, ctx, lineno);
        let s = expanded.trim();
        if s.starts_with('#') || s.is_empty() {
            continue;
        }
        let s = strip_inline_comment(s).trim();
        if s.is_empty() {
            continue; // line was value + inline comment only
        }

        // `include glob-pattern` -- not key=value, handled before the
        // generic '=' split.
        if let Some(rest) = s.strip_prefix("include") {
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                let pattern = strip_quotes(rest.trim());
                if pattern.is_empty() {
                    ctx.warn(lineno, "include missing a glob pattern");
                } else {
                    handle_include(cfg, pattern, lineno, depth, ctx);
                }
                continue;
            }
        }

        // `[pool NAME]` / `[tls_cert HOSTNAME]` section header.
        if let Some(inner) = s.strip_prefix('[') {
            let Some(close) = inner.find(']') else {
                ctx.warn(lineno, format!("unterminated section header: {s}"));
                continue;
            };
            let inner = &inner[..close];
            active_sni_cert = None; // any new section header clears this

            if let Some(name) = inner
                .strip_prefix("pool")
                .filter(|r| r.is_empty() || r.starts_with(char::is_whitespace))
            {
                let name = name.trim();
                if cfg.pools.len() >= 16 {
                    ctx.warn(
                        lineno,
                        format!("max 16 [pool] sections exceeded, ignoring '{name}'"),
                    );
                    active_pool = None;
                } else {
                    let mut pool = LbPoolConfig::default();
                    pool.name = name.to_string();
                    pool.lb_enabled = true;
                    cfg.pools.push(pool);
                    active_pool = Some(cfg.pools.len() - 1);
                }
            } else if let Some(hostname) = inner
                .strip_prefix("tls_cert")
                .filter(|r| r.is_empty() || r.starts_with(char::is_whitespace))
            {
                active_pool = None;
                let hostname = hostname.trim();
                if hostname.is_empty() {
                    ctx.warn(lineno, "[tls_cert] section missing hostname");
                } else if cfg.sni_certs.len() >= 32 {
                    ctx.warn(
                        lineno,
                        format!("max 32 [tls_cert] sections exceeded, ignoring '{hostname}'"),
                    );
                } else {
                    cfg.sni_certs.push(SniCertConfig {
                        hostname: hostname.to_string(),
                        ..Default::default()
                    });
                    active_sni_cert = Some(cfg.sni_certs.len() - 1);
                }
            } else {
                ctx.warn(lineno, format!("unknown section '[{inner}]'"));
                active_pool = None;
            }
            continue;
        }

        // `upstream HOST:PORT [weight=N]` -- not key=value, handled
        // before the generic '=' split. https:// prefix marks TLS/H2.
        if let Some(rest) = s.strip_prefix("upstream") {
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                parse_upstream_line(cfg, rest.trim(), &mut active_pool, lineno, ctx);
                continue;
            }
        }

        let Some(eq) = s.find('=') else {
            ctx.warn(lineno, format!("missing '=' in line: {s}"));
            continue;
        };
        let key = s[..eq].trim();
        let val = strip_quotes(s[eq + 1..].trim());

        // Inside a [tls_cert HOSTNAME] section: only cert/key belong to
        // it. A non-cert/key line implicitly closes the section and
        // falls through to normal top-level key handling.
        if let Some(idx) = active_sni_cert {
            match key {
                "cert" => {
                    cfg.sni_certs[idx].cert = val.to_string();
                    continue;
                }
                "key" => {
                    cfg.sni_certs[idx].key = val.to_string();
                    continue;
                }
                _ => active_sni_cert = None,
            }
        }

        // lb_* keys apply to the active pool, or the implicit legacy
        // pool (pools[0]) if no [pool ...] section has been seen yet.
        if let Some(stripped) = key.strip_prefix("lb_") {
            let pool_idx = ensure_pool(cfg, active_pool);
            parse_lb_key(&mut cfg.pools[pool_idx], stripped, val, lineno, ctx);
            continue;
        }

        // Pool-scoped ACL: only when inside a [pool ...] section --
        // otherwise falls through to the global acl_* handling below.
        if matches!(key, "acl_default" | "acl_allow" | "acl_deny") {
            if let Some(idx) = active_pool {
                parse_pool_acl_key(&mut cfg.pools[idx], key, val);
                continue;
            }
            // active_pool is None: fall through to global handling below.
        }

        // Pool-scoped header manipulation (same active-pool targeting
        // rule as lb_*, but these keys don't start with "lb_").
        if matches!(
            key,
            "request_header_add"
                | "request_header_remove"
                | "response_header_add"
                | "response_header_remove"
        ) {
            let pool_idx = ensure_pool(cfg, active_pool);
            parse_pool_header_key(&mut cfg.pools[pool_idx], key, val, lineno, ctx);
            continue;
        }

        parse_top_level_key(cfg, key, val, lineno, ctx);
    }
}

/// Returns the index of the pool that untagged lb_*/header/acl lines
/// should apply to: the active `[pool ...]` section, or pools[0] as an
/// implicitly-created legacy pool if none has been opened yet.
fn ensure_pool(cfg: &mut RoutaConfig, active_pool: Option<usize>) -> usize {
    if let Some(idx) = active_pool {
        return idx;
    }
    if cfg.pools.is_empty() {
        let mut pool = LbPoolConfig::default();
        pool.lb_enabled = true;
        cfg.pools.push(pool);
    }
    0
}

fn parse_upstream_line(
    cfg: &mut RoutaConfig,
    rest: &str,
    active_pool: &mut Option<usize>,
    lineno: usize,
    ctx: &mut ParseContext,
) {
    let pool_idx = ensure_pool(cfg, *active_pool);

    let (use_tls, rest) = if let Some(r) = rest.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = rest.strip_prefix("http://") {
        (false, r)
    } else {
        (false, rest)
    };

    let (hostport, weight_part) = match rest.split_once(char::is_whitespace) {
        Some((hp, w)) => (hp, Some(w.trim())),
        None => (rest, None),
    };

    let Some(colon_idx) = hostport.rfind(':') else {
        ctx.warn(lineno, format!("upstream missing ':port': {hostport}"));
        return;
    };
    let (mut host, port_str) = (&hostport[..colon_idx], &hostport[colon_idx + 1..]);

    // IPv6 literal: "[::1]" -- strip brackets so callers get a bare
    // address. rfind(':') above already found the right ':' since it's
    // the last colon and IPv6 literals in this syntax are always
    // bracketed.
    if host.len() >= 2 && host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }

    let Ok(port) = port_str.parse::<u16>() else {
        ctx.warn(lineno, format!("upstream invalid port: {port_str}"));
        return;
    };
    if port == 0 {
        ctx.warn(lineno, format!("upstream invalid port: {port_str}"));
        return;
    }

    let weight = weight_part
        .and_then(|w| w.strip_prefix("weight="))
        .and_then(|w| w.parse::<i32>().ok())
        .unwrap_or(1);

    cfg.pools[pool_idx].upstreams.push(UpstreamConfig {
        host: host.to_string(),
        port,
        weight,
        use_tls,
    });
    let _ = active_pool; // pool creation already happened via ensure_pool
}

fn parse_lb_key(
    pool: &mut LbPoolConfig,
    key: &str, // with "lb_" prefix already stripped
    val: &str,
    lineno: usize,
    ctx: &mut ParseContext,
) {
    match key {
        "route" => pool.route = val.to_string(),
        "algo" => {
            pool.lb_algo = match val.to_ascii_lowercase().as_str() {
                "round_robin" => LbAlgo::RoundRobin,
                "weighted_rr" => LbAlgo::WeightedRr,
                "least_conn" => LbAlgo::LeastConn,
                "ip_hash" => LbAlgo::IpHash,
                "random" => LbAlgo::Random,
                "p2c" => LbAlgo::P2c,
                "consistent_hash" => LbAlgo::ConsistentHash,
                _ => LbAlgo::RoundRobin,
            };
        }
        "pool_max_per_node" => pool.lb_pool_max_per_node = cfg_atoi(val, 64),
        "pool_connect_timeout_ms" => {
            pool.lb_pool_connect_timeout_ms = cfg_duration_ms(val, 2000, ctx, lineno)
        }
        "upstream_read_timeout_ms" => {
            pool.lb_upstream_read_timeout_ms = cfg_duration_ms(val, 30_000, ctx, lineno)
        }
        "upstream_write_timeout_ms" => {
            pool.lb_upstream_write_timeout_ms = cfg_duration_ms(val, 30_000, ctx, lineno)
        }
        "pool_idle_timeout_s" => {
            pool.lb_pool_idle_timeout_s = cfg_duration_s(val, 60, ctx, lineno)
        }
        "passive_fail_threshold" => pool.lb_passive_fail_threshold = cfg_atoi(val, 3),
        "passive_recover_threshold" => pool.lb_passive_recover_threshold = cfg_atoi(val, 2),
        "half_open_retry_after_ms" => {
            pool.lb_half_open_retry_after_ms = cfg_duration_ms(val, 30_000, ctx, lineno)
        }
        "hc_type" => {
            pool.lb_hc_type = match val.to_ascii_lowercase().as_str() {
                "none" => HcType::None,
                "tcp" => HcType::Tcp,
                "http" => HcType::Http,
                "custom" => HcType::Custom,
                _ => HcType::None,
            };
        }
        "hc_path" => pool.lb_hc_path = val.to_string(),
        "hc_interval_ms" => pool.lb_hc_interval_ms = cfg_duration_ms(val, 5000, ctx, lineno),
        "hc_timeout_ms" => pool.lb_hc_timeout_ms = cfg_duration_ms(val, 2000, ctx, lineno),
        "hc_threshold_up" => pool.lb_hc_threshold_up = cfg_atoi(val, 2),
        "hc_threshold_down" => pool.lb_hc_threshold_down = cfg_atoi(val, 3),
        "max_retries" => pool.lb_max_retries = cfg_atoi(val, 1),
        "retry_on_5xx" => pool.lb_retry_on_5xx = cfg_atob(val, false, ctx, lineno),
        "consistent_hash_vnodes" => pool.lb_consistent_hash_vnodes = cfg_atoi(val, 150),
        "sticky_session_enabled" => {
            pool.sticky_session_enabled = cfg_atob(val, false, ctx, lineno)
        }
        "sticky_cookie_name" => pool.sticky_cookie_name = val.to_string(),
        other => ctx.warn(lineno, format!("unknown lb_* key 'lb_{other}'")),
    }
}

fn parse_pool_acl_key(pool: &mut LbPoolConfig, key: &str, val: &str) {
    pool.acl_enabled = true;
    match key {
        "acl_default" => {
            pool.acl_default_allow = val.eq_ignore_ascii_case("allow");
        }
        "acl_allow" => pool.acl_rules.push(AclRule {
            rule: val.to_string(),
            action: AclAction::Allow,
        }),
        "acl_deny" => pool.acl_rules.push(AclRule {
            rule: val.to_string(),
            action: AclAction::Deny,
        }),
        _ => unreachable!(),
    }
}

fn parse_pool_header_key(
    pool: &mut LbPoolConfig,
    key: &str,
    val: &str,
    lineno: usize,
    ctx: &mut ParseContext,
) {
    match key {
        "request_header_add" => match val.split_once(':') {
            Some((name, value)) => pool.request_header_add.push(HeaderRule {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            }),
            None => ctx.warn(lineno, format!("request_header_add missing ':': {val}")),
        },
        "request_header_remove" => pool.request_header_remove.push(val.to_string()),
        "response_header_add" => match val.split_once(':') {
            Some((name, value)) => pool.response_header_add.push(HeaderRule {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            }),
            None => ctx.warn(lineno, format!("response_header_add missing ':': {val}")),
        },
        "response_header_remove" => pool.response_header_remove.push(val.to_string()),
        _ => unreachable!(),
    }
}

fn parse_top_level_key(
    cfg: &mut RoutaConfig,
    key: &str,
    val: &str,
    lineno: usize,
    ctx: &mut ParseContext,
) {
    match key {
        // Already applied by a resource-profile prescan pass before this
        // loop runs -- see apply_resource_profile(). Recognized here only
        // so it doesn't fall into the "unknown key" branch.
        "resource_profile" => {}

        "port" => cfg.port = cfg_atoi(val, 8080),
        "workers" => cfg.n_workers = cfg_atoi(val, 12),
        "backlog" => cfg.backlog = cfg_atoi(val, 128),
        "tls_cert" => {
            cfg.tls_cert = val.to_string();
            cfg.tls_enabled = true;
        }
        "tls_key" => {
            cfg.tls_key = val.to_string();
            cfg.tls_enabled = true;
        }
        "log_level" => cfg.log_level = parse_log_level(val),
        "log_file" => cfg.log_file = val.to_string(),
        "keepalive_timeout" => {
            cfg.keepalive_timeout_ms = cfg_duration_ms(val, 30_000, ctx, lineno)
        }
        "request_timeout" => {
            cfg.request_timeout_ms = cfg_duration_ms(val, 10_000, ctx, lineno)
        }
        "max_connections" => cfg.max_connections = cfg_atoi(val, 10_000),
        "cache_memory_mb" => cfg.cache_memory_mb = cfg_size_mb(val, 64, ctx, lineno),
        "cache_dir" => {
            cfg.cache_dir = val.to_string();
            cfg.cache_enabled = true;
        }
        "static_dir" => match val.split_once("->") {
            Some((prefix, docroot)) => {
                cfg.static_dirs
                    .push((prefix.trim().to_string(), docroot.trim().to_string()));
            }
            None => ctx.warn(lineno, format!("static_dir missing '->': {val}")),
        },

        "file_cache_enabled" => cfg.file_cache_enabled = cfg_atob(val, true, ctx, lineno),
        "file_cache_entries" => cfg.file_cache_max_entries = cfg_atoi(val, 512),
        "file_cache_ttl" => cfg.file_cache_ttl_s = cfg_duration_s(val, 5, ctx, lineno),
        "file_cache_strategy" => {
            cfg.file_cache_strategy = match val.to_ascii_lowercase().as_str() {
                "ttl" => FileCacheStrategy::Ttl,
                "stat_ttl" => FileCacheStrategy::StatTtl,
                "inotify" => FileCacheStrategy::Inotify,
                _ => FileCacheStrategy::StatTtl,
            };
        }
        "file_cache_mode" => {
            cfg.file_cache_mode = match val.to_ascii_lowercase().as_str() {
                "local" => FileCacheMode::Local,
                "shared_metadata" => FileCacheMode::SharedMetadata,
                "shared_content" => FileCacheMode::SharedContent,
                _ => FileCacheMode::SharedMetadata,
            };
        }
        "file_cache_lock" => {
            cfg.file_cache_lock = match val.to_ascii_lowercase().as_str() {
                "global" => FileCacheLock::Global,
                "sharded" => FileCacheLock::Sharded,
                _ => FileCacheLock::Sharded,
            };
        }
        "file_cache_shards" => {
            let shards = cfg_atoi(val, 16).max(1);
            // Round up to the next power of 2.
            let mut p = 1;
            while p < shards {
                p <<= 1;
            }
            cfg.file_cache_shards = p;
        }
        "file_cache_eviction" => {
            cfg.file_cache_eviction = match val.to_ascii_lowercase().as_str() {
                "lru" => FileCacheEviction::Lru,
                "lfu" => FileCacheEviction::Lfu,
                "ttl_only" => FileCacheEviction::TtlOnly,
                _ => FileCacheEviction::Lru,
            };
        }
        "file_cache_negative_ttl" => {
            cfg.file_cache_negative_ttl_s = cfg_duration_s(val, 0, ctx, lineno)
        }
        "file_cache_mmap_threshold" => cfg.file_cache_mmap_threshold = cfg_atoi(val, 64 * 1024),
        "file_cache_max_memory_mb" => cfg.file_cache_max_memory_mb = cfg_atoi(val, 0),
        "file_cache_watch" => {
            cfg.file_cache_watch = match val.to_ascii_lowercase().as_str() {
                "none" => FileCacheWatch::None,
                "inotify" => FileCacheWatch::Inotify,
                _ => FileCacheWatch::None,
            };
        }

        "tls_session_timeout" => {
            cfg.tls_session_timeout = cfg_duration_s(val, 3600, ctx, lineno)
        }
        "tls_ocsp_response" => cfg.tls_ocsp_response = val.to_string(),
        "max_request_size" => {
            cfg.max_request_size = cfg_size_bytes(val, 1_048_576, ctx, lineno).max(0) as u64
        }
        "shutdown_timeout_ms" => {
            cfg.shutdown_timeout_ms = cfg_duration_ms(val, 30_000, ctx, lineno)
        }

        "h2_enabled" => cfg.h2.enabled = cfg_atob(val, true, ctx, lineno),
        "h2_header_table_size" => {
            cfg.h2.header_table_size = cfg_size_bytes(val, 4096, ctx, lineno).max(0) as u32
        }
        "h2_huffman_encoding" => cfg.h2.huffman_encoding = cfg_atob(val, true, ctx, lineno),
        "h2_dynamic_table_update" => {
            cfg.h2.dynamic_table_update = cfg_atob(val, true, ctx, lineno)
        }
        "h2_initial_window_size" => {
            cfg.h2.initial_window_size = cfg_size_bytes(val, 65_535, ctx, lineno).max(0) as u32
        }
        "h2_max_frame_size" => {
            cfg.h2.max_frame_size = cfg_size_bytes(val, 16_384, ctx, lineno).max(0) as u32
        }
        "h2_max_header_list_size" => {
            cfg.h2.max_header_list_size = cfg_size_bytes(val, 0, ctx, lineno).max(0) as u32
        }
        "h2_max_concurrent_streams" => {
            cfg.h2.max_concurrent_streams = cfg_atoi(val, 128).max(0) as u32
        }
        "h2_max_concurrent_streams_hard_cap" => {
            cfg.h2.max_concurrent_streams_hard_cap = cfg_atoi(val, 256).max(0) as u32
        }
        "h2_stream_timeout_ms" => {
            cfg.h2.stream_timeout_ms = cfg_duration_ms(val, 30_000, ctx, lineno)
        }
        "h2_keepalive_timeout_ms" => {
            cfg.h2.keepalive_timeout_ms = cfg_duration_ms(val, 120_000, ctx, lineno)
        }
        "h2_server_push_enabled" => {
            cfg.h2.server_push_enabled = cfg_atob(val, true, ctx, lineno)
        }
        "h2_c_upgrade_enabled" => {
            cfg.h2.h2c_upgrade_enabled = cfg_atob(val, true, ctx, lineno)
        }
        "h2_stream_lookup" => {
            cfg.h2.stream_lookup = match val.to_ascii_lowercase().as_str() {
                "linear" => H2StreamLookup::Linear,
                "hashmap" => H2StreamLookup::Hashmap,
                _ => H2StreamLookup::Linear,
            };
        }

        "logger_enabled" => cfg.logger_enabled = cfg_atob(val, true, ctx, lineno),
        "compress_enabled" => cfg.compress_enabled = cfg_atob(val, true, ctx, lineno),
        "compress_min_size" => {
            cfg.compress_min_size = cfg_size_bytes(val, 256, ctx, lineno).max(0) as u64
        }
        "compress_level" => cfg.compress_level = cfg_atoi(val, 6),
        "cors_enabled" => cfg.cors_enabled = cfg_atob(val, false, ctx, lineno),
        "cors_origin" => cfg.cors_origin = val.to_string(),
        "cors_methods" => cfg.cors_methods = val.to_string(),
        "cors_headers" => cfg.cors_headers = val.to_string(),

        "auth_basic_enabled" => cfg.auth_basic_enabled = cfg_atob(val, false, ctx, lineno),
        "auth_basic_realm" => cfg.auth_basic_realm = val.to_string(),
        "auth_basic_user" => match val.split_once(':') {
            Some((user, pass)) => {
                if cfg.auth_basic_users.len() >= 32 {
                    ctx.warn(lineno, "max 32 auth_basic_user entries exceeded");
                } else {
                    cfg.auth_basic_users
                        .insert(user.to_string(), pass.to_string());
                }
            }
            None => ctx.warn(lineno, format!("auth_basic_user missing ':password': {val}")),
        },

        "auth_jwt_enabled" => cfg.auth_jwt_enabled = cfg_atob(val, false, ctx, lineno),
        "auth_jwt_secret" => cfg.auth_jwt_secret = val.to_string(),
        "auth_jwt_pubkey_path" => cfg.auth_jwt_pubkey_path = val.to_string(),
        "auth_jwt_verify_exp" => cfg.auth_jwt_verify_exp = cfg_atob(val, true, ctx, lineno),
        "auth_jwt_issuer" => cfg.auth_jwt_issuer = val.to_string(),
        "auth_jwt_audience" => cfg.auth_jwt_audience = val.to_string(),

        "rate_limit_enabled" => cfg.rate_limit_enabled = cfg_atob(val, false, ctx, lineno),
        "rate_limit_requests_per_second" => {
            cfg.rate_limit_requests_per_second = cfg_atoi(val, 100)
        }
        "rate_limit_burst" => cfg.rate_limit_burst = cfg_atoi(val, 200),

        "metrics_enabled" => cfg.metrics_enabled = cfg_atob(val, true, ctx, lineno),
        "metrics_path" => cfg.metrics_path = val.to_string(),

        "global_response_header_add" => match val.split_once(':') {
            Some((name, value)) => {
                if cfg.response_header_add.len() >= 16 {
                    ctx.warn(lineno, "max 16 global_response_header_add rules exceeded");
                } else {
                    cfg.response_header_add.push(HeaderRule {
                        name: name.trim().to_string(),
                        value: value.trim().to_string(),
                    });
                }
            }
            None => ctx.warn(
                lineno,
                format!("global_response_header_add missing ':': {val}"),
            ),
        },
        "global_response_header_remove" => {
            if cfg.response_header_remove.len() >= 16 {
                ctx.warn(lineno, "max 16 global_response_header_remove rules exceeded");
            } else {
                cfg.response_header_remove.push(val.to_string());
            }
        }

        "socket_recv_buf_size" => {
            cfg.socket_recv_buf_size = cfg_size_bytes(val, 0, ctx, lineno) as i32
        }
        "socket_send_buf_size" => {
            cfg.socket_send_buf_size = cfg_size_bytes(val, 0, ctx, lineno) as i32
        }
        "cpu_affinity_enabled" => cfg.cpu_affinity_enabled = cfg_atob(val, false, ctx, lineno),
        "cpu_affinity_start_core" => cfg.cpu_affinity_start_core = cfg_atoi(val, 0),
        "memory_soft_limit_mb" => {
            cfg.memory_soft_limit_mb = cfg_size_mb(val, 0, ctx, lineno) as i32
        }
        "memory_hard_limit_mb" => {
            cfg.memory_hard_limit_mb = cfg_size_mb(val, 0, ctx, lineno) as i32
        }
        "numa_aware_enabled" => cfg.numa_aware_enabled = cfg_atob(val, false, ctx, lineno),

        "ws_enabled" => cfg.ws.enabled = cfg_atob(val, false, ctx, lineno),
        "ws_max_connections" => cfg.ws.max_connections = cfg_atoi(val, 10_000),
        "ws_handshake_timeout_ms" => {
            cfg.ws.handshake_timeout_ms = cfg_duration_ms(val, 5000, ctx, lineno)
        }
        "ws_idle_timeout_ms" => {
            cfg.ws.idle_timeout_ms = cfg_duration_ms(val, 0, ctx, lineno)
        }
        "ws_max_frame_size" => {
            cfg.ws.max_frame_size =
                cfg_size_bytes(val, 16 * 1024 * 1024, ctx, lineno).max(0) as u64
        }
        "ws_max_message_size" => {
            cfg.ws.max_message_size =
                cfg_size_bytes(val, 64 * 1024 * 1024, ctx, lineno).max(0) as u64
        }
        "ws_ping_interval_ms" => {
            cfg.ws.ping_interval_ms = cfg_duration_ms(val, 30_000, ctx, lineno)
        }
        "ws_ping_timeout_ms" => {
            cfg.ws.ping_timeout_ms = cfg_duration_ms(val, 10_000, ctx, lineno)
        }
        "ws_max_ping_misses" => cfg.ws.max_ping_misses = cfg_atoi(val, 3),
        "ws_read_buf_size" => {
            cfg.ws.read_buf_size = cfg_size_bytes(val, 65_536, ctx, lineno).max(0) as u64
        }
        "ws_write_buf_size" => {
            cfg.ws.write_buf_size = cfg_size_bytes(val, 65_536, ctx, lineno).max(0) as u64
        }
        "ws_write_queue_max" => cfg.ws.write_queue_max = cfg_atoi(val, 128),
        "ws_permessage_deflate" => {
            cfg.ws.permessage_deflate = cfg_atob(val, false, ctx, lineno)
        }
        "ws_compression_level" => cfg.ws.compression_level = cfg_atoi(val, 6),
        "ws_compression_threshold" => {
            cfg.ws.compression_threshold = cfg_size_bytes(val, 512, ctx, lineno).max(0) as u64
        }
        "ws_require_masking" => cfg.ws.require_masking = cfg_atob(val, true, ctx, lineno),

        "acl_default" => {
            cfg.acl_enabled = true;
            cfg.acl_default_allow = val.eq_ignore_ascii_case("allow");
        }
        "acl_allow" => {
            cfg.acl_enabled = true;
            if cfg.acl_rules.len() >= 64 {
                ctx.warn(lineno, "max 64 acl_allow/acl_deny rules exceeded");
            } else {
                cfg.acl_rules.push(AclRule {
                    rule: val.to_string(),
                    action: AclAction::Allow,
                });
            }
        }
        "acl_deny" => {
            cfg.acl_enabled = true;
            if cfg.acl_rules.len() >= 64 {
                ctx.warn(lineno, "max 64 acl_allow/acl_deny rules exceeded");
            } else {
                cfg.acl_rules.push(AclRule {
                    rule: val.to_string(),
                    action: AclAction::Deny,
                });
            }
        }

        other => ctx.warn(lineno, format!("unknown key '{other}'")),
    }
}

/// Resolves `pattern` (a glob, relative to the process's cwd -- matching
/// the process's current working directory) and recursively parses every
/// matching file. Silently does nothing on zero matches (warns) or a
/// glob error (warns) rather than aborting the whole parse.
fn handle_include(
    cfg: &mut RoutaConfig,
    pattern: &str,
    lineno: usize,
    depth: i32,
    ctx: &mut ParseContext,
) {
    const MAX_INCLUDE_DEPTH: i32 = 8;
    if depth >= MAX_INCLUDE_DEPTH {
        ctx.warn(
            lineno,
            format!(
                "include depth exceeded ({MAX_INCLUDE_DEPTH}), possible include cycle -- ignoring 'include {pattern}'"
            ),
        );
        return;
    }

    let paths = match glob_paths(pattern) {
        Ok(p) => p,
        Err(e) => {
            ctx.warn(lineno, format!("include '{pattern}' failed ({e})"));
            return;
        }
    };
    if paths.is_empty() {
        ctx.warn(lineno, format!("include '{pattern}' matched no files"));
        return;
    }

    for path in paths {
        if let Err(e) = parse_file(cfg, &path, depth + 1, ctx) {
            ctx.warn(lineno, format!("including {}: {e}", path.display()));
        }
    }
}

/// Minimal glob: supports a single `*` wildcard per path component
/// (covers every pattern used in routa's own config/examples/tests,
/// e.g. "conf.d/*.conf"). A full glob crate can replace this later
/// without changing any caller.
fn glob_paths(pattern: &str) -> std::io::Result<Vec<std::path::PathBuf>> {
    let path = Path::new(pattern);
    let (dir, file_pattern) = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => (p, path.file_name().unwrap()),
        _ => (Path::new("."), path.as_os_str()),
    };
    let file_pattern = file_pattern.to_string_lossy();
    let Some((prefix, suffix)) = file_pattern.split_once('*') else {
        // No wildcard: treat as a literal path.
        return Ok(if path.exists() {
            vec![path.to_path_buf()]
        } else {
            vec![]
        });
    };

    let mut matches = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(prefix) && name.ends_with(suffix) {
                matches.push(entry.path());
            }
        }
    }
    matches.sort();
    Ok(matches)
}

/// Reads and parses a real file on disk, recursing into any `include`
/// lines it contains.
pub fn parse_file(
    cfg: &mut RoutaConfig,
    path: &Path,
    depth: i32,
    ctx: &mut ParseContext,
) -> std::io::Result<()> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let lines = reader.lines().map(|l| l.unwrap_or_default());
    parse_lines(cfg, lines, depth, ctx);
    Ok(())
}

/// Scans `path` for a top-level `resource_profile = ...` line and
/// applies it (see apply_resource_profile()) before the real parse
/// pass runs, so that later explicit keys in the file always win over
/// the profile's defaults regardless of where in the file
/// `resource_profile` itself appears.
pub fn prescan_resource_profile(cfg: &mut RoutaConfig, path: &Path) -> std::io::Result<()> {
    let content = std::fs::read_to_string(path)?;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if let Some((key, val)) = t.split_once('=') {
            if key.trim() == "resource_profile" {
                let profile = match val.trim().to_ascii_lowercase().as_str() {
                    "light" => ResourceProfile::Light,
                    "performance" => ResourceProfile::Performance,
                    _ => ResourceProfile::Balanced,
                };
                apply_resource_profile(cfg, profile);
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Top-level entry point: builds a fresh RoutaConfig from a file on
/// disk, applying any resource_profile first and then the rest of the
/// file's keys (which always override the profile's defaults).
pub fn load(path: &Path) -> std::io::Result<(RoutaConfig, ParseContext)> {
    let mut cfg = RoutaConfig::default();
    prescan_resource_profile(&mut cfg, path)?;
    let mut ctx = ParseContext {
        warnings: Vec::new(),
        depth: 0,
    };
    parse_file(&mut cfg, path, 0, &mut ctx)?;
    Ok((cfg, ctx))
}
