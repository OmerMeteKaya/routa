//! Config validation: checked once, after parsing and before
//! `RoutaServer::from_config` builds any runtime component from it.
//! Deliberately more thorough than the archived C implementation's
//! `routa_config_validate` (port/worker-count/TLS-cert-presence only)
//! -- catching an inconsistent config at load time (a pool routed
//! with zero upstreams, a rate limit of 0 req/s that would reject
//! every request, a TLS cert path that doesn't exist) is far cheaper
//! than discovering it once the server is already accepting traffic
//! and something silently doesn't work.
//!
//! Returns every problem found, not just the first one -- an operator
//! fixing a config file benefits from seeing all of its mistakes in
//! one pass rather than fixing one, re-running, hitting the next one.

use super::types::RoutaConfig;

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Validates `cfg`, returning every problem found. An empty `Vec`
/// means the config is valid and safe to build a server from.
pub fn validate(cfg: &RoutaConfig) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let err = |msg: String| ValidationError { message: msg };

    if !(1..=65535).contains(&cfg.port) {
        errors.push(err(format!("invalid port: {} (must be 1-65535)", cfg.port)));
    }
    if !(1..=256).contains(&cfg.n_workers) {
        errors.push(err(format!("invalid n_workers: {} (must be 1-256)", cfg.n_workers)));
    }

    if !(8..=4096).contains(&cfg.io_uring.ring_entries) {
        errors.push(err(format!(
            "invalid io_uring_ring_entries: {} (must be 8-4096)",
            cfg.io_uring.ring_entries
        )));
    } else if !(cfg.io_uring.ring_entries as u32).is_power_of_two() {
        errors.push(err(format!(
            "invalid io_uring_ring_entries: {} (must be a power of two -- io_uring's submission/completion rings require it)",
            cfg.io_uring.ring_entries
        )));
    }
    if cfg.io_uring.recv_buf_size < 512 {
        errors.push(err(format!(
            "invalid io_uring_recv_buf_size: {} (must be at least 512 bytes)",
            cfg.io_uring.recv_buf_size
        )));
    }

    if cfg.tls_enabled {
        if cfg.tls_cert.is_empty() || cfg.tls_key.is_empty() {
            errors.push(err("tls_enabled is set but tls_cert/tls_key are not both provided".to_string()));
        } else {
            if !std::path::Path::new(&cfg.tls_cert).exists() {
                errors.push(err(format!("tls_cert path does not exist: {}", cfg.tls_cert)));
            }
            if !std::path::Path::new(&cfg.tls_key).exists() {
                errors.push(err(format!("tls_key path does not exist: {}", cfg.tls_key)));
            }
        }
    }

    for sni in &cfg.sni_certs {
        if sni.cert.is_empty() || sni.key.is_empty() {
            errors.push(err(format!("[tls_cert {}] missing cert or key path", sni.hostname)));
        }
        if !cfg.tls_enabled {
            errors.push(err(format!(
                "[tls_cert {}] defined but top-level tls_enabled is false",
                sni.hostname
            )));
        }
    }

    if cfg.max_connections < 1 {
        errors.push(err(format!("invalid max_connections: {} (must be >= 1)", cfg.max_connections)));
    }
    if cfg.keepalive_timeout_ms < 0 {
        errors.push(err("keepalive_timeout_ms must not be negative".to_string()));
    }
    if cfg.request_timeout_ms < 0 {
        errors.push(err("request_timeout_ms must not be negative".to_string()));
    }

    if cfg.rate_limit_enabled {
        if cfg.rate_limit_requests_per_second <= 0 {
            errors.push(err(format!(
                "rate_limit_enabled is set but rate_limit_requests_per_second is {} (would reject every request)",
                cfg.rate_limit_requests_per_second
            )));
        }
        if cfg.rate_limit_burst <= 0 {
            errors.push(err(format!(
                "rate_limit_enabled is set but rate_limit_burst is {} (would reject every request)",
                cfg.rate_limit_burst
            )));
        }
    }

    if cfg.compress_enabled && !(1..=9).contains(&cfg.compress_level) {
        errors.push(err(format!("invalid compress_level: {} (must be 1-9)", cfg.compress_level)));
    }

    if cfg.auth_basic_enabled && cfg.auth_basic_users.is_empty() {
        errors.push(err("auth_basic_enabled is set but no users are configured".to_string()));
    }

    if cfg.auth_jwt_enabled && cfg.auth_jwt_secret.is_empty() && cfg.auth_jwt_pubkey_path.is_empty() {
        errors.push(err(
            "auth_jwt_enabled is set but neither auth_jwt_secret nor auth_jwt_pubkey_path is provided".to_string(),
        ));
    }
    if cfg.auth_jwt_enabled && !cfg.auth_jwt_pubkey_path.is_empty() && !std::path::Path::new(&cfg.auth_jwt_pubkey_path).exists() {
        errors.push(err(format!("auth_jwt_pubkey_path does not exist: {}", cfg.auth_jwt_pubkey_path)));
    }

    for (url_prefix, doc_root) in &cfg.static_dirs {
        if !std::path::Path::new(doc_root).exists() {
            errors.push(err(format!("static dir for '{url_prefix}' does not exist: {doc_root}")));
        }
    }

    for pool in &cfg.pools {
        if pool.lb_enabled && pool.upstreams.is_empty() {
            let name = if pool.name.is_empty() { "(default)" } else { &pool.name };
            errors.push(err(format!("pool '{name}' has lb_enabled=true but no upstreams configured")));
        }
        for upstream in &pool.upstreams {
            if upstream.weight < 0 {
                errors.push(err(format!(
                    "pool '{}' upstream {}:{} has a negative weight ({})",
                    pool.name, upstream.host, upstream.port, upstream.weight
                )));
            }
        }
        if pool.lb_max_retries < 0 {
            errors.push(err(format!("pool '{}' has a negative lb_max_retries ({})", pool.name, pool.lb_max_retries)));
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = RoutaConfig::default();
        assert!(validate(&cfg).is_empty(), "default config should have no validation errors");
    }

    #[test]
    fn invalid_port_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.port = 0;
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("port")));
    }

    #[test]
    fn invalid_worker_count_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.n_workers = 0;
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("n_workers")));
    }

    #[test]
    fn tls_enabled_without_cert_key_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.tls_enabled = true;
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("tls_cert")));
    }

    #[test]
    fn tls_cert_path_that_does_not_exist_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.tls_enabled = true;
        cfg.tls_cert = "/nonexistent/cert.pem".to_string();
        cfg.tls_key = "/nonexistent/key.pem".to_string();
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("does not exist")));
    }

    #[test]
    fn sni_cert_without_top_level_tls_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.sni_certs.push(crate::core::config::SniCertConfig {
            hostname: "example.com".to_string(),
            cert: "cert.pem".to_string(),
            key: "key.pem".to_string(),
        });
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("tls_enabled is false")));
    }

    #[test]
    fn rate_limit_with_zero_rps_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.rate_limit_enabled = true;
        cfg.rate_limit_requests_per_second = 0;
        cfg.rate_limit_burst = 10;
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("rate_limit_requests_per_second")));
    }

    #[test]
    fn invalid_compress_level_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.compress_enabled = true;
        cfg.compress_level = 15;
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("compress_level")));
    }

    #[test]
    fn basic_auth_enabled_without_users_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.auth_basic_enabled = true;
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("no users")));
    }

    #[test]
    fn jwt_enabled_without_secret_or_pubkey_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.auth_jwt_enabled = true;
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("auth_jwt_secret")));
    }

    #[test]
    fn static_dir_that_does_not_exist_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.static_dirs.push(("/".to_string(), "/nonexistent/doc/root".to_string()));
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("does not exist")));
    }

    #[test]
    fn pool_with_lb_enabled_and_no_upstreams_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            lb_enabled: true,
            upstreams: Vec::new(),
            ..Default::default()
        });
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("no upstreams")));
    }

    #[test]
    fn pool_upstream_with_negative_weight_is_caught() {
        let mut cfg = RoutaConfig::default();
        cfg.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            lb_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig {
                host: "10.0.0.1".to_string(),
                port: 8080,
                weight: -1,
                use_tls: false,
            }],
            ..Default::default()
        });
        let errors = validate(&cfg);
        assert!(errors.iter().any(|e| e.message.contains("negative weight")));
    }

    #[test]
    fn multiple_errors_are_all_reported_not_just_the_first() {
        let mut cfg = RoutaConfig::default();
        cfg.port = 0;
        cfg.n_workers = 0;
        let errors = validate(&cfg);
        assert!(errors.len() >= 2, "expected at least 2 errors, got {}", errors.len());
    }
}
