//! Config type definitions for routa's server configuration.

use std::collections::HashMap;

// ─── Resource profile ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceProfile {
    #[default]
    Balanced,
    Light,
    Performance,
}

// ─── Load balancer algorithm ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LbAlgo {
    #[default]
    RoundRobin,
    WeightedRr,
    LeastConn,
    IpHash,
    Random,
    P2c,
    ConsistentHash,
}

// ─── Health check type ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HcType {
    #[default]
    None,
    Tcp,
    Http,
    Custom,
}

// ─── H2 stream lookup strategy ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H2StreamLookup {
    #[default]
    Linear, // fixed pool, linear scan, default
    Hashmap, // open addressing hashmap
}

// ─── ACL ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct AclRule {
    pub rule: String, // CIDR or single IP
    pub action: AclAction,
}

// ─── Header manipulation rule ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HeaderRule {
    pub name: String,
    pub value: String,
}

// ─── WebSocket config ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WsConfig {
    pub enabled: bool,

    pub max_connections: i32,      // default: 10000
    pub idle_timeout_ms: i32,      // default: 0

    // Frame
    pub max_frame_size: u64,   // default: 16MB
    pub max_message_size: u64, // fragmented, default: 64MB

    // Ping/Pong
    pub ping_interval_ms: i32,
    pub ping_timeout_ms: i32,
    pub max_ping_misses: i32,

    // Buffer
    pub read_buf_size: u64,
    pub write_buf_size: u64,
    pub write_queue_max: i32, // backpressure limit, default: 128

    // Compression (RFC 7692 permessage-deflate)
    pub permessage_deflate: bool,
    pub compression_level: i32,
    pub compression_threshold: u64,
    pub require_masking: bool,
}

impl Default for WsConfig {
    fn default() -> Self {
        WsConfig {
            enabled: false,
            max_connections: 10_000,
            idle_timeout_ms: 0,
            max_frame_size: 16 * 1024 * 1024,
            max_message_size: 64 * 1024 * 1024,
            ping_interval_ms: 30_000,
            ping_timeout_ms: 10_000,
            max_ping_misses: 3,
            read_buf_size: 65_536,
            write_buf_size: 65_536,
            write_queue_max: 128,
            permessage_deflate: false,
            compression_level: 6,
            compression_threshold: 512,
            require_masking: true,
        }
    }
}

// ─── File cache sub-enums ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileCacheStrategy {
    Ttl,
    #[default]
    StatTtl,
    Inotify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileCacheMode {
    Local,
    #[default]
    SharedMetadata,
    SharedContent, // reserved for future work, falls back to SharedMetadata
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileCacheLock {
    Global,
    #[default]
    Sharded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileCacheEviction {
    #[default]
    Lru,
    Lfu,
    TtlOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileCacheWatch {
    #[default]
    None,
    Inotify,
}

// ─── Upstream (single backend node inside a pool) ─────────────────────────

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub host: String,
    pub port: u16,
    pub weight: i32,
    pub use_tls: bool, // set when the upstream line used https://
}

// ─── One independently-configured upstream pool ───────────────────────────
// See routa_config_t.pools[] for the config file syntax ([pool NAME]).

#[derive(Debug, Clone)]
pub struct LbPoolConfig {
    pub name: String,  // from "[pool NAME]", "" for the implicit/legacy pool
    pub route: String, // from lb_route = ..., default "/*"

    pub lb_enabled: bool,
    pub lb_algo: LbAlgo,
    pub upstreams: Vec<UpstreamConfig>,

    // Connection pool
    pub lb_pool_max_per_node: i32,
    pub lb_pool_connect_timeout_ms: i32,
    pub lb_upstream_read_timeout_ms: i32,
    pub lb_upstream_write_timeout_ms: i32,
    pub lb_pool_idle_timeout_s: i32,

    // Passive health
    pub lb_passive_fail_threshold: i32,
    pub lb_passive_recover_threshold: i32,
    pub lb_half_open_retry_after_ms: i32, // circuit-breaker half-open, ms. 0=disabled

    // Success-rate outlier detection (see lb::outlier) -- distinct
    // from the passive circuit breaker above: this compares a node's
    // success rate against its peers' rather than reacting only to
    // that node's own consecutive failures.
    pub outlier_detection_enabled: bool,
    pub outlier_interval_ms: i32,
    pub outlier_min_request_volume: i32,
    pub outlier_min_hosts: i32,
    pub outlier_stdev_factor: f64,
    pub outlier_base_ejection_time_ms: i32,
    pub outlier_max_ejection_time_ms: i32,
    pub outlier_max_ejection_percent: i32,

    // Active health check
    pub lb_hc_type: HcType,
    pub lb_hc_path: String,
    pub lb_hc_interval_ms: i32,
    pub lb_hc_timeout_ms: i32,
    pub lb_hc_threshold_up: i32,
    pub lb_hc_threshold_down: i32,

    // Retry
    pub lb_max_retries: i32,
    pub lb_retry_on_5xx: bool,

    // Consistent hash
    pub lb_consistent_hash_vnodes: i32,

    // Header manipulation (applied on top of routa's own automatic headers)
    pub request_header_add: Vec<HeaderRule>,
    pub request_header_remove: Vec<String>,
    pub response_header_add: Vec<HeaderRule>,
    pub response_header_remove: Vec<String>,

    // Pool-scoped ACL, applied in addition to (after) any global ACL rules
    pub acl_enabled: bool,
    pub acl_default_allow: bool,
    pub acl_rules: Vec<AclRule>,

    // Cookie-based sticky sessions
    pub sticky_session_enabled: bool,
    pub sticky_cookie_name: String,
}

impl Default for LbPoolConfig {
    fn default() -> Self {
        LbPoolConfig {
            name: String::new(),
            route: "/*".to_string(),
            lb_enabled: false,
            lb_algo: LbAlgo::default(),
            upstreams: Vec::new(),
            lb_pool_max_per_node: 32,
            lb_pool_connect_timeout_ms: 5_000,
            lb_upstream_read_timeout_ms: 30_000,
            lb_upstream_write_timeout_ms: 30_000,
            lb_pool_idle_timeout_s: 60,
            lb_passive_fail_threshold: 3,
            lb_passive_recover_threshold: 2,
            lb_half_open_retry_after_ms: 30_000,
            outlier_detection_enabled: false,
            outlier_interval_ms: 10_000,
            outlier_min_request_volume: 100,
            outlier_min_hosts: 3,
            outlier_stdev_factor: 1.9,
            outlier_base_ejection_time_ms: 30_000,
            outlier_max_ejection_time_ms: 300_000,
            outlier_max_ejection_percent: 20,
            lb_hc_type: HcType::default(),
            lb_hc_path: "/healthz".to_string(),
            lb_hc_interval_ms: 5_000,
            lb_hc_timeout_ms: 2_000,
            lb_hc_threshold_up: 2,
            lb_hc_threshold_down: 3,
            lb_max_retries: 1,
            lb_retry_on_5xx: false,
            lb_consistent_hash_vnodes: 100,
            request_header_add: Vec::new(),
            request_header_remove: Vec::new(),
            response_header_add: Vec::new(),
            response_header_remove: Vec::new(),
            acl_enabled: false,
            acl_default_allow: true,
            acl_rules: Vec::new(),
            sticky_session_enabled: false,
            sticky_cookie_name: String::new(),
        }
    }
}

// ─── HTTP/2 config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RoutaH2Config {
    pub enabled: bool, // default: true

    // HPACK
    pub header_table_size: u32,    // dynamic table per-conn, default: 4096
    pub huffman_encoding: bool,    // outbound Huffman, default: true
    pub dynamic_table_update: bool, // server writes to dyn table, default: true

    // Flow control
    pub initial_window_size: u32, // stream window, default: 65535
    pub max_frame_size: u32,      // default: 16384 (RFC min)
    pub max_header_list_size: u32, // default: 0 (unlimited)

    // Concurrency
    pub max_concurrent_streams: u32, // per-conn, default: 128
    pub max_concurrent_streams_hard_cap: u32, // pool hard cap, default: 256

    // Timeouts
    pub stream_timeout_ms: i32,    // idle stream, default: 30000
    pub keepalive_timeout_ms: i32, // h2 conn idle, default: 120000

    // H2
    pub server_push_enabled: bool,
    pub h2c_upgrade_enabled: bool,
    pub stream_lookup: H2StreamLookup,
}

impl Default for RoutaH2Config {
    fn default() -> Self {
        RoutaH2Config {
            enabled: true,
            header_table_size: 4096,
            huffman_encoding: true,
            dynamic_table_update: true,
            initial_window_size: 65_535,
            max_frame_size: 16_384,
            max_header_list_size: 0,
            max_concurrent_streams: 128,
            max_concurrent_streams_hard_cap: 256,
            stream_timeout_ms: 30_000,
            keepalive_timeout_ms: 120_000,
            server_push_enabled: true,
            h2c_upgrade_enabled: true,
            stream_lookup: H2StreamLookup::default(),
        }
    }
}

// ─── SNI cert (extra TLS cert selected by hostname at handshake) ──────────

#[derive(Debug, Clone, Default)]
pub struct SniCertConfig {
    pub hostname: String, // may be a single-label wildcard: "*.api.example.com"
    pub cert: String,
    pub key: String,
}

// ─── Top-level config ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RoutaConfig {
    pub resource_profile: ResourceProfile,

    // Network
    pub port: i32,        // default: 8080 (kept as i32, matching C's plain int)
    pub n_workers: i32,   // default: CPU count
    pub backlog: i32,     // default: 128
    pub max_request_size: u64, // widened from C's `int` (32-bit) by design -- see PR discussion
    pub shutdown_timeout_ms: i32,

    // TLS
    pub tls_enabled: bool,
    pub tls_cert: String,
    pub tls_key: String,
    pub tls_session_timeout: i32, // seconds, default: 3600
    pub tls_ocsp_response: String, // path to DER file, empty=disabled
    pub sni_certs: Vec<SniCertConfig>,

    // Logging
    pub log_level: String,
    pub log_file: String,

    // Timeouts & connection limits
    pub keepalive_timeout_ms: i32,
    pub request_timeout_ms: i32,
    pub max_connections: i32,

    // In-memory response cache
    pub cache_enabled: bool, // implicitly true once cache_dir is set
    pub cache_memory_mb: i64,
    pub cache_dir: String,

    // Static file serving: (url_prefix, doc_root) pairs
    pub static_dirs: Vec<(String, String)>,

    // Static file cache
    pub file_cache_enabled: bool,
    pub file_cache_max_entries: i32,
    pub file_cache_ttl_s: i32, // seconds, not milliseconds
    pub file_cache_strategy: FileCacheStrategy,
    pub file_cache_mode: FileCacheMode,
    pub file_cache_lock: FileCacheLock,
    pub file_cache_shards: i32, // always rounded up to a power of 2
    pub file_cache_eviction: FileCacheEviction,
    pub file_cache_negative_ttl_s: i32,
    pub file_cache_mmap_threshold: i32,
    pub file_cache_max_memory_mb: i32,
    pub file_cache_watch: FileCacheWatch,

    // HTTP/2
    pub h2: RoutaH2Config,

    // WebSocket
    pub ws: WsConfig,

    // Socket buffer sizes (0 = OS default)
    pub socket_recv_buf_size: i32,
    pub socket_send_buf_size: i32,

    // CPU affinity
    pub cpu_affinity_enabled: bool,
    pub cpu_affinity_start_core: i32,

    // Process-wide memory limits (MB, 0 = disabled)
    pub memory_soft_limit_mb: i32,
    pub memory_hard_limit_mb: i32,

    // NUMA-aware worker placement
    pub numa_aware_enabled: bool,

    // Global IP-based ACL
    pub acl_enabled: bool,
    pub acl_default_allow: bool, // default: true
    pub acl_rules: Vec<AclRule>,

    // Global header manipulation
    pub response_header_add: Vec<HeaderRule>,
    pub response_header_remove: Vec<String>,

    // Access logging
    pub logger_enabled: bool,

    // Response compression
    pub compress_enabled: bool,
    pub compress_min_size: u64,
    pub compress_level: i32,

    // CORS
    pub cors_enabled: bool,
    pub cors_origin: String,
    pub cors_methods: String,
    pub cors_headers: String,

    // Basic Auth
    pub auth_basic_enabled: bool,
    pub auth_basic_realm: String,
    pub auth_basic_users: HashMap<String, String>, // user -> password

    // JWT Auth (mutually exclusive with basic auth in the default chain)
    pub auth_jwt_enabled: bool,
    pub auth_jwt_secret: String,      // HS256 shared secret
    pub auth_jwt_pubkey_path: String, // RS256 public key PEM file path
    pub auth_jwt_verify_exp: bool,    // default: true
    pub auth_jwt_issuer: String,
    pub auth_jwt_audience: String,

    // Rate limiting
    pub rate_limit_enabled: bool,
    pub rate_limit_requests_per_second: i32,
    pub rate_limit_burst: i32,

    // Metrics endpoint
    pub metrics_enabled: bool,
    pub metrics_path: String,

    // Load-balancer pools
    pub pools: Vec<LbPoolConfig>,
}

impl Default for RoutaConfig {
    fn default() -> Self {
        RoutaConfig {
            resource_profile: ResourceProfile::default(),
            port: 8080,
            n_workers: num_cpus(),
            backlog: 128,
            max_request_size: 1024 * 1024, // 1MB
            shutdown_timeout_ms: 10_000,
            tls_enabled: false,
            tls_cert: String::new(),
            tls_key: String::new(),
            tls_session_timeout: 3600,
            tls_ocsp_response: String::new(),
            sni_certs: Vec::new(),
            log_level: "info".to_string(),
            log_file: String::new(),
            keepalive_timeout_ms: 60_000,
            request_timeout_ms: 30_000,
            max_connections: 10_000,
            cache_enabled: false,
            cache_memory_mb: 0,
            cache_dir: String::new(),
            static_dirs: Vec::new(),
            file_cache_enabled: false,
            file_cache_max_entries: 1024,
            file_cache_ttl_s: 5,
            file_cache_strategy: FileCacheStrategy::default(),
            file_cache_mode: FileCacheMode::default(),
            file_cache_lock: FileCacheLock::default(),
            file_cache_shards: 16,
            file_cache_eviction: FileCacheEviction::default(),
            file_cache_negative_ttl_s: 0,
            file_cache_mmap_threshold: 65_536,
            file_cache_max_memory_mb: 0,
            file_cache_watch: FileCacheWatch::default(),
            h2: RoutaH2Config::default(),
            ws: WsConfig::default(),
            socket_recv_buf_size: 0,
            socket_send_buf_size: 0,
            cpu_affinity_enabled: false,
            cpu_affinity_start_core: 0,
            memory_soft_limit_mb: 0,
            memory_hard_limit_mb: 0,
            numa_aware_enabled: false,
            acl_enabled: false,
            acl_default_allow: true,
            acl_rules: Vec::new(),
            response_header_add: Vec::new(),
            response_header_remove: Vec::new(),
            logger_enabled: false,
            compress_enabled: false,
            compress_min_size: 1024,
            compress_level: 6,
            cors_enabled: false,
            cors_origin: String::new(),
            cors_methods: String::new(),
            cors_headers: String::new(),
            auth_basic_enabled: false,
            auth_basic_realm: "Restricted".to_string(),
            auth_basic_users: HashMap::new(),
            auth_jwt_enabled: false,
            auth_jwt_secret: String::new(),
            auth_jwt_pubkey_path: String::new(),
            auth_jwt_verify_exp: true,
            auth_jwt_issuer: String::new(),
            auth_jwt_audience: String::new(),
            rate_limit_enabled: false,
            rate_limit_requests_per_second: 100,
            rate_limit_burst: 200,
            metrics_enabled: true,
            metrics_path: "/metrics".to_string(),
            pools: Vec::new(),
        }
    }
}

fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(1)
}

/// Applies a resource profile's defaults. Only called once, right after
/// RoutaConfig::default(), before the rest of the file is parsed -- any
/// key written explicitly later in the file always overrides this,
/// since parsing happens after this call.
pub fn apply_resource_profile(cfg: &mut RoutaConfig, profile: ResourceProfile) {
    cfg.resource_profile = profile;

    if profile == ResourceProfile::Balanced {
        // No-op: RoutaConfig::default()'s hardcoded defaults already ARE
        // the balanced profile -- nothing to override.
        return;
    }

    let cpu_count = num_cpus().max(1);

    match profile {
        ResourceProfile::Balanced => unreachable!(), // handled above
        ResourceProfile::Light => {
            // Weak/resource-constrained machines (e.g. laptops): fewer
            // workers, smaller caches, tighter connection limits, and
            // memory guard-rails enabled by default since such machines
            // are the most likely to actually run out of memory under load.
            let workers = (cpu_count / 2).max(1);
            cfg.n_workers = workers;
            cfg.cache_memory_mb = 16;
            cfg.max_connections = 1_000;
            cfg.file_cache_max_entries = 128;
            cfg.file_cache_shards = 4;    // fewer shards, low core count
            cfg.socket_recv_buf_size = 0; // OS default
            cfg.socket_send_buf_size = 0; // OS default
            cfg.cpu_affinity_enabled = false; // not worth it on few cores
            cfg.numa_aware_enabled = false;
            cfg.memory_soft_limit_mb = 512;
            cfg.memory_hard_limit_mb = 1024;
            cfg.compress_level = 3; // less CPU per request
            cfg.keepalive_timeout_ms = 15_000;
        }
        ResourceProfile::Performance => {
            // Large multi-core servers: many workers, big caches, high
            // connection ceiling, CPU/NUMA pinning on, memory limits left
            // disabled (operators at this scale typically already have
            // cgroups/systemd limits in place).
            let workers = cpu_count * 2;
            cfg.n_workers = workers;
            cfg.cache_memory_mb = 512;
            cfg.max_connections = 100_000;
            cfg.file_cache_max_entries = 4096;
            cfg.file_cache_shards = 64;    // more shards, less lock contention
            cfg.socket_recv_buf_size = 262_144;
            cfg.socket_send_buf_size = 262_144;
            cfg.cpu_affinity_enabled = true;
            cfg.numa_aware_enabled = true;
            cfg.memory_soft_limit_mb = 0; // disabled
            cfg.memory_hard_limit_mb = 0; // disabled
            cfg.compress_level = 9;       // more CPU available, better ratio
            cfg.keepalive_timeout_ms = 60_000;
        }
    }
}
