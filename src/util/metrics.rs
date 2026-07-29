//! Prometheus metrics: one process-wide `Metrics` registry covering
//! HTTP, connection, upstream/load-balancer, file-cache, and process
//! layers -- the goal is Envoy-comparable observability depth (per-route
//! and per-upstream breakdowns, circuit-breaker state, retry-reason
//! attribution, connection-pool saturation), not just the handful of
//! global counters a minimal implementation would track.
//!
//! Uses the `prometheus` crate rather than a hand-rolled counter/gauge/
//! histogram system: correctly producing the Prometheus text exposition
//! format (the `# HELP`/`# TYPE` preamble, histogram bucket encoding
//! via `le=` labels, escaping) is a fixed external standard with no
//! real design freedom left in it, so writing it from scratch adds
//! implementation risk without adding anything this codebase's own
//! judgment actually improves on. The crate's label-vector types
//! (`CounterVec`, `HistogramVec`) also make truly Prometheus-native
//! multi-dimensional metrics (`method="GET",status="200"`) direct,
//! rather than requiring a fixed enum of pre-declared combinations the
//! way a hand-rolled fixed-size-array approach would.
//!
//! `Metrics` is constructed once at server startup and shared (`Arc`)
//! across every worker -- every counter/gauge/histogram inside it is
//! already safely concurrent (that's what the underlying crate
//! provides), so no additional locking is needed to record from
//! multiple worker threads at once.

use std::sync::Arc;

use prometheus::{
    CounterVec, Encoder, Gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};

const LATENCY_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

const SIZE_BUCKETS: &[f64] = &[
    64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1_048_576.0, 4_194_304.0, 16_777_216.0,
];

/// HTTP-layer request/response metrics.
pub struct HttpMetrics {
    pub requests_total: CounterVec,
    pub responses_total: CounterVec,
    pub request_duration_seconds: HistogramVec,
    pub request_body_bytes: HistogramVec,
    pub response_body_bytes: HistogramVec,
    pub requests_in_flight: IntGaugeVec,
}

impl HttpMetrics {
    fn register(registry: &Registry) -> prometheus::Result<Self> {
        let requests_total = CounterVec::new(
            Opts::new("routa_http_requests_total", "Total HTTP requests received, by method and route."),
            &["method", "route"],
        )?;
        let responses_total = CounterVec::new(
            Opts::new("routa_http_responses_total", "Total HTTP responses sent, by method, route, and status class."),
            &["method", "route", "status_class"],
        )?;
        let request_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "routa_http_request_duration_seconds",
                "End-to-end request handling latency (middleware chain start to response ready), by method and route.",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["method", "route"],
        )?;
        let request_body_bytes = HistogramVec::new(
            prometheus::HistogramOpts::new("routa_http_request_body_bytes", "Request body size, by route.")
                .buckets(SIZE_BUCKETS.to_vec()),
            &["route"],
        )?;
        let response_body_bytes = HistogramVec::new(
            prometheus::HistogramOpts::new("routa_http_response_body_bytes", "Response body size, by route.")
                .buckets(SIZE_BUCKETS.to_vec()),
            &["route"],
        )?;
        let requests_in_flight = IntGaugeVec::new(
            Opts::new("routa_http_requests_in_flight", "Requests currently being handled, by protocol version."),
            &["protocol"],
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(responses_total.clone()))?;
        registry.register(Box::new(request_duration_seconds.clone()))?;
        registry.register(Box::new(request_body_bytes.clone()))?;
        registry.register(Box::new(response_body_bytes.clone()))?;
        registry.register(Box::new(requests_in_flight.clone()))?;

        Ok(HttpMetrics {
            requests_total,
            responses_total,
            request_duration_seconds,
            request_body_bytes,
            response_body_bytes,
            requests_in_flight,
        })
    }
}

fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// Connection-layer metrics: accept/close counts, TLS handshake
/// outcomes/timing, and protocol distribution (H1/H2/WS) -- the kind
/// of transport-level visibility Envoy's listener stats provide.
pub struct ConnectionMetrics {
    pub connections_accepted_total: IntCounter,
    pub connections_closed_total: IntCounter,
    pub connections_active: IntGauge,
    pub tls_handshakes_total: IntCounterVec, // labels: result ("success", "failure")
    pub tls_handshake_duration_seconds: HistogramVec, // labels: protocol_version (TLS 1.2/1.3), cipher
    pub protocol_selected_total: IntCounterVec, // labels: protocol ("http1", "http2", "websocket")
}

impl ConnectionMetrics {
    fn register(registry: &Registry) -> prometheus::Result<Self> {
        let connections_accepted_total = IntCounter::new(
            "routa_connections_accepted_total",
            "Total connections accepted across all workers.",
        )?;
        let connections_closed_total = IntCounter::new(
            "routa_connections_closed_total",
            "Total connections closed across all workers.",
        )?;
        let connections_active = IntGauge::new(
            "routa_connections_active",
            "Connections currently open across all workers.",
        )?;
        let tls_handshakes_total = IntCounterVec::new(
            Opts::new("routa_tls_handshakes_total", "Total TLS handshakes attempted, by outcome."),
            &["result"],
        )?;
        let tls_handshake_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "routa_tls_handshake_duration_seconds",
                "TLS handshake duration, by negotiated protocol version.",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["tls_version"],
        )?;
        let protocol_selected_total = IntCounterVec::new(
            Opts::new("routa_protocol_selected_total", "Total connections, by application protocol selected."),
            &["protocol"],
        )?;

        registry.register(Box::new(connections_accepted_total.clone()))?;
        registry.register(Box::new(connections_closed_total.clone()))?;
        registry.register(Box::new(connections_active.clone()))?;
        registry.register(Box::new(tls_handshakes_total.clone()))?;
        registry.register(Box::new(tls_handshake_duration_seconds.clone()))?;
        registry.register(Box::new(protocol_selected_total.clone()))?;

        Ok(ConnectionMetrics {
            connections_accepted_total,
            connections_closed_total,
            connections_active,
            tls_handshakes_total,
            tls_handshake_duration_seconds,
            protocol_selected_total,
        })
    }
}

/// Upstream/load-balancer metrics: per-pool and per-node request/error
/// counts, circuit-breaker state transitions, retry-reason
/// attribution, connection-pool saturation, and health-check outcomes
/// -- the metrics that let an operator answer "which specific backend
/// is unhealthy and why" rather than only "the pool overall has some
/// error rate", matching the granularity Envoy's cluster stats provide.
pub struct UpstreamMetrics {
    pub requests_total: IntCounterVec,       // labels: pool, node
    pub errors_total: IntCounterVec,         // labels: pool, node, reason ("connect_failed", "timeout", "5xx", "reset")
    pub retries_total: IntCounterVec,        // labels: pool, reason
    pub circuit_breaker_trips_total: IntCounterVec, // labels: pool, node
    pub circuit_breaker_state: IntGaugeVec,  // labels: pool, node ; value: 0=up, 1=down, 2=half_open, 3=draining
    pub half_open_trials_total: IntCounterVec, // labels: pool, node
    pub pool_connections_active: IntGaugeVec, // labels: pool, node
    pub pool_connections_idle: IntGaugeVec,   // labels: pool, node
    pub health_check_total: IntCounterVec,    // labels: pool, node, result ("ok", "fail")
    pub outlier_ejections_total: IntCounterVec, // labels: pool, node -- see lb::outlier
    pub upstream_request_duration_seconds: HistogramVec, // labels: pool, node
}

impl UpstreamMetrics {
    fn register(registry: &Registry) -> prometheus::Result<Self> {
        let requests_total = IntCounterVec::new(
            Opts::new("routa_upstream_requests_total", "Total requests forwarded to an upstream node."),
            &["pool", "node"],
        )?;
        let errors_total = IntCounterVec::new(
            Opts::new("routa_upstream_errors_total", "Total forwarding errors, by pool, node, and reason."),
            &["pool", "node", "reason"],
        )?;
        let retries_total = IntCounterVec::new(
            Opts::new("routa_upstream_retries_total", "Total retry attempts, by pool and reason."),
            &["pool", "reason"],
        )?;
        let circuit_breaker_trips_total = IntCounterVec::new(
            Opts::new("routa_upstream_circuit_breaker_trips_total", "Total times a node's circuit breaker tripped to Down."),
            &["pool", "node"],
        )?;
        let circuit_breaker_state = IntGaugeVec::new(
            Opts::new(
                "routa_upstream_circuit_breaker_state",
                "Current circuit-breaker state per node (0=up, 1=down, 2=half_open, 3=draining).",
            ),
            &["pool", "node"],
        )?;
        let half_open_trials_total = IntCounterVec::new(
            Opts::new("routa_upstream_half_open_trials_total", "Total half-open recovery trial requests sent."),
            &["pool", "node"],
        )?;
        let pool_connections_active = IntGaugeVec::new(
            Opts::new("routa_upstream_pool_connections_active", "Connections currently in use, by pool and node."),
            &["pool", "node"],
        )?;
        let pool_connections_idle = IntGaugeVec::new(
            Opts::new("routa_upstream_pool_connections_idle", "Idle pooled connections available for reuse, by pool and node."),
            &["pool", "node"],
        )?;
        let health_check_total = IntCounterVec::new(
            Opts::new("routa_upstream_health_check_total", "Total active health check probes, by pool, node, and result."),
            &["pool", "node", "result"],
        )?;
        let outlier_ejections_total = IntCounterVec::new(
            Opts::new("routa_upstream_outlier_ejections_total", "Total times a node was ejected by success-rate outlier detection."),
            &["pool", "node"],
        )?;
        let upstream_request_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "routa_upstream_request_duration_seconds",
                "Upstream request latency (connection acquisition through response received), by pool and node.",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["pool", "node"],
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(errors_total.clone()))?;
        registry.register(Box::new(retries_total.clone()))?;
        registry.register(Box::new(circuit_breaker_trips_total.clone()))?;
        registry.register(Box::new(circuit_breaker_state.clone()))?;
        registry.register(Box::new(half_open_trials_total.clone()))?;
        registry.register(Box::new(pool_connections_active.clone()))?;
        registry.register(Box::new(pool_connections_idle.clone()))?;
        registry.register(Box::new(health_check_total.clone()))?;
        registry.register(Box::new(outlier_ejections_total.clone()))?;
        registry.register(Box::new(upstream_request_duration_seconds.clone()))?;

        Ok(UpstreamMetrics {
            requests_total,
            errors_total,
            retries_total,
            circuit_breaker_trips_total,
            circuit_breaker_state,
            half_open_trials_total,
            pool_connections_active,
            pool_connections_idle,
            health_check_total,
            outlier_ejections_total,
            upstream_request_duration_seconds,
        })
    }
}

/// File-cache metrics: hit/miss/eviction counts and current occupancy.
pub struct CacheMetrics {
    pub requests_total: IntCounterVec, // labels: result ("hit", "miss", "negative_hit")
    pub evictions_total: IntCounter,
    pub entries: IntGauge,
    /// How much of `http::file_cache::FileCache::evictions_total`'s
    /// running total (a plain counter on the cache itself, not a
    /// Prometheus metric) has already been folded into
    /// `evictions_total` above -- see `core::server`'s `/metrics`
    /// handler, the only place this is read/written, for why: a
    /// Prometheus `Counter` only exposes `inc()`/`inc_by()`, so
    /// reconciling it with an externally-tracked absolute total needs
    /// this same delta-tracking `main.rs` already does for
    /// `worker_restarts_total`.
    pub evictions_reported: std::sync::atomic::AtomicU64,
}

impl CacheMetrics {
    fn register(registry: &Registry) -> prometheus::Result<Self> {
        let requests_total = IntCounterVec::new(
            Opts::new("routa_cache_requests_total", "Total file-cache lookups, by result."),
            &["result"],
        )?;
        let evictions_total = IntCounter::new(
            "routa_cache_evictions_total",
            "Total cache entries evicted to make room for a new one.",
        )?;
        let entries = IntGauge::new("routa_cache_entries", "Current number of entries held in the file cache.")?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(evictions_total.clone()))?;
        registry.register(Box::new(entries.clone()))?;

        Ok(CacheMetrics {
            requests_total,
            evictions_total,
            entries,
            evictions_reported: std::sync::atomic::AtomicU64::new(0),
        })
    }
}

/// Process-wide metrics: memory usage and worker lifecycle.
pub struct ProcessMetrics {
    pub rss_bytes: Gauge,
    pub worker_restarts_total: IntCounter,
    pub workers_alive: IntGauge,
}

impl ProcessMetrics {
    fn register(registry: &Registry) -> prometheus::Result<Self> {
        let rss_bytes = Gauge::new("routa_process_rss_bytes", "Resident set size, in bytes.")?;
        let worker_restarts_total = IntCounter::new(
            "routa_worker_restarts_total",
            "Total times a worker thread was restarted after a panic.",
        )?;
        let workers_alive = IntGauge::new("routa_workers_alive", "Number of currently-running worker threads.")?;

        registry.register(Box::new(rss_bytes.clone()))?;
        registry.register(Box::new(worker_restarts_total.clone()))?;
        registry.register(Box::new(workers_alive.clone()))?;

        Ok(ProcessMetrics {
            rss_bytes,
            worker_restarts_total,
            workers_alive,
        })
    }

    /// Reads this process's own RSS from `/proc/self/status` (Linux-
    /// specific -- the only platform routa currently targets for
    /// production deployment) and updates `rss_bytes`. A no-op (silently
    /// leaves the gauge at its last value) if the read fails for any
    /// reason, since a metrics-collection failure shouldn't itself
    /// affect request handling.
    pub fn refresh_rss(&self) {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return;
        };
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb: f64 = rest.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0.0);
                self.rss_bytes.set(kb * 1024.0);
                return;
            }
        }
    }
}

/// Rejection counters for middleware that turns a request away before
/// it reaches its route handler -- kept separate from the generic
/// `HttpMetrics::responses_total` 4xx bucket, which conflates rate
/// limiting, ACL denial, and auth failures with ordinary
/// application-level 4xx responses. An operator paging on a 4xx spike
/// needs to know which of these it actually is.
pub struct MiddlewareMetrics {
    pub rate_limit_rejected_total: IntCounter,
    pub acl_denied_total: IntCounter,
    pub auth_basic_failures_total: IntCounter,
    pub auth_jwt_failures_total: IntCounter,
}

impl MiddlewareMetrics {
    fn register(registry: &Registry) -> prometheus::Result<Self> {
        let rate_limit_rejected_total = IntCounter::new(
            "routa_rate_limit_rejected_total",
            "Total requests rejected by the rate-limit middleware.",
        )?;
        let acl_denied_total = IntCounter::new("routa_acl_denied_total", "Total requests denied by ACL rules.")?;
        let auth_basic_failures_total = IntCounter::new(
            "routa_auth_basic_failures_total",
            "Total Basic Authentication failures.",
        )?;
        let auth_jwt_failures_total = IntCounter::new("routa_auth_jwt_failures_total", "Total JWT authentication failures.")?;

        registry.register(Box::new(rate_limit_rejected_total.clone()))?;
        registry.register(Box::new(acl_denied_total.clone()))?;
        registry.register(Box::new(auth_basic_failures_total.clone()))?;
        registry.register(Box::new(auth_jwt_failures_total.clone()))?;

        Ok(MiddlewareMetrics {
            rate_limit_rejected_total,
            acl_denied_total,
            auth_basic_failures_total,
            auth_jwt_failures_total,
        })
    }
}

/// The complete metrics registry. Constructed once at server startup
/// (see `core::server::RoutaServer`) and shared across every worker
/// thread via `Arc` -- every field's underlying counters/gauges/
/// histograms are already safely concurrent on their own.
pub struct Metrics {
    registry: Registry,
    pub http: HttpMetrics,
    pub connection: ConnectionMetrics,
    pub upstream: UpstreamMetrics,
    pub cache: CacheMetrics,
    pub process: ProcessMetrics,
    pub middleware: MiddlewareMetrics,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        let registry = Registry::new();
        // Registration only fails if a metric name collides with an
        // already-registered one -- every name here is unique by
        // construction (see each *Metrics::register's own literal
        // names), so this can't realistically fail; unwrap rather than
        // threading a Result through server startup for a case that
        // amounts to "this module has an internal naming bug".
        let http = HttpMetrics::register(&registry).expect("metric registration should not fail with unique names");
        let connection = ConnectionMetrics::register(&registry).expect("metric registration should not fail with unique names");
        let upstream = UpstreamMetrics::register(&registry).expect("metric registration should not fail with unique names");
        let cache = CacheMetrics::register(&registry).expect("metric registration should not fail with unique names");
        let process = ProcessMetrics::register(&registry).expect("metric registration should not fail with unique names");
        let middleware = MiddlewareMetrics::register(&registry).expect("metric registration should not fail with unique names");

        Arc::new(Metrics {
            registry,
            http,
            connection,
            upstream,
            cache,
            process,
            middleware,
        })
    }

    /// Renders every registered metric in Prometheus text exposition
    /// format -- what `http::middleware::metrics::handle` serves at
    /// the configured `/metrics` endpoint. Refreshes process-level
    /// gauges (RSS) immediately before encoding, so a scrape always
    /// sees a reasonably fresh value rather than whatever the last
    /// periodic refresh happened to leave.
    pub fn prometheus_text(&self) -> Vec<u8> {
        self.process.refresh_rss();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        // encode() only fails on a write error into `buffer` (a Vec,
        // which never fails to grow) -- silently returning whatever
        // was encoded so far (possibly empty) is preferable to a
        // panic in a metrics-serving path that must never itself take
        // the server down.
        let _ = encoder.encode(&metric_families, &mut buffer);
        buffer
    }

    /// Records a completed request's outcome across every relevant
    /// metric in one call -- the single place `core::event_loop`
    /// (H1 and H2 paths alike) reports a finished request, so both
    /// protocols' requests are counted identically rather than each
    /// needing to remember the same sequence of individual metric
    /// updates.
    pub fn record_request(&self, method: &str, route: &str, status: u16, duration_secs: f64, request_body_len: usize, response_body_len: usize) {
        self.http.requests_total.with_label_values(&[method, route]).inc();
        self.http
            .responses_total
            .with_label_values(&[method, route, status_class(status)])
            .inc();
        self.http
            .request_duration_seconds
            .with_label_values(&[method, route])
            .observe(duration_secs);
        self.http
            .request_body_bytes
            .with_label_values(&[route])
            .observe(request_body_len as f64);
        self.http
            .response_body_bytes
            .with_label_values(&[route])
            .observe(response_body_len as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_class_maps_correctly() {
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(301), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(500), "5xx");
        assert_eq!(status_class(101), "1xx");
    }

    #[test]
    fn new_metrics_registers_without_panicking() {
        let _metrics = Metrics::new();
    }

    #[test]
    fn record_request_updates_http_counters() {
        let metrics = Metrics::new();
        metrics.record_request("GET", "/api/users", 200, 0.05, 0, 1024);

        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("routa_http_requests_total"));
        assert!(text.contains("method=\"GET\""));
        assert!(text.contains("route=\"/api/users\""));
        assert!(text.contains("routa_http_responses_total"));
        assert!(text.contains("status_class=\"2xx\""));
    }

    #[test]
    fn prometheus_text_includes_help_and_type_lines() {
        let metrics = Metrics::new();
        metrics.record_request("GET", "/", 200, 0.01, 0, 0);
        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("# HELP routa_http_requests_total"));
        assert!(text.contains("# TYPE routa_http_requests_total counter"));
    }

    #[test]
    fn upstream_metrics_support_per_node_labels() {
        let metrics = Metrics::new();
        metrics.upstream.requests_total.with_label_values(&["api-pool", "10.0.0.1:8080"]).inc();
        metrics.upstream.requests_total.with_label_values(&["api-pool", "10.0.0.2:8080"]).inc();
        metrics.upstream.requests_total.with_label_values(&["api-pool", "10.0.0.2:8080"]).inc();

        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("node=\"10.0.0.1:8080\""));
        assert!(text.contains("node=\"10.0.0.2:8080\""));
    }

    #[test]
    fn circuit_breaker_state_gauge_reflects_current_value() {
        let metrics = Metrics::new();
        metrics.upstream.circuit_breaker_state.with_label_values(&["api-pool", "10.0.0.1:8080"]).set(1); // Down
        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("routa_upstream_circuit_breaker_state"));
    }

    #[test]
    fn cache_metrics_track_hit_and_miss_separately() {
        let metrics = Metrics::new();
        metrics.cache.requests_total.with_label_values(&["hit"]).inc();
        metrics.cache.requests_total.with_label_values(&["hit"]).inc();
        metrics.cache.requests_total.with_label_values(&["miss"]).inc();

        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("result=\"hit\""));
        assert!(text.contains("result=\"miss\""));
    }

    #[test]
    fn process_metrics_rss_refresh_does_not_panic() {
        let metrics = Metrics::new();
        metrics.process.refresh_rss();
        // On Linux (this project's target platform) this should
        // actually pick up a nonzero value; elsewhere it silently
        // no-ops -- either way, no panic and a well-formed gauge line.
        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("routa_process_rss_bytes"));
    }

    #[test]
    fn connection_metrics_track_protocol_distribution() {
        let metrics = Metrics::new();
        metrics.connection.protocol_selected_total.with_label_values(&["http1"]).inc();
        metrics.connection.protocol_selected_total.with_label_values(&["http2"]).inc();
        metrics.connection.protocol_selected_total.with_label_values(&["http2"]).inc();

        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("protocol=\"http1\""));
        assert!(text.contains("protocol=\"http2\""));
    }

    #[test]
    fn retries_total_tracks_reason() {
        let metrics = Metrics::new();
        metrics.upstream.retries_total.with_label_values(&["api-pool", "connect_failed"]).inc();
        metrics.upstream.retries_total.with_label_values(&["api-pool", "timeout"]).inc();

        let text = String::from_utf8(metrics.prometheus_text()).unwrap();
        assert!(text.contains("reason=\"connect_failed\""));
        assert!(text.contains("reason=\"timeout\""));
    }
}
