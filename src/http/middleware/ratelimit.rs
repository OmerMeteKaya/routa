//! Per-client rate limiting via a token bucket, keyed by the client's
//! IP address.
//!
//! Client IP resolution defaults to the real TCP connection's address
//! (`req.remote_addr`), which can never be spoofed since it comes
//! from the TCP handshake itself. `X-Forwarded-For`/`X-Real-IP`
//! headers are only ever consulted when the connection's own address
//! is in a configured, operator-specified `trusted_proxies` list --
//! otherwise any client could bypass rate limiting entirely by
//! sending an arbitrary `X-Forwarded-For` value (a real vulnerability
//! in a naive "trust the header" implementation). When a proxy chain
//! is trusted, the `X-Forwarded-For` value is walked from the right
//! (most recently appended) end, skipping entries that are themselves
//! trusted proxies, so a client can't defeat this by prepending a
//! fake IP to the header -- only the first entry that isn't itself a
//! trusted proxy is treated as the real client.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::http::middleware::cidr::CidrRange;
use crate::http::middleware::{Middleware, Next};
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub burst: f64,
    /// IP ranges allowed to supply a trustworthy `X-Forwarded-For`/
    /// `X-Real-IP` value. Empty (the default) means never trust these
    /// headers -- only `req.remote_addr` is used.
    pub trusted_proxies: Vec<CidrRange>,
}

impl RateLimitConfig {
    pub fn new(requests_per_second: f64, burst: f64) -> Self {
        RateLimitConfig {
            requests_per_second,
            burst,
            trusted_proxies: Vec::new(),
        }
    }

    pub fn trust_proxy(mut self, cidr: &str) -> Self {
        if let Some(range) = CidrRange::parse(cidr) {
            self.trusted_proxies.push(range);
        }
        self
    }

    fn is_trusted(&self, addr: &IpAddr) -> bool {
        self.trusted_proxies.iter().any(|r| r.contains(addr))
    }
}

/// Resolves the client IP to rate-limit on: `req.remote_addr` unless
/// it's a trusted proxy and a forwarding header points to a further
/// client, in which case the chain is walked from the right, skipping
/// any entries that are themselves trusted proxies -- see this
/// module's doc comment for why this direction/skip logic matters.
fn resolve_client_ip(req: &HttpRequest, config: &RateLimitConfig) -> Option<IpAddr> {
    let connection_addr = req.remote_addr?;

    if config.trusted_proxies.is_empty() || !config.is_trusted(&connection_addr) {
        return Some(connection_addr);
    }

    let forwarded = req
        .get_header("X-Forwarded-For")
        .or_else(|| req.get_header("X-Real-IP"));

    let Some(forwarded) = forwarded else {
        return Some(connection_addr);
    };

    // Walk right-to-left: the rightmost entry was appended by the
    // proxy closest to us. Skip over entries that are themselves
    // trusted proxies (multi-hop trusted chain), and stop at the
    // first entry that isn't -- that's the real client, since nothing
    // beyond a trusted proxy in the chain can be attacker-controlled
    // without that proxy itself being compromised.
    for candidate in forwarded.split(',').rev() {
        let candidate = candidate.trim();
        let Ok(addr) = candidate.parse::<IpAddr>() else {
            continue; // malformed entry -- skip rather than abort resolution
        };
        if !config.is_trusted(&addr) {
            return Some(addr);
        }
    }

    // Every entry in the chain was itself a trusted proxy (or the
    // header was empty/unparseable) -- fall back to the connection's
    // own address.
    Some(connection_addr)
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Bucket state is keyed by client IP, one shared table across all
/// requests this middleware instance handles. `Mutex<HashMap<..>>`
/// rather than something more elaborate (sharding, a concurrent map)
/// since rate-limit bucket lookups are cheap and this isn't expected
/// to be a bottleneck at the scale a single `RateLimitMiddleware`
/// instance serves -- can revisit with a sharded structure if
/// profiling ever shows otherwise.
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
}

const BUCKET_MAX_AGE: Duration = Duration::from_secs(60);

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        RateLimitMiddleware {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request should be allowed (a token was
    /// available and consumed), `false` if it should be rejected.
    fn check_and_consume(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();

        // Opportunistic cleanup of stale entries -- bounded by however
        // many distinct IPs have been seen, not per-request cost for
        // any one client, and keeps long-running processes from
        // accumulating unbounded bucket state for IPs that stopped
        // sending requests.
        buckets.retain(|_, b| now.duration_since(b.last_refill) <= BUCKET_MAX_AGE);

        let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.config.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let refilled = bucket.tokens + elapsed * self.config.requests_per_second;
        bucket.tokens = refilled.min(self.config.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Middleware for RateLimitMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        // No resolvable client IP at all (shouldn't normally happen
        // for a real accepted connection) -- fail open rather than
        // blocking every such request.
        let Some(ip) = resolve_client_ip(req, &self.config) else {
            return next.run(req);
        };

        if self.check_and_consume(ip) {
            next.run(req)
        } else {
            let mut resp = HttpResponse::new(429, "Too Many Requests");
            resp.set_header("Content-Type", "text/plain");
            resp.set_body(b"Too Many Requests\n".to_vec());
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;

    fn make_request(remote_addr: Option<&str>, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            remote_addr: remote_addr.map(|s| s.parse().unwrap()),
            path: "/".to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Vec::new(),
            keep_alive: true,
            trailers: Vec::new(),
        }
    }

    // ─── Client IP resolution ───────────────────────────────────────

    #[test]
    fn untrusted_connection_ignores_forwarded_header() {
        // No trusted_proxies configured -- X-Forwarded-For must be
        // ignored entirely, even though it's present. This is the
        // exact vulnerability class this module's doc comment
        // describes: a client can't spoof its rate-limit identity by
        // just sending this header.
        let config = RateLimitConfig::new(10.0, 10.0);
        let req = make_request(
            Some("203.0.113.1"),
            &[("X-Forwarded-For", "1.2.3.4")],
        );
        let resolved = resolve_client_ip(&req, &config).unwrap();
        assert_eq!(resolved, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_proxy_forwarded_header_is_honored() {
        let config = RateLimitConfig::new(10.0, 10.0).trust_proxy("203.0.113.0/24");
        let req = make_request(
            Some("203.0.113.1"), // inside the trusted range
            &[("X-Forwarded-For", "1.2.3.4")],
        );
        let resolved = resolve_client_ip(&req, &config).unwrap();
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn multi_hop_chain_skips_trusted_proxies_from_the_right() {
        let config = RateLimitConfig::new(10.0, 10.0)
            .trust_proxy("203.0.113.0/24")
            .trust_proxy("198.51.100.0/24");
        let req = make_request(
            Some("203.0.113.1"),
            // Chain: real_client, trusted_proxy_1 -- rightmost entry
            // (closest hop) is a trusted proxy, so we skip past it to
            // find the real client.
            &[("X-Forwarded-For", "9.9.9.9, 198.51.100.5")],
        );
        let resolved = resolve_client_ip(&req, &config).unwrap();
        assert_eq!(resolved, "9.9.9.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn spoofed_prepended_ip_does_not_fool_resolution() {
        // A malicious client behind a trusted proxy tries to prepend a
        // fake IP to make it look like the request came from
        // elsewhere. Since we walk from the right and only trust
        // entries the actual connecting proxy vouches for, the
        // leftmost (attacker-controlled, prepended) entry is never
        // reached as long as there's at least one non-trusted entry
        // closer to the right that resolves first.
        let config = RateLimitConfig::new(10.0, 10.0).trust_proxy("203.0.113.0/24");
        let req = make_request(
            Some("203.0.113.1"),
            &[("X-Forwarded-For", "1.2.3.4, 9.9.9.9")],
        );
        // The proxy itself only ever appends the IP it directly
        // observed (9.9.9.9, the rightmost entry) -- so that's what
        // gets trusted, not the attacker's prepended 1.2.3.4.
        let resolved = resolve_client_ip(&req, &config).unwrap();
        assert_eq!(resolved, "9.9.9.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn untrusted_connection_with_no_forwarded_header_uses_remote_addr() {
        let config = RateLimitConfig::new(10.0, 10.0);
        let req = make_request(Some("203.0.113.1"), &[]);
        let resolved = resolve_client_ip(&req, &config).unwrap();
        assert_eq!(resolved, "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    // ─── Token bucket ───────────────────────────────────────────────

    #[test]
    fn requests_within_burst_are_allowed() {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new(1.0, 5.0));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(mw.check_and_consume(ip));
        }
    }

    #[test]
    fn requests_beyond_burst_are_rejected() {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new(1.0, 3.0));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..3 {
            assert!(mw.check_and_consume(ip));
        }
        assert!(!mw.check_and_consume(ip));
    }

    #[test]
    fn tokens_refill_over_time() {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new(1000.0, 1.0));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(mw.check_and_consume(ip)); // consumes the only token
        assert!(!mw.check_and_consume(ip)); // none left yet

        // At 1000 req/s, waiting a bit should refill well over 1 token.
        std::thread::sleep(Duration::from_millis(20));
        assert!(mw.check_and_consume(ip));
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new(1.0, 1.0));
        let ip_a: IpAddr = "127.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "127.0.0.2".parse().unwrap();

        assert!(mw.check_and_consume(ip_a));
        assert!(!mw.check_and_consume(ip_a)); // ip_a exhausted
        assert!(mw.check_and_consume(ip_b)); // ip_b independent, still has its token
    }

    // ─── Middleware integration ──────────────────────────────────────

    #[test]
    fn middleware_returns_429_when_exhausted() {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new(1.0, 1.0));
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some("127.0.0.1"), &[]);
        let first = chain.execute(&req);
        assert_eq!(first.status, 200);

        let second = chain.execute(&req);
        assert_eq!(second.status, 429);
    }

    #[test]
    fn middleware_fails_open_when_no_remote_addr() {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new(0.0, 0.0)); // would always reject
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(None, &[]);
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 200);
    }
}
