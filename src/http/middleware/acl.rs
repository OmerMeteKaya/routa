//! IP-based access control: CIDR rules checked in registration order,
//! first match wins; `default_allow` decides the outcome when nothing
//! matches. Uses `std::net::IpAddr` for parsing rather than
//! hand-rolled address parsing -- the standard library already parses
//! both IPv4 and IPv6 addresses correctly. CIDR prefix matching itself
//! is a small amount of direct bitmask arithmetic, same approach (and
//! same performance characteristics) as comparing masked address
//! bytes directly.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::http::middleware::cidr::CidrRange;
use crate::http::middleware::{Middleware, Next};
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
struct AclRule {
    range: CidrRange,
    action: AclAction,
}

impl AclRule {
    fn parse(rule: &str, action: AclAction) -> Option<AclRule> {
        Some(AclRule {
            range: CidrRange::parse(rule)?,
            action,
        })
    }

    fn matches(&self, addr: &IpAddr) -> bool {
        self.range.contains(addr)
    }
}

#[derive(Debug, Clone)]
pub struct AclConfig {
    rules: Vec<AclRule>,
    pub default_allow: bool,
}

impl AclConfig {
    pub fn new(default_allow: bool) -> Self {
        AclConfig {
            rules: Vec::new(),
            default_allow,
        }
    }

    /// Adds a rule. Returns `false` (and adds nothing) if `rule`
    /// doesn't parse as a valid IPv4/IPv6 address or CIDR range.
    pub fn add_rule(&mut self, rule: &str, action: AclAction) -> bool {
        match AclRule::parse(rule, action) {
            Some(r) => {
                self.rules.push(r);
                true
            }
            None => false,
        }
    }

    /// Checks whether `addr` is allowed: the first matching rule (in
    /// registration order) decides; `default_allow` applies if nothing
    /// matches.
    pub fn check(&self, addr: &IpAddr) -> bool {
        for rule in &self.rules {
            if rule.matches(addr) {
                return rule.action == AclAction::Allow;
            }
        }
        self.default_allow
    }
}

/// ACL middleware. Config is held behind an `ArcSwap` so it can be
/// hot-reloaded (SIGHUP) without a lock on the request path -- see
/// `http::middleware`'s module doc comment for the general pattern.
pub struct AclMiddleware {
    config: ArcSwap<AclConfig>,
}

impl AclMiddleware {
    pub fn new(config: AclConfig) -> Self {
        AclMiddleware {
            config: ArcSwap::from_pointee(config),
        }
    }

    /// Atomically replaces the ACL config used by subsequent requests.
    /// A request already mid-flight keeps using the `Arc` it already
    /// loaded.
    pub fn reload(&self, config: AclConfig) {
        self.config.store(Arc::new(config));
    }
}

impl Middleware for AclMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        let config = self.config.load();
        let allowed = match req.remote_addr {
            Some(addr) => config.check(&addr),
            // No known remote address on the request -- fail open to
            // default_allow.
            None => config.default_allow,
        };

        if !allowed {
            let mut resp = HttpResponse::new(403, "Forbidden");
            resp.set_header("Content-Type", "text/plain");
            resp.set_body(b"Forbidden\n".to_vec());
            return resp;
        }

        next.run(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;

    fn make_request(remote_ip: &str) -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            remote_addr: Some(remote_ip.parse().unwrap()),
            path: "/".to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: Vec::new(),
            body: Vec::new(),
            keep_alive: true,
            trailers: Vec::new(),
        }
    }

    // ─── AclConfig::check ───────────────────────────────────────────

    #[test]
    fn exact_ip_match() {
        let mut cfg = AclConfig::new(true);
        cfg.add_rule("192.168.1.100", AclAction::Deny);
        assert!(!cfg.check(&"192.168.1.100".parse().unwrap()));
        assert!(cfg.check(&"192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn cidr_range_match() {
        let mut cfg = AclConfig::new(true);
        cfg.add_rule("10.0.0.0/8", AclAction::Deny);
        assert!(!cfg.check(&"10.1.2.3".parse().unwrap()));
        assert!(!cfg.check(&"10.255.255.255".parse().unwrap()));
        assert!(cfg.check(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_range_match() {
        let mut cfg = AclConfig::new(true);
        cfg.add_rule("2001:db8::/32", AclAction::Deny);
        assert!(!cfg.check(&"2001:db8::1".parse().unwrap()));
        assert!(cfg.check(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut cfg = AclConfig::new(true);
        cfg.add_rule("10.0.0.0/8", AclAction::Deny);
        cfg.add_rule("10.0.0.1", AclAction::Allow);
        // The broader deny rule was registered first, so it wins even
        // though a more specific allow rule also matches.
        assert!(!cfg.check(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn default_allow_applies_when_no_rule_matches() {
        let mut cfg = AclConfig::new(false);
        cfg.add_rule("10.0.0.0/8", AclAction::Allow);
        assert!(!cfg.check(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn invalid_rule_is_rejected() {
        let mut cfg = AclConfig::new(true);
        assert!(!cfg.add_rule("not-an-ip", AclAction::Deny));
        assert!(!cfg.add_rule("10.0.0.0/99", AclAction::Deny)); // prefix too large
    }

    // ─── Middleware integration ──────────────────────────────────────

    #[test]
    fn middleware_blocks_denied_ip() {
        let mut cfg = AclConfig::new(true);
        cfg.add_rule("10.0.0.0/8", AclAction::Deny);
        let mw = AclMiddleware::new(cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request("10.1.2.3"));
        assert_eq!(resp.status, 403);
    }

    #[test]
    fn middleware_allows_permitted_ip() {
        let mut cfg = AclConfig::new(true);
        cfg.add_rule("10.0.0.0/8", AclAction::Deny);
        let mw = AclMiddleware::new(cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request("192.168.1.1"));
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn reload_replaces_config_atomically() {
        let mw = AclMiddleware::new(AclConfig::new(true));

        let mut new_cfg = AclConfig::new(true);
        new_cfg.add_rule("10.0.0.0/8", AclAction::Deny);
        mw.reload(new_cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request("10.1.2.3"));
        assert_eq!(resp.status, 403);
    }
}
