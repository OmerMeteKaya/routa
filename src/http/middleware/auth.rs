//! Authentication middleware: HTTP Basic Auth and JWT bearer-token
//! verification.
//!
//! Basic Auth credential comparison uses `subtle::ConstantTimeEq`
//! rather than a plain string comparison -- a naive `==`/`strcmp`
//! returns as soon as the first differing byte is found, so how long
//! the comparison takes leaks (in principle) how many leading
//! characters of a guessed password were correct. Constant-time
//! comparison always examines every byte regardless of where the
//! first mismatch is, closing that side channel. In practice, network
//! jitter usually makes this attack impractical over a real network,
//! but it costs nothing to close here.
//!
//! JWT verification uses the `jsonwebtoken` crate (HS256 and RS256)
//! rather than hand-rolled HMAC/RSA signature verification --
//! signature verification is exactly the kind of code where a subtle
//! bug has serious security consequences, and `jsonwebtoken` is the
//! de facto standard, widely-audited choice in the Rust ecosystem.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::http::middleware::{Middleware, Next};
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

// ─── Basic Auth ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BasicAuthConfig {
    pub realm: String,
    users: HashMap<String, String>, // username -> password
}

impl BasicAuthConfig {
    pub fn new(realm: impl Into<String>) -> Self {
        BasicAuthConfig {
            realm: realm.into(),
            users: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }

    /// Checks `username`/`password` against the configured users.
    /// Compares the password with a constant-time comparison (see this
    /// module's doc comment) -- looking up `username` in the map first
    /// is not constant-time (`HashMap` lookup timing can vary), but
    /// only the password comparison is meant to resist timing analysis
    /// here, matching typical Basic Auth threat models where usernames
    /// aren't considered secret.
    fn verify(&self, username: &str, password: &str) -> bool {
        match self.users.get(username) {
            Some(expected) => {
                let a = expected.as_bytes();
                let b = password.as_bytes();
                a.len() == b.len() && bool::from(a.ct_eq(b))
            }
            None => false,
        }
    }
}

pub struct BasicAuthMiddleware {
    config: ArcSwap<BasicAuthConfig>,
    metrics: Option<Arc<crate::util::metrics::Metrics>>,
}

impl BasicAuthMiddleware {
    pub fn new(config: BasicAuthConfig) -> Self {
        BasicAuthMiddleware {
            config: ArcSwap::from_pointee(config),
            metrics: None,
        }
    }

    pub fn with_metrics(config: BasicAuthConfig, metrics: Arc<crate::util::metrics::Metrics>) -> Self {
        BasicAuthMiddleware {
            config: ArcSwap::from_pointee(config),
            metrics: Some(metrics),
        }
    }

    pub fn reload(&self, config: BasicAuthConfig) {
        self.config.store(Arc::new(config));
    }
}

fn unauthorized_basic(realm: &str, metrics: &Option<Arc<crate::util::metrics::Metrics>>) -> HttpResponse {
    if let Some(metrics) = metrics {
        metrics.middleware.auth_basic_failures_total.inc();
    }
    let mut resp = HttpResponse::new(401, "Unauthorized");
    resp.set_header(
        "WWW-Authenticate",
        format!("Basic realm=\"{realm}\", charset=\"UTF-8\""),
    );
    resp.set_body(b"Unauthorized\n".to_vec());
    resp
}

impl Middleware for BasicAuthMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        let config = self.config.load();

        let Some(auth) = req.get_header("Authorization") else {
            return unauthorized_basic(&config.realm, &self.metrics);
        };
        let Some(encoded) = auth.strip_prefix("Basic ").or_else(|| auth.strip_prefix("basic "))
        else {
            return unauthorized_basic(&config.realm, &self.metrics);
        };

        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return unauthorized_basic(&config.realm, &self.metrics);
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return unauthorized_basic(&config.realm, &self.metrics);
        };
        let Some((username, password)) = decoded.split_once(':') else {
            return unauthorized_basic(&config.realm, &self.metrics);
        };

        if !config.verify(username, password) {
            return unauthorized_basic(&config.realm, &self.metrics);
        }

        next.run(req)
    }
}

// ─── JWT ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum JwtKey {
    Hs256 { secret: String },
    Rs256 { public_key_pem: String },
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub key: JwtKey,
    pub verify_exp: bool,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl JwtConfig {
    pub fn hs256(secret: impl Into<String>) -> Self {
        JwtConfig {
            key: JwtKey::Hs256 {
                secret: secret.into(),
            },
            verify_exp: true,
            issuer: None,
            audience: None,
        }
    }

    pub fn rs256(public_key_pem: impl Into<String>) -> Self {
        JwtConfig {
            key: JwtKey::Rs256 {
                public_key_pem: public_key_pem.into(),
            },
            verify_exp: true,
            issuer: None,
            audience: None,
        }
    }
}

/// Decoded claims as a flat string map -- a handler reads a claim back
/// by name rather than needing to know a fixed claims shape ahead of
/// time. Standard numeric/boolean claim values are stringified; nested
/// objects/arrays are JSON-encoded as their string form.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwtClaims(HashMap<String, serde_json::Value>);

impl JwtClaims {
    pub fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }
}

fn build_validation(cfg: &JwtConfig, alg: Algorithm) -> Validation {
    let mut validation = Validation::new(alg);
    validation.validate_exp = cfg.verify_exp;
    if let Some(iss) = &cfg.issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = &cfg.audience {
        validation.set_audience(&[aud]);
    }
    validation
}

/// Verifies `token` against `cfg`, returning the decoded claims on
/// success.
pub fn verify(cfg: &JwtConfig, token: &str) -> Option<JwtClaims> {
    let (decoding_key, alg) = match &cfg.key {
        JwtKey::Hs256 { secret } => {
            (DecodingKey::from_secret(secret.as_bytes()), Algorithm::HS256)
        }
        JwtKey::Rs256 { public_key_pem } => (
            DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).ok()?,
            Algorithm::RS256,
        ),
    };
    let validation = build_validation(cfg, alg);
    let data = decode::<JwtClaims>(token, &decoding_key, &validation).ok()?;
    Some(data.claims)
}

pub struct JwtAuthMiddleware {
    config: ArcSwap<JwtConfig>,
    metrics: Option<Arc<crate::util::metrics::Metrics>>,
}

impl JwtAuthMiddleware {
    pub fn new(config: JwtConfig) -> Self {
        JwtAuthMiddleware {
            config: ArcSwap::from_pointee(config),
            metrics: None,
        }
    }

    pub fn with_metrics(config: JwtConfig, metrics: Arc<crate::util::metrics::Metrics>) -> Self {
        JwtAuthMiddleware {
            config: ArcSwap::from_pointee(config),
            metrics: Some(metrics),
        }
    }

    pub fn reload(&self, config: JwtConfig) {
        self.config.store(Arc::new(config));
    }
}

fn unauthorized_jwt(metrics: &Option<Arc<crate::util::metrics::Metrics>>) -> HttpResponse {
    if let Some(metrics) = metrics {
        metrics.middleware.auth_jwt_failures_total.inc();
    }
    let mut resp = HttpResponse::new(401, "Unauthorized");
    resp.set_header("WWW-Authenticate", "Bearer");
    resp.set_body(b"Unauthorized\n".to_vec());
    resp
}

impl Middleware for JwtAuthMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        let config = self.config.load();

        let Some(auth) = req.get_header("Authorization") else {
            return unauthorized_jwt(&self.metrics);
        };
        let Some(token) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "))
        else {
            return unauthorized_jwt(&self.metrics);
        };

        if verify(&config, token.trim()).is_none() {
            return unauthorized_jwt(&self.metrics);
        }

        // Claims aren't currently attached back onto the request for
        // downstream handlers to read -- once there's a place to carry
        // per-request extension data through the chain, this is where
        // it would be populated.
        next.run(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn make_request(auth_header: Option<&str>) -> HttpRequest {
        let mut req = HttpRequest {
            method: HttpMethod::Get,
            remote_addr: None,
            path: "/".to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: Vec::new(),
            body: Vec::new(),
            keep_alive: true,
            trailers: Vec::new(),
        };
        if let Some(v) = auth_header {
            req.headers.push(("Authorization".to_string(), v.to_string()));
        }
        req
    }

    fn basic_header(username: &str, password: &str) -> String {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        format!("Basic {encoded}")
    }

    // ─── Basic Auth ─────────────────────────────────────────────────

    #[test]
    fn valid_credentials_pass() {
        let mut cfg = BasicAuthConfig::new("Restricted");
        cfg.add_user("admin", "s3cret");
        let mw = BasicAuthMiddleware::new(cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some(&basic_header("admin", "s3cret")));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn wrong_password_rejected() {
        let mut cfg = BasicAuthConfig::new("Restricted");
        cfg.add_user("admin", "s3cret");
        let mw = BasicAuthMiddleware::new(cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some(&basic_header("admin", "wrong")));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 401);
        assert!(resp
            .get_header("WWW-Authenticate")
            .unwrap()
            .contains("Restricted"));
    }

    #[test]
    fn missing_header_rejected() {
        let cfg = BasicAuthConfig::new("Restricted");
        let mw = BasicAuthMiddleware::new(cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request(None));
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn malformed_base64_rejected() {
        let cfg = BasicAuthConfig::new("Restricted");
        let mw = BasicAuthMiddleware::new(cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some("Basic not-valid-base64!!!"));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn reload_replaces_credentials() {
        let mw = BasicAuthMiddleware::new(BasicAuthConfig::new("Restricted"));

        let mut new_cfg = BasicAuthConfig::new("Restricted");
        new_cfg.add_user("admin", "newpass");
        mw.reload(new_cfg);

        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some(&basic_header("admin", "newpass")));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 200);
    }

    // ─── JWT ────────────────────────────────────────────────────────

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn valid_hs256_token_passes() {
        let secret = "test-secret";
        let claims = TestClaims {
            sub: "user1".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let mw = JwtAuthMiddleware::new(JwtConfig::hs256(secret));
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some(&format!("Bearer {token}")));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn expired_token_rejected() {
        let secret = "test-secret";
        let claims = TestClaims {
            sub: "user1".to_string(),
            exp: 1, // long expired
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let mw = JwtAuthMiddleware::new(JwtConfig::hs256(secret));
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some(&format!("Bearer {token}")));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn wrong_secret_rejected() {
        let claims = TestClaims {
            sub: "user1".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"correct-secret"),
        )
        .unwrap();

        let mw = JwtAuthMiddleware::new(JwtConfig::hs256("wrong-secret"));
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some(&format!("Bearer {token}")));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn missing_bearer_prefix_rejected() {
        let mw = JwtAuthMiddleware::new(JwtConfig::hs256("secret"));
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some("not-a-bearer-token"));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn issuer_mismatch_rejected() {
        let secret = "test-secret";
        #[derive(Serialize)]
        struct ClaimsWithIssuer {
            sub: String,
            exp: usize,
            iss: String,
        }
        let claims = ClaimsWithIssuer {
            sub: "user1".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
            iss: "wrong-issuer".to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let mut cfg = JwtConfig::hs256(secret);
        cfg.issuer = Some("expected-issuer".to_string());
        let mw = JwtAuthMiddleware::new(cfg);
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let req = make_request(Some(&format!("Bearer {token}")));
        let resp = chain.execute(&req);
        assert_eq!(resp.status, 401);
    }
}
