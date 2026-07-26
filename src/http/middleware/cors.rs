//! CORS (Cross-Origin Resource Sharing) middleware: adds the standard
//! `Access-Control-Allow-*` headers to every response, and short-circuits
//! `OPTIONS` preflight requests with a bare 204 (no need to reach the
//! route handler for a preflight -- the browser only wants the
//! allow-* headers back).

use crate::http::middleware::{Middleware, Next};
use crate::http::request::{HttpMethod, HttpRequest};
use crate::http::response::HttpResponse;

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub origin: String,
    pub methods: String,
    pub headers: String,
}

impl Default for CorsConfig {
    fn default() -> Self {
        CorsConfig {
            origin: "*".to_string(),
            methods: "GET, POST, OPTIONS".to_string(),
            headers: "Content-Type".to_string(),
        }
    }
}

pub struct CorsMiddleware {
    config: CorsConfig,
}

impl CorsMiddleware {
    pub fn new(config: CorsConfig) -> Self {
        CorsMiddleware { config }
    }
}

impl Middleware for CorsMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        if req.method == HttpMethod::Options {
            let mut resp = HttpResponse::new(204, "No Content");
            apply_headers(&mut resp, &self.config);
            return resp;
        }

        let mut resp = next.run(req);
        apply_headers(&mut resp, &self.config);
        resp
    }
}

fn apply_headers(resp: &mut HttpResponse, cfg: &CorsConfig) {
    resp.set_header("Access-Control-Allow-Origin", cfg.origin.clone());
    resp.set_header("Access-Control-Allow-Methods", cfg.methods.clone());
    resp.set_header("Access-Control-Allow-Headers", cfg.headers.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: HttpMethod) -> HttpRequest {
        HttpRequest {
            method,
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
        }
    }

    #[test]
    fn default_headers_applied() {
        let mw = CorsMiddleware::new(CorsConfig::default());
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request(HttpMethod::Get));
        assert_eq!(resp.get_header("Access-Control-Allow-Origin"), Some("*"));
        assert_eq!(
            resp.get_header("Access-Control-Allow-Methods"),
            Some("GET, POST, OPTIONS")
        );
        assert_eq!(
            resp.get_header("Access-Control-Allow-Headers"),
            Some("Content-Type")
        );
    }

    #[test]
    fn custom_config_applied() {
        let cfg = CorsConfig {
            origin: "https://example.com".to_string(),
            methods: "GET".to_string(),
            headers: "Authorization".to_string(),
        };
        let mw = CorsMiddleware::new(cfg);
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request(HttpMethod::Get));
        assert_eq!(
            resp.get_header("Access-Control-Allow-Origin"),
            Some("https://example.com")
        );
    }

    #[test]
    fn options_request_short_circuits_with_204() {
        let mw = CorsMiddleware::new(CorsConfig::default());
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request(HttpMethod::Options));
        assert_eq!(resp.status, 204);
        assert_eq!(resp.get_header("Access-Control-Allow-Origin"), Some("*"));
    }

    #[test]
    fn non_options_request_reaches_handler() {
        let mw = CorsMiddleware::new(CorsConfig::default());
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        let resp = chain.execute(&make_request(HttpMethod::Get));
        assert_eq!(resp.status, 200);
    }
}
