//! `/metrics` route handler: renders Prometheus text format. Not a
//! `Middleware` (doesn't sit in the request chain) -- registered
//! directly as a route: `GET /metrics`.
//!
//! The actual metric collection/formatting logic lives in
//! `util::metrics`; this handler is a thin wrapper that reads the
//! caller-supplied `Metrics` registry and serves its current state.

use std::sync::Arc;

use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
use crate::util::metrics::Metrics;

/// Renders the `/metrics` response. Returns Prometheus text format
/// (content-type `text/plain; version=0.0.4; charset=utf-8`, per the
/// Prometheus exposition format spec) with caching disabled, since
/// metrics should always be scraped fresh.
pub fn handle(_req: &HttpRequest, metrics: &Arc<Metrics>) -> HttpResponse {
    let mut resp = HttpResponse::new(200, "OK");
    resp.set_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
    resp.set_header("Cache-Control", "no-cache");
    resp.set_body(metrics.prometheus_text());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;

    fn make_request() -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            remote_addr: None,
            path: "/metrics".to_string(),
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
    fn returns_200_with_correct_content_type() {
        let metrics = crate::util::metrics::Metrics::new();
        let resp = handle(&make_request(), &metrics);
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.get_header("Content-Type"),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );
    }

    #[test]
    fn disables_caching() {
        let metrics = crate::util::metrics::Metrics::new();
        let resp = handle(&make_request(), &metrics);
        assert_eq!(resp.get_header("Cache-Control"), Some("no-cache"));
    }

    #[test]
    fn body_contains_real_metric_output() {
        let metrics = crate::util::metrics::Metrics::new();
        metrics.record_request("GET", "/", 200, 0.01, 0, 0);
        let resp = handle(&make_request(), &metrics);
        let body = String::from_utf8(resp.body().to_vec()).unwrap();
        assert!(body.contains("routa_http_requests_total"));
    }
}
