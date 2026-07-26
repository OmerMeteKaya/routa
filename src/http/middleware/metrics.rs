//! `/metrics` route handler: renders Prometheus text format. Not a
//! `Middleware` (doesn't sit in the request chain) -- registered
//! directly as a route, same as the archived C implementation's
//! `routa_metrics_handler` (see its own doc comment for the intended
//! registration: `GET /metrics`).
//!
//! The actual metric collection/formatting logic lives in
//! `util::metrics` (not yet implemented -- see the project roadmap's
//! observability layer, deliberately sequenced after the request/
//! response/proxy layers that produce the numbers being reported).
//! This handler is intentionally a thin wrapper around that: once
//! `util::metrics::prometheus_text()` exists, this is the only place
//! that needs to change to serve real data instead of a placeholder.

use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

/// Renders the `/metrics` response. Returns Prometheus text format
/// (content-type `text/plain; version=0.0.4; charset=utf-8`, per the
/// Prometheus exposition format spec) with caching disabled, since
/// metrics should always be scraped fresh.
pub fn handle(_req: &HttpRequest) -> HttpResponse {
    let mut resp = HttpResponse::new(200, "OK");
    resp.set_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
    resp.set_header("Cache-Control", "no-cache");
    resp.set_body(prometheus_text());
    resp
}

/// Placeholder pending `util::metrics`. Returns an empty exposition
/// (Prometheus scrapers tolerate an empty body -- no metrics reported
/// yet is a valid, if uninteresting, response) rather than fabricating
/// fake metric lines.
fn prometheus_text() -> Vec<u8> {
    Vec::new()
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
        let resp = handle(&make_request());
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.get_header("Content-Type"),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );
    }

    #[test]
    fn disables_caching() {
        let resp = handle(&make_request());
        assert_eq!(resp.get_header("Cache-Control"), Some("no-cache"));
    }
}
