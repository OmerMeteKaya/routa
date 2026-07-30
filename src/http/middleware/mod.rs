//! Middleware chain: a sequence of request/response interceptors run
//! before a route's final handler. Each `Middleware` decides whether
//! to call `next` (continue the chain) or short-circuit by returning
//! its own response directly (e.g. a rate limiter returning 429
//! without ever reaching the handler).
//!
//! Each `Middleware` implements a `call` method taking a `Next` handle
//! to invoke -- a continuation-passing shape using trait objects
//! rather than raw function pointers, so a middleware can hold
//! arbitrary state (closures capturing config, `Arc`-shared caches,
//! etc.) directly rather than through a separate `void *ctx` parameter
//! threaded through every call site.
//!
//! Hot-reloadable middleware config (ACL rules, rate limits, etc.)
//! uses `arc_swap::ArcSwap`: reading a middleware's current config
//! from the request path is a lock-free load, and swapping in a
//! freshly-reloaded config (SIGHUP) is a single atomic store. A
//! request already mid-flight through a middleware keeps using the
//! `Arc` it already loaded (reference-counted, so it stays alive
//! exactly as long as needed) -- no manual "don't free the old
//! config, a request might still be using it" bookkeeping required.

pub mod acl;
pub mod auth;
pub mod cidr;
pub mod compress;
pub mod cors;
pub mod logger;
pub mod metrics;
pub mod ratelimit;
pub mod response_cache;

use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

/// A middleware's view of "what happens next" in the chain: either
/// another middleware, or the route's final handler. Calling
/// `next.run(req)` continues the chain; a middleware that never calls
/// it has short-circuited (e.g. returned an error response directly).
pub struct Next<'a> {
    remaining: &'a [Box<dyn Middleware>],
    final_handler: &'a dyn Fn(&HttpRequest) -> HttpResponse,
}

impl<'a> Next<'a> {
    pub fn run(&self, req: &HttpRequest) -> HttpResponse {
        match self.remaining.split_first() {
            Some((mw, rest)) => {
                let next = Next {
                    remaining: rest,
                    final_handler: self.final_handler,
                };
                mw.call(req, next)
            }
            None => (self.final_handler)(req),
        }
    }
}

/// A single middleware. `call` receives the request and a `Next`
/// handle for continuing the chain -- implementations decide whether
/// to call `next.run(req)` (optionally inspecting/modifying the
/// resulting response before returning it) or return their own
/// response without ever calling `next` at all.
pub trait Middleware: Send + Sync {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse;
}

/// The full chain: an ordered list of middlewares plus the final
/// route handler they wrap. Built once at startup (see `ChainBuilder`)
/// and shared (via `Arc`) across every worker; individual middlewares
/// hold their own `ArcSwap`-based config for anything that needs to be
/// hot-reloadable.
pub struct Chain {
    middlewares: Vec<Box<dyn Middleware>>,
    final_handler: Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>,
}

impl Chain {
    pub fn execute(&self, req: &HttpRequest) -> HttpResponse {
        let next = Next {
            remaining: &self.middlewares,
            final_handler: &*self.final_handler,
        };
        next.run(req)
    }
}

pub struct ChainBuilder {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl ChainBuilder {
    pub fn new() -> Self {
        ChainBuilder {
            middlewares: Vec::new(),
        }
    }

    pub fn use_middleware(mut self, mw: impl Middleware + 'static) -> Self {
        self.middlewares.push(Box::new(mw));
        self
    }

    pub fn build(
        self,
        final_handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> Chain {
        Chain {
            middlewares: self.middlewares,
            final_handler: Box::new(final_handler),
        }
    }
}

impl Default for ChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;

    fn make_request(path: &str) -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            remote_addr: None,
            path: path.to_string(),
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

    struct TagHeader(&'static str);
    impl Middleware for TagHeader {
        fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
            let mut resp = next.run(req);
            resp.set_header("X-Chain", self.0);
            resp
        }
    }

    struct ShortCircuit;
    impl Middleware for ShortCircuit {
        fn call(&self, _req: &HttpRequest, _next: Next<'_>) -> HttpResponse {
            HttpResponse::new(403, "Forbidden")
        }
    }

    #[test]
    fn empty_chain_calls_final_handler() {
        let chain = ChainBuilder::new().build(|_req| HttpResponse::new(200, "OK"));
        let resp = chain.execute(&make_request("/"));
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn middleware_runs_before_handler() {
        let chain = ChainBuilder::new()
            .use_middleware(TagHeader("first"))
            .build(|_req| HttpResponse::new(200, "OK"));
        let resp = chain.execute(&make_request("/"));
        assert_eq!(resp.get_header("X-Chain"), Some("first"));
    }

    #[test]
    fn multiple_middlewares_run_in_order() {
        // Each middleware overwrites the header on its way back out,
        // so the last one to run (closest to the handler) wins --
        // confirms both ordering and that each middleware's post-next
        // logic actually executes.
        let chain = ChainBuilder::new()
            .use_middleware(TagHeader("outer"))
            .use_middleware(TagHeader("inner"))
            .build(|_req| HttpResponse::new(200, "OK"));
        let resp = chain.execute(&make_request("/"));
        assert_eq!(resp.get_header("X-Chain"), Some("outer"));
    }

    #[test]
    fn middleware_can_short_circuit() {
        let chain = ChainBuilder::new()
            .use_middleware(ShortCircuit)
            .use_middleware(TagHeader("never-reached"))
            .build(|_req| HttpResponse::new(200, "OK"));
        let resp = chain.execute(&make_request("/"));
        assert_eq!(resp.status, 403);
        assert!(resp.get_header("X-Chain").is_none());
    }
}
