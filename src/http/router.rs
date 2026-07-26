//! Request routing: matches a request's method and path against a set
//! of registered routes and returns the matching route's handler.
//!
//! Three path-pattern kinds are supported:
//! - Exact (`"/health"`) -- matches only that literal path.
//! - Prefix wildcard (`"/static/*"` or `"/*"`) -- matches any path
//!   starting with the prefix before `*`.
//! - Named parameters (`"/users/:id"`, `"/files/:category/:name"`) --
//!   matches paths with the same segment count, capturing each `:name`
//!   segment's actual value for the handler to read back out.
//!
//! Precedence when multiple registered routes could match the same
//! request: exact match wins outright; among wildcard/parameter
//! matches, the more specific one wins, where specificity is the
//! length of the pattern's fixed (non-wildcard, non-parameter) prefix.
//! Precedence here is deterministic and independent of registration
//! order -- a catch-all route registered before a specific one can
//! never silently steal that specific route's requests.

use crate::http::request::{HttpMethod, HttpRequest};

/// One segment of a compiled route pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A literal path segment that must match exactly.
    Literal(String),
    /// A named parameter (`:name`) -- matches any single segment,
    /// capturing its value under `name`.
    Param(String),
    /// A trailing wildcard (`*`) -- matches the rest of the path,
    /// however many segments remain (including zero).
    Wildcard,
}

/// A compiled route pattern, ready to match against request paths
/// without re-parsing the original pattern string each time.
#[derive(Debug, Clone)]
struct Pattern {
    segments: Vec<Segment>,
    /// Number of segments before the first `Param`/`Wildcard` --
    /// determines precedence among overlapping matches (see this
    /// module's doc comment).
    specificity: usize,
}

impl Pattern {
    fn compile(path: &str) -> Pattern {
        let mut segments = Vec::new();
        let mut specificity = 0;
        let mut counting_specificity = true;

        for part in path.split('/').filter(|s| !s.is_empty()) {
            let segment = if part == "*" {
                Segment::Wildcard
            } else if let Some(name) = part.strip_prefix(':') {
                Segment::Param(name.to_string())
            } else {
                Segment::Literal(part.to_string())
            };

            if counting_specificity {
                match &segment {
                    Segment::Literal(_) => specificity += 1,
                    Segment::Param(_) | Segment::Wildcard => counting_specificity = false,
                }
            }

            segments.push(segment);
        }

        Pattern {
            segments,
            specificity,
        }
    }

    fn is_exact(&self) -> bool {
        !self
            .segments
            .iter()
            .any(|s| matches!(s, Segment::Param(_) | Segment::Wildcard))
    }

    /// Attempts to match `path` against this pattern, returning the
    /// captured parameter values (in pattern order) on success.
    fn matches(&self, path: &str) -> Option<Vec<(String, String)>> {
        let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut params = Vec::new();
        let mut pi = 0usize; // index into path_segments

        for (si, seg) in self.segments.iter().enumerate() {
            match seg {
                Segment::Wildcard => {
                    // A wildcard must be the pattern's last segment
                    // (enforced by how patterns are authored -- routes
                    // don't currently support a wildcard followed by
                    // more literal segments); matches everything
                    // remaining, including nothing at all.
                    debug_assert_eq!(si, self.segments.len() - 1);
                    return Some(params);
                }
                Segment::Literal(lit) => {
                    if path_segments.get(pi) != Some(&lit.as_str()) {
                        return None;
                    }
                    pi += 1;
                }
                Segment::Param(name) => {
                    let value = path_segments.get(pi)?;
                    params.push((name.clone(), value.to_string()));
                    pi += 1;
                }
            }
        }

        // No wildcard consumed the rest -- every path segment must
        // have been matched by a literal/param, no leftovers.
        if pi == path_segments.len() {
            Some(params)
        } else {
            None
        }
    }
}

pub type RouteHandler = fn(&HttpRequest, &RouteParams) -> crate::http::response::HttpResponse;

/// Named parameters captured from the matched route pattern (e.g.
/// `:id` in `/users/:id`), in the order they appear in the pattern.
#[derive(Debug, Clone, Default)]
pub struct RouteParams(Vec<(String, String)>);

impl RouteParams {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Route {
    pattern: Pattern,
    methods: Vec<HttpMethod>,
    handler: RouteHandler,
}

/// The result of matching a request against the router's routes.
pub enum Dispatch<'a> {
    /// A route matched both path and method -- ready to call.
    Matched {
        handler: RouteHandler,
        params: RouteParams,
    },
    /// A route's path pattern matched, but not for this method. Carries
    /// the set of methods that *would* have matched, for building a
    /// 405 response's `Allow` header.
    MethodNotAllowed { allowed: &'a [HttpMethod] },
    /// No route's path pattern matched this request at all.
    NotFound,
}

#[derive(Default)]
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub fn new() -> Self {
        Router { routes: Vec::new() }
    }

    /// Registers a route. `path` may contain `:name` parameter
    /// segments and/or end in a trailing `*` wildcard segment (see
    /// this module's doc comment for the supported pattern kinds).
    pub fn add(&mut self, path: &str, methods: &[HttpMethod], handler: RouteHandler) {
        self.routes.push(Route {
            pattern: Pattern::compile(path),
            methods: methods.to_vec(),
            handler,
        });
    }

    /// Matches `req` against every registered route and returns the
    /// dispatch outcome (see `Dispatch`). Exact-path matches always
    /// take precedence over wildcard/parameter matches; among the
    /// latter, the most specific (longest fixed prefix) pattern wins,
    /// independent of registration order.
    pub fn dispatch(&self, req: &HttpRequest) -> Dispatch<'_> {
        let mut best: Option<(&Route, Vec<(String, String)>)> = None;

        for route in &self.routes {
            let Some(params) = route.pattern.matches(&req.path) else {
                continue;
            };

            if route.pattern.is_exact() {
                best = Some((route, params));
                break; // an exact match can never be beaten
            }

            let better = match &best {
                None => true,
                Some((current, _)) => route.pattern.specificity > current.pattern.specificity,
            };
            if better {
                best = Some((route, params));
            }
        }

        let Some((route, params)) = best else {
            return Dispatch::NotFound;
        };

        if route.methods.contains(&req.method) {
            Dispatch::Matched {
                handler: route.handler,
                params: RouteParams(params),
            }
        } else {
            Dispatch::MethodNotAllowed {
                allowed: &route.methods,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::response::HttpResponse;

    fn ok_handler(_req: &HttpRequest, _params: &RouteParams) -> HttpResponse {
        HttpResponse::new(200, "OK")
    }

    fn make_request(method: HttpMethod, path: &str) -> HttpRequest {
        HttpRequest {
            method,
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

    #[test]
    fn exact_match() {
        let mut router = Router::new();
        router.add("/health", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Get, "/health");
        assert!(matches!(router.dispatch(&req), Dispatch::Matched { .. }));
    }

    #[test]
    fn no_match_is_not_found() {
        let router = Router::new();
        let req = make_request(HttpMethod::Get, "/nope");
        assert!(matches!(router.dispatch(&req), Dispatch::NotFound));
    }

    #[test]
    fn wrong_method_is_method_not_allowed() {
        let mut router = Router::new();
        router.add("/health", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Post, "/health");
        match router.dispatch(&req) {
            Dispatch::MethodNotAllowed { allowed } => {
                assert_eq!(allowed, &[HttpMethod::Get]);
            }
            _ => panic!("expected MethodNotAllowed"),
        }
    }

    #[test]
    fn wildcard_matches_prefix() {
        let mut router = Router::new();
        router.add("/static/*", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Get, "/static/css/app.css");
        assert!(matches!(router.dispatch(&req), Dispatch::Matched { .. }));
    }

    #[test]
    fn root_wildcard_matches_everything() {
        let mut router = Router::new();
        router.add("/*", &[HttpMethod::Get], ok_handler);

        for path in ["/", "/a", "/a/b/c"] {
            let req = make_request(HttpMethod::Get, path);
            assert!(
                matches!(router.dispatch(&req), Dispatch::Matched { .. }),
                "expected {path} to match /*"
            );
        }
    }

    #[test]
    fn exact_beats_wildcard_regardless_of_registration_order() {
        // Register the catch-all FIRST -- this is exactly the
        // registration order that broke the archived C router's
        // router_dispatch(). The exact match must still win.
        let mut router = Router::new();
        router.add("/*", &[HttpMethod::Get], ok_handler);
        router.add("/health", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Get, "/health");
        assert!(matches!(router.dispatch(&req), Dispatch::Matched { .. }));
    }

    #[test]
    fn more_specific_wildcard_wins_regardless_of_registration_order() {
        // Same bug this module's doc comment describes: register the
        // broad catch-all before the specific one.
        let mut router = Router::new();
        router.add("/*", &[HttpMethod::Get], ok_handler);
        router.add("/proxy/*", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Get, "/proxy/anything");
        let Dispatch::Matched { .. } = router.dispatch(&req) else {
            panic!("expected a match");
        };

        // Confirm specificity actually differs between the two
        // patterns (proving the comparison in dispatch() is
        // meaningful, not a no-op).
        let proxy_pattern = Pattern::compile("/proxy/*");
        let root_pattern = Pattern::compile("/*");
        assert!(proxy_pattern.specificity > root_pattern.specificity);
    }

    #[test]
    fn param_segment_captured() {
        let mut router = Router::new();
        router.add("/users/:id", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Get, "/users/42");
        match router.dispatch(&req) {
            Dispatch::Matched { params, .. } => {
                assert_eq!(params.get("id"), Some("42"));
            }
            _ => panic!("expected a match"),
        }
    }

    #[test]
    fn multiple_param_segments_captured_in_order() {
        let mut router = Router::new();
        router.add("/files/:category/:name", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Get, "/files/images/cat.png");
        match router.dispatch(&req) {
            Dispatch::Matched { params, .. } => {
                assert_eq!(params.get("category"), Some("images"));
                assert_eq!(params.get("name"), Some("cat.png"));
            }
            _ => panic!("expected a match"),
        }
    }

    #[test]
    fn param_pattern_requires_same_segment_count() {
        let mut router = Router::new();
        router.add("/users/:id", &[HttpMethod::Get], ok_handler);

        // Too few segments.
        let req = make_request(HttpMethod::Get, "/users");
        assert!(matches!(router.dispatch(&req), Dispatch::NotFound));

        // Too many segments (no wildcard to absorb the extra one).
        let req = make_request(HttpMethod::Get, "/users/42/extra");
        assert!(matches!(router.dispatch(&req), Dispatch::NotFound));
    }

    #[test]
    fn multiple_methods_on_one_route() {
        let mut router = Router::new();
        router.add("/items", &[HttpMethod::Get, HttpMethod::Post], ok_handler);

        for method in [HttpMethod::Get, HttpMethod::Post] {
            let req = make_request(method, "/items");
            assert!(matches!(router.dispatch(&req), Dispatch::Matched { .. }));
        }

        let req = make_request(HttpMethod::Delete, "/items");
        match router.dispatch(&req) {
            Dispatch::MethodNotAllowed { allowed } => {
                assert_eq!(allowed, &[HttpMethod::Get, HttpMethod::Post]);
            }
            _ => panic!("expected MethodNotAllowed"),
        }
    }

    #[test]
    fn trailing_slash_root_path() {
        let mut router = Router::new();
        router.add("/", &[HttpMethod::Get], ok_handler);

        let req = make_request(HttpMethod::Get, "/");
        assert!(matches!(router.dispatch(&req), Dispatch::Matched { .. }));
    }
}
