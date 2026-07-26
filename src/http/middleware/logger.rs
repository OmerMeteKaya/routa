//! Structured (JSON) access logging. Runs as the outermost middleware
//! in a chain (so its timing measurement covers every inner
//! middleware plus the route handler) and emits one JSON line per
//! request: timestamp, trace id, method, path, status, latency,
//! remote address, worker id, and response body size.
//!
//! Unlike deriving this from connection-level state stashed during
//! response writing (useful in an implementation where a middleware
//! chain doesn't see the whole request/response lifecycle), this
//! middleware measures directly: it calls `next.run(req)`, times how
//! long that took, and reads the resulting `HttpResponse` -- no
//! separate stash/consume step needed since the middleware chain
//! already sees both ends of the request here.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::http::middleware::{Middleware, Next};
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

static TRACE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a 16-hex-digit trace id, unique within this process.
fn next_trace_id() -> String {
    let id = TRACE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{id:016x}")
}

/// Replaces characters that would break JSON string encoding or allow
/// log injection (embedded quotes, backslashes, control characters
/// including newlines) with `?`, mirroring the archived C
/// implementation's `safe_path` sanitization. Applied to the request
/// path specifically, since it's the one field in this log line that
/// echoes attacker-controlled input verbatim.
fn sanitize_for_json(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '"' || c == '\\' || (c as u32) < 0x20 {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Where access log lines are written. A trait rather than a concrete
/// `Write` target so tests can capture output without touching stdio,
/// and so a future config option (log to file vs stdout) doesn't
/// require changing the middleware itself.
pub trait AccessLogSink: Send + Sync {
    fn write_line(&self, line: &str);
}

/// Writes to stderr, matching common access-log conventions of keeping
/// application stdout free for other output.
pub struct StderrSink;

impl AccessLogSink for StderrSink {
    fn write_line(&self, line: &str) {
        let mut stderr = std::io::stderr();
        let _ = writeln!(stderr, "{line}");
    }
}

/// Writes to an in-memory buffer -- used by this module's own tests,
/// and potentially useful for a future admin/debug endpoint that
/// tails recent access log lines.
pub struct BufferSink {
    lines: Mutex<Vec<String>>,
}

impl BufferSink {
    pub fn new() -> Self {
        BufferSink {
            lines: Mutex::new(Vec::new()),
        }
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

impl Default for BufferSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessLogSink for BufferSink {
    fn write_line(&self, line: &str) {
        self.lines.lock().unwrap().push(line.to_string());
    }
}

pub struct LoggerMiddleware {
    sink: Box<dyn AccessLogSink>,
    worker_id: i32,
}

impl LoggerMiddleware {
    pub fn new(sink: impl AccessLogSink + 'static, worker_id: i32) -> Self {
        LoggerMiddleware {
            sink: Box::new(sink),
            worker_id,
        }
    }
}

impl Middleware for LoggerMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        let trace_id = next_trace_id();
        let start = Instant::now();

        let resp = next.run(req);

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let remote_ip = req
            .remote_addr
            .map(|a| a.to_string())
            .unwrap_or_default();
        let method = format!("{:?}", req.method).to_uppercase();
        let safe_path = sanitize_for_json(&req.path);

        let line = format!(
            "{{\"ts\":{ts:.3},\"level\":\"ACCESS\",\"trace_id\":\"{trace_id}\",\"method\":\"{method}\",\"path\":\"{safe_path}\",\"status\":{status},\"latency_ms\":{latency_ms:.3},\"remote_ip\":\"{remote_ip}\",\"worker\":{worker},\"bytes\":{bytes}}}",
            status = resp.status,
            worker = self.worker_id,
            bytes = resp.body().len(),
        );
        self.sink.write_line(&line);

        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;
    use std::sync::Arc;

    fn make_request(path: &str, remote_ip: Option<&str>) -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            remote_addr: remote_ip.map(|s| s.parse().unwrap()),
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
    fn logs_one_line_per_request() {
        let sink = Arc::new(BufferSink::new());
        let mw = LoggerMiddleware::new(SharedSink(Arc::clone(&sink)), 0);
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        chain.execute(&make_request("/hello", Some("127.0.0.1")));
        assert_eq!(sink.lines().len(), 1);
    }

    #[test]
    fn log_line_contains_expected_fields() {
        let sink = Arc::new(BufferSink::new());
        let mw = LoggerMiddleware::new(SharedSink(Arc::clone(&sink)), 3);
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| {
                let mut resp = HttpResponse::new(404, "Not Found");
                resp.set_body(b"missing".to_vec());
                resp
            });

        chain.execute(&make_request("/missing", Some("192.168.1.1")));
        let lines = sink.lines();
        let line = &lines[0];

        assert!(line.contains("\"status\":404"));
        assert!(line.contains("\"path\":\"/missing\""));
        assert!(line.contains("\"remote_ip\":\"192.168.1.1\""));
        assert!(line.contains("\"worker\":3"));
        assert!(line.contains("\"bytes\":7")); // "missing".len()
        assert!(line.contains("\"method\":\"GET\""));
        assert!(line.contains("\"trace_id\":\""));
        assert!(line.contains("\"latency_ms\":"));
    }

    #[test]
    fn path_with_quotes_and_control_chars_is_sanitized() {
        let sink = Arc::new(BufferSink::new());
        let mw = LoggerMiddleware::new(SharedSink(Arc::clone(&sink)), 0);
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        chain.execute(&make_request("/a\"b\\c\nd", None));
        let lines = sink.lines();
        // The sanitized path shouldn't contain a literal quote,
        // backslash, or newline that could break JSON framing or
        // allow log-line injection.
        let path_start = lines[0].find("\"path\":\"").unwrap() + 8;
        let path_end = lines[0][path_start..].find("\",\"status\"").unwrap() + path_start;
        let logged_path = &lines[0][path_start..path_end];
        assert!(!logged_path.contains('\n'));
        assert_eq!(logged_path.matches('"').count(), 0);
    }

    #[test]
    fn trace_ids_are_unique_across_requests() {
        let sink = Arc::new(BufferSink::new());
        let mw = LoggerMiddleware::new(SharedSink(Arc::clone(&sink)), 0);
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(|_req| HttpResponse::new(200, "OK"));

        chain.execute(&make_request("/a", None));
        chain.execute(&make_request("/b", None));

        let lines = sink.lines();
        let extract_trace_id = |line: &str| -> String {
            let start = line.find("\"trace_id\":\"").unwrap() + 12;
            let end = line[start..].find('"').unwrap() + start;
            line[start..end].to_string()
        };
        assert_ne!(extract_trace_id(&lines[0]), extract_trace_id(&lines[1]));
    }

    /// Wraps an `Arc<BufferSink>` so it can be handed to
    /// `LoggerMiddleware::new` (which takes ownership of a sink) while
    /// the test keeps its own handle to read back logged lines.
    struct SharedSink(Arc<BufferSink>);
    impl AccessLogSink for SharedSink {
        fn write_line(&self, line: &str) {
            self.0.write_line(line);
        }
    }
}
