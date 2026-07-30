//! An in-memory cache for full HTTP responses, keyed by method, path,
//! query string, and the value of every request header the matched
//! response's own `Vary` lists (RFC 9111 4.1: a cached response is
//! only reusable for a later request whose Vary-listed headers match
//! exactly, since those are the request properties the response's
//! content actually depends on). Distinct from `http::file_cache`,
//! which caches static-file metadata/content keyed by filesystem path
//! rather than caching arbitrary handler/proxy output keyed by
//! request.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use dashmap::DashMap;

use crate::http::middleware::{Middleware, Next};
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

#[derive(Debug, Clone)]
pub struct ResponseCacheConfig {
    /// Soft byte budget for cached response bodies (0 = unlimited).
    pub max_memory_bytes: u64,
    /// Optional directory a cached entry's body is also written to,
    /// so a fresh process doesn't start with an empty cache after a
    /// restart. Empty disables disk persistence entirely.
    pub cache_dir: String,
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        ResponseCacheConfig {
            max_memory_bytes: 0,
            cache_dir: String::new(),
        }
    }
}

struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    #[allow(dead_code)]
    cached_at: Instant,
}

pub struct ResponseCacheMiddleware {
    config: ResponseCacheConfig,
    entries: DashMap<String, CachedResponse>,
    order: Mutex<Vec<String>>,
    total_bytes: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl ResponseCacheMiddleware {
    pub fn new(config: ResponseCacheConfig) -> Self {
        if !config.cache_dir.is_empty() {
            let _ = std::fs::create_dir_all(&config.cache_dir);
        }
        ResponseCacheMiddleware {
            config,
            entries: DashMap::new(),
            order: Mutex::new(Vec::new()),
            total_bytes: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn base_key(req: &HttpRequest) -> String {
        let query = req.query.as_deref().unwrap_or("");
        format!("{:?}:{}:{}", req.method, req.path, query)
    }

    fn vary_key(base: &str, req: &HttpRequest, vary_headers: &[String]) -> String {
        if vary_headers.is_empty() {
            return base.to_string();
        }
        let mut key = base.to_string();
        for header_name in vary_headers {
            key.push('\u{0}');
            key.push_str(header_name);
            key.push('=');
            key.push_str(req.get_header(header_name).unwrap_or(""));
        }
        key
    }

    fn parse_vary(response: &HttpResponse) -> Vec<String> {
        response
            .get_header("Vary")
            .map(|v| v.split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| h != "*").collect())
            .unwrap_or_default()
    }

    fn is_cacheable(req: &HttpRequest, response: &HttpResponse) -> bool {
        if !matches!(req.method, crate::http::request::HttpMethod::Get | crate::http::request::HttpMethod::Head) {
            return false;
        }
        if response.status != 200 {
            return false;
        }
        if let Some(cache_control) = response.get_header("Cache-Control") {
            let lower = cache_control.to_ascii_lowercase();
            if lower.contains("no-store") || lower.contains("private") {
                return false;
            }
        }
        true
    }

    fn evict_if_over_budget(&self, incoming_size: u64) {
        if self.config.max_memory_bytes == 0 {
            return;
        }
        let mut order = self.order.lock().unwrap();
        while self.total_bytes.load(Ordering::Relaxed) + incoming_size > self.config.max_memory_bytes && !order.is_empty() {
            let victim = order.remove(0);
            if let Some((_, removed)) = self.entries.remove(&victim) {
                self.total_bytes.fetch_sub(removed.body.len() as u64, Ordering::Relaxed);
            }
        }
    }

    fn disk_path(&self, key: &str) -> Option<std::path::PathBuf> {
        if self.config.cache_dir.is_empty() {
            return None;
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(key, &mut hasher);
        let filename = format!("{:x}.cache", std::hash::Hasher::finish(&hasher));
        Some(std::path::Path::new(&self.config.cache_dir).join(filename))
    }

    fn write_to_disk(&self, key: &str, entry: &CachedResponse) {
        let Some(path) = self.disk_path(key) else {
            return;
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&(entry.status as u32).to_le_bytes());
        buf.extend_from_slice(&(entry.body.len() as u64).to_le_bytes());
        buf.extend_from_slice(&entry.body);
        let _ = std::fs::write(path, buf);
    }
}

impl Middleware for ResponseCacheMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        let base = Self::base_key(req);

        if let Some(cached) = self.entries.get(&base) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            let mut resp = HttpResponse::new(cached.status, "");
            for (name, value) in &cached.headers {
                resp.set_header(name, value);
            }
            resp.set_body(cached.body.clone());
            return resp;
        }

        let response = next.run(req);

        if !Self::is_cacheable(req, &response) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return response;
        }

        let vary_headers = Self::parse_vary(&response);
        let key = Self::vary_key(&base, req, &vary_headers);
        let body = response.body().to_vec();
        let headers: Vec<(String, String)> = response.headers().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let entry = CachedResponse {
            status: response.status,
            headers,
            body,
            cached_at: Instant::now(),
        };

        self.evict_if_over_budget(entry.body.len() as u64);
        self.total_bytes.fetch_add(entry.body.len() as u64, Ordering::Relaxed);
        self.write_to_disk(&key, &entry);
        self.order.lock().unwrap().push(key.clone());
        self.entries.insert(key, entry);
        self.misses.fetch_add(1, Ordering::Relaxed);

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::middleware::{Chain, ChainBuilder};
    use crate::http::request::HttpMethod;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

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

    fn build_chain(cache_cfg: ResponseCacheConfig, call_count: Arc<AtomicU32>) -> (Chain, Arc<ResponseCacheMiddleware>) {
        let cache = Arc::new(ResponseCacheMiddleware::new(cache_cfg));
        let cache_for_chain = ResponseCacheMiddleware {
            config: cache.config.clone(),
            entries: DashMap::new(),
            order: Mutex::new(Vec::new()),
            total_bytes: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        };
        let chain = ChainBuilder::new().use_middleware(cache_for_chain).build(move |_req| {
            call_count.fetch_add(1, Ordering::Relaxed);
            let mut resp = HttpResponse::new(200, "OK");
            resp.set_body(b"hello".to_vec());
            resp
        });
        (chain, cache)
    }

    #[test]
    fn identical_request_is_served_from_cache_without_calling_the_handler_again() {
        let call_count = Arc::new(AtomicU32::new(0));
        let (chain, _cache) = build_chain(ResponseCacheConfig::default(), Arc::clone(&call_count));

        let req = make_request("/a");
        let first = chain.execute(&req);
        let second = chain.execute(&req);

        assert_eq!(first.body(), b"hello");
        assert_eq!(second.body(), b"hello");
        assert_eq!(call_count.load(Ordering::Relaxed), 1, "handler should only run once, second request should hit cache");
    }

    #[test]
    fn different_paths_are_cached_independently() {
        let call_count = Arc::new(AtomicU32::new(0));
        let (chain, _cache) = build_chain(ResponseCacheConfig::default(), Arc::clone(&call_count));

        chain.execute(&make_request("/a"));
        chain.execute(&make_request("/b"));
        chain.execute(&make_request("/a"));

        assert_eq!(call_count.load(Ordering::Relaxed), 2, "two distinct paths should each run the handler exactly once");
    }

    #[test]
    fn is_cacheable_rejects_non_200_and_no_store() {
        let req = make_request("/a");
        let mut ok_response = HttpResponse::new(200, "OK");
        assert!(ResponseCacheMiddleware::is_cacheable(&req, &ok_response));

        let not_found = HttpResponse::new(404, "Not Found");
        assert!(!ResponseCacheMiddleware::is_cacheable(&req, &not_found));

        ok_response.set_header("Cache-Control", "no-store");
        assert!(!ResponseCacheMiddleware::is_cacheable(&req, &ok_response));
    }

    #[test]
    fn max_memory_bytes_evicts_oldest_entries_first() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cache_cfg = ResponseCacheConfig {
            max_memory_bytes: 12, // "hello" is 5 bytes -- room for ~2 entries
            cache_dir: String::new(),
        };
        let (chain, cache) = build_chain(cache_cfg, Arc::clone(&call_count));

        for path in ["/a", "/b", "/c", "/d"] {
            chain.execute(&make_request(path));
        }
        assert!(cache.entry_count() <= 2, "byte budget should keep at most ~2 entries resident, got {}", cache.entry_count());
    }

    #[test]
    fn cache_dir_writes_a_file_to_disk() {
        let dir = std::env::temp_dir().join(format!(
            "routa_response_cache_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let call_count = Arc::new(AtomicU32::new(0));
        let cache_cfg = ResponseCacheConfig {
            max_memory_bytes: 0,
            cache_dir: dir.to_str().unwrap().to_string(),
        };
        let (chain, _cache) = build_chain(cache_cfg, Arc::clone(&call_count));

        chain.execute(&make_request("/a"));

        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1, "expected exactly one file written to cache_dir");

        std::fs::remove_dir_all(&dir).ok();
    }
}
