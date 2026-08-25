//! Static file serving: resolves a request path against a configured
//! document root (with path-traversal protection), consults
//! `http::file_cache` for metadata/content, and builds the appropriate
//! response -- including conditional requests (`If-None-Match` -> 304)
//! and byte-range requests (RFC 9110 14 -> 206/416).
//!
//! Only `GET`/`HEAD` are served; every other method gets 405. Actually
//! writing the response body to a socket (mmap'd content today, a
//! zero-copy sendfile path for large files as a later optimization)
//! is the caller's job, not this module's: `serve` returns an
//! `HttpResponse` the same way any other route handler does, keeping
//! this consistent with `http::router`'s handler shape rather than
//! doing its own I/O.

use std::path::{Path, PathBuf};

use crate::http::file_cache::{FileCache, Lookup, WorkerMmapCache};
use crate::http::request::{HttpMethod, HttpRequest};
use crate::http::response::HttpResponse;

#[derive(Debug, Clone)]
pub struct StaticConfig {
    pub doc_root: PathBuf,
    pub url_prefix: String,
    pub enable_index: bool,
}

/// Carries what's needed to finish serving a static file after an
/// asynchronous OPENAT+STATX round-trip -- set on
/// `HttpResponse::file_cache_pending` by `serve`'s own cache-miss path
/// instead of calling `std::fs::metadata` synchronously (see that
/// field's own doc comment). A backend that drives this
/// asynchronously (currently only `uring_backend`) opens/stats
/// `resolved_path`, then calls `finish_after_stat` with the result to
/// produce the real response -- mirrors `core::proxy::ProxyPending`'s
/// own "here's what you need, come back to me once the I/O
/// completes" shape.
#[derive(Debug)]
pub struct FileCachePending {
    pub resolved_path: PathBuf,
    /// The original request path -- this is the cache key `FileCache`
    /// indexes by, which may differ from `resolved_path` (the actual
    /// filesystem location `resolve_path` resolved it to).
    pub request_path: String,
}

/// Resolves `request_path` against `cfg`, returning the real
/// filesystem path to serve: strips the configured URL prefix, joins
/// onto `doc_root`, canonicalizes, and rejects anything that
/// canonicalizes outside `doc_root` (a symlink pointing outside the
/// doc root, or a `..` sequence that survived request parsing's own
/// traversal rejection some other way, are both caught here as a
/// second, filesystem-level line of defense).
fn resolve_path(request_path: &str, cfg: &StaticConfig) -> Result<PathBuf, u16> {
    let prefix = cfg.url_prefix.as_str();

    let rel_path = if prefix == "/" {
        request_path.trim_start_matches('/')
    } else if let Some(rest) = request_path.strip_prefix(prefix) {
        if rest.is_empty() || rest.starts_with('/') {
            rest.trim_start_matches('/')
        } else {
            return Err(404); // prefix matched a longer segment, not a real boundary
        }
    } else {
        return Err(404);
    };

    let full_path = cfg.doc_root.join(rel_path);

    let resolved = std::fs::canonicalize(&full_path).map_err(|_| 404u16)?;
    let canonical_root = std::fs::canonicalize(&cfg.doc_root).map_err(|_| 404u16)?;
    if !resolved.starts_with(&canonical_root) {
        return Err(403);
    }

    let metadata = std::fs::metadata(&resolved).map_err(|_| 404u16)?;
    if metadata.is_dir() {
        if !cfg.enable_index {
            return Err(403);
        }
        let index = resolved.join("index.html");
        let index_meta = std::fs::metadata(&index).map_err(|_| 403u16)?;
        if !index_meta.is_file() {
            return Err(403);
        }
        return Ok(index);
    }

    if !metadata.is_file() {
        return Err(404);
    }
    Ok(resolved)
}

/// A parsed `Range: bytes=...` request, resolved against the actual
/// file size.
struct ByteRange {
    start: u64,
    len: u64,
}

enum RangeOutcome {
    /// No `Range` header was present, or it wasn't a `bytes=` range
    /// this module understands -- RFC 9110 14.2 allows a server to
    /// just ignore a Range header it doesn't understand and return the
    /// full 200 response instead of erroring.
    NoRange,
    Satisfiable(ByteRange),
    Unsatisfiable,
}

fn parse_range(range_header: Option<&str>, file_size: u64) -> RangeOutcome {
    let Some(range_header) = range_header else {
        return RangeOutcome::NoRange;
    };
    let Some(spec) = range_header.strip_prefix("bytes=") else {
        return RangeOutcome::NoRange;
    };
    let Some((first_str, last_str)) = spec.split_once('-') else {
        return RangeOutcome::NoRange;
    };

    let first: Option<i64> = if first_str.is_empty() {
        None
    } else {
        first_str.parse().ok()
    };
    let last: Option<i64> = if last_str.is_empty() {
        None
    } else {
        last_str.parse().ok()
    };

    let (start, end_inclusive) = match (first, last) {
        // "bytes=-N" -- last N bytes of the file.
        (None, Some(suffix_len)) if suffix_len > 0 => {
            let suffix_len = suffix_len as u64;
            let start = file_size.saturating_sub(suffix_len);
            (start, file_size.saturating_sub(1))
        }
        // "bytes=N-" -- from N to end of file.
        (Some(first), None) if first >= 0 => (first as u64, file_size.saturating_sub(1)),
        // "bytes=N-M" -- explicit range.
        (Some(first), Some(last)) if first >= 0 => {
            let end = if last < 0 || (last as u64) >= file_size {
                file_size.saturating_sub(1)
            } else {
                last as u64
            };
            (first as u64, end)
        }
        _ => return RangeOutcome::NoRange,
    };

    if start > end_inclusive || start >= file_size {
        return RangeOutcome::Unsatisfiable;
    }

    RangeOutcome::Satisfiable(ByteRange {
        start,
        len: end_inclusive - start + 1,
    })
}

/// Serves `req` as a static file lookup against `cfg`, using `cache`
/// for metadata/content caching and `worker_mmap` for this worker's
/// own mapping cache in `SharedMetadata` mode (ignored in `Local`
/// mode).
pub fn serve(
    req: &HttpRequest,
    cfg: &StaticConfig,
    cache: &FileCache,
    worker_mmap: &mut WorkerMmapCache,
    metrics: Option<&crate::util::metrics::Metrics>,
    watcher: Option<&crate::http::file_cache::FileWatcher>,
) -> HttpResponse {
    if req.method != HttpMethod::Get && req.method != HttpMethod::Head {
        return HttpResponse::new(405, "Method Not Allowed");
    }

    let cache_lookup_result = cache.get(&req.path, worker_mmap);
    if let Some(metrics) = metrics {
        let result_label = match &cache_lookup_result {
            Some(l) if l.negative => "negative_hit",
            Some(_) => "hit",
            None => "miss",
        };
        metrics.cache.requests_total.with_label_values(&[result_label]).inc();
    }
    let lookup = match cache_lookup_result {
        Some(lookup) if !lookup.negative => lookup,
        Some(_) => return not_found_response(),
        None => match resolve_path(&req.path, cfg) {
            Ok(resolved) => {
                // Cache-miss: rather than calling std::fs::metadata
                // synchronously here (blocking whichever worker thread
                // is driving this request until the stat(2) syscall
                // returns), hand back a sentinel response carrying
                // what's needed to finish once a backend has stat'd
                // resolved_path asynchronously -- see
                // FileCachePending's own doc comment. mio_backend
                // never looks at file_cache_pending, so for it this
                // sentinel is dead weight on the HttpResponse it
                // returns -- see finish_after_stat's own doc comment
                // for the synchronous equivalent every backend can
                // still fall back to.
                let mut resp = HttpResponse::new(200, "OK");
                resp.file_cache_pending = Some(FileCachePending {
                    resolved_path: resolved,
                    request_path: req.path.clone(),
                });
                return resp;
            }
            Err(404) => {
                cache.put_negative(&req.path, PathBuf::from(&req.path));
                return not_found_response();
            }
            Err(403) => return forbidden_response(),
            Err(_) => return HttpResponse::new(500, "Internal Server Error"),
        },
    };

    build_response(req, lookup)
}

/// Calls `serve`, then synchronously resolves a `file_cache_pending`
/// sentinel if one comes back (via a direct `std::fs::metadata` call)
/// rather than returning it to the caller -- the full synchronous
/// behavior `serve` itself used to have inline before
/// `FileCachePending` existed. This is what `mio_backend` calls
/// instead of `serve` directly (mio's own model already tolerates
/// blocking I/O on its worker threads, so there's no reason for it to
/// drive the async two-step at all), and what this module's own tests
/// use so they can keep asserting against a real, complete response
/// rather than needing to drive the async handshake themselves.
pub fn serve_sync(
    req: &HttpRequest,
    cfg: &StaticConfig,
    cache: &FileCache,
    worker_mmap: &mut WorkerMmapCache,
    metrics: Option<&crate::util::metrics::Metrics>,
    watcher: Option<&crate::http::file_cache::FileWatcher>,
) -> HttpResponse {
    let resp = serve(req, cfg, cache, worker_mmap, metrics, watcher);
    let Some(pending) = &resp.file_cache_pending else {
        return resp;
    };
    let stat_result = std::fs::metadata(&pending.resolved_path)
        .ok()
        .map(|m| (m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH)));
    finish_after_stat(req, pending, stat_result, cache, worker_mmap, watcher)
}

/// The synchronous equivalent of what a backend driving
/// FileCachePending asynchronously does after its own OPENAT+STATX
/// completes -- called directly (with a real, already-obtained size
/// and mtime) by mio_backend's own dispatch path, which never looks
/// at file_cache_pending and instead calls std::fs::metadata
/// synchronously itself, exactly as `serve` used to inline before
/// FileCachePending existed. uring_backend calls this too, from its
/// own OPENAT+STATX completion handler.
///
/// Takes `(size, mtime)` rather than a `std::fs::Metadata` -- the
/// latter has no public constructor, so there's no way to build one
/// from a raw kernel `statx` result the way uring_backend's own async
/// path needs to; `(u64, SystemTime)` is the only subset of Metadata
/// this module actually needs, and both a real Metadata (mio's
/// synchronous path) and a raw statx result (uring's async path) can
/// supply it identically.
pub fn finish_after_stat(
    req: &HttpRequest,
    pending: &FileCachePending,
    stat_result: Option<(u64, std::time::SystemTime)>,
    cache: &FileCache,
    worker_mmap: &mut WorkerMmapCache,
    watcher: Option<&crate::http::file_cache::FileWatcher>,
) -> HttpResponse {
    let Some((size, mtime)) = stat_result else {
        cache.put_negative(&pending.request_path, pending.resolved_path.clone());
        return not_found_response();
    };
    cache.put(&pending.request_path, pending.resolved_path.clone(), size, mtime);
    if let Some(watcher) = watcher {
        watcher.watch_path(&pending.resolved_path, &pending.request_path);
    }
    match cache.get(&pending.request_path, worker_mmap) {
        Some(lookup) => build_response(req, lookup),
        None => HttpResponse::new(500, "Internal Server Error"),
    }
}

fn not_found_response() -> HttpResponse {
    let mut resp = HttpResponse::new(404, "Not Found");
    resp.set_body(b"Not Found\n".to_vec());
    resp
}

fn forbidden_response() -> HttpResponse {
    let mut resp = HttpResponse::new(403, "Forbidden");
    resp.set_body(b"Forbidden\n".to_vec());
    resp
}

fn build_response(req: &HttpRequest, lookup: Lookup) -> HttpResponse {
    // Conditional request: ETag / If-None-Match.
    if let Some(inm) = req.get_header("If-None-Match") {
        if inm == lookup.etag {
            let mut resp = HttpResponse::new(304, "Not Modified");
            resp.set_header("ETag", lookup.etag.clone());
            resp.set_header("Last-Modified", lookup.last_modified.clone());
            return resp;
        }
    }

    let range_outcome = parse_range(req.get_header("Range"), lookup.size);
    let (status, reason, range) = match range_outcome {
        RangeOutcome::NoRange => (200u16, "OK", None),
        RangeOutcome::Satisfiable(r) => (206, "Partial Content", Some(r)),
        RangeOutcome::Unsatisfiable => {
            let mut resp = HttpResponse::new(416, "Range Not Satisfiable");
            resp.set_header("Content-Range", format!("bytes */{}", lookup.size));
            return resp;
        }
    };

    let mut resp = HttpResponse::new(status, reason);
    resp.set_header("Content-Type", lookup.mime_type.clone());
    resp.set_header("Last-Modified", lookup.last_modified.clone());
    resp.set_header("ETag", lookup.etag.clone());
    resp.set_header("Accept-Ranges", "bytes");

    let (range_start, range_len) = match &range {
        Some(r) => (r.start, r.len),
        None => (0, lookup.size),
    };

    if let Some(r) = &range {
        resp.set_header(
            "Content-Range",
            format!("bytes {}-{}/{}", r.start, r.start + r.len - 1, lookup.size),
        );
    }

    if req.method == HttpMethod::Head {
        resp.set_header("Content-Length", range_len.to_string());
        return resp;
    }

    match &lookup.mapped {
        Some(mapped) => {
            let start = range_start as usize;
            let end = (range_start + range_len) as usize;
            let slice = mapped.get(start..end).unwrap_or(&[]);
            resp.set_body(slice.to_vec());
        }
        None => {
            // Large file, not mmap'd -- hand the event loop a file
            // descriptor + range to send directly via sendfile(2)
            // rather than reading the whole range into memory here.
            // See HttpResponse::set_body_file and core::event_loop's
            // flush logic for where this is actually acted on (with a
            // read+write fallback on TLS transports, which can't use
            // sendfile at all).
            match std::fs::File::open(&lookup.resolved_path) {
                Ok(file) => resp.set_body_file(file, range_start, range_len),
                Err(_) => return HttpResponse::new(500, "Internal Server Error"),
            }
        }
    }

    resp
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::file_cache::{CacheMode, FileCacheConfig};
    use std::io::Write;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "routa_static_files_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, rel: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    fn make_request(method: HttpMethod, path: &str, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method,
            remote_addr: None,
            path: path.to_string(),
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

    fn test_cache() -> FileCache {
        FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            ..Default::default()
        })
    }

    #[test]
    fn serves_existing_file() {
        let dir = temp_dir();
        write_file(&dir, "hello.txt", b"hello world");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/hello.txt", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body(), b"hello world");
        assert_eq!(resp.get_header("Content-Type"), Some("text/plain"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_404() {
        let dir = temp_dir();
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/nope.txt", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 404);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_method_is_405() {
        let dir = temp_dir();
        write_file(&dir, "a.txt", b"x");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Post, "/a.txt", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 405);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn head_request_has_no_body_but_has_content_length() {
        let dir = temp_dir();
        write_file(&dir, "a.txt", b"twelve bytes");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Head, "/a.txt", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 200);
        assert!(resp.body().is_empty());
        assert_eq!(resp.get_header("Content-Length"), Some("12"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn if_none_match_returns_304() {
        let dir = temp_dir();
        write_file(&dir, "a.txt", b"content");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let first_req = make_request(HttpMethod::Get, "/a.txt", &[]);
        let first_resp = serve_sync(&first_req, &cfg, &cache, &mut mmap_cache, None, None);
        let etag = first_resp.get_header("ETag").unwrap().to_string();

        let second_req = make_request(HttpMethod::Get, "/a.txt", &[("If-None-Match", &etag)]);
        let second_resp = serve_sync(&second_req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(second_resp.status, 304);
        assert!(second_resp.body().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn range_request_returns_partial_content() {
        let dir = temp_dir();
        write_file(&dir, "a.txt", b"0123456789");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/a.txt", &[("Range", "bytes=2-4")]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 206);
        assert_eq!(resp.body(), b"234");
        assert_eq!(resp.get_header("Content-Range"), Some("bytes 2-4/10"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn range_suffix_returns_last_n_bytes() {
        let dir = temp_dir();
        write_file(&dir, "a.txt", b"0123456789");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/a.txt", &[("Range", "bytes=-3")]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 206);
        assert_eq!(resp.body(), b"789");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn range_open_ended_returns_rest_of_file() {
        let dir = temp_dir();
        write_file(&dir, "a.txt", b"0123456789");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/a.txt", &[("Range", "bytes=7-")]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 206);
        assert_eq!(resp.body(), b"789");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unsatisfiable_range_returns_416() {
        let dir = temp_dir();
        write_file(&dir, "a.txt", b"0123456789");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/a.txt", &[("Range", "bytes=100-200")]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 416);
        assert_eq!(resp.get_header("Content-Range"), Some("bytes */10"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn url_prefix_stripped_correctly() {
        let dir = temp_dir();
        write_file(&dir, "app.js", b"console.log(1)");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/assets".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/assets/app.js", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body(), b"console.log(1)");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prefix_mismatch_on_longer_segment_is_404() {
        let dir = temp_dir();
        write_file(&dir, "app.js", b"x");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/assets".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        // "/assets-other/app.js" should NOT match prefix "/assets"
        // (must be a real path-segment boundary, not just a string
        // prefix).
        let req = make_request(HttpMethod::Get, "/assets-other/app.js", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 404);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn directory_without_index_is_403() {
        let dir = temp_dir();
        std::fs::create_dir_all(dir.join("subdir")).unwrap();
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/subdir", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 403);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn directory_with_index_enabled_serves_index_html() {
        let dir = temp_dir();
        write_file(&dir, "subdir/index.html", b"<h1>index</h1>");
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: true,
        };
        let cache = test_cache();
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/subdir", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body(), b"<h1>index</h1>");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn negative_cache_hit_returns_404_without_restat() {
        let dir = temp_dir();
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            negative_ttl: Some(std::time::Duration::from_secs(30)),
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/nope.txt", &[]);
        let first = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(first.status, 404);

        let second = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(second.status, 404);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn large_file_served_via_read_range_path() {
        // A file at or above the mmap threshold takes the read_range
        // fallback path instead of the mmap path -- exercise it
        // directly with a tiny configured threshold.
        let dir = temp_dir();
        let content = vec![b'x'; 100];
        write_file(&dir, "big.txt", &content);
        let cfg = StaticConfig {
            doc_root: dir.clone(),
            url_prefix: "/".to_string(),
            enable_index: false,
        };
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            mmap_threshold: 10, // force big.txt (100 bytes) past the threshold
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        let req = make_request(HttpMethod::Get, "/big.txt", &[]);
        let resp = serve_sync(&req, &cfg, &cache, &mut mmap_cache, None, None);
        assert_eq!(resp.status, 200);
        // Large, non-mmap'd files are now sent via a FileBody
        // (sendfile-eligible) rather than being read into resp.body()
        // -- verify the file descriptor/range actually covers the
        // expected content instead of checking an in-memory buffer
        // that's deliberately left empty for this path.
        let file_body = resp.file_body.as_ref().expect("large file should use set_body_file, not set_body");
        assert_eq!(file_body.offset, 0);
        assert_eq!(file_body.len, content.len() as u64);
        assert_eq!(resp.get_header("Content-Length"), Some(content.len().to_string()).as_deref());

        use std::io::{Read, Seek, SeekFrom};
        let mut file = &file_body.file;
        file.seek(SeekFrom::Start(file_body.offset)).unwrap();
        let mut actual = vec![0u8; file_body.len as usize];
        file.read_exact(&mut actual).unwrap();
        assert_eq!(actual, content);

        std::fs::remove_dir_all(&dir).ok();
    }
}
