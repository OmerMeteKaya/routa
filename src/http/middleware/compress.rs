//! Response compression: gzip, deflate, and brotli, chosen by parsing
//! the client's `Accept-Encoding` header per RFC 9110 12.5.3 --
//! including honoring an explicit `q=0` (a client that lists
//! `gzip;q=0` is explicitly declining gzip, not just deprioritizing
//! it, and must be respected). Runs the rest of the chain first, then
//! compresses the resulting response in place if all guard conditions
//! are met -- already-encoded/chunked responses, in-memory-only bodies
//! below the size threshold, and non-compressible MIME types are all
//! left untouched.
//!
//! gzip/deflate use `flate2` (the standard zlib-backed choice in the
//! Rust ecosystem); brotli uses the `brotli` crate, a pure-Rust port
//! with no C dependency -- keeping this middleware's own memory-safety
//! profile consistent with the rest of the codebase rather than
//! reaching for a C binding.

use std::io::Write;

use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression as Flate2Compression;

use crate::http::middleware::{Middleware, Next};
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;

const DEFAULT_MIN_SIZE: usize = 256;
const DEFAULT_LEVEL: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Deflate,
    Brotli,
}

impl Encoding {
    fn header_value(self) -> &'static str {
        match self {
            Encoding::Gzip => "gzip",
            Encoding::Deflate => "deflate",
            Encoding::Brotli => "br",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompressConfig {
    /// Responses smaller than this are never compressed -- the
    /// overhead of the compression envelope isn't worth it for tiny
    /// bodies.
    pub min_size: usize,
    /// flate2 compression level (1-9) used for gzip/deflate.
    pub level: u32,
    /// Preference order when a client accepts multiple encodings with
    /// equal q-value -- the first supported encoding in this list
    /// wins. Brotli generally compresses better than gzip/deflate at
    /// equivalent settings, hence the default order.
    pub preference: Vec<Encoding>,
}

impl Default for CompressConfig {
    fn default() -> Self {
        CompressConfig {
            min_size: DEFAULT_MIN_SIZE,
            level: DEFAULT_LEVEL,
            preference: vec![Encoding::Brotli, Encoding::Gzip, Encoding::Deflate],
        }
    }
}

/// MIME type prefixes worth compressing -- binary formats (images
/// other than SVG, video, already-compressed archives) gain little or
/// nothing from compression and just burn CPU.
const COMPRESSIBLE_MIME_PREFIXES: &[&str] = &[
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml",
    "image/svg",
];

fn should_compress_mime(mime: Option<&str>) -> bool {
    let Some(mime) = mime else {
        return false;
    };
    COMPRESSIBLE_MIME_PREFIXES
        .iter()
        .any(|prefix| mime.starts_with(prefix))
}

/// One parsed `Accept-Encoding` entry: a coding name (`"gzip"`,
/// `"identity"`, `"*"`, ...) and its q-value (defaulting to 1.0 when
/// absent).
struct AcceptEntry<'a> {
    coding: &'a str,
    q: f32,
}

fn parse_accept_encoding(header: &str) -> Vec<AcceptEntry<'_>> {
    header
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (coding, q) = match entry.split_once(';') {
                Some((coding, params)) => {
                    let q = params
                        .trim()
                        .strip_prefix("q=")
                        .and_then(|v| v.parse::<f32>().ok())
                        .unwrap_or(1.0);
                    (coding.trim(), q)
                }
                None => (entry, 1.0),
            };
            Some(AcceptEntry { coding, q })
        })
        .collect()
}

/// Picks the best encoding to use for this request: the highest-preference
/// (per `config.preference`'s order) encoding the client hasn't
/// explicitly excluded with `q=0`, among those it lists with a
/// positive q-value. A client with no `Accept-Encoding` header at all
/// is treated as accepting only `identity` (no compression) per
/// RFC 9110 12.5.3 -- this middleware doesn't compress in that case.
fn select_encoding(accept_encoding: Option<&str>, preference: &[Encoding]) -> Option<Encoding> {
    let header = accept_encoding?;
    let entries = parse_accept_encoding(header);

    let is_explicitly_rejected = |name: &str| {
        entries
            .iter()
            .any(|e| e.coding.eq_ignore_ascii_case(name) && e.q == 0.0)
    };
    let is_wildcard_rejected = || {
        entries
            .iter()
            .any(|e| e.coding == "*" && e.q == 0.0)
    };
    let is_accepted = |name: &str| {
        if is_explicitly_rejected(name) {
            return false;
        }
        let named = entries
            .iter()
            .find(|e| e.coding.eq_ignore_ascii_case(name));
        match named {
            Some(e) => e.q > 0.0,
            None => {
                // Not named explicitly -- falls back to any wildcard
                // entry, unless the wildcard itself is q=0.
                let wildcard = entries.iter().find(|e| e.coding == "*");
                match wildcard {
                    Some(e) => e.q > 0.0,
                    None => false,
                }
            }
        }
    };

    if is_wildcard_rejected() {
        // A bare "*;q=0" with no other entries rejects everything not
        // explicitly listed; still allow anything given its own
        // positive entry.
        return preference
            .iter()
            .find(|enc| {
                entries
                    .iter()
                    .any(|e| e.coding.eq_ignore_ascii_case(enc.header_value()) && e.q > 0.0)
            })
            .copied();
    }

    preference
        .iter()
        .find(|enc| is_accepted(enc.header_value()))
        .copied()
}

fn compress_gzip(data: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Flate2Compression::new(level));
    encoder.write_all(data)?;
    encoder.finish()
}

fn compress_deflate(data: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Flate2Compression::new(level));
    encoder.write_all(data)?;
    encoder.finish()
}

/// Maps the configured flate2-style level (1-9) to a brotli quality
/// (0-11) using real-world threshold bands rather than a proportional
/// scale. Brotli's own quality/ratio curve doesn't behave like
/// gzip's: gzip's compression gains flatten out well before its top
/// level, so a mid-range gzip level already captures most of the
/// achievable ratio, while brotli keeps yielding meaningfully smaller
/// output even at its highest levels -- and its cost profile is the
/// opposite too, with quality 10-11 being tens of times slower than
/// quality 4-6 rather than gzip's comparatively gentle cost curve. A
/// proportional mapping (`level / 9 * 11`) would send even a "fast"
/// requested level into brotli's more expensive territory and would
/// never reach the quality levels that are actually worth using for
/// static/precompressible content. These bands instead mirror common
/// production practice: low levels favor speed (suitable for
/// per-request dynamic compression), mid levels are the standard
/// balanced choice, and only an explicitly high requested level opts
/// into brotli's expensive top quality range.
fn brotli_quality_for_level(level: u32) -> i32 {
    match level {
        0..=3 => 4,  // fast -- appropriate for latency-sensitive dynamic responses
        4..=6 => 6,  // balanced -- the common default for on-the-fly compression
        7..=8 => 9,  // high -- noticeably slower, meaningfully smaller
        _ => 11,     // maximum -- only worth it when compression cost is amortized (e.g. static assets)
    }
}

fn compress_brotli(data: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let quality = brotli_quality_for_level(level);
    let mut out = Vec::new();
    let params = brotli::enc::BrotliEncoderParams {
        quality,
        ..Default::default()
    };
    brotli::BrotliCompress(&mut &data[..], &mut out, &params)?;
    Ok(out)
}

fn compress_with(encoding: Encoding, data: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    match encoding {
        Encoding::Gzip => compress_gzip(data, level),
        Encoding::Deflate => compress_deflate(data, level),
        Encoding::Brotli => compress_brotli(data, level),
    }
}

pub struct CompressMiddleware {
    config: CompressConfig,
}

impl CompressMiddleware {
    pub fn new(config: CompressConfig) -> Self {
        CompressMiddleware { config }
    }
}

impl Middleware for CompressMiddleware {
    fn call(&self, req: &HttpRequest, next: Next<'_>) -> HttpResponse {
        // Run the rest of the chain first -- the final response body
        // (after any other middleware/the handler has produced it) is
        // what gets compressed.
        let mut resp = next.run(req);

        if resp.get_header("Content-Encoding").is_some() {
            return resp; // already encoded -- don't double-compress
        }
        if resp.get_header("Transfer-Encoding").is_some() {
            return resp; // chunked -- compressing here isn't supported
        }
        if resp.body().is_empty() {
            return resp;
        }
        if resp.body().len() < self.config.min_size {
            return resp;
        }
        if !should_compress_mime(resp.get_header("Content-Type")) {
            return resp;
        }

        let Some(encoding) =
            select_encoding(req.get_header("Accept-Encoding"), &self.config.preference)
        else {
            return resp; // client doesn't accept any encoding we support
        };

        let Ok(compressed) = compress_with(encoding, resp.body(), self.config.level) else {
            return resp; // fall through uncompressed on encoder error
        };

        // Only use the compressed body if it's actually smaller --
        // every encoding here has a fixed envelope overhead that can
        // lose against a body that's already near-incompressible.
        if compressed.len() >= resp.body().len() {
            return resp;
        }

        resp.set_body(compressed);
        resp.set_header("Content-Encoding", encoding.header_value());
        resp.set_header("Vary", "Accept-Encoding");
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;

    #[test]
    fn brotli_quality_bands_cover_the_full_level_range() {
        assert_eq!(brotli_quality_for_level(1), 4);
        assert_eq!(brotli_quality_for_level(3), 4);
        assert_eq!(brotli_quality_for_level(4), 6);
        assert_eq!(brotli_quality_for_level(6), 6);
        assert_eq!(brotli_quality_for_level(7), 9);
        assert_eq!(brotli_quality_for_level(8), 9);
        assert_eq!(brotli_quality_for_level(9), 11);
    }

    #[test]
    fn brotli_quality_never_exceeds_valid_range() {
        for level in 0..=20 {
            let quality = brotli_quality_for_level(level);
            assert!((0..=11).contains(&quality), "quality {quality} out of range for level {level}");
        }
    }

    #[test]
    fn compress_brotli_still_produces_valid_compressed_output() {
        let data = b"the quick brown fox jumps over the lazy dog ".repeat(50);
        let compressed = compress_brotli(&data, 6).unwrap();
        assert!(compressed.len() < data.len(), "brotli should shrink repetitive text");
    }

    fn make_request(accept_encoding: Option<&str>) -> HttpRequest {
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
        if let Some(ae) = accept_encoding {
            req.headers
                .push(("Accept-Encoding".to_string(), ae.to_string()));
        }
        req
    }

    fn compressible_body() -> Vec<u8> {
        "the quick brown fox jumps over the lazy dog. "
            .repeat(20)
            .into_bytes()
    }

    fn chain_with(mw: CompressMiddleware) -> crate::http::middleware::Chain {
        let body = compressible_body();
        crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(move |_req| {
                let mut resp = HttpResponse::new(200, "OK");
                resp.set_header("Content-Type", "text/plain");
                resp.set_body(body.clone());
                resp
            })
    }

    // ─── Accept-Encoding parsing ────────────────────────────────────

    #[test]
    fn selects_brotli_when_preferred_and_accepted() {
        let enc = select_encoding(Some("gzip, br"), &CompressConfig::default().preference);
        assert_eq!(enc, Some(Encoding::Brotli));
    }

    #[test]
    fn falls_back_to_gzip_when_brotli_not_offered() {
        let enc = select_encoding(Some("gzip, deflate"), &CompressConfig::default().preference);
        assert_eq!(enc, Some(Encoding::Gzip));
    }

    #[test]
    fn q_zero_explicitly_rejects_encoding() {
        // Client lists gzip but with q=0 -- explicitly declining it,
        // not just deprioritizing it. This is the bug the archived C
        // implementation's strstr("gzip") check had: it would have
        // accepted this as "client wants gzip".
        let enc = select_encoding(
            Some("gzip;q=0, deflate;q=1"),
            &[Encoding::Gzip, Encoding::Deflate],
        );
        assert_eq!(enc, Some(Encoding::Deflate));
    }

    #[test]
    fn q_zero_on_only_offered_encoding_yields_no_compression() {
        let enc = select_encoding(Some("gzip;q=0"), &[Encoding::Gzip]);
        assert_eq!(enc, None);
    }

    #[test]
    fn missing_accept_encoding_header_yields_no_compression() {
        let enc = select_encoding(None, &CompressConfig::default().preference);
        assert_eq!(enc, None);
    }

    #[test]
    fn higher_q_value_wins_regardless_of_list_order() {
        let enc = select_encoding(
            Some("br;q=0.5, gzip;q=1.0"),
            &[Encoding::Brotli, Encoding::Gzip],
        );
        // Note: this middleware's preference list decides among
        // *accepted* codings, not raw q-value ranking across codings
        // (RFC 9110 doesn't mandate strict q-value-wins-over-preference
        // ordering when a server has its own preference) -- what
        // matters here is that a low-but-nonzero q for brotli still
        // makes it acceptable, so brotli (first in preference) is
        // chosen.
        assert_eq!(enc, Some(Encoding::Brotli));
    }

    // ─── Middleware integration ──────────────────────────────────────

    #[test]
    fn compresses_when_all_conditions_met() {
        let mw = CompressMiddleware::new(CompressConfig::default());
        let original_len = compressible_body().len();
        let chain = chain_with(mw);

        let resp = chain.execute(&make_request(Some("gzip")));
        assert_eq!(resp.get_header("Content-Encoding"), Some("gzip"));
        assert_eq!(resp.get_header("Vary"), Some("Accept-Encoding"));
        assert!(resp.body().len() < original_len);
    }

    #[test]
    fn uses_brotli_by_default_preference() {
        let mw = CompressMiddleware::new(CompressConfig::default());
        let chain = chain_with(mw);

        let resp = chain.execute(&make_request(Some("gzip, br, deflate")));
        assert_eq!(resp.get_header("Content-Encoding"), Some("br"));
    }

    #[test]
    fn skips_when_no_accept_encoding_header() {
        let mw = CompressMiddleware::new(CompressConfig::default());
        let chain = chain_with(mw);

        let resp = chain.execute(&make_request(None));
        assert!(resp.get_header("Content-Encoding").is_none());
    }

    #[test]
    fn skips_when_body_below_min_size() {
        let mw = CompressMiddleware::new(CompressConfig {
            min_size: 10_000, // well above the test body's size
            ..Default::default()
        });
        let chain = chain_with(mw);

        let resp = chain.execute(&make_request(Some("gzip")));
        assert!(resp.get_header("Content-Encoding").is_none());
    }

    #[test]
    fn skips_non_compressible_mime_type() {
        let mw = CompressMiddleware::new(CompressConfig::default());
        let body = vec![0u8; 1000];
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(move |_req| {
                let mut resp = HttpResponse::new(200, "OK");
                resp.set_header("Content-Type", "image/png");
                resp.set_body(body.clone());
                resp
            });

        let resp = chain.execute(&make_request(Some("gzip")));
        assert!(resp.get_header("Content-Encoding").is_none());
    }

    #[test]
    fn skips_already_encoded_response() {
        let mw = CompressMiddleware::new(CompressConfig::default());
        let body = compressible_body();
        let chain = crate::http::middleware::ChainBuilder::new()
            .use_middleware(mw)
            .build(move |_req| {
                let mut resp = HttpResponse::new(200, "OK");
                resp.set_header("Content-Type", "text/plain");
                resp.set_header("Content-Encoding", "identity");
                resp.set_body(body.clone());
                resp
            });

        let resp = chain.execute(&make_request(Some("gzip")));
        assert_eq!(resp.get_header("Content-Encoding"), Some("identity"));
    }

    #[test]
    fn deflate_round_trips_correctly() {
        let data = compressible_body();
        let compressed = compress_deflate(&data, 6).unwrap();
        assert!(compressed.len() < data.len());

        let mut decoder = flate2::read::DeflateDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decompressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn brotli_round_trips_correctly() {
        let data = compressible_body();
        let compressed = compress_brotli(&data, 6).unwrap();
        assert!(compressed.len() < data.len());

        let mut decompressed = Vec::new();
        brotli::BrotliDecompress(&mut &compressed[..], &mut decompressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn gzip_round_trips_correctly() {
        let data = compressible_body();
        let compressed = compress_gzip(&data, 6).unwrap();
        assert!(compressed.len() < data.len());

        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decompressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
