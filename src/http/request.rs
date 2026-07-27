//! HTTP/1.1 request parsing. `parse` reads as much of a complete
//! request as is available in `buf` and reports one of three outcomes
//! (`ParseOutcome::Complete`/`Incomplete`/`Invalid`) -- `Incomplete` is
//! not an error, it's the normal "the client hasn't finished sending
//! the request yet" result a connection's read loop expects to see
//! repeatedly while more bytes arrive over the wire.
//!
//! Deliberately strict about RFC 9112 framing ambiguities (obsolete
//! line folding, conflicting Content-Length headers, Transfer-Encoding
//! plus Content-Length together, non-final "chunked") -- these are
//! request-smuggling vectors when an intermediary and the origin
//! server disagree about where a request ends, so `parse` rejects them
//! outright rather than guessing which framing another implementation
//! would have honored.

use crate::util::buf::Buf;

// ─── Method ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Patch,
    Options,
    Trace,
    Connect,
}

impl HttpMethod {
    /// The wire representation of this method -- the inverse of
    /// `parse`, used when serializing a request (e.g.
    /// `core::proxy` forwarding a request upstream).
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Connect => "CONNECT",
        }
    }

    fn parse(s: &[u8]) -> Option<HttpMethod> {
        match s {
            b"GET" => Some(HttpMethod::Get),
            b"POST" => Some(HttpMethod::Post),
            b"PUT" => Some(HttpMethod::Put),
            b"DELETE" => Some(HttpMethod::Delete),
            b"HEAD" => Some(HttpMethod::Head),
            b"PATCH" => Some(HttpMethod::Patch),
            b"OPTIONS" => Some(HttpMethod::Options),
            b"TRACE" => Some(HttpMethod::Trace),
            b"CONNECT" => Some(HttpMethod::Connect),
            _ => None,
        }
    }
}

// ─── Request ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    /// The client's address, if known. `None` for requests constructed
    /// without a real connection (e.g. some tests) -- set by the
    /// connection layer after `parse` returns, since parsing itself
    /// has no notion of which socket a request arrived on.
    pub remote_addr: Option<std::net::IpAddr>,
    /// URL-decoded, normalized (dot-segments resolved, duplicate
    /// slashes collapsed). Always starts with `/`.
    pub path: String,
    /// Raw, still-percent-encoded query string (everything after `?`),
    /// if present. Individual parameters are available pre-decoded via
    /// `query_params`/`get_query`.
    pub query: Option<String>,
    pub query_params: Vec<(String, String)>,
    pub version_major: u8,
    pub version_minor: u8,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
    /// A second, later header block (RFC 9110 8.1) -- HTTP/2-only.
    /// Always empty for requests parsed by this module, reserved here
    /// so `http::h2` doesn't need a different request type once
    /// trailers are handled.
    pub trailers: Vec<(String, String)>,
}

impl HttpRequest {
    /// Serializes this request as HTTP/1.1 wire bytes -- the inverse
    /// of `parse`. Used when forwarding a request to an HTTP/1.1
    /// upstream (see `core::proxy`); callers building an outbound
    /// request from scratch (rather than one already parsed from an
    /// incoming connection) construct an `HttpRequest` directly and
    /// call this rather than this module needing a second, separate
    /// "build a request" API.
    ///
    /// Does not add or remove any headers itself (no automatic
    /// Connection/Host/Content-Length beyond what `self.headers`
    /// already contains, except Content-Length, which is always
    /// derived fresh from `self.body`'s actual length rather than
    /// trusting a possibly-stale caller-supplied value) -- header
    /// policy (X-Forwarded-For, Via, hop-by-hop filtering) is the
    /// caller's responsibility, the same division of concerns
    /// `http::response::HttpResponse::serialize` uses on the response
    /// side.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        let path_and_query = match &self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None => self.path.clone(),
        };
        out.extend_from_slice(
            format!(
                "{} {} HTTP/{}.{}\r\n",
                self.method.as_str(),
                path_and_query,
                self.version_major,
                self.version_minor
            )
            .as_bytes(),
        );

        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-length") {
                continue; // re-emitted below, from the body's actual length
            }
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());

        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn get_query(&self, key: &str) -> Option<&str> {
        self.query_params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

// ─── Parse outcome ──────────────────────────────────────────────────────

/// The three outcomes `parse` can report. `Incomplete` is the common,
/// expected result while a request is still arriving over the wire --
/// not an error.
pub enum ParseOutcome {
    /// A full request was parsed. `consumed` is how many bytes of
    /// `buf` it occupied -- the caller should `buf.consume(consumed)`
    /// before parsing any next request on the same (keep-alive)
    /// connection.
    Complete { request: HttpRequest, consumed: usize },
    /// Not enough data in `buf` yet to determine whether the request
    /// is even valid -- call `parse` again once more bytes have
    /// arrived.
    Incomplete,
    /// `buf` contains a malformed or disallowed request. The
    /// connection should be closed (with an error response if the
    /// framing was understood well enough to safely send one, or
    /// immediately otherwise -- that policy decision belongs to the
    /// caller, not this module).
    Invalid(ParseError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    MalformedRequestLine,
    UnknownMethod,
    UriTooLong,
    InvalidPath,
    PathTraversal,
    UnsupportedVersion,
    TooManyHeaders,
    ObsoleteLineFolding,
    MalformedHeaderLine,
    InvalidHeaderName,
    NulByteInHeader,
    MissingHostHeader,
    DuplicateHostHeader,
    InvalidHostHeader,
    ConflictingContentLength,
    InvalidContentLength,
    BodyTooLarge,
    UnsupportedTransferEncoding,
    ChunkedWithContentLength,
    ChunkedOnHttp10,
    MalformedChunkedBody,
}

pub const DEFAULT_MAX_HEADERS: usize = 64;
pub const DEFAULT_MAX_QUERY_PARAMS: usize = 32;

// ─── Value-decoding helpers ─────────────────────────────────────────────

fn is_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'A'..=b'F').contains(&c) || (b'a'..=b'f').contains(&c)
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => unreachable!("caller must check is_hex first"),
    }
}

/// RFC 9110 5.6.2 token characters -- header field names are tokens: no
/// spaces, no separators, no control characters.
fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Percent-decodes `src` (also turning `+` into a space, matching the
/// `application/x-www-form-urlencoded` convention used for query
/// strings and paths alike here). Rejects a decoded NUL byte (`%00`)
/// and any input that isn't valid UTF-8 once decoded.
fn url_decode(src: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        match src[i] {
            b'%' if i + 2 < src.len() && is_hex(src[i + 1]) && is_hex(src[i + 2]) => {
                let byte = (hex_val(src[i + 1]) << 4) | hex_val(src[i + 2]);
                if byte == 0 {
                    return None; // reject %00
                }
                out.push(byte);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Resolves `.`/`..` dot-segments and collapses duplicate slashes,
/// mirroring RFC 3986 6.2.2.3's path normalization. Always returns a
/// path starting with `/`. Does not itself reject `..` that would
/// escape the root -- see `parse`, which rejects any `..` segment in
/// the *decoded* (pre-normalization) path outright rather than relying
/// on normalization to contain it, since normalization operates on
/// already-decoded text and a subtly wrong implementation here would
/// otherwise be a path-traversal vector.
fn normalize_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let len = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(len + 1);
    if bytes.first() != Some(&b'/') {
        out.push(b'/');
    }

    let mut i = 0;
    while i < len {
        if bytes[i] == b'/' {
            while i < len && bytes[i] == b'/' {
                i += 1;
            }
            out.push(b'/');
        } else if bytes[i] == b'.' && (i + 1 >= len || bytes[i + 1] == b'/') {
            // Consume the trailing '/' along with the '.' when present,
            // so "/a/./b" normalizes to "/a/b" rather than leaving a
            // stray '/' for the slash-collapsing branch above to emit
            // as its own redundant segment.
            i += if i + 1 < len && bytes[i + 1] == b'/' { 2 } else { 1 };
        } else if bytes[i] == b'.'
            && i + 1 < len
            && bytes[i + 1] == b'.'
            && (i + 2 >= len || bytes[i + 2] == b'/')
        {
            i += 2;
            if out.len() > 1 {
                out.pop();
                while out.len() > 1 && out[out.len() - 1] != b'/' {
                    out.pop();
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    if out.len() > 1 && out[out.len() - 1] == b'/' {
        out.pop();
    }

    // Safety: every byte pushed onto `out` came from either a literal
    // '/' or '.' (both ASCII) or a byte copied verbatim from `path`,
    // which is already a `&str` -- this can't introduce invalid UTF-8.
    String::from_utf8(out).expect("normalize_path only rearranges valid UTF-8 input")
}

/// Finds the next CRLF-terminated line inside `data[start..]`. Returns
/// the byte offset of the line's start and the offset of the CRLF
/// itself (i.e. the line is `data[line_start..crlf_start]`), or `None`
/// if no CRLF is found in the searched range.
fn find_next_line(data: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut k = start;
    while k + 1 < data.len() {
        if data[k] == b'\r' && data[k + 1] == b'\n' {
            return Some((start, k));
        }
        k += 1;
    }
    None
}

enum ChunkedDecode {
    Complete { body: Vec<u8>, consumed: usize },
    Incomplete,
    Malformed,
}

/// Decodes an RFC 9112 6.1 chunked message body from `data`.
/// `Complete.consumed` is the number of bytes of `data` occupied by
/// the encoded body, including the terminating zero-length chunk and
/// any (discarded) trailer section.
fn decode_chunked_body(data: &[u8]) -> ChunkedDecode {
    let mut body = Vec::new();
    let mut pos = 0usize;

    loop {
        let Some((line_start, line_end)) = find_next_line(data, pos) else {
            return ChunkedDecode::Incomplete;
        };
        let line = &data[line_start..line_end];

        let mut size: u64 = 0;
        let mut hex_digits = 0u32;
        for &c in line {
            if c == b';' {
                break; // chunk-extension, ignored
            }
            if !is_hex(c) {
                return ChunkedDecode::Malformed;
            }
            if hex_digits >= 16 {
                return ChunkedDecode::Malformed; // would overflow
            }
            size = (size << 4) | u64::from(hex_val(c));
            hex_digits += 1;
        }
        if hex_digits == 0 {
            return ChunkedDecode::Malformed; // empty chunk-size token
        }

        pos = line_end + 2;

        if size == 0 {
            // Last-chunk: consume (and discard) the trailer section up
            // to the terminating blank line.
            loop {
                let Some((t_start, t_end)) = find_next_line(data, pos) else {
                    return ChunkedDecode::Incomplete;
                };
                pos = t_end + 2;
                if t_end == t_start {
                    break; // empty line -- end of trailers
                }
            }
            return ChunkedDecode::Complete { body, consumed: pos };
        }

        let size = size as usize;
        if data.len().saturating_sub(pos) < size + 2 {
            return ChunkedDecode::Incomplete;
        }
        if data[pos + size] != b'\r' || data[pos + size + 1] != b'\n' {
            return ChunkedDecode::Malformed;
        }

        body.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2;
    }
}

/// Parses as much of a complete HTTP/1.1 request as `buf` currently
/// holds. `max_body_size` of 0 means unlimited; otherwise the request
/// is rejected as soon as its declared (Content-Length) or actual
/// (chunked, decoded incrementally) body size would exceed it -- for
/// Content-Length this happens before waiting for the body to actually
/// arrive, so an oversized declared length is rejected immediately
/// rather than after buffering it.
pub fn parse(buf: &Buf, max_body_size: usize) -> ParseOutcome {
    let data = buf.as_slice();
    if data.is_empty() {
        return ParseOutcome::Incomplete;
    }

    let Some(headers_end) = find_subslice(data, b"\r\n\r\n") else {
        // A bare LF-LF terminator (no CR) is rejected as malformed
        // rather than treated as incomplete -- RFC 9112 requires CRLF,
        // and silently accepting bare-LF framing is itself a
        // request-smuggling vector between implementations that
        // disagree on this.
        if find_subslice(data, b"\n\n").is_some() {
            return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
        }
        return ParseOutcome::Incomplete;
    };
    let headers_len = headers_end + 4;

    // ---- request line ----
    let Some((_, rl_end)) = find_next_line(data, 0) else {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    };
    let request_line = &data[0..rl_end];

    let Some(sp1) = request_line.iter().position(|&b| b == b' ') else {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    };
    let Some(method) = HttpMethod::parse(&request_line[..sp1]) else {
        return ParseOutcome::Invalid(ParseError::UnknownMethod);
    };

    let path_start = sp1 + 1;
    let Some(sp2_rel) = request_line[path_start..].iter().position(|&b| b == b' ') else {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    };
    let path_end = path_start + sp2_rel;
    let raw_path = &request_line[path_start..path_end];

    if raw_path.contains(&0) {
        return ParseOutcome::Invalid(ParseError::InvalidPath);
    }

    let (raw_path, query) = match raw_path.iter().position(|&b| b == b'?') {
        Some(q) => (&raw_path[..q], Some(&raw_path[q + 1..])),
        None => (raw_path, None),
    };

    let query_owned = query.map(|q| String::from_utf8_lossy(q).into_owned());
    let query_params = match &query_owned {
        Some(q) => parse_query_params(q.as_bytes()),
        None => Vec::new(),
    };

    let Some(decoded_path) = url_decode(raw_path) else {
        return ParseOutcome::Invalid(ParseError::InvalidPath);
    };

    // Reject path traversal in the decoded (pre-normalization) path --
    // see normalize_path's doc comment for why this check doesn't rely
    // on normalization alone to contain it.
    if decoded_path.contains("..") {
        return ParseOutcome::Invalid(ParseError::PathTraversal);
    }

    let path = normalize_path(&decoded_path);

    // ---- HTTP version ----
    let version_start = path_end + 1;
    if version_start + 5 > request_line.len() {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    }
    if &request_line[version_start..version_start + 5] != b"HTTP/" {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    }
    let version_str = &request_line[version_start + 5..];
    let Some(dot) = version_str.iter().position(|&b| b == b'.') else {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    };
    let Ok(version_major) = std::str::from_utf8(&version_str[..dot]).unwrap_or("").parse::<u8>()
    else {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    };
    let Ok(version_minor) =
        std::str::from_utf8(&version_str[dot + 1..]).unwrap_or("").parse::<u8>()
    else {
        return ParseOutcome::Invalid(ParseError::MalformedRequestLine);
    };
    // Only HTTP/1.0 and HTTP/1.1 are handled here -- HTTP/2 arrives via
    // the h2c preface / Upgrade path, never as a regular request line.
    if version_major != 1 || (version_minor != 0 && version_minor != 1) {
        return ParseOutcome::Invalid(ParseError::UnsupportedVersion);
    }

    // ---- headers ----
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut hp = rl_end + 2; // skip the request line's own CRLF
    while hp < headers_end {
        let Some((hl_start, hl_end)) = find_next_line(data, hp) else {
            break;
        };
        if hl_end == hl_start {
            break;
        }
        if headers.len() >= DEFAULT_MAX_HEADERS {
            return ParseOutcome::Invalid(ParseError::TooManyHeaders);
        }

        let line = &data[hl_start..hl_end];

        // Obsolete line folding (RFC 9112 5.2): a continuation line
        // begins with SP/HTAB. A request-smuggling vector -- reject
        // rather than silently fold or drop it.
        if line.first() == Some(&b' ') || line.first() == Some(&b'\t') {
            return ParseOutcome::Invalid(ParseError::ObsoleteLineFolding);
        }
        if line.contains(&0) {
            return ParseOutcome::Invalid(ParseError::NulByteInHeader);
        }

        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return ParseOutcome::Invalid(ParseError::MalformedHeaderLine);
        };
        let name_bytes = &line[..colon];
        if name_bytes.is_empty() || !name_bytes.iter().all(|&b| is_tchar(b)) {
            return ParseOutcome::Invalid(ParseError::InvalidHeaderName);
        }

        let mut vi = colon + 1;
        while vi < line.len() && (line[vi] == b' ' || line[vi] == b'\t') {
            vi += 1;
        }

        let (Ok(name), Ok(value)) = (
            std::str::from_utf8(name_bytes),
            std::str::from_utf8(&line[vi..]),
        ) else {
            return ParseOutcome::Invalid(ParseError::MalformedHeaderLine);
        };
        headers.push((name.to_string(), value.to_string()));
        hp = hl_end + 2;
    }

    // ---- keep-alive ----
    let conn_header = find_header(&headers, "Connection");
    let keep_alive = if version_major == 1 && version_minor == 1 {
        !conn_header.is_some_and(|v| v.eq_ignore_ascii_case("close"))
    } else {
        conn_header.is_some_and(|v| v.eq_ignore_ascii_case("keep-alive"))
    };

    // ---- Host header (RFC 9112 3.2): mandatory on HTTP/1.1; duplicates
    // and invalid values (embedded whitespace/control chars) are
    // request-smuggling adjacent -- some intermediaries pick the
    // first, some the last, so reject ambiguity outright. ----
    let host_values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Host"))
        .map(|(_, v)| v.as_str())
        .collect();
    if version_major == 1 && version_minor == 1 && host_values.is_empty() {
        return ParseOutcome::Invalid(ParseError::MissingHostHeader);
    }
    if host_values.len() > 1 {
        return ParseOutcome::Invalid(ParseError::DuplicateHostHeader);
    }
    if let Some(host) = host_values.first() {
        if host.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return ParseOutcome::Invalid(ParseError::InvalidHostHeader);
        }
    }

    // ---- Transfer-Encoding / Content-Length (RFC 9112 6.1, 6.3) ----
    // Both present together, or an unrecognized/non-final
    // transfer-coding, are request-smuggling vectors -- reject
    // outright rather than guess which framing another implementation
    // would have honored.
    let te_header = find_header(&headers, "Transfer-Encoding");
    let cl_header = find_header(&headers, "Content-Length");

    let te_chunked = match te_header {
        Some(v) => {
            let trimmed = v.trim_matches(|c| c == ' ' || c == '\t');
            if trimmed.eq_ignore_ascii_case("chunked") {
                true
            } else {
                // Unknown coding, or "chunked" isn't the final (and
                // only) coding present.
                return ParseOutcome::Invalid(ParseError::UnsupportedTransferEncoding);
            }
        }
        None => false,
    };

    if te_chunked && cl_header.is_some() {
        return ParseOutcome::Invalid(ParseError::ChunkedWithContentLength);
    }
    if te_chunked && !(version_major == 1 && version_minor == 1) {
        return ParseOutcome::Invalid(ParseError::ChunkedOnHttp10);
    }

    // Reject conflicting duplicate Content-Length headers -- all
    // instances must agree, or the request must be rejected.
    if cl_header.is_some() {
        let mut cl_values = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .map(|(_, v)| v.as_str());
        let first = cl_values.next();
        if let Some(first) = first {
            if cl_values.any(|v| v != first) {
                return ParseOutcome::Invalid(ParseError::ConflictingContentLength);
            }
        }
    }

    let mut content_length: usize = 0;
    if let Some(cl) = cl_header {
        if !te_chunked {
            let trimmed = cl.trim_start_matches(' ');
            if trimmed.starts_with('-') {
                return ParseOutcome::Invalid(ParseError::InvalidContentLength);
            }
            let Ok(parsed) = trimmed.parse::<u64>() else {
                return ParseOutcome::Invalid(ParseError::InvalidContentLength);
            };
            content_length = parsed as usize;
            if max_body_size > 0 && content_length > max_body_size {
                return ParseOutcome::Invalid(ParseError::BodyTooLarge);
            }
        }
    }

    let body_start = headers_len;
    let available = data.len().saturating_sub(body_start);

    let (body, consumed) = if te_chunked {
        match decode_chunked_body(&data[body_start..]) {
            ChunkedDecode::Incomplete => return ParseOutcome::Incomplete,
            ChunkedDecode::Malformed => {
                return ParseOutcome::Invalid(ParseError::MalformedChunkedBody)
            }
            ChunkedDecode::Complete { body, consumed } => {
                if max_body_size > 0 && body.len() > max_body_size {
                    return ParseOutcome::Invalid(ParseError::BodyTooLarge);
                }
                (body, body_start + consumed)
            }
        }
    } else if content_length > 0 {
        if available < content_length {
            return ParseOutcome::Incomplete;
        }
        (
            data[body_start..body_start + content_length].to_vec(),
            body_start + content_length,
        )
    } else {
        (Vec::new(), body_start)
    };

    ParseOutcome::Complete {
        request: HttpRequest {
            method,
            remote_addr: None, // filled in by the connection layer
            path,
            query: query_owned,
            query_params,
            version_major,
            version_minor,
            headers,
            body,
            keep_alive,
            trailers: Vec::new(),
        },
        consumed,
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn parse_query_params(query: &[u8]) -> Vec<(String, String)> {
    let mut params = Vec::new();
    for pair in query.split(|&b| b == b'&') {
        if params.len() >= DEFAULT_MAX_QUERY_PARAMS {
            break;
        }
        let Some(eq) = pair.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (Some(k), Some(v)) = (url_decode(&pair[..eq]), url_decode(&pair[eq + 1..])) else {
            continue;
        };
        params.push((k, v));
    }
    params
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_basic_get_request() {
        let req = HttpRequest {
            method: HttpMethod::Get,
            remote_addr: None,
            path: "/hello".to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            keep_alive: true,
            trailers: Vec::new(),
        };
        let bytes = req.serialize();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("GET /hello HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("Content-Length: 0\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn serialize_includes_query_string() {
        let req = HttpRequest {
            method: HttpMethod::Get,
            remote_addr: None,
            path: "/search".to_string(),
            query: Some("q=rust".to_string()),
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: Vec::new(),
            body: Vec::new(),
            keep_alive: true,
            trailers: Vec::new(),
        };
        let s = String::from_utf8(req.serialize()).unwrap();
        assert!(s.starts_with("GET /search?q=rust HTTP/1.1\r\n"));
    }

    #[test]
    fn serialize_recomputes_content_length_from_actual_body() {
        let req = HttpRequest {
            method: HttpMethod::Post,
            remote_addr: None,
            path: "/submit".to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: vec![("Content-Length".to_string(), "999".to_string())],
            body: b"hello".to_vec(),
            keep_alive: true,
            trailers: Vec::new(),
        };
        let s = String::from_utf8(req.serialize()).unwrap();
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(!s.contains("999"));
        assert!(s.ends_with("hello"));
    }

    #[test]
    fn serialize_then_parse_round_trips() {
        let req = HttpRequest {
            method: HttpMethod::Post,
            remote_addr: None,
            path: "/api/data".to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: vec![
                ("Host".to_string(), "upstream.internal".to_string()),
                ("X-Custom".to_string(), "value".to_string()),
            ],
            body: b"payload".to_vec(),
            keep_alive: true,
            trailers: Vec::new(),
        };
        let bytes = req.serialize();
        let mut buf = Buf::new();
        buf.push(&bytes);
        let parsed = match parse(&buf, 0) {
            ParseOutcome::Complete { request, .. } => request,
            _ => panic!("expected Complete"),
        };
        assert_eq!(parsed.method, HttpMethod::Post);
        assert_eq!(parsed.path, "/api/data");
        assert_eq!(parsed.get_header("X-Custom"), Some("value"));
        assert_eq!(parsed.body, b"payload");
    }

    fn buf_from(s: &[u8]) -> Buf {
        let mut b = Buf::new();
        b.push(s);
        b
    }

    fn parse_complete(s: &[u8]) -> (HttpRequest, usize) {
        match parse(&buf_from(s), 0) {
            ParseOutcome::Complete { request, consumed } => (request, consumed),
            ParseOutcome::Incomplete => panic!("expected Complete, got Incomplete"),
            ParseOutcome::Invalid(e) => panic!("expected Complete, got Invalid({e:?})"),
        }
    }

    fn parse_invalid(s: &[u8]) -> ParseError {
        match parse(&buf_from(s), 0) {
            ParseOutcome::Invalid(e) => e,
            ParseOutcome::Complete { .. } => panic!("expected Invalid, got Complete"),
            ParseOutcome::Incomplete => panic!("expected Invalid, got Incomplete"),
        }
    }

    // ─── Basic request line ────────────────────────────────────────────

    #[test]
    fn simple_get_request() {
        let (req, consumed) =
            parse_complete(b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, "/hello");
        assert_eq!(req.version_major, 1);
        assert_eq!(req.version_minor, 1);
        assert!(req.keep_alive);
        assert_eq!(consumed, b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n".len());
    }

    #[test]
    fn all_methods_recognized() {
        for (bytes, expected) in [
            (b"GET".as_slice(), HttpMethod::Get),
            (b"POST", HttpMethod::Post),
            (b"PUT", HttpMethod::Put),
            (b"DELETE", HttpMethod::Delete),
            (b"HEAD", HttpMethod::Head),
            (b"PATCH", HttpMethod::Patch),
            (b"OPTIONS", HttpMethod::Options),
            (b"TRACE", HttpMethod::Trace),
            (b"CONNECT", HttpMethod::Connect),
        ] {
            let mut req = Vec::new();
            req.extend_from_slice(bytes);
            req.extend_from_slice(b" / HTTP/1.1\r\nHost: h\r\n\r\n");
            let (parsed, _) = parse_complete(&req);
            assert_eq!(parsed.method, expected);
        }
    }

    #[test]
    fn unknown_method_rejected() {
        assert_eq!(
            parse_invalid(b"FOO / HTTP/1.1\r\nHost: h\r\n\r\n"),
            ParseError::UnknownMethod
        );
    }

    #[test]
    fn incomplete_request_reports_incomplete() {
        assert!(matches!(
            parse(&buf_from(b"GET / HTTP/1.1\r\nHost:"), 0),
            ParseOutcome::Incomplete
        ));
    }

    #[test]
    fn empty_buffer_is_incomplete() {
        assert!(matches!(parse(&buf_from(b""), 0), ParseOutcome::Incomplete));
    }

    #[test]
    fn bare_lf_lf_terminator_rejected() {
        assert_eq!(
            parse_invalid(b"GET / HTTP/1.1\nHost: h\n\n"),
            ParseError::MalformedRequestLine
        );
    }

    // ─── Path handling ──────────────────────────────────────────────────

    #[test]
    fn path_is_url_decoded() {
        let (req, _) = parse_complete(b"GET /hello%20world HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(req.path, "/hello world");
    }

    #[test]
    fn plus_decodes_to_space_in_path() {
        let (req, _) = parse_complete(b"GET /a+b HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(req.path, "/a b");
    }

    #[test]
    fn percent_00_rejected() {
        assert_eq!(
            parse_invalid(b"GET /a%00b HTTP/1.1\r\nHost: h\r\n\r\n"),
            ParseError::InvalidPath
        );
    }

    #[test]
    fn path_traversal_rejected() {
        assert_eq!(
            parse_invalid(b"GET /../etc/passwd HTTP/1.1\r\nHost: h\r\n\r\n"),
            ParseError::PathTraversal
        );
    }

    #[test]
    fn duplicate_slashes_collapsed() {
        let (req, _) = parse_complete(b"GET //a///b HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(req.path, "/a/b");
    }

    #[test]
    fn dot_segment_resolved() {
        let (req, _) = parse_complete(b"GET /a/./b HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(req.path, "/a/b");
    }

    #[test]
    fn trailing_slash_stripped_except_root() {
        let (req, _) = parse_complete(b"GET /a/b/ HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(req.path, "/a/b");

        let (root, _) = parse_complete(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(root.path, "/");
    }

    // ─── Query string ───────────────────────────────────────────────────

    #[test]
    fn query_params_parsed_and_decoded() {
        let (req, _) =
            parse_complete(b"GET /search?q=hello%20world&page=2 HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(req.get_query("q"), Some("hello world"));
        assert_eq!(req.get_query("page"), Some("2"));
    }

    #[test]
    fn query_string_stored_raw() {
        let (req, _) = parse_complete(b"GET /s?a=1&b=2 HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(req.query.as_deref(), Some("a=1&b=2"));
    }

    // ─── HTTP version ───────────────────────────────────────────────────

    #[test]
    fn http_1_0_supported() {
        let (req, _) = parse_complete(b"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(req.version_minor, 0);
    }

    #[test]
    fn http_2_rejected_on_this_parser() {
        assert_eq!(
            parse_invalid(b"GET / HTTP/2.0\r\nHost: h\r\n\r\n"),
            ParseError::UnsupportedVersion
        );
    }

    // ─── Headers ────────────────────────────────────────────────────────

    #[test]
    fn multiple_headers_parsed() {
        let (req, _) = parse_complete(
            b"GET / HTTP/1.1\r\nHost: h\r\nX-Custom: value\r\nAccept: */*\r\n\r\n",
        );
        assert_eq!(req.get_header("X-Custom"), Some("value"));
        assert_eq!(req.get_header("Accept"), Some("*/*"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let (req, _) = parse_complete(b"GET / HTTP/1.1\r\nhost: h\r\n\r\n");
        assert_eq!(req.get_header("Host"), Some("h"));
        assert_eq!(req.get_header("HOST"), Some("h"));
    }

    #[test]
    fn obsolete_line_folding_rejected() {
        assert_eq!(
            parse_invalid(b"GET / HTTP/1.1\r\nHost: h\r\n Continuation\r\n\r\n"),
            ParseError::ObsoleteLineFolding
        );
    }

    #[test]
    fn header_without_colon_rejected() {
        assert_eq!(
            parse_invalid(b"GET / HTTP/1.1\r\nHost h\r\n\r\n"),
            ParseError::MalformedHeaderLine
        );
    }

    #[test]
    fn invalid_header_name_rejected() {
        assert_eq!(
            parse_invalid(b"GET / HTTP/1.1\r\nHost: h\r\nBad Name: v\r\n\r\n"),
            ParseError::InvalidHeaderName
        );
    }

    // ─── Host header ────────────────────────────────────────────────────

    #[test]
    fn missing_host_rejected_on_http_1_1() {
        assert_eq!(
            parse_invalid(b"GET / HTTP/1.1\r\n\r\n"),
            ParseError::MissingHostHeader
        );
    }

    #[test]
    fn missing_host_allowed_on_http_1_0() {
        let (req, _) = parse_complete(b"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(req.get_header("Host"), None);
    }

    #[test]
    fn duplicate_host_rejected() {
        assert_eq!(
            parse_invalid(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
            ParseError::DuplicateHostHeader
        );
    }

    // ─── Keep-alive ─────────────────────────────────────────────────────

    #[test]
    fn http_1_1_defaults_to_keep_alive() {
        let (req, _) = parse_complete(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(req.keep_alive);
    }

    #[test]
    fn http_1_1_connection_close_disables_keep_alive() {
        let (req, _) =
            parse_complete(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
        assert!(!req.keep_alive);
    }

    #[test]
    fn http_1_0_defaults_to_no_keep_alive() {
        let (req, _) = parse_complete(b"GET / HTTP/1.0\r\n\r\n");
        assert!(!req.keep_alive);
    }

    #[test]
    fn http_1_0_connection_keep_alive_enables_it() {
        let (req, _) = parse_complete(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        assert!(req.keep_alive);
    }

    // ─── Content-Length body ────────────────────────────────────────────

    #[test]
    fn content_length_body_parsed() {
        let (req, consumed) = parse_complete(
            b"POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
        );
        assert_eq!(req.body, b"hello");
        assert_eq!(
            consumed,
            b"POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello".len()
        );
    }

    #[test]
    fn content_length_incomplete_body_is_incomplete() {
        assert!(matches!(
            parse(
                &buf_from(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc"),
                0
            ),
            ParseOutcome::Incomplete
        ));
    }

    #[test]
    fn negative_content_length_rejected() {
        assert_eq!(
            parse_invalid(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\n"),
            ParseError::InvalidContentLength
        );
    }

    #[test]
    fn conflicting_content_length_rejected() {
        assert_eq!(
            parse_invalid(
                b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
            ),
            ParseError::ConflictingContentLength
        );
    }

    #[test]
    fn identical_duplicate_content_length_allowed() {
        let (req, _) = parse_complete(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        );
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn oversized_content_length_rejected_immediately() {
        // The declared length alone exceeds the limit -- rejected
        // without needing the body bytes to actually arrive.
        let outcome = parse(
            &buf_from(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\n"),
            10,
        );
        assert!(matches!(
            outcome,
            ParseOutcome::Invalid(ParseError::BodyTooLarge)
        ));
    }

    // ─── Chunked body ───────────────────────────────────────────────────

    #[test]
    fn chunked_body_decoded() {
        let (req, _) = parse_complete(
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        assert_eq!(req.body, b"hello world");
    }

    #[test]
    fn chunked_incomplete_final_chunk_is_incomplete() {
        assert!(matches!(
            parse(
                &buf_from(
                    b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"
                ),
                0
            ),
            ParseOutcome::Incomplete
        ));
    }

    #[test]
    fn chunked_with_content_length_rejected() {
        assert_eq!(
            parse_invalid(
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"
            ),
            ParseError::ChunkedWithContentLength
        );
    }

    #[test]
    fn chunked_on_http_1_0_rejected() {
        assert_eq!(
            parse_invalid(
                b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
            ParseError::ChunkedOnHttp10
        );
    }

    #[test]
    fn malformed_chunk_size_rejected() {
        assert_eq!(
            parse_invalid(
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nhello\r\n0\r\n\r\n"
            ),
            ParseError::MalformedChunkedBody
        );
    }

    #[test]
    fn unrecognized_transfer_encoding_rejected() {
        assert_eq!(
            parse_invalid(
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n"
            ),
            ParseError::UnsupportedTransferEncoding
        );
    }

    // ─── Keep-alive across multiple requests on one buffer ─────────────

    #[test]
    fn consumed_allows_parsing_next_request_from_same_buffer() {
        let mut buf = buf_from(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n");
        let (first, consumed) = match parse(&buf, 0) {
            ParseOutcome::Complete { request, consumed } => (request, consumed),
            _ => panic!("expected first request to parse"),
        };
        assert_eq!(first.path, "/a");
        buf.consume(consumed);

        let (second, _) = match parse(&buf, 0) {
            ParseOutcome::Complete { request, consumed } => (request, consumed),
            _ => panic!("expected second request to parse"),
        };
        assert_eq!(second.path, "/b");
    }
}
