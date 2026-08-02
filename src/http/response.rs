//! HTTP/1.1 response construction and serialization. `HttpResponse`
//! only builds the byte representation of a response (`serialize`,
//! writing into a `Buf`) -- it does no socket I/O itself. Actually
//! sending those bytes (including retrying on `WouldBlock`, and any
//! zero-copy `sendfile` path for static files) is the event loop's
//! and `http::static_files`'s responsibility, not this module's: this
//! keeps response construction a pure, easily-tested function of "what
//! headers/body were set" rather than something that depends on
//! socket/TLS state to even test.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::buf::Buf;
use crate::util::time::format_http_date;

/// A single response header. Stored as an ordered list (not a map) so
/// that `serialize` emits headers in the order they were set --
/// matters for interoperability with clients/intermediaries that are
/// sensitive to header order (rare, but harmless to preserve).
#[derive(Debug)]
/// A response body backed by an open file descriptor rather than an
/// in-memory buffer -- lets the event loop send the body via
/// `sendfile(2)` (kernel-space file-to-socket copy, no userspace
/// buffer) instead of reading the whole file into memory first. Only
/// usable on a plaintext transport: TLS must encrypt in userspace, so
/// a TLS connection's event-loop path falls back to a normal read+
/// write for a `FileBody` response (see `core::event_loop`'s flush
/// logic).
pub struct FileBody {
    pub file: std::fs::File,
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Set instead of populating `body` when the response body should
    /// be sent directly from a file via `sendfile(2)` -- see
    /// `set_body_file`. Mutually exclusive with `body` in practice
    /// (whichever was set most recently via `set_body`/`set_body_file`
    /// is what `core::event_loop` actually sends); both existing
    /// unconditionally rather than as an enum keeps `body()`'s
    /// existing signature and every current caller of it unchanged.
    pub file_body: Option<FileBody>,
    /// `Transfer-Encoding: chunked` instead of `Content-Length`. When
    /// set, `serialize` emits the body (if any) as a single chunk
    /// followed by the terminating zero-length chunk, and suppresses
    /// any `Content-Length` header a caller may have set (the two are
    /// mutually exclusive per RFC 9112 6.1).
    pub chunked: bool,
    /// Header fields for a `103 Early Hints` informational response
    /// (RFC 8297) to send ahead of this response's own status/headers
    /// -- lets a client start fetching resources (stylesheets,
    /// scripts) this response's `Link` headers point to before the
    /// full response is even ready. Empty means no early hints are
    /// sent; a route handler populates this the same way it populates
    /// any other header.
    pub early_hints: Vec<(String, String)>,
    /// Set instead of a real status/body when this response should be
    /// obtained by proxying the original request to an upstream
    /// server, rather than this response itself being sent to the
    /// client -- see `crate::core::proxy::ProxyPending`'s own doc
    /// comment. `status`/`reason`/`body` on a response with this set
    /// are meaningless placeholders (`HttpResponse::new`'s own
    /// defaults, never actually inspected); a backend checks this
    /// field before treating any of the rest of the response as real.
    /// Kept as an opaque `Option` here (rather than, say, an enum
    /// replacing `status`/`body` outright) so route-dispatch code that
    /// has nothing to do with proxying -- the overwhelming majority of
    /// `HttpResponse` construction -- never needs to know this variant
    /// exists at all; only `core::proxy`'s own route handler ever sets
    /// it, and only each backend's own dispatch code ever reads it.
    pub proxy_pending: Option<crate::core::proxy::ProxyPending>,
}

impl HttpResponse {
    pub fn new(status: u16, reason: impl Into<String>) -> Self {
        HttpResponse {
            status,
            reason: reason.into(),
            headers: Vec::new(),
            body: Vec::new(),
            file_body: None,
            chunked: false,
            early_hints: Vec::new(),
            proxy_pending: None,
        }
    }

    /// Adds one `Link` header value to this response's early hints --
    /// call once per resource to hint (e.g. once for a stylesheet,
    /// once for a script). No-op if `early_hints` was never populated
    /// by anything -- a route handler that never calls this simply
    /// sends no 103 at all.
    pub fn add_early_hint_link(&mut self, link_value: impl Into<String>) {
        self.early_hints.push(("Link".to_string(), link_value.into()));
    }

    /// Sets this response's body to be sent directly from `file`
    /// starting at `offset` for `len` bytes, via `sendfile(2)` where
    /// the transport allows it (see `FileBody`'s own doc comment for
    /// the TLS fallback). Clears any body previously set via
    /// `set_body` -- the two are mutually exclusive. Sets
    /// `Content-Length` from `len` the same way `set_body` derives it
    /// from the in-memory body's actual size.
    pub fn set_body_file(&mut self, file: std::fs::File, offset: u64, len: u64) {
        self.body = Vec::new();
        self.file_body = Some(FileBody { file, offset, len });
        if !self.chunked {
            self.set_header("Content-Length", len.to_string());
        }
    }

    /// The effective body length regardless of which body source is
    /// in use -- callers computing `Content-Length` need this instead
    /// of `body().len()`, which is always 0 for a `FileBody` response.
    pub fn effective_body_len(&self) -> u64 {
        match &self.file_body {
            Some(fb) => fb.len,
            None => self.body.len() as u64,
        }
    }

    /// Sets a header, overwriting any existing header with the same
    /// name (case-insensitive) rather than appending a duplicate --
    /// e.g. calling this twice for `Content-Length` (once from
    /// `set_body`, once from a middleware rewriting it) produces one
    /// header line, not two ambiguous ones.
    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(existing) = self
            .headers
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(&key))
        {
            existing.1 = value;
        } else {
            self.headers.push((key, value));
        }
    }

    /// Removes every header matching `name` (case-insensitive). Used
    /// for config-driven `response_header_remove` rules.
    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every header currently set, in the order they were added --
    /// used by callers that need to re-encode this response's headers
    /// into a different wire format (e.g. core::event_loop's H2 path,
    /// which HPACK-encodes them rather than writing HTTP/1.1 text).
    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Sets the response body, replacing any previously set body.
    /// Automatically sets `Content-Length` unless `chunked` is set (in
    /// which case `serialize` computes chunk framing from the body's
    /// length itself, and an explicit `Content-Length` would be
    /// incorrect/misleading anyway).
    pub fn set_body(&mut self, data: impl Into<Vec<u8>>) {
        self.body = data.into();
        if !self.chunked {
            self.set_header("Content-Length", self.body.len().to_string());
        }
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Clears this response's actual body content (both the in-memory
    /// buffer and any file-backed body) while leaving `Content-Length`
    /// untouched -- used for a `HEAD` request's response, which per
    /// RFC 9110 9.3.2 must report the same headers a `GET` would but
    /// send no body at all. Keeping this as a post-processing step
    /// applied uniformly to whatever a route/proxy produced (see
    /// `core::event_loop`'s HEAD handling) means no individual route
    /// handler needs its own HEAD-specific logic.
    pub fn strip_body_for_head(&mut self) {
        self.body = Vec::new();
        self.file_body = None;
    }

    /// Serializes the full HTTP/1.1 response (status line, headers,
    /// body) into `out`. Adds `Date`/`Server`/`Connection` headers if
    /// the caller hasn't already set them -- RFC 9110 doesn't require
    /// any of these, but omitting them entirely is unusual enough to
    /// confuse some clients/intermediaries, so routa always sends a
    /// reasonable default.
    pub fn serialize(&self, out: &mut Buf) {
        let has_date = self.get_header("Date").is_some();
        let has_server = self.get_header("Server").is_some();
        let has_connection = self.get_header("Connection").is_some();
        let has_transfer_encoding = self.get_header("Transfer-Encoding").is_some();

        out.push_str(&format!(
            "HTTP/1.1 {} {}\r\n",
            self.status,
            if self.reason.is_empty() {
                "Unknown"
            } else {
                &self.reason
            }
        ));

        if !has_date {
            out.push_str(&format!("Date: {}\r\n", http_date_now()));
        }
        if !has_server {
            out.push_str("Server: routa/0.1\r\n");
        }
        if !has_connection {
            out.push_str("Connection: close\r\n");
        }
        if self.chunked && !has_transfer_encoding {
            out.push_str("Transfer-Encoding: chunked\r\n");
        }

        for (key, value) in &self.headers {
            if self.chunked && key.eq_ignore_ascii_case("Content-Length") {
                continue; // chunked and Content-Length are mutually exclusive
            }
            out.push_str(key);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");

        if self.chunked {
            if !self.body.is_empty() {
                append_chunk(out, &self.body);
            }
            append_chunk(out, &[]); // terminating zero-length chunk
        } else if !self.body.is_empty() {
            out.push(&self.body);
        }
    }
}

/// Encodes one RFC 9112 6.1 chunk into `out`. An empty `data` writes
/// the terminating chunk (`"0\r\n\r\n"`).
pub fn append_chunk(out: &mut Buf, data: &[u8]) {
    if data.is_empty() {
        out.push(b"0\r\n\r\n");
        return;
    }
    out.push_str(&format!("{:x}\r\n", data.len()));
    out.push(data);
    out.push(b"\r\n");
}

/// Builds a complete, serialized response in one call -- for simple
/// cases (error pages, small JSON responses) that don't need the
/// builder's full flexibility.
pub fn simple(
    out: &mut Buf,
    status: u16,
    reason: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) {
    let mut resp = HttpResponse::new(status, reason);
    if let Some(ct) = content_type {
        resp.set_header("Content-Type", ct);
    }
    if let Some(b) = body {
        resp.set_body(b.to_vec());
    }
    resp.serialize(out);
}

/// Formats the current time as an RFC 9110 5.6.7 IMF-fixdate (the
/// format required for the `Date` header), e.g.
/// `"Tue, 15 Nov 1994 08:12:31 GMT"`. Implemented directly against
/// `SystemTime` rather than pulling in a datetime crate, since this is
/// the only place routa needs calendar/wall-clock formatting.
fn http_date_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_http_date(now.as_secs())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn serialize_to_string(resp: &HttpResponse) -> String {
        let mut buf = Buf::new();
        resp.serialize(&mut buf);
        String::from_utf8_lossy(buf.as_slice()).into_owned()
    }

    #[test]
    fn status_line_formatted_correctly() {
        let resp = HttpResponse::new(200, "OK");
        let out = serialize_to_string(&resp);
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn empty_reason_defaults_to_unknown() {
        let resp = HttpResponse::new(299, "");
        let out = serialize_to_string(&resp);
        assert!(out.starts_with("HTTP/1.1 299 Unknown\r\n"));
    }

    #[test]
    fn default_headers_added_when_absent() {
        let resp = HttpResponse::new(200, "OK");
        let out = serialize_to_string(&resp);
        assert!(out.contains("Date: "));
        assert!(out.contains("Server: routa/0.1\r\n"));
        assert!(out.contains("Connection: close\r\n"));
    }

    #[test]
    fn explicit_headers_not_overridden() {
        let mut resp = HttpResponse::new(200, "OK");
        resp.set_header("Connection", "keep-alive");
        resp.set_header("Server", "custom-server");
        let out = serialize_to_string(&resp);
        assert!(out.contains("Connection: keep-alive\r\n"));
        assert!(!out.contains("Connection: close\r\n"));
        assert!(out.contains("Server: custom-server\r\n"));
        assert!(!out.contains("Server: routa/0.1\r\n"));
    }

    #[test]
    fn set_header_overwrites_not_duplicates() {
        let mut resp = HttpResponse::new(200, "OK");
        resp.set_header("X-Custom", "first");
        resp.set_header("X-Custom", "second");
        let out = serialize_to_string(&resp);
        assert_eq!(out.matches("X-Custom").count(), 1);
        assert!(out.contains("X-Custom: second\r\n"));
    }

    #[test]
    fn set_header_is_case_insensitive_for_overwrite() {
        let mut resp = HttpResponse::new(200, "OK");
        resp.set_header("Content-Type", "text/plain");
        resp.set_header("content-type", "application/json");
        let out = serialize_to_string(&resp);
        // Case-insensitive match: only one header line should exist for
        // this name, regardless of casing on either call.
        assert_eq!(out.to_lowercase().matches("content-type").count(), 1);
        assert!(out
            .to_lowercase()
            .contains("content-type: application/json\r\n"));
    }

    #[test]
    fn remove_header_removes_case_insensitively() {
        let mut resp = HttpResponse::new(200, "OK");
        resp.set_header("X-Debug", "1");
        resp.remove_header("x-debug");
        assert!(resp.get_header("X-Debug").is_none());
    }

    #[test]
    fn set_body_sets_content_length() {
        let mut resp = HttpResponse::new(200, "OK");
        resp.set_body(b"hello".to_vec());
        assert_eq!(resp.get_header("Content-Length"), Some("5"));
        let out = serialize_to_string(&resp);
        assert!(out.ends_with("hello"));
    }

    #[test]
    fn add_early_hint_link_populates_early_hints_as_a_link_header() {
        let mut resp = HttpResponse::new(200, "OK");
        assert!(resp.early_hints.is_empty());
        resp.add_early_hint_link("</style.css>; rel=preload; as=style");
        resp.add_early_hint_link("</app.js>; rel=preload; as=script");
        assert_eq!(resp.early_hints.len(), 2);
        assert_eq!(resp.early_hints[0], ("Link".to_string(), "</style.css>; rel=preload; as=style".to_string()));
        assert_eq!(resp.early_hints[1], ("Link".to_string(), "</app.js>; rel=preload; as=script".to_string()));
    }

    #[test]
    fn chunked_response_omits_content_length_and_frames_body() {
        let mut resp = HttpResponse::new(200, "OK");
        resp.chunked = true;
        resp.set_body(b"hello".to_vec());
        let out = serialize_to_string(&resp);
        assert!(!out.contains("Content-Length"));
        assert!(out.contains("Transfer-Encoding: chunked\r\n"));
        // "hello" is 5 bytes -> chunk size "5" in hex, then the data,
        // then the terminating zero-length chunk.
        assert!(out.contains("5\r\nhello\r\n"));
        assert!(out.ends_with("0\r\n\r\n"));
    }

    #[test]
    fn chunked_with_empty_body_still_writes_terminator() {
        let mut resp = HttpResponse::new(204, "No Content");
        resp.chunked = true;
        let out = serialize_to_string(&resp);
        assert!(out.ends_with("0\r\n\r\n"));
    }

    #[test]
    fn append_chunk_encodes_size_in_hex() {
        let mut buf = Buf::new();
        append_chunk(&mut buf, b"hello world"); // 11 bytes = 0xb
        let s = String::from_utf8_lossy(buf.as_slice());
        assert!(s.starts_with("b\r\nhello world\r\n"));
    }

    #[test]
    fn append_chunk_empty_writes_terminator_only() {
        let mut buf = Buf::new();
        append_chunk(&mut buf, &[]);
        assert_eq!(buf.as_slice(), b"0\r\n\r\n");
    }

    #[test]
    fn simple_builds_complete_response() {
        let mut buf = Buf::new();
        simple(
            &mut buf,
            404,
            "Not Found",
            Some("text/plain"),
            Some(b"missing"),
        );
        let s = String::from_utf8_lossy(buf.as_slice());
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.ends_with("missing"));
    }

    #[test]
    fn simple_with_no_body_has_no_content_length() {
        let mut buf = Buf::new();
        simple(&mut buf, 204, "No Content", None, None);
        let s = String::from_utf8_lossy(buf.as_slice());
        assert!(!s.contains("Content-Length"));
    }

}
