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

/// A single response header. Stored as an ordered list (not a map) so
/// that `serialize` emits headers in the order they were set --
/// matters for interoperability with clients/intermediaries that are
/// sensitive to header order (rare, but harmless to preserve).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// `Transfer-Encoding: chunked` instead of `Content-Length`. When
    /// set, `serialize` emits the body (if any) as a single chunk
    /// followed by the terminating zero-length chunk, and suppresses
    /// any `Content-Length` header a caller may have set (the two are
    /// mutually exclusive per RFC 9112 6.1).
    pub chunked: bool,
}

impl HttpResponse {
    pub fn new(status: u16, reason: impl Into<String>) -> Self {
        HttpResponse {
            status,
            reason: reason.into(),
            headers: Vec::new(),
            body: Vec::new(),
            chunked: false,
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

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Converts a Unix timestamp (seconds since epoch, UTC) to the
/// RFC 9110 IMF-fixdate format. Implements the same civil-calendar
/// arithmetic `gmtime` does, restricted to what formatting the `Date`
/// header needs (no timezone handling -- always UTC).
pub(crate) fn format_http_date(unix_secs: u64) -> String {
    let days_since_epoch = unix_secs / 86400;
    let secs_of_day = unix_secs % 86400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // 1970-01-01 was a Thursday (weekday index 4).
    let weekday = WEEKDAYS[((days_since_epoch + 4) % 7) as usize];

    let (year, month, day) = civil_from_days(days_since_epoch as i64);

    format!(
        "{weekday}, {day:02} {month} {year} {hour:02}:{minute:02}:{second:02} GMT",
        month = MONTHS[(month - 1) as usize]
    )
}

/// Howard Hinnant's `civil_from_days` algorithm: converts a day count
/// since the Unix epoch into a proleptic-Gregorian (year, month, day).
/// A standard, well-tested piece of civil calendar arithmetic (avoids
/// hand-rolling leap-year logic, a well-known source of off-by-one
/// bugs at century/400-year boundaries).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as i64; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as i64; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
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

    // ─── HTTP-date formatting ────────────────────────────────────────

    #[test]
    fn known_epoch_formats_correctly() {
        // 0 = 1970-01-01T00:00:00Z, a Thursday.
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn known_recent_date_formats_correctly() {
        // 2024-01-01T00:00:00Z was a Monday.
        assert_eq!(
            format_http_date(1_704_067_200),
            "Mon, 01 Jan 2024 00:00:00 GMT"
        );
    }

    #[test]
    fn leap_day_formats_correctly() {
        // 2024-02-29T12:00:00Z (2024 is a leap year) was a Thursday.
        assert_eq!(
            format_http_date(1_709_208_000),
            "Thu, 29 Feb 2024 12:00:00 GMT"
        );
    }

    #[test]
    fn year_end_formats_correctly() {
        // 2023-12-31T23:59:59Z was a Sunday.
        assert_eq!(
            format_http_date(1_704_067_199),
            "Sun, 31 Dec 2023 23:59:59 GMT"
        );
    }
}
