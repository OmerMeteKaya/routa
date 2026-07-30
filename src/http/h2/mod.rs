pub mod stream;
pub mod hpack;
pub mod frame;

/// Whether an HTTP/1.1 request is asking to switch this connection to
/// HTTP/2 over cleartext (RFC 9113 3.2) -- distinct from `http::ws`'s
/// own upgrade check, which looks for `Upgrade: websocket` instead.
pub fn is_h2c_upgrade_request(req: &crate::http::request::HttpRequest) -> bool {
    let upgrade_ok = req.get_header("Upgrade").is_some_and(|v| v.eq_ignore_ascii_case("h2c"));
    let connection_ok = req.get_header("Connection").is_some_and(|v| {
        v.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
    });
    let has_settings = req.get_header("HTTP2-Settings").is_some();
    upgrade_ok && connection_ok && has_settings
}

/// Decodes an `Upgrade: h2c` request's `HTTP2-Settings` header (RFC
/// 9113 3.2: base64url, no padding) into the raw SETTINGS frame
/// payload bytes it represents -- `None` if the header is missing or
/// isn't valid base64url.
pub fn decode_http2_settings_header(req: &crate::http::request::HttpRequest) -> Option<Vec<u8>> {
    let raw = req.get_header("HTTP2-Settings")?;
    base64_url_decode(raw)
}

fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut lookup = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let s = s.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in s.bytes() {
        let value = lookup[byte as usize];
        if value == 255 {
            return None;
        }
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}
