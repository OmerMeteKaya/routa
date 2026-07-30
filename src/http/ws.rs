//! WebSocket (RFC 6455) server-side implementation: HTTP Upgrade
//! handshake, frame parsing/serialization, fragmentation reassembly,
//! ping/pong keepalive, and RFC 7692 permessage-deflate compression.
//!
//! Text-frame UTF-8 validation is `String::from_utf8`'s job here
//! rather than a hand-rolled validator -- Rust's standard string
//! conversion already performs full RFC 3629 validation, so there's
//! no separate validation routine to get right or keep in sync with
//! the standard.
//!
//! Cross-worker broadcast (`WsRegistry`) uses `std::sync::mpsc` plus a
//! `mio::Waker` rather than a hand-rolled locked queue and an
//! eventfd/pipe pair -- `mpsc::Sender` is already safe to clone and
//! send from any thread, and `Waker` is mio's own cross-platform
//! primitive for exactly this "wake a poller blocked in another
//! thread" purpose (no separate `#[cfg(target_os = ...)]` branch
//! needed for Linux vs BSD/macOS the way an eventfd/pipe choice
//! would require).

use sha1::{Digest, Sha1};

use crate::http::request::HttpRequest;
use crate::net::poller::PollKey;

// ─── Opcodes (RFC 6455 5.2) ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    fn from_byte(b: u8) -> Option<Opcode> {
        match b {
            0x0 => Some(Opcode::Continuation),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Close),
            0x9 => Some(Opcode::Ping),
            0xa => Some(Opcode::Pong),
            _ => None, // reserved opcodes -- RFC 6455 requires failing the connection
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xa,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

// ─── Close codes (RFC 6455 7.4.1) ───────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    InvalidFramePayloadData = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    InternalError = 1011,
}

// ─── Handshake (RFC 6455 4.2) ────────────────────────────────────────────

/// The GUID RFC 6455 4.2.2 fixes for computing `Sec-WebSocket-Accept`
/// -- a constant from the spec itself, not a secret or configurable
/// value.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Computes the `Sec-WebSocket-Accept` header value from a client's
/// `Sec-WebSocket-Key`, per RFC 6455 1.3/4.2.2: SHA-1 of the key
/// concatenated with the fixed GUID above, base64-encoded.
fn compute_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let digest = hasher.finalize();
    base64_encode(&digest)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Checks whether `req` is a valid WebSocket upgrade request per
/// RFC 6455 4.2.1: `Upgrade: websocket`, a `Connection` header whose
/// comma-separated token list includes `upgrade` (case-insensitively,
/// and tolerant of it appearing alongside other tokens like
/// `keep-alive`), a `Sec-WebSocket-Key`, and `Sec-WebSocket-Version: 13`.
pub fn is_upgrade_request(req: &HttpRequest) -> bool {
    let upgrade_ok = req
        .get_header("Upgrade")
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let connection_ok = req.get_header("Connection").is_some_and(|v| {
        v.split(',')
            .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
    });
    let has_key = req.get_header("Sec-WebSocket-Key").is_some();
    let version_ok = req
        .get_header("Sec-WebSocket-Version")
        .is_some_and(|v| v.trim() == "13");

    upgrade_ok && connection_ok && has_key && version_ok
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PmdParams {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
}

/// Parses a `Sec-WebSocket-Extensions` header for a `permessage-deflate`
/// offer, if present. Returns `None` if the client didn't offer it (or
/// the header is absent) -- PMD is only ever used if both sides
/// affirmatively want it.
fn negotiate_pmd(ext_header: Option<&str>) -> Option<PmdParams> {
    let ext_header = ext_header?;
    let offer = ext_header
        .split(',')
        .find(|part| part.trim_start().starts_with("permessage-deflate"))?;

    let mut params = PmdParams::default();
    for token in offer.split(';').skip(1) {
        match token.trim() {
            "server_no_context_takeover" => params.server_no_context_takeover = true,
            "client_no_context_takeover" => params.client_no_context_takeover = true,
            _ => {} // unrecognized/unsupported parameter (e.g. a custom window size) -- ignored
        }
    }
    Some(params)
}

fn pmd_response_extension_header(params: &PmdParams) -> String {
    let mut s = "permessage-deflate".to_string();
    if params.server_no_context_takeover {
        s.push_str("; server_no_context_takeover");
    }
    if params.client_no_context_takeover {
        s.push_str("; client_no_context_takeover");
    }
    s
}

/// Builds the `101 Switching Protocols` response for a successful
/// handshake. `pmd` is `Some` if the client offered permessage-deflate
/// and the server accepted it -- the response then advertises
/// acceptance via `Sec-WebSocket-Extensions`.
pub fn build_handshake_response(req: &HttpRequest, pmd: Option<PmdParams>) -> crate::http::response::HttpResponse {
    let mut resp = crate::http::response::HttpResponse::new(101, "Switching Protocols");
    resp.set_header("Upgrade", "websocket");
    resp.set_header("Connection", "Upgrade");
    if let Some(key) = req.get_header("Sec-WebSocket-Key") {
        resp.set_header("Sec-WebSocket-Accept", compute_accept(key));
    }
    if let Some(params) = pmd {
        resp.set_header("Sec-WebSocket-Extensions", pmd_response_extension_header(&params));
    }
    resp
}

// ─── Frame header build/parse (RFC 6455 5.2) ────────────────────────────

/// Builds a frame header (everything before the payload) for a
/// server-to-client frame. Servers never mask their own frames (RFC
/// 6455 5.1: masking is one-directional, client-to-server only) --
/// there's no mask-key parameter here at all, unlike the client-side
/// framing this same RFC section describes.
fn build_frame_header(opcode: Opcode, fin: bool, rsv1: bool, payload_len: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(14);
    let byte0 = (if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | opcode.to_byte();
    header.push(byte0);

    if payload_len <= 125 {
        header.push(payload_len as u8);
    } else if payload_len <= u64::from(u16::MAX) {
        header.push(126);
        header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        header.push(127);
        header.extend_from_slice(&payload_len.to_be_bytes());
    }

    header
}

fn unmask_payload(data: &mut [u8], mask: [u8; 4]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
}

/// One parsed frame header (the fixed + extended-length + mask-key
/// part, everything before the payload bytes start).
#[derive(Debug, PartialEq)]
struct ParsedHeader {
    fin: bool,
    rsv1: bool,
    opcode: Opcode,
    mask: Option<[u8; 4]>,
    payload_len: u64,
    header_len: usize, // total bytes this header occupied
}

fn parse_frame_header(data: &[u8], require_masking: bool) -> Result<Option<ParsedHeader>, CloseCode> {
    if data.len() < 2 {
        return Ok(None); // need at least the two fixed bytes
    }

    let byte0 = data[0];
    let byte1 = data[1];
    let fin = byte0 & 0x80 != 0;
    let rsv1 = byte0 & 0x40 != 0;
    let rsv2 = byte0 & 0x20 != 0;
    let rsv3 = byte0 & 0x10 != 0;
    if rsv2 || rsv3 {
        // RSV2/RSV3 have no meaning without an extension that defines
        // them (permessage-deflate only uses RSV1) -- a peer setting
        // either is a protocol error per RFC 6455 5.2.
        return Err(CloseCode::ProtocolError);
    }

    let Some(opcode) = Opcode::from_byte(byte0 & 0x0f) else {
        return Err(CloseCode::ProtocolError); // reserved opcode
    };

    let masked = byte1 & 0x80 != 0;
    if !masked && require_masking {
        // RFC 6455 5.1: every client-to-server frame MUST be masked.
        // `require_masking` exists purely as an interop escape hatch
        // (see `WsConfig::require_masking`) -- disabling it accepts
        // non-conformant clients (e.g. certain test/debug tooling) at
        // the cost of RFC compliance, never the other way around.
        return Err(CloseCode::ProtocolError);
    }

    let len_field = byte1 & 0x7f;
    let mut pos = 2;

    let payload_len: u64 = if len_field <= 125 {
        u64::from(len_field)
    } else if len_field == 126 {
        if data.len() < pos + 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        u64::from(len)
    } else {
        if data.len() < pos + 8 {
            return Ok(None);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[pos..pos + 8]);
        pos += 8;
        u64::from_be_bytes(bytes)
    };

    if opcode.is_control() && (payload_len > 125 || !fin) {
        // RFC 6455 5.4/5.5: control frames can't be fragmented and are
        // capped at a 125-byte payload.
        return Err(CloseCode::ProtocolError);
    }

    let mask = if masked {
        if data.len() < pos + 4 {
            return Ok(None);
        }
        let mut mask = [0u8; 4];
        mask.copy_from_slice(&data[pos..pos + 4]);
        pos += 4;
        Some(mask)
    } else {
        None
    };

    Ok(Some(ParsedHeader {
        fin,
        rsv1,
        opcode,
        mask,
        payload_len,
        header_len: pos,
    }))
}

// ─── permessage-deflate (RFC 7692) ──────────────────────────────────────

/// A raw-deflate (no zlib header) trailer RFC 7692 7.2.1 requires
/// removing from a compressed message before sending, and re-adding
/// before decompressing -- both sides implicitly agree it's there
/// (it's always the same 4 bytes), so transmitting it on every message
/// would be pure overhead.
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// One direction's persistent deflate stream state. `no_context_takeover`
/// resets the compressor/decompressor after every message instead of
/// carrying dictionary state forward -- trades away some compression
/// ratio for not having to keep that much state alive across messages
/// (relevant for a server holding many idle WS connections open at
/// once).
pub struct PmdContext {
    compress: flate2::Compress,
    decompress: flate2::Decompress,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
}

impl PmdContext {
    pub fn new(params: PmdParams) -> Self {
        Self::with_compression_level(params, 6)
    }

    /// Same as `new`, but with `WsConfig::compression_level` (1-9,
    /// zlib/deflate's usual speed-vs-ratio knob) applied instead of
    /// flate2's default -- kept separate from `new` for the same
    /// reason `WsConnection::with_limits` is separate from
    /// `WsConnection::new` (see its doc comment).
    pub fn with_compression_level(params: PmdParams, compression_level: u32) -> Self {
        let level = flate2::Compression::new(compression_level.clamp(0, 9));
        PmdContext {
            compress: flate2::Compress::new(level, false),
            decompress: flate2::Decompress::new(false),
            server_no_context_takeover: params.server_no_context_takeover,
            client_no_context_takeover: params.client_no_context_takeover,
        }
    }

    /// Compresses one message's payload for sending, per RFC 7692
    /// 7.2.1: deflate with `Z_SYNC_FLUSH`, then strip the trailing 4
    /// bytes that flush always appends (both sides know to re-add
    /// them before decompressing).
    pub fn compress(&mut self, data: &[u8]) -> Vec<u8> {
        if self.server_no_context_takeover {
            self.compress.reset();
        }
        let mut out = Vec::with_capacity(data.len());
        // Tracked locally rather than derived from the stream's
        // total_in()/total_out() -- those are CUMULATIVE across every
        // call ever made to this Compress instance (that's exactly
        // what makes context takeover -- carrying dictionary state
        // across messages -- work), so using them to compute an
        // offset into THIS call's `data` slice would misalign as soon
        // as a second message came through with a nonzero prior
        // total_in().
        let mut input_consumed: usize = 0;
        loop {
            let before_out = self.compress.total_out();
            out.resize(out.len() + 4096, 0);
            let out_len = out.len();
            let before_in_this_call = self.compress.total_in();
            let status = self
                .compress
                .compress(&data[input_consumed..], &mut out[out_len - 4096..], flate2::FlushCompress::Sync)
                .unwrap_or(flate2::Status::Ok);
            let consumed_this_round = (self.compress.total_in() - before_in_this_call) as usize;
            input_consumed += consumed_this_round;
            let produced = (self.compress.total_out() - before_out) as usize;
            out.truncate(out.len() - 4096 + produced);
            if input_consumed >= data.len() || status == flate2::Status::StreamEnd {
                break;
            }
        }
        if out.ends_with(&DEFLATE_TAIL) {
            out.truncate(out.len() - DEFLATE_TAIL.len());
        }
        out
    }

    /// Decompresses one received message's payload, reversing
    /// `compress` -- re-appends the 4-byte tail `compress` stripped,
    /// then inflates. Enforces `max_output` to guard against a
    /// maliciously (or accidentally) crafted small input that expands
    /// to an enormous output ("zip bomb") -- returns `Err` rather than
    /// letting decompression run unbounded.
    pub fn decompress(&mut self, data: &[u8], max_output: usize) -> Result<Vec<u8>, ()> {
        if self.client_no_context_takeover {
            self.decompress.reset(false);
        }
        let mut input = data.to_vec();
        input.extend_from_slice(&DEFLATE_TAIL);

        // Tracked locally for the same reason `compress` does -- see
        // its comment. Decompress's total_in()/total_out() are
        // likewise cumulative across every call on this instance.
        let mut input_consumed: usize = 0;
        let mut out = Vec::new();
        loop {
            let before_out = self.decompress.total_out();
            let chunk_cap = 4096.min(max_output.saturating_sub(out.len()) + 1);
            if out.len() >= max_output {
                return Err(());
            }
            out.resize(out.len() + chunk_cap, 0);
            let out_len = out.len();
            let before_in_this_call = self.decompress.total_in();
            let status = self
                .decompress
                .decompress(&input[input_consumed..], &mut out[out_len - chunk_cap..], flate2::FlushDecompress::Sync)
                .map_err(|_| ())?;
            let consumed_this_round = (self.decompress.total_in() - before_in_this_call) as usize;
            input_consumed += consumed_this_round;
            let produced = (self.decompress.total_out() - before_out) as usize;
            out.truncate(out.len() - chunk_cap + produced);

            if out.len() > max_output {
                return Err(());
            }
            if input_consumed >= input.len() || status == flate2::Status::StreamEnd {
                break;
            }
        }
        Ok(out)
    }
}

// ─── permessage-deflate (RFC 7692) ──────────────────────────────────────

/// A raw-deflate (no zlib header) trailer RFC 7692 7.2.1 requires
/// removing from a compressed message before sending, and re-adding
/// before decompressing -- both sides implicitly agree it's there
/// (it's always the same 4 bytes), so transmitting it on every message
/// would be pure overhead.
// ─── WsConnection: per-connection fragmentation + dispatch state ────────

#[derive(Debug, Clone)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
}

/// One event `WsConnection::advance` reports back to its caller.
pub enum WsEvent {
    Message(WsMessage),
    /// A close handshake was received (and, if this is the first
    /// close either side has sent, echoed back automatically -- see
    /// `WsConnection::advance`'s doc comment). The connection should
    /// be torn down once any queued `to_send` bytes are flushed.
    Closed { code: Option<u16>, reason: String },
}

#[derive(Default)]
pub struct WsAdvanceResult {
    pub to_send: Vec<u8>,
    pub events: Vec<WsEvent>,
    pub protocol_error: bool,
    /// Set when a PONG frame was received this call -- see
    /// `WsRegistry::record_pong`, which this drives (through
    /// `core::event_loop`) to reset the connection's missed-ping count.
    pub pong_received: bool,
}

enum FragmentState {
    None,
    /// Accumulating a fragmented text/binary message. `compressed`
    /// reflects the RSV1 bit on the *first* fragment (RFC 7692 6.1: PMD
    /// applies to the whole message, RSV1 is only meaningful on the
    /// first fragment).
    InProgress {
        opcode: Opcode, // Text or Binary -- which the reassembled message will be
        data: Vec<u8>,
        compressed: bool,
    },
}

pub struct WsConnection {
    read_buf: Vec<u8>,
    fragment: FragmentState,
    pmd: Option<PmdContext>,
    max_message_size: usize,
    max_frame_size: u64,
    require_masking: bool,
    close_sent: bool,
    close_received: bool,
}

impl WsConnection {
    pub fn new(pmd: Option<PmdContext>, max_message_size: usize) -> Self {
        Self::with_limits(pmd, max_message_size, u64::MAX, true)
    }

    /// Same as `new`, but with `WsConfig::max_frame_size` and
    /// `WsConfig::require_masking` also applied -- kept as a separate
    /// constructor rather than extra `new` parameters so every existing
    /// caller/test that only cares about PMD and the message-size cap
    /// (the two limits this type has always enforced) doesn't need to
    /// grow two more arguments it has no opinion on.
    pub fn with_limits(pmd: Option<PmdContext>, max_message_size: usize, max_frame_size: u64, require_masking: bool) -> Self {
        Self::with_read_buf_capacity(pmd, max_message_size, max_frame_size, require_masking, 0)
    }

    /// Same as `with_limits`, but additionally reserves
    /// `WsConfig::read_buf_size` bytes of capacity in `read_buf` up
    /// front -- purely a throughput optimization (avoids repeated
    /// reallocation as the first few frames arrive), never a hard cap:
    /// `read_buf` still grows past this if a frame needs more room.
    pub fn with_read_buf_capacity(
        pmd: Option<PmdContext>,
        max_message_size: usize,
        max_frame_size: u64,
        require_masking: bool,
        read_buf_size: usize,
    ) -> Self {
        WsConnection {
            read_buf: Vec::with_capacity(read_buf_size),
            fragment: FragmentState::None,
            pmd,
            max_message_size,
            max_frame_size,
            require_masking,
            close_sent: false,
            close_received: false,
        }
    }

    /// Feeds newly-arrived bytes and parses as many complete frames as
    /// are available, reassembling fragmented messages and answering
    /// control frames (PING -> PONG automatically; the first CLOSE
    /// received gets echoed back automatically, matching RFC 6455
    /// 5.5.1's closing handshake). A protocol violation closes the
    /// connection (`protocol_error: true`, with a CLOSE frame already
    /// queued in `to_send`) rather than silently ignoring the bad
    /// frame -- WebSocket framing errors are inherently unrecoverable
    /// (there's no way to resynchronize mid-stream), so continuing to
    /// parse after one would just misinterpret subsequent bytes.
    pub fn advance(&mut self, data: &[u8]) -> WsAdvanceResult {
        self.read_buf.extend_from_slice(data);
        let mut result = WsAdvanceResult::default();

        loop {
            let header = match parse_frame_header(&self.read_buf, self.require_masking) {
                Ok(Some(h)) => h,
                Ok(None) => break, // incomplete -- wait for more bytes
                Err(close_code) => {
                    self.fail(close_code, &mut result);
                    return result;
                }
            };

            if header.payload_len > self.max_frame_size {
                // WsConfig::max_frame_size bounds a single frame's
                // payload -- distinct from max_message_size, which
                // bounds a (possibly multi-frame) reassembled message.
                self.fail(CloseCode::MessageTooBig, &mut result);
                return result;
            }

            let total_len = header.header_len + header.payload_len as usize;
            if self.read_buf.len() < total_len {
                break; // header parsed, but payload hasn't fully arrived yet
            }

            let mut payload = self.read_buf[header.header_len..total_len].to_vec();
            if let Some(mask) = header.mask {
                unmask_payload(&mut payload, mask);
            }

            if let Err(close_code) = self.handle_frame(&header, payload, &mut result) {
                self.fail(close_code, &mut result);
                return result;
            }
            if self.close_sent {
                break;
            }

            self.read_buf.drain(..total_len);
        }

        result
    }

    fn fail(&mut self, code: CloseCode, result: &mut WsAdvanceResult) {
        if !self.close_sent {
            self.queue_close(code as u16, "", result);
        }
        result.protocol_error = true;
    }

    fn queue_close(&mut self, code: u16, reason: &str, result: &mut WsAdvanceResult) {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        let header = build_frame_header(Opcode::Close, true, false, payload.len() as u64);
        result.to_send.extend_from_slice(&header);
        result.to_send.extend_from_slice(&payload);
        self.close_sent = true;
    }
}

impl WsConnection {
    fn handle_frame(
        &mut self,
        header: &ParsedHeader,
        payload: Vec<u8>,
        result: &mut WsAdvanceResult,
    ) -> Result<(), CloseCode> {
        match header.opcode {
            Opcode::Ping => {
                let pong_header = build_frame_header(Opcode::Pong, true, false, payload.len() as u64);
                result.to_send.extend_from_slice(&pong_header);
                result.to_send.extend_from_slice(&payload);
                Ok(())
            }
            Opcode::Pong => {
                result.pong_received = true;
                Ok(())
            }
            Opcode::Close => {
                self.close_received = true;
                let (code, reason) = parse_close_payload(&payload)?;
                if !self.close_sent {
                    self.queue_close(CloseCode::Normal as u16, "", result);
                }
                result.events.push(WsEvent::Closed { code, reason });
                Ok(())
            }
            Opcode::Continuation => {
                let FragmentState::InProgress { data, .. } = &mut self.fragment else {
                    return Err(CloseCode::ProtocolError); // continuation with no message in progress
                };
                if data.len() + payload.len() > self.max_message_size {
                    return Err(CloseCode::MessageTooBig);
                }
                data.extend_from_slice(&payload);
                if header.fin {
                    self.finish_message(result)?;
                }
                Ok(())
            }
            Opcode::Text | Opcode::Binary => {
                if matches!(self.fragment, FragmentState::InProgress { .. }) {
                    return Err(CloseCode::ProtocolError); // new message before previous fragment sequence finished
                }
                if payload.len() > self.max_message_size {
                    return Err(CloseCode::MessageTooBig);
                }
                self.fragment = FragmentState::InProgress {
                    opcode: header.opcode,
                    data: payload,
                    compressed: header.rsv1,
                };
                if header.fin {
                    self.finish_message(result)?;
                }
                Ok(())
            }
        }
    }

    /// Called once a message's final fragment (or a whole unfragmented
    /// frame) has arrived -- decompresses if PMD was used, validates
    /// UTF-8 for text messages, and emits the assembled `WsMessage`.
    fn finish_message(&mut self, result: &mut WsAdvanceResult) -> Result<(), CloseCode> {
        let FragmentState::InProgress { opcode, data, compressed } =
            std::mem::replace(&mut self.fragment, FragmentState::None)
        else {
            unreachable!("finish_message is only called with a fragment in progress")
        };

        let payload = if compressed {
            let Some(pmd) = &mut self.pmd else {
                // RSV1 set but PMD was never negotiated -- protocol error.
                return Err(CloseCode::ProtocolError);
            };
            pmd.decompress(&data, self.max_message_size)
                .map_err(|_| CloseCode::MessageTooBig)?
        } else {
            data
        };

        let message = match opcode {
            Opcode::Text => {
                let text = String::from_utf8(payload).map_err(|_| CloseCode::InvalidFramePayloadData)?;
                WsMessage::Text(text)
            }
            Opcode::Binary => WsMessage::Binary(payload),
            _ => unreachable!("finish_message is only reached for Text/Binary fragment sequences"),
        };

        result.events.push(WsEvent::Message(message));
        Ok(())
    }
}

/// Parses a CLOSE frame's payload per RFC 6455 5.5.1: an optional
/// 2-byte big-endian status code followed by an optional UTF-8 reason
/// string. Validates the code is in a sendable range (rejecting
/// reserved/never-sent codes like 1005/1006/1015, which describe
/// conditions rather than being codes a peer would ever actually
/// transmit) and that the reason (if present) is valid UTF-8.
fn parse_close_payload(payload: &[u8]) -> Result<(Option<u16>, String), CloseCode> {
    if payload.is_empty() {
        return Ok((None, String::new()));
    }
    if payload.len() < 2 {
        return Err(CloseCode::ProtocolError); // a lone code byte makes no sense
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if !is_valid_close_code(code) {
        return Err(CloseCode::ProtocolError);
    }
    let reason = String::from_utf8(payload[2..].to_vec()).map_err(|_| CloseCode::InvalidFramePayloadData)?;
    Ok((Some(code), reason))
}

/// RFC 6455 7.4: codes 1004, 1005, 1006, and 1015 describe local/internal
/// conditions and must never actually appear on the wire; codes below
/// 1000 or above 4999 are outside any defined range at all. This
/// deliberately doesn't enumerate every code in the 1012-2999
/// reserved-for-future-use range as individually invalid, so a
/// legitimately IANA-registered future code isn't rejected just for
/// being unrecognized today.
fn is_valid_close_code(code: u16) -> bool {
    !matches!(code, 1004 | 1005 | 1006 | 1015) && (1000..=4999).contains(&code)
}

impl WsConnection {
    /// Builds the frame(s) for sending `data` as a single (unfragmented)
    /// message of the given opcode -- routa never fragments its own
    /// outbound messages (fragmentation is purely a sender's choice per
    /// RFC 6455 5.4; there's no benefit to it for messages routa
    /// generates itself, since the whole payload is available up
    /// front). Compresses via PMD first if negotiated and the payload
    /// meets `compression_threshold`.
    fn send_frame(&mut self, data: &[u8], opcode: Opcode, compression_threshold: usize) -> Vec<u8> {
        let (payload, rsv1): (std::borrow::Cow<'_, [u8]>, bool) =
            match (&mut self.pmd, opcode) {
                (Some(pmd), Opcode::Text | Opcode::Binary) if data.len() >= compression_threshold => {
                    (std::borrow::Cow::Owned(pmd.compress(data)), true)
                }
                _ => (std::borrow::Cow::Borrowed(data), false),
            };

        let mut out = build_frame_header(opcode, true, rsv1, payload.len() as u64);
        out.extend_from_slice(&payload);
        out
    }

    pub fn send_text(&mut self, text: &str, compression_threshold: usize) -> Vec<u8> {
        self.send_frame(text.as_bytes(), Opcode::Text, compression_threshold)
    }

    pub fn send_binary(&mut self, data: &[u8], compression_threshold: usize) -> Vec<u8> {
        self.send_frame(data, Opcode::Binary, compression_threshold)
    }

    /// Control frames (RFC 6455 5.5) never use PMD, regardless of
    /// negotiation -- compression only ever applies to Text/Binary
    /// payloads.
    pub fn ping(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = build_frame_header(Opcode::Ping, true, false, payload.len() as u64);
        out.extend_from_slice(payload);
        out
    }

    pub fn pong(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = build_frame_header(Opcode::Pong, true, false, payload.len() as u64);
        out.extend_from_slice(payload);
        out
    }

    /// Initiates a close handshake (RFC 6455 5.5.1) if one hasn't
    /// already been sent -- a no-op otherwise, so callers can call this
    /// unconditionally without checking state themselves.
    pub fn close(&mut self, code: CloseCode, reason: &str) -> Vec<u8> {
        if self.close_sent {
            return Vec::new();
        }
        let mut result = WsAdvanceResult::default();
        self.queue_close(code as u16, reason, &mut result);
        result.to_send
    }

    pub fn is_closed(&self) -> bool {
        self.close_sent && self.close_received
    }
}

// ─── WsRegistry: per-worker connection registry + broadcast ─────────────

use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A message queued for broadcast to every open WebSocket connection a
/// worker owns.
pub struct BroadcastMessage {
    pub data: Vec<u8>,
    pub opcode: Opcode,
}

/// The sending half of a worker's broadcast channel -- cheap to clone
/// and hand to however many other threads need to be able to
/// broadcast to this worker's connections (e.g. an admin/pubsub
/// endpoint handled by a different worker).
#[derive(Clone)]
pub struct BroadcastSender {
    tx: mpsc::Sender<BroadcastMessage>,
    waker: Arc<mio::Waker>,
}

impl BroadcastSender {
    /// Queues `message` for delivery and wakes the owning worker's
    /// poller so it notices the message promptly rather than only at
    /// its next unrelated timeout/readiness event.
    pub fn send(&self, message: BroadcastMessage) -> Result<(), ()> {
        self.tx.send(message).map_err(|_| ())?;
        self.waker.wake().map_err(|_| ())
    }
}

/// One worker's registry of open WebSocket connections, keyed by
/// whatever connection identifier the caller's connection table
/// already uses (see `core::conn::ConnId`) -- this module doesn't
/// need to know anything about the connection beyond that id and its
/// ping/pong bookkeeping.
pub struct WsRegistry {
    connections: std::collections::HashMap<u64, ConnectionEntry>,
    broadcast_rx: mpsc::Receiver<BroadcastMessage>,
    broadcast_tx: mpsc::Sender<BroadcastMessage>,
    waker: Arc<mio::Waker>,
}

struct ConnectionEntry {
    last_pong: Instant,
    ping_misses: u32,
}

impl WsRegistry {
    /// `waker_token` is the `PollKey`/token this registry's internal
    /// `mio::Waker` will report as ready in `poll()` -- the caller
    /// should treat readiness on that specific key as "drain the
    /// broadcast queue via `dispatch_broadcast`", distinct from any
    /// real socket's readiness.
    pub fn new(poller_registry: &mio::Registry, waker_token: PollKey) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let waker = Arc::new(mio::Waker::new(poller_registry, mio::Token(waker_token_index(waker_token)))?);
        Ok(WsRegistry {
            connections: std::collections::HashMap::new(),
            broadcast_rx: rx,
            broadcast_tx: tx,
            waker,
        })
    }

    /// A cloneable handle other threads use to broadcast to this
    /// registry's connections.
    pub fn sender(&self) -> BroadcastSender {
        BroadcastSender {
            tx: self.broadcast_tx.clone(),
            waker: Arc::clone(&self.waker),
        }
    }

    pub fn add(&mut self, conn_id: u64) {
        self.connections.insert(
            conn_id,
            ConnectionEntry {
                last_pong: Instant::now(),
                ping_misses: 0,
            },
        );
    }

    pub fn remove(&mut self, conn_id: u64) {
        self.connections.remove(&conn_id);
    }

    pub fn record_pong(&mut self, conn_id: u64) {
        if let Some(entry) = self.connections.get_mut(&conn_id) {
            entry.last_pong = Instant::now();
            entry.ping_misses = 0;
        }
    }

    /// Drains every currently-queued broadcast message and returns the
    /// framed bytes to send to every currently-registered connection
    /// (same bytes for all of them -- caller writes this to each
    /// connection's own write buffer). Called when this registry's
    /// waker token reports readiness.
    pub fn dispatch_broadcast(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Ok(msg) = self.broadcast_rx.try_recv() {
            let header = build_frame_header(msg.opcode, true, false, msg.data.len() as u64);
            out.extend_from_slice(&header);
            out.extend_from_slice(&msg.data);
        }
        out
    }

    /// Returns the connection ids that need a PING sent (haven't ponged
    /// within `ping_timeout` since their last one) and, separately,
    /// which have missed `max_misses` consecutive pings and should be
    /// forcibly closed. Callers call this on a periodic sweep (e.g.
    /// every `ping_interval`), send a PING to every id in the first
    /// list (bumping their miss counter -- see `record_ping_sent`), and
    /// tear down every id in the second.
    pub fn ping_sweep(&self, now: Instant, ping_timeout: Duration, max_misses: u32) -> (Vec<u64>, Vec<u64>) {
        let mut due_for_ping = Vec::new();
        let mut should_close = Vec::new();
        for (&id, entry) in &self.connections {
            if now.duration_since(entry.last_pong) >= ping_timeout {
                if entry.ping_misses >= max_misses {
                    should_close.push(id);
                } else {
                    due_for_ping.push(id);
                }
            }
        }
        (due_for_ping, should_close)
    }

    pub fn record_ping_sent(&mut self, conn_id: u64) {
        if let Some(entry) = self.connections.get_mut(&conn_id) {
            entry.ping_misses += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    pub fn contains(&self, conn_id: u64) -> bool {
        self.connections.contains_key(&conn_id)
    }

    pub fn ids(&self) -> Vec<u64> {
        self.connections.keys().copied().collect()
    }
}

fn waker_token_index(key: PollKey) -> usize {
    // PollKey's inner index isn't publicly exposed (by design -- see
    // its own doc comment), but a Waker's token only needs to be
    // *some* value the caller's poll() loop can recognize as "this is
    // the waker, not a real connection" -- reusing the same
    // slab-index encoding PollKey itself uses keeps this consistent
    // with how every other registration in this codebase picks a
    // token, rather than inventing a separate, disconnected numbering
    // scheme just for this one waker.
    key.slab_index()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;

    fn make_upgrade_request(key: Option<&str>, version: Option<&str>) -> HttpRequest {
        let mut headers = vec![
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
        ];
        if let Some(k) = key {
            headers.push(("Sec-WebSocket-Key".to_string(), k.to_string()));
        }
        if let Some(v) = version {
            headers.push(("Sec-WebSocket-Version".to_string(), v.to_string()));
        }
        HttpRequest {
            method: HttpMethod::Get,
            remote_addr: None,
            path: "/ws".to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers,
            body: Vec::new(),
            keep_alive: true,
            trailers: Vec::new(),
        }
    }

    // ─── Handshake ────────────────────────────────────────────────────

    #[test]
    fn valid_upgrade_request_recognized() {
        let req = make_upgrade_request(Some("dGhlIHNhbXBsZSBub25jZQ=="), Some("13"));
        assert!(is_upgrade_request(&req));
    }

    #[test]
    fn missing_key_is_not_an_upgrade() {
        let req = make_upgrade_request(None, Some("13"));
        assert!(!is_upgrade_request(&req));
    }

    #[test]
    fn wrong_version_is_not_an_upgrade() {
        let req = make_upgrade_request(Some("dGhlIHNhbXBsZSBub25jZQ=="), Some("8"));
        assert!(!is_upgrade_request(&req));
    }

    #[test]
    fn connection_header_with_multiple_tokens_still_recognized() {
        // "Connection: keep-alive, Upgrade" -- a real client is allowed
        // to list multiple tokens, "upgrade" just needs to be one of
        // them (case-insensitively).
        let mut req = make_upgrade_request(Some("dGhlIHNhbXBsZSBub25jZQ=="), Some("13"));
        req.headers.retain(|(k, _)| k != "Connection");
        req.headers.push(("Connection".to_string(), "keep-alive, Upgrade".to_string()));
        assert!(is_upgrade_request(&req));
    }

    #[test]
    fn accept_key_matches_rfc_6455_worked_example() {
        // RFC 6455 1.3's own worked example.
        let accept = compute_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn build_handshake_response_has_101_and_accept_header() {
        let req = make_upgrade_request(Some("dGhlIHNhbXBsZSBub25jZQ=="), Some("13"));
        let resp = build_handshake_response(&req, None);
        assert_eq!(resp.status, 101);
        assert_eq!(resp.get_header("Sec-WebSocket-Accept"), Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert_eq!(resp.get_header("Upgrade"), Some("websocket"));
    }

    // ─── PMD negotiation ────────────────────────────────────────────

    #[test]
    fn pmd_negotiated_when_offered() {
        let params = negotiate_pmd(Some("permessage-deflate"));
        assert!(params.is_some());
    }

    #[test]
    fn pmd_not_negotiated_when_absent() {
        assert!(negotiate_pmd(None).is_none());
        assert!(negotiate_pmd(Some("some-other-extension")).is_none());
    }

    #[test]
    fn pmd_context_takeover_params_parsed() {
        let params = negotiate_pmd(Some(
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
        ))
        .unwrap();
        assert!(params.server_no_context_takeover);
        assert!(params.client_no_context_takeover);
    }

    #[test]
    fn pmd_offered_among_multiple_extensions() {
        let params = negotiate_pmd(Some("foo, permessage-deflate; server_no_context_takeover, bar"));
        assert!(params.is_some());
        assert!(params.unwrap().server_no_context_takeover);
    }

    // ─── Frame header build/parse ────────────────────────────────────

    fn mask_data(data: &mut [u8], mask: [u8; 4]) {
        unmask_payload(data, mask); // XOR is its own inverse -- same function masks and unmasks
    }

    /// Parses a server-to-client frame (unmasked, per RFC 6455 5.1) --
    /// distinct from `parse_frame_header`, which enforces the
    /// client-to-server masking requirement and would reject anything
    /// this module itself produces. Returns just the opcode and
    /// payload for the tests that only need to confirm what routa sent
    /// back, not the full header.
    struct ServerFrame {
        opcode: Opcode,
        payload_len: usize,
        header_len: usize,
    }

    fn parse_server_frame(data: &[u8]) -> ServerFrame {
        assert!(data.len() >= 2, "expected at least a 2-byte frame header");
        let byte0 = data[0];
        let byte1 = data[1];
        assert_eq!(byte1 & 0x80, 0, "server-to-client frames must never be masked");
        let opcode = Opcode::from_byte(byte0 & 0x0f).expect("valid opcode");

        let len_field = byte1 & 0x7f;
        let (payload_len, header_len) = if len_field <= 125 {
            (len_field as usize, 2)
        } else if len_field == 126 {
            let len = u16::from_be_bytes([data[2], data[3]]) as usize;
            (len, 4)
        } else {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[2..10]);
            (u64::from_be_bytes(bytes) as usize, 10)
        };

        ServerFrame {
            opcode,
            payload_len,
            header_len,
        }
    }

    fn build_client_frame(opcode: Opcode, fin: bool, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let mut frame = Vec::new();
        let byte0 = (if fin { 0x80 } else { 0 }) | opcode.to_byte();
        frame.push(byte0);

        let len = payload.len();
        if len <= 125 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);

        let mut masked_payload = payload.to_vec();
        mask_data(&mut masked_payload, mask);
        frame.extend_from_slice(&masked_payload);
        frame
    }

    #[test]
    fn parses_small_masked_frame() {
        let frame = build_client_frame(Opcode::Text, true, b"hello", [1, 2, 3, 4]);
        let header = parse_frame_header(&frame, true).unwrap().unwrap();
        assert_eq!(header.opcode, Opcode::Text);
        assert!(header.fin);
        assert_eq!(header.payload_len, 5);
    }

    #[test]
    fn unmasked_client_frame_is_protocol_error() {
        let mut frame = build_client_frame(Opcode::Text, true, b"hi", [0, 0, 0, 0]);
        frame[1] &= 0x7f; // clear the mask bit -- client frames must always be masked
        let result = parse_frame_header(&frame, true);
        assert_eq!(result, Err(CloseCode::ProtocolError));
    }

    #[test]
    fn extended_16_bit_length_parses_correctly() {
        let payload = vec![b'x'; 200]; // > 125, needs the 16-bit length form
        let frame = build_client_frame(Opcode::Binary, true, &payload, [9, 9, 9, 9]);
        let header = parse_frame_header(&frame, true).unwrap().unwrap();
        assert_eq!(header.payload_len, 200);
    }

    #[test]
    fn extended_64_bit_length_parses_correctly() {
        let payload = vec![b'x'; 70_000]; // > 65535, needs the 64-bit length form
        let frame = build_client_frame(Opcode::Binary, true, &payload, [1, 1, 1, 1]);
        let header = parse_frame_header(&frame, true).unwrap().unwrap();
        assert_eq!(header.payload_len, 70_000);
    }

    #[test]
    fn incomplete_header_returns_none_not_error() {
        assert_eq!(parse_frame_header(&[0x81], true).unwrap(), None);
    }

    #[test]
    fn reserved_opcode_is_protocol_error() {
        let mut frame = build_client_frame(Opcode::Text, true, b"x", [1, 2, 3, 4]);
        frame[0] = (frame[0] & 0xf0) | 0x3; // 0x3 is a reserved (undefined) opcode
        assert_eq!(parse_frame_header(&frame, true), Err(CloseCode::ProtocolError));
    }

    #[test]
    fn rsv2_or_rsv3_set_is_protocol_error() {
        let mut frame = build_client_frame(Opcode::Text, true, b"x", [1, 2, 3, 4]);
        frame[0] |= 0x20; // RSV2
        assert_eq!(parse_frame_header(&frame, true), Err(CloseCode::ProtocolError));
    }

    #[test]
    fn fragmented_control_frame_is_protocol_error() {
        let frame = build_client_frame(Opcode::Ping, false, b"x", [1, 2, 3, 4]); // fin=false
        assert_eq!(parse_frame_header(&frame, true), Err(CloseCode::ProtocolError));
    }

    #[test]
    fn oversized_control_frame_is_protocol_error() {
        let payload = vec![b'x'; 126]; // > 125-byte control frame limit
        let frame = build_client_frame(Opcode::Ping, true, &payload, [1, 2, 3, 4]);
        assert_eq!(parse_frame_header(&frame, true), Err(CloseCode::ProtocolError));
    }

    // ─── WsConnection: single-frame messages ─────────────────────────

    fn make_connection() -> WsConnection {
        WsConnection::new(None, 1024 * 1024)
    }

    fn extract_messages(result: &WsAdvanceResult) -> Vec<WsMessage> {
        result
            .events
            .iter()
            .filter_map(|e| match e {
                WsEvent::Message(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn single_text_frame_produces_message() {
        let mut conn = make_connection();
        let frame = build_client_frame(Opcode::Text, true, b"hello", [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(!result.protocol_error);
        let messages = extract_messages(&result);
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            WsMessage::Text(t) => assert_eq!(t, "hello"),
            _ => panic!("expected a text message"),
        }
    }

    #[test]
    fn single_binary_frame_produces_message() {
        let mut conn = make_connection();
        let frame = build_client_frame(Opcode::Binary, true, &[1, 2, 3], [5, 5, 5, 5]);
        let result = conn.advance(&frame);
        let messages = extract_messages(&result);
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            WsMessage::Binary(b) => assert_eq!(b, &vec![1, 2, 3]),
            _ => panic!("expected a binary message"),
        }
    }

    #[test]
    fn partial_frame_produces_no_message_yet() {
        let mut conn = make_connection();
        let frame = build_client_frame(Opcode::Text, true, b"hello", [1, 2, 3, 4]);
        let result = conn.advance(&frame[..frame.len() - 2]); // withhold the last 2 bytes
        assert!(extract_messages(&result).is_empty());
        assert!(!result.protocol_error);
    }

    #[test]
    fn frame_split_across_two_advance_calls() {
        let mut conn = make_connection();
        let frame = build_client_frame(Opcode::Text, true, b"hello world", [1, 2, 3, 4]);
        let (first_half, second_half) = frame.split_at(frame.len() / 2);

        let result1 = conn.advance(first_half);
        assert!(extract_messages(&result1).is_empty());

        let result2 = conn.advance(second_half);
        let messages = extract_messages(&result2);
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            WsMessage::Text(t) => assert_eq!(t, "hello world"),
            _ => panic!("expected a text message"),
        }
    }

    // ─── Fragmentation ────────────────────────────────────────────────

    #[test]
    fn fragmented_text_message_reassembles() {
        let mut conn = make_connection();
        let mut input = Vec::new();
        input.extend_from_slice(&build_client_frame(Opcode::Text, false, b"hello ", [1, 1, 1, 1]));
        input.extend_from_slice(&build_client_frame(Opcode::Continuation, false, b"cruel ", [2, 2, 2, 2]));
        input.extend_from_slice(&build_client_frame(Opcode::Continuation, true, b"world", [3, 3, 3, 3]));

        let result = conn.advance(&input);
        let messages = extract_messages(&result);
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            WsMessage::Text(t) => assert_eq!(t, "hello cruel world"),
            _ => panic!("expected a text message"),
        }
    }

    #[test]
    fn orphan_continuation_is_protocol_error() {
        let mut conn = make_connection();
        let frame = build_client_frame(Opcode::Continuation, true, b"x", [1, 1, 1, 1]);
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    #[test]
    fn new_message_before_fragment_complete_is_protocol_error() {
        let mut conn = make_connection();
        let mut input = Vec::new();
        input.extend_from_slice(&build_client_frame(Opcode::Text, false, b"start", [1, 1, 1, 1]));
        input.extend_from_slice(&build_client_frame(Opcode::Text, true, b"new message", [2, 2, 2, 2]));

        let result = conn.advance(&input);
        assert!(result.protocol_error);
    }

    #[test]
    fn control_frame_interleaved_with_fragmentation_is_allowed() {
        // RFC 6455 5.4: control frames MAY be injected in the middle of
        // a fragmented message.
        let mut conn = make_connection();
        let mut input = Vec::new();
        input.extend_from_slice(&build_client_frame(Opcode::Text, false, b"hello ", [1, 1, 1, 1]));
        input.extend_from_slice(&build_client_frame(Opcode::Ping, true, b"ping-payload", [2, 2, 2, 2]));
        input.extend_from_slice(&build_client_frame(Opcode::Continuation, true, b"world", [3, 3, 3, 3]));

        let result = conn.advance(&input);
        assert!(!result.protocol_error);
        let messages = extract_messages(&result);
        assert_eq!(messages.len(), 1);

        // The interleaved PING should still have gotten a PONG queued.
        let pong_header = parse_server_frame(&result.to_send);
        assert_eq!(pong_header.opcode, Opcode::Pong);
    }

    // ─── UTF-8 validation ────────────────────────────────────────────

    #[test]
    fn invalid_utf8_text_message_is_protocol_error() {
        let mut conn = make_connection();
        let invalid_utf8 = vec![0xff, 0xfe, 0xfd];
        let frame = build_client_frame(Opcode::Text, true, &invalid_utf8, [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    #[test]
    fn valid_multibyte_utf8_text_message_accepted() {
        let mut conn = make_connection();
        let text = "héllo wörld 日本語"; // multi-byte UTF-8
        let frame = build_client_frame(Opcode::Text, true, text.as_bytes(), [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(!result.protocol_error);
        let messages = extract_messages(&result);
        match &messages[0] {
            WsMessage::Text(t) => assert_eq!(t, text),
            _ => panic!("expected a text message"),
        }
    }

    #[test]
    fn invalid_utf8_split_across_fragments_is_protocol_error() {
        // The invalid byte sequence only becomes apparent once the
        // fragments are reassembled -- a naive per-fragment UTF-8 check
        // could miss a multi-byte sequence split across a fragment
        // boundary; validation must happen on the reassembled whole.
        let mut conn = make_connection();
        let mut input = Vec::new();
        input.extend_from_slice(&build_client_frame(Opcode::Text, false, &[0xe2, 0x82], [1, 1, 1, 1])); // incomplete 3-byte sequence
        input.extend_from_slice(&build_client_frame(Opcode::Continuation, true, &[0xff], [2, 2, 2, 2])); // invalid continuation
        let result = conn.advance(&input);
        assert!(result.protocol_error);
    }

    // ─── Ping/Pong/Close ──────────────────────────────────────────────

    #[test]
    fn ping_gets_automatic_pong() {
        let mut conn = make_connection();
        let frame = build_client_frame(Opcode::Ping, true, b"payload", [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        let header = parse_server_frame(&result.to_send);
        assert_eq!(header.opcode, Opcode::Pong);
        assert!(!result.protocol_error);
    }

    #[test]
    fn close_frame_gets_echoed_and_reported() {
        let mut conn = make_connection();
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(b"bye");
        let frame = build_client_frame(Opcode::Close, true, &payload, [1, 2, 3, 4]);
        let result = conn.advance(&frame);

        assert!(conn.close_sent);
        let has_close_event = result
            .events
            .iter()
            .any(|e| matches!(e, WsEvent::Closed { code: Some(1000), reason } if reason == "bye"));
        assert!(has_close_event);

        let echoed = parse_server_frame(&result.to_send);
        assert_eq!(echoed.opcode, Opcode::Close);
    }

    #[test]
    fn close_with_no_payload_is_valid() {
        let mut conn = make_connection();
        let frame = build_client_frame(Opcode::Close, true, &[], [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(!result.protocol_error);
    }

    #[test]
    fn close_with_forbidden_code_is_protocol_error() {
        let mut conn = make_connection();
        let mut payload = Vec::new();
        payload.extend_from_slice(&1006u16.to_be_bytes()); // 1006 must never appear on the wire
        let frame = build_client_frame(Opcode::Close, true, &payload, [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    #[test]
    fn close_with_invalid_utf8_reason_is_protocol_error() {
        let mut conn = make_connection();
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8 reason
        let frame = build_client_frame(Opcode::Close, true, &payload, [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    #[test]
    fn send_close_is_idempotent() {
        let mut conn = make_connection();
        let first = conn.close(CloseCode::Normal, "bye");
        assert!(!first.is_empty());
        let second = conn.close(CloseCode::Normal, "bye again");
        assert!(second.is_empty(), "calling close() twice should be a no-op the second time");
    }

    // ─── Message size limits ─────────────────────────────────────────

    #[test]
    fn oversized_message_is_rejected() {
        let mut conn = WsConnection::new(None, 10); // tiny limit for this test
        let frame = build_client_frame(Opcode::Text, true, b"this is way more than 10 bytes", [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    #[test]
    fn oversized_fragmented_message_is_rejected() {
        let mut conn = WsConnection::new(None, 10);
        let mut input = Vec::new();
        input.extend_from_slice(&build_client_frame(Opcode::Text, false, b"12345", [1, 1, 1, 1]));
        input.extend_from_slice(&build_client_frame(Opcode::Continuation, true, b"678910111213", [2, 2, 2, 2]));
        let result = conn.advance(&input);
        assert!(result.protocol_error);
    }

    #[test]
    fn max_frame_size_rejects_a_single_oversized_frame() {
        // WsConfig::max_frame_size bounds one frame's payload, distinct
        // from max_message_size (which governs the reassembled total).
        // A generous message-size limit here proves it's genuinely the
        // frame-size check firing, not the message-size one.
        let mut conn = WsConnection::with_limits(None, 1024 * 1024, 10, true);
        let frame = build_client_frame(Opcode::Binary, true, &[0u8; 50], [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    #[test]
    fn max_frame_size_allows_frames_at_or_under_the_limit() {
        let mut conn = WsConnection::with_limits(None, 1024, 10, true);
        let frame = build_client_frame(Opcode::Binary, true, &[0u8; 10], [1, 2, 3, 4]);
        let result = conn.advance(&frame);
        assert!(!result.protocol_error);
    }

    #[test]
    fn require_masking_false_accepts_unmasked_frames() {
        let mut conn = WsConnection::with_limits(None, 1024, 1024, false);
        let mut frame = build_client_frame(Opcode::Text, true, b"hi", [0, 0, 0, 0]);
        frame[1] &= 0x7f; // clear the mask bit -- an unmasked frame, which default (require_masking=true) rejects
        // Payload bytes are sent raw (never masked) to match the cleared bit.
        let header_len = 2; // opcode/fin byte + length byte, no mask key present
        frame.truncate(header_len);
        frame.extend_from_slice(b"hi");
        let result = conn.advance(&frame);
        assert!(!result.protocol_error);
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], WsEvent::Message(WsMessage::Text(t)) if t == "hi"));
    }

    #[test]
    fn require_masking_true_still_rejects_unmasked_frames() {
        let mut conn = WsConnection::with_limits(None, 1024, 1024, true);
        let mut frame = build_client_frame(Opcode::Text, true, b"hi", [0, 0, 0, 0]);
        frame[1] &= 0x7f;
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    // ─── permessage-deflate ──────────────────────────────────────────

    #[test]
    fn pmd_compress_decompress_round_trips() {
        let mut server = PmdContext::new(PmdParams::default());
        let mut client = PmdContext::new(PmdParams::default());
        let original = "the quick brown fox jumps over the lazy dog ".repeat(20);

        let compressed = server.compress(original.as_bytes());
        assert!(compressed.len() < original.len(), "compression should actually shrink repetitive text");

        let decompressed = client.decompress(&compressed, 1024 * 1024).unwrap();
        assert_eq!(decompressed, original.as_bytes());
    }

    #[test]
    fn pmd_context_takeover_across_multiple_messages() {
        // Without no_context_takeover, the compressor's dictionary
        // persists across messages -- later messages referencing
        // earlier content should compress at least as well.
        let mut server = PmdContext::new(PmdParams::default());
        let mut client = PmdContext::new(PmdParams::default());

        let msg1 = "hello world hello world hello world";
        let msg2 = "hello world hello world hello world"; // identical content, second message

        let c1 = server.compress(msg1.as_bytes());
        let d1 = client.decompress(&c1, 1024).unwrap();
        assert_eq!(d1, msg1.as_bytes());

        let c2 = server.compress(msg2.as_bytes());
        let d2 = client.decompress(&c2, 1024).unwrap();
        assert_eq!(d2, msg2.as_bytes());
    }

    #[test]
    fn pmd_no_context_takeover_resets_between_messages() {
        let params = PmdParams {
            server_no_context_takeover: true,
            client_no_context_takeover: true,
        };
        let mut server = PmdContext::new(params);
        let mut client = PmdContext::new(params);

        let msg1 = "first message content";
        let msg2 = "second message content";

        let c1 = server.compress(msg1.as_bytes());
        assert_eq!(client.decompress(&c1, 1024).unwrap(), msg1.as_bytes());

        let c2 = server.compress(msg2.as_bytes());
        assert_eq!(client.decompress(&c2, 1024).unwrap(), msg2.as_bytes());
    }

    #[test]
    fn pmd_decompress_respects_output_limit() {
        let mut server = PmdContext::new(PmdParams::default());
        let mut client = PmdContext::new(PmdParams::default());
        let large = "x".repeat(100_000);
        let compressed = server.compress(large.as_bytes());
        let result = client.decompress(&compressed, 100); // far smaller than the real output
        assert!(result.is_err());
    }

    #[test]
    fn end_to_end_compressed_message_via_ws_connection() {
        let pmd_params = PmdParams::default();
        let mut sender_ctx = PmdContext::new(pmd_params);
        let mut receiver = WsConnection::new(Some(PmdContext::new(pmd_params)), 1024 * 1024);

        let text = "compressible compressible compressible compressible text";
        let compressed = sender_ctx.compress(text.as_bytes());
        let header = build_frame_header(Opcode::Text, true, true, compressed.len() as u64); // rsv1 = true

        // Build a masked client frame manually with RSV1 set (build_client_frame
        // doesn't set RSV1, so this constructs it directly).
        let mut frame = Vec::new();
        let mask = [7u8, 7, 7, 7];
        frame.push(header[0]); // already has FIN+RSV1+opcode from build_frame_header
        let len = compressed.len();
        if len <= 125 {
            frame.push(0x80 | len as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        let mut masked = compressed.clone();
        mask_data(&mut masked, mask);
        frame.extend_from_slice(&masked);

        let result = receiver.advance(&frame);
        assert!(!result.protocol_error, "compressed message should decode successfully");
        let messages = extract_messages(&result);
        match &messages[0] {
            WsMessage::Text(t) => assert_eq!(t, text),
            _ => panic!("expected a text message"),
        }
    }

    #[test]
    fn rsv1_without_negotiated_pmd_is_protocol_error() {
        let mut conn = WsConnection::new(None, 1024 * 1024); // no PMD negotiated
        let mut frame = build_client_frame(Opcode::Text, true, b"data", [1, 2, 3, 4]);
        frame[0] |= 0x40; // set RSV1 anyway
        let result = conn.advance(&frame);
        assert!(result.protocol_error);
    }

    // ─── WsRegistry ─────────────────────────────────────────────────

    fn make_registry() -> (WsRegistry, MioPoller) {
        let poller = crate::net::poller::MioPoller::new(16).unwrap();
        let waker_key = PollKey::from_slab_index(9999);
        let registry = WsRegistry::new(poller.registry(), waker_key).unwrap();
        (registry, poller)
    }

    use crate::net::poller::MioPoller;

    #[test]
    fn registry_tracks_add_and_remove() {
        let (mut registry, _poller) = make_registry();
        registry.add(1);
        registry.add(2);
        assert_eq!(registry.len(), 2);
        registry.remove(1);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn broadcast_message_is_dispatched() {
        let (mut registry, _poller) = make_registry();
        registry.add(1);
        registry.add(2);

        let sender = registry.sender();
        sender
            .send(BroadcastMessage {
                data: b"hello all".to_vec(),
                opcode: Opcode::Text,
            })
            .unwrap();

        let out = registry.dispatch_broadcast();
        let header = parse_server_frame(&out);
        assert_eq!(header.opcode, Opcode::Text);
        assert_eq!(&out[header.header_len..], b"hello all");
    }

    #[test]
    fn dispatch_broadcast_drains_multiple_queued_messages() {
        let (mut registry, _poller) = make_registry();
        let sender = registry.sender();
        sender.send(BroadcastMessage { data: b"one".to_vec(), opcode: Opcode::Text }).unwrap();
        sender.send(BroadcastMessage { data: b"two".to_vec(), opcode: Opcode::Text }).unwrap();

        let out = registry.dispatch_broadcast();
        // Both messages should be present, concatenated -- parse the
        // first frame, then confirm a second complete frame follows it.
        let first_header = parse_server_frame(&out);
        let first_total_len = first_header.header_len + first_header.payload_len;
        assert!(out.len() > first_total_len, "expected a second frame after the first");

        let second_header = parse_server_frame(&out[first_total_len..]);
        assert_eq!(second_header.opcode, Opcode::Text);
    }

    #[test]
    fn ping_sweep_identifies_due_connections() {
        let (mut registry, _poller) = make_registry();
        registry.add(1);

        // Immediately after adding, nothing is due yet (last_pong == now).
        let (due, closed) = registry.ping_sweep(Instant::now(), Duration::from_secs(30), 3);
        assert!(due.is_empty());
        assert!(closed.is_empty());

        // Simulate time passing by checking against a "now" far in the future.
        let future = Instant::now() + Duration::from_secs(60);
        let (due, closed) = registry.ping_sweep(future, Duration::from_secs(30), 3);
        assert_eq!(due, vec![1]);
        assert!(closed.is_empty());
    }

    #[test]
    fn ping_sweep_closes_after_max_misses() {
        let (mut registry, _poller) = make_registry();
        registry.add(1);

        let future = Instant::now() + Duration::from_secs(60);
        for _ in 0..3 {
            registry.record_ping_sent(1);
        }
        let (_due, closed) = registry.ping_sweep(future, Duration::from_secs(30), 3);
        assert_eq!(closed, vec![1]);
    }

    #[test]
    fn record_pong_resets_miss_counter() {
        let (mut registry, _poller) = make_registry();
        registry.add(1);
        registry.record_ping_sent(1);
        registry.record_ping_sent(1);
        registry.record_pong(1);

        let future = Instant::now() + Duration::from_secs(60);
        let (due, closed) = registry.ping_sweep(future, Duration::from_secs(30), 3);
        assert_eq!(due, vec![1]); // due again since time passed, but not closed
        assert!(closed.is_empty());
    }
}
