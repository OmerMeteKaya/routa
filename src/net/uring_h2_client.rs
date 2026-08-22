//! HTTP/2 client state machine for uring_backend's upstream
//! connections -- the io_uring-completion-model counterpart to
//! `net::h2_client::H2Client`. Frame/HPACK handling is deliberately
//! identical to that module (copied rather than shared -- see this
//! module's own top doc comment for why a generic/trait-based merge
//! wasn't chosen), but this type does none of its own I/O: unlike
//! `H2Client`, which owns a `mio::net::TcpStream` and calls
//! `advance_io` on it directly, this type only ever receives already-
//! decrypted plaintext bytes (fed in by uring_backend's own
//! OP_TAG_RECV handling, after TLS decryption the same way any other
//! upstream connection's response bytes are) and produces bytes to
//! send (drained via `take_write_buf`, the same way uring_backend's
//! own submit_send drains any other protocol's write_buf) -- the
//! "state machine advances, caller owns all I/O" pattern taken one
//! step further than H2Client's own version of it, since even TLS
//! itself is the caller's concern here rather than this type's.
//!
//! Kept in `net` (rather than `core::conn` alongside uring_backend's
//! other protocol state) since, like `H2Client`, this is fundamentally
//! about speaking the H2 wire protocol as a client -- not about this
//! backend's own connection/Slab bookkeeping, which
//! `core::conn::uring_conn::ConnectionRole::Upstream` already carries
//! separately (this type doesn't know or care what node, pool, or
//! downstream connection it's serving).

use std::collections::HashMap;

use crate::http::h2::frame::{self, Frame, FrameType};
use crate::http::h2::hpack::{HeaderField, HpackContext};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DEFAULT_WINDOW_SIZE: i32 = 65_535;
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

/// One request/response exchange in flight on the connection -- same
/// shape and role as `h2_client::ClientStream`.
struct ClientStream {
    send_window: i64,
    header_block: Vec<u8>,
    response_headers: Vec<HeaderField>,
    response_body: Vec<u8>,
    headers_done: bool,
    end_stream_received: bool,
    last_io: std::time::Instant,
}

impl ClientStream {
    fn new(send_window: i32) -> Self {
        ClientStream {
            send_window: i64::from(send_window),
            header_block: Vec::new(),
            response_headers: Vec::new(),
            response_body: Vec::new(),
            headers_done: false,
            end_stream_received: false,
            last_io: std::time::Instant::now(),
        }
    }
}

/// A completed response, handed back once a stream's END_STREAM has
/// arrived and its headers have been fully decoded -- same shape as
/// `h2_client::ClientResponse`.
pub struct ClientResponse {
    pub status: u16,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
}

/// Whether the initial connection-establishment sequence (preface +
/// SETTINGS exchange) has completed -- unlike `H2Client`'s own
/// `H2ClientState`, this doesn't track `Connecting`/`TlsHandshake` at
/// all, since uring_backend's own OP_TAG_CONNECT/TLS-handshake
/// handling already covers both before a `UringH2Client` is ever
/// constructed (see `UringH2Client::new`, called only once a real TCP
/// connection -- and, for a TLS node, a real TLS handshake -- has
/// already finished).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefaceState {
    /// The client preface + SETTINGS haven't been sent yet -- call
    /// `initial_send` once to get them.
    NotSent,
    /// Sent, waiting for the peer's own initial SETTINGS frame.
    AwaitingPeerSettings,
    /// Peer's SETTINGS seen and ACKed -- `open_stream` may now be
    /// called.
    Ready,
}

pub struct UringH2Client {
    pub preface_state: PrefaceState,

    next_stream_id: u32,
    streams: HashMap<u32, ClientStream>,

    peer_max_concurrent_streams: u32,
    peer_max_frame_size: u32,
    stream_init_window: i32,
    conn_send_window: i64,

    encoder: HpackContext,
    decoder: HpackContext,

    read_buf: Vec<u8>,
    pub write_buf: Vec<u8>,
}

impl UringH2Client {
    pub fn new() -> Self {
        UringH2Client {
            preface_state: PrefaceState::NotSent,
            next_stream_id: 1,
            streams: HashMap::new(),
            peer_max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            peer_max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
            stream_init_window: DEFAULT_WINDOW_SIZE,
            conn_send_window: i64::from(DEFAULT_WINDOW_SIZE),
            encoder: HpackContext::new(4096),
            decoder: HpackContext::new(4096),
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    /// Queues the client preface, initial SETTINGS, and an initial
    /// connection-level WINDOW_UPDATE into `write_buf` -- call once,
    /// immediately after construction, before submitting this
    /// connection's first Send. Mirrors `H2Client::advance`'s own
    /// `SendingPreface` state, minus the state machine (there's
    /// nothing to poll for here -- see `PrefaceState`'s own doc
    /// comment on why TLS/TCP establishment isn't this type's concern).
    pub fn initial_send(&mut self) {
        self.write_buf.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut self.write_buf, &[]);
        let mut window_update = Vec::new();
        frame::write_window_update(&mut window_update, 0, 0x3fff_ffff);
        self.write_buf.extend_from_slice(&window_update);
        self.preface_state = PrefaceState::AwaitingPeerSettings;
    }

    pub fn has_capacity(&self) -> bool {
        (self.streams.len() as u32) < self.peer_max_concurrent_streams
    }

    /// Opens a new stream and writes its HEADERS (+ DATA, if `body`
    /// is non-empty) frames -- same contract as
    /// `H2Client::open_stream`.
    pub fn open_stream(&mut self, headers: &[HeaderField], body: &[u8]) -> Option<u32> {
        if !self.has_capacity() {
            return None;
        }
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        self.streams.insert(stream_id, ClientStream::new(self.stream_init_window));
        let encoded = self.encoder.encode(headers);
        let end_stream = body.is_empty();
        write_header_block_frames(&mut self.write_buf, stream_id, &encoded, self.peer_max_frame_size, end_stream);
        if !body.is_empty() {
            frame::write_data(&mut self.write_buf, stream_id, body, true);
        }
        Some(stream_id)
    }

    /// Bytes ready to send to the transport -- read-only view, paired
    /// with `consume_write_buf` for after a (possibly partial) Send
    /// completes. Kept as a borrow-and-consume pair rather than
    /// `H2Client::take_write_buf`'s own "take it all, caller re-queues
    /// leftovers if the write was partial" shape, since
    /// uring_backend's own `submit_send`/`consume_active_write_buf`
    /// pattern (shared across every other protocol's write_buf)
    /// already assumes this shape -- matching it here means
    /// UpstreamH2 needs no special-casing in that shared code beyond
    /// the lookup itself.
    pub fn write_buf_slice(&self) -> &[u8] {
        &self.write_buf
    }

    pub fn consume_write_buf(&mut self, n: usize) {
        self.write_buf.drain(..n);
    }

    pub fn has_pending_write(&self) -> bool {
        !self.write_buf.is_empty()
    }

    /// Feeds newly-arrived plaintext (already TLS-decrypted, if this
    /// connection is TLS -- see this module's own top doc comment) and
    /// processes every complete frame it can find, including this
    /// connection's own initial SETTINGS exchange if that hasn't
    /// happened yet. Returns every stream id whose response just
    /// became complete this call -- same contract as
    /// `H2Client::process_readable`, minus that method's own
    /// `advance_io`/`read_plaintext` calls (the caller already did the
    /// TLS-decryption equivalent of both before calling this).
    pub fn feed_plaintext(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u32>> {
        self.read_buf.extend_from_slice(plaintext);

        let mut completed = Vec::new();
        let mut pos = 0;
        loop {
            let Some((header, payload_owned, consumed)) = ({
                let Some((frame, consumed)) = frame::parse_frame(&self.read_buf[pos..]) else {
                    break;
                };
                Some((frame.header, frame.payload.to_vec(), consumed))
            }) else {
                break;
            };

            if self.preface_state == PrefaceState::AwaitingPeerSettings
                && header.frame_type == FrameType::Settings
                && header.flags & frame::FLAG_ACK == 0
            {
                self.apply_settings(&payload_owned);
                frame::write_settings_ack(&mut self.write_buf);
                self.preface_state = PrefaceState::Ready;
            } else {
                self.dispatch_frame(header, &payload_owned, &mut completed);
            }
            pos += consumed;
        }
        self.read_buf.drain(..pos);

        Ok(completed)
    }

    fn dispatch_frame(&mut self, header: frame::FrameHeader, payload: &[u8], completed: &mut Vec<u32>) {
        let frame = Frame { header, payload };
        let frame = &frame;
        match frame.header.frame_type {
            FrameType::Settings => {
                if frame.header.flags & frame::FLAG_ACK == 0 {
                    self.apply_settings(frame.payload);
                    frame::write_settings_ack(&mut self.write_buf);
                }
            }
            FrameType::Headers => self.handle_headers(frame, completed),
            FrameType::Continuation => self.handle_continuation(frame, completed),
            FrameType::Data => self.handle_data(frame, completed),
            FrameType::WindowUpdate => self.handle_window_update(frame),
            FrameType::RstStream => {
                self.streams.remove(&frame.header.stream_id);
            }
            FrameType::Ping => {
                if frame.header.flags & frame::FLAG_ACK == 0 && frame.payload.len() == 8 {
                    let mut payload = [0u8; 8];
                    payload.copy_from_slice(frame.payload);
                    frame::write_ping(&mut self.write_buf, &payload, true);
                }
            }
            FrameType::GoAway => {
                // The upstream is going away -- nothing to send in
                // response; the caller's connection-pool/circuit-
                // breaker logic is responsible for not reusing this
                // client for new streams once it notices this
                // connection won't accept more.
            }
            FrameType::Priority | FrameType::PushPromise | FrameType::Unknown(_) => {}
        }
    }

    fn handle_headers(&mut self, frame: &Frame<'_>, completed: &mut Vec<u32>) {
        let stream_id = frame.header.stream_id;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.last_io = std::time::Instant::now();

        let mut payload = frame.payload;
        if frame.header.flags & frame::FLAG_PADDED != 0 {
            let Some(&pad_len) = payload.first() else { return };
            let pad_len = pad_len as usize;
            if payload.len() < 1 + pad_len {
                return;
            }
            payload = &payload[1..payload.len() - pad_len];
        }
        if frame.header.flags & frame::FLAG_PRIORITY != 0 {
            if payload.len() < 5 {
                return;
            }
            payload = &payload[5..];
        }

        stream.header_block.extend_from_slice(payload);

        if frame.header.flags & frame::FLAG_END_HEADERS != 0 {
            self.finish_headers(stream_id);
        }

        if frame.header.flags & frame::FLAG_END_STREAM != 0 {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.end_stream_received = true;
                if stream.headers_done {
                    completed.push(stream_id);
                }
            }
        }
    }

    fn handle_continuation(&mut self, frame: &Frame<'_>, completed: &mut Vec<u32>) {
        let stream_id = frame.header.stream_id;
        if !self.streams.contains_key(&stream_id) {
            return;
        }
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.header_block.extend_from_slice(frame.payload);
        }
        if frame.header.flags & frame::FLAG_END_HEADERS != 0 {
            self.finish_headers(stream_id);
            if let Some(stream) = self.streams.get(&stream_id) {
                if stream.end_stream_received {
                    completed.push(stream_id);
                }
            }
        }
    }

    fn finish_headers(&mut self, stream_id: u32) {
        if self.streams.get(&stream_id).is_none() {
            return;
        }
        let header_block = std::mem::take(&mut self.streams.get_mut(&stream_id).unwrap().header_block);
        let Ok(fields) = self.decoder.decode(&header_block) else {
            self.streams.remove(&stream_id);
            return;
        };
        let stream = self.streams.get_mut(&stream_id).unwrap();
        stream.response_headers = fields;
        stream.headers_done = true;
    }

    fn handle_data(&mut self, frame: &Frame<'_>, completed: &mut Vec<u32>) {
        let stream_id = frame.header.stream_id;

        let mut payload = frame.payload;
        if frame.header.flags & frame::FLAG_PADDED != 0 {
            let Some(&pad_len) = payload.first() else { return };
            let pad_len = pad_len as usize;
            if payload.len() < 1 + pad_len {
                return;
            }
            payload = &payload[1..payload.len() - pad_len];
        }

        if !payload.is_empty() {
            frame::write_window_update(&mut self.write_buf, 0, payload.len() as u32);
            frame::write_window_update(&mut self.write_buf, stream_id, payload.len() as u32);
        }

        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        stream.last_io = std::time::Instant::now();
        stream.response_body.extend_from_slice(payload);

        if frame.header.flags & frame::FLAG_END_STREAM != 0 {
            stream.end_stream_received = true;
            if stream.headers_done {
                completed.push(stream_id);
            }
        }
    }

    fn handle_window_update(&mut self, frame: &Frame<'_>) {
        if frame.payload.len() != 4 {
            return;
        }
        let increment = u32::from_be_bytes([frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3]]) & 0x7fff_ffff;
        if frame.header.stream_id == 0 {
            self.conn_send_window += i64::from(increment);
        } else if let Some(stream) = self.streams.get_mut(&frame.header.stream_id) {
            stream.send_window += i64::from(increment);
            stream.last_io = std::time::Instant::now();
        }
    }

    fn apply_settings(&mut self, payload: &[u8]) {
        for chunk in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            match id {
                0x3 => self.peer_max_concurrent_streams = value,
                0x4 => {
                    if value <= 0x7fff_ffff {
                        self.stream_init_window = value as i32;
                        for stream in self.streams.values_mut() {
                            stream.send_window = i64::from(self.stream_init_window);
                        }
                    }
                }
                0x5 => {
                    if (frame::DEFAULT_MAX_FRAME_SIZE..=frame::ABSOLUTE_MAX_FRAME_SIZE).contains(&value) {
                        self.peer_max_frame_size = value;
                    }
                }
                _ => {}
            }
        }
    }

    pub fn timed_out_streams(&self, timeout: std::time::Duration) -> Vec<u32> {
        let now = std::time::Instant::now();
        self.streams
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_io) >= timeout)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn abandon_stream(&mut self, stream_id: u32) {
        if self.streams.remove(&stream_id).is_some() {
            frame::write_rst_stream(&mut self.write_buf, stream_id, 0x8);
        }
    }

    pub fn take_response(&mut self, stream_id: u32) -> Option<ClientResponse> {
        let stream = self.streams.remove(&stream_id)?;
        let status = stream
            .response_headers
            .iter()
            .find(|f| f.name == ":status")
            .and_then(|f| f.value.parse::<u16>().ok())
            .unwrap_or(200);
        let headers = stream
            .response_headers
            .into_iter()
            .filter(|f| !f.name.starts_with(':'))
            .collect();
        Some(ClientResponse {
            status,
            headers,
            body: stream.response_body,
        })
    }
}

impl Default for UringH2Client {
    fn default() -> Self {
        Self::new()
    }
}

fn write_header_block_frames(out: &mut Vec<u8>, stream_id: u32, encoded: &[u8], max_frame_size: u32, end_stream: bool) {
    let max_frame_size = max_frame_size as usize;
    if encoded.len() <= max_frame_size {
        frame::write_headers(out, stream_id, encoded, end_stream, true);
        return;
    }
    let (first, rest) = encoded.split_at(max_frame_size);
    frame::write_headers(out, stream_id, first, end_stream, false);
    let mut remaining = rest;
    while remaining.len() > max_frame_size {
        let (chunk, next_rest) = remaining.split_at(max_frame_size);
        frame::write_continuation(out, stream_id, chunk, false);
        remaining = next_rest;
    }
    frame::write_continuation(out, stream_id, remaining, true);
}
