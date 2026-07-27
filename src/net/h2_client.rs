//! HTTP/2 client for talking to upstream servers -- the counterpart
//! to `http::h2::stream::Connection`, which handles the server side.
//! Kept as a separate, client-specific state machine rather than a
//! "role" flag threaded through the server-side `Connection` type:
//! client and server streams have different lifecycles (a server
//! stream begins when a request arrives; a client stream begins when
//! *we* decide to open one and immediately write our own HEADERS),
//! different stream-id allocation rules (a client picks and increments
//! its own ids; a server only ever validates ids the peer chose), and
//! different concerns entirely (request validation/pseudo-header
//! checking is meaningless on the client side, since we're the one
//! constructing the request). Squeezing both into one type would mean
//! branching on role throughout every method rather than each side
//! being independently simple. The frame (`http::h2::frame`) and HPACK
//! (`http::h2::hpack`) layers are still shared -- those really are
//! identical on both sides of the connection.
//!
//! Connection establishment is a multi-step async state machine (TCP
//! connect -> TLS handshake with ALPN -> H2 preface send -> initial
//! SETTINGS exchange), advanced one poller event at a time via
//! `advance()` -- the same "state machine advances, caller owns all
//! I/O" shape used throughout this codebase (see
//! `net::tls::TlsConnection::advance_io` and the health-check probes
//! in `lb::upstream`), so establishing a connection never blocks the
//! calling worker thread regardless of how slow or unresponsive the
//! upstream is.
//!
//! Request header preparation (X-Forwarded-For/Via chains, hop-by-hop
//! header filtering, and any configured header add/remove rules) is
//! deliberately NOT this module's job -- `core::proxy` builds the
//! final header list once, the same way for both an H1 and an H2
//! upstream, so that policy lives in exactly one place rather than
//! risking the two paths drifting out of sync with each other.

use std::collections::HashMap;
use mio::net::TcpStream;

use crate::http::h2::frame::{self, Frame, FrameType};
use crate::http::h2::hpack::{HeaderField, HpackContext};
use crate::net::tls::TlsConnection;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DEFAULT_WINDOW_SIZE: i32 = 65_535;
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ClientState {
    Connecting,
    TlsHandshake,
    SendingPreface,
    ReadingSettings,
    Ready,
    Failed,
}

/// One request/response exchange in flight on the connection.
struct ClientStream {
    send_window: i64,
    header_block: Vec<u8>,
    response_headers: Vec<HeaderField>,
    response_body: Vec<u8>,
    headers_done: bool,
    end_stream_received: bool,
    /// Last time this stream saw any I/O activity (a HEADERS/DATA/
    /// WINDOW_UPDATE frame concerning it, in either direction) --
    /// lets a caller apply the same read/write timeout policy to an H2
    /// upstream that `lb::upstream`'s connection-pool timeout applies
    /// to an H1 one, at per-stream granularity rather than only being
    /// able to time out the whole shared connection at once. Updated
    /// in `open_stream` (a stream starts "alive" the moment it's
    /// opened) and every frame handler that touches a specific stream.
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
/// arrived and its headers have been fully decoded.
pub struct ClientResponse {
    pub status: u16,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
}

pub struct H2Client {
    pub state: H2ClientState,
    stream: TcpStream,
    tls: Box<TlsConnection>,

    preface_sent: bool,

    next_stream_id: u32,
    streams: HashMap<u32, ClientStream>,

    peer_max_concurrent_streams: u32,
    peer_max_frame_size: u32,
    stream_init_window: i32,
    conn_send_window: i64,

    encoder: HpackContext,
    decoder: HpackContext,

    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl H2Client {
    /// Starts a non-blocking connection to `addr`. Returns immediately
    /// with the client in `Connecting` state -- the caller registers
    /// the returned stream with a poller and calls `advance()` on
    /// every subsequent readiness event until it reports `Ready` or
    /// `Failed`.
    pub fn connect(addr: std::net::SocketAddr, tls_server_name: &str) -> std::io::Result<Self> {
        let tls = TlsConnection::new_client(
            tls_server_name,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Self::connect_with_tls(addr, tls)
    }

    /// Same as `connect`, but with an explicit trust store rather than
    /// the platform default -- exposed for this module's own tests,
    /// which need to trust a freshly-generated self-signed test
    /// certificate rather than a real CA-issued one (see
    /// `net::tls::TlsConnection::new_client_with_roots`, which this
    /// mirrors).
    #[cfg(test)]
    pub fn connect_with_roots(
        addr: std::net::SocketAddr,
        tls_server_name: &str,
        root_store: rustls::RootCertStore,
    ) -> std::io::Result<Self> {
        let tls = TlsConnection::new_client_with_roots(
            tls_server_name,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            root_store,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Self::connect_with_tls(addr, tls)
    }

    fn connect_with_tls(addr: std::net::SocketAddr, tls: TlsConnection) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let _ = stream.set_nodelay(true);

        Ok(H2Client {
            state: H2ClientState::Connecting,
            stream,
            tls: Box::new(tls),
            preface_sent: false,
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
        })
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Whether the negotiated ALPN protocol was actually "h2" -- checked
    /// once the TLS handshake completes; a peer that only supports
    /// HTTP/1.1 should fail this client over rather than speaking H2
    /// framing to a server that never agreed to it.
    fn alpn_is_h2(&self) -> bool {
        self.tls.alpn_protocol() == Some(b"h2".as_slice())
    }
}

impl H2Client {
    /// Advances connection establishment by one step in response to a
    /// poller readiness event. Returns:
    /// - `Ok(true)` once the connection reaches `Ready` (H2 negotiated
    ///   via ALPN, preface sent, initial SETTINGS exchanged) --
    ///   `open_stream` can now be called.
    /// - `Ok(false)` if still in progress -- keep waiting for the next
    ///   readiness event.
    /// - `Err(_)` on a fatal failure (state is now `Failed`) -- the
    ///   caller should treat this exactly like a failed connection
    ///   attempt: drop it and let the caller's retry/failover logic
    ///   (see `lb::upstream`'s circuit breaker) record the failure.
    pub fn advance(&mut self) -> std::io::Result<bool> {
        if self.state == H2ClientState::Connecting {
            match self.stream.take_error() {
                Ok(None) => {}
                _ => {
                    self.state = H2ClientState::Failed;
                    return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connect failed"));
                }
            }
            self.state = H2ClientState::TlsHandshake;
        }

        if self.state == H2ClientState::TlsHandshake {
            match self.tls.advance_io(&mut self.stream) {
                Ok(advance) => {
                    if self.tls.is_handshaking() {
                        return Ok(false);
                    }
                    if advance.peer_closed {
                        self.state = H2ClientState::Failed;
                        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "peer closed during handshake"));
                    }
                    if !self.alpn_is_h2() {
                        self.state = H2ClientState::Failed;
                        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "peer did not negotiate h2 via ALPN"));
                    }
                    self.state = H2ClientState::SendingPreface;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) => {
                    self.state = H2ClientState::Failed;
                    return Err(e);
                }
            }
        }

        if self.state == H2ClientState::SendingPreface {
            if !self.preface_sent {
                self.write_buf.extend_from_slice(CLIENT_PREFACE);
                frame::write_settings(&mut self.write_buf, &[]);
                let mut window_update = Vec::new();
                frame::write_window_update(&mut window_update, 0, 0x3fff_ffff);
                self.write_buf.extend_from_slice(&window_update);
                self.preface_sent = true;
            }
            match self.flush_write_buf() {
                Ok(true) => self.state = H2ClientState::ReadingSettings,
                Ok(false) => return Ok(false),
                Err(e) => {
                    self.state = H2ClientState::Failed;
                    return Err(e);
                }
            }
        }

        if self.state == H2ClientState::ReadingSettings {
            match self.advance_initial_settings_read() {
                Ok(true) => {
                    self.state = H2ClientState::Ready;
                    return Ok(true);
                }
                Ok(false) => return Ok(false),
                Err(e) => {
                    self.state = H2ClientState::Failed;
                    return Err(e);
                }
            }
        }

        Ok(self.state == H2ClientState::Ready)
    }

    /// Writes as much of `write_buf` as the underlying transport
    /// accepts right now, draining what's sent. Returns `Ok(true)`
    /// once fully drained, `Ok(false)` if more remains (would block).
    fn flush_write_buf(&mut self) -> std::io::Result<bool> {
        if self.write_buf.is_empty() {
            // Nothing queued -- no need to touch the transport at all.
            // Calling advance_io here unconditionally would risk
            // surfacing a connection-closed/reset error from a peer
            // that's done nothing wrong (e.g. it already sent its
            // response and is now closing normally) purely because
            // this side happened to poll I/O with nothing to say.
            return Ok(true);
        }
        while !self.write_buf.is_empty() {
            match self.tls.write_plaintext(&self.write_buf) {
                Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write returned 0")),
                Ok(n) => {
                    self.write_buf.drain(..n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        // write_plaintext only queues into rustls's own outgoing
        // buffer -- advance_io is what actually flushes that buffer to
        // the real socket via write_tls (see write_plaintext's doc
        // comment in net::tls). Without this, queued bytes sit in
        // rustls's buffer forever and the peer never receives them,
        // regardless of how many times write_plaintext itself reports
        // success.
        match self.tls.advance_io(&mut self.stream) {
            Ok(_) => Ok(self.write_buf.is_empty()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(self.write_buf.is_empty()),
            Err(e) => Err(e),
        }
    }

    /// Reads and processes frames until the upstream's initial
    /// (non-ACK) SETTINGS frame has been seen and ACKed -- mirrors the
    /// same "skip anything else, wait specifically for SETTINGS"
    /// contract during initial negotiation, bounded so a misbehaving
    /// peer sending an unbounded stream of non-SETTINGS frames can't
    /// hang this forever.
    fn advance_initial_settings_read(&mut self) -> std::io::Result<bool> {
        const MAX_SKIPPED_FRAMES: u32 = 20;
        let mut skipped = 0u32;

        loop {
            // read_plaintext only surfaces bytes rustls has ALREADY
            // decrypted into its own internal buffer -- advance_io is
            // what actually reads new TLS records off the real socket
            // and feeds rustls's decryption in the first place (the
            // mirror-image of write_plaintext needing advance_io to
            // flush its own outgoing buffer -- see flush_write_buf's
            // comment). Without this, read_plaintext would spin
            // forever seeing nothing new, even once the peer has
            // genuinely sent more data.
            match self.tls.advance_io(&mut self.stream) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }

            let mut chunk = [0u8; 4096];
            let n = match self.tls.read_plaintext(&mut chunk) {
                Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "peer closed during settings exchange")),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Nothing new arrived this call -- try to make
                    // progress on whatever's already buffered, or
                    // report "still waiting" if there isn't enough yet.
                    0
                }
                Err(e) => return Err(e),
            };
            if n == 0 && self.read_buf.is_empty() {
                return Ok(false); // genuinely nothing new -- wait for the next readiness event
            }
            self.read_buf.extend_from_slice(&chunk[..n]);

            let Some((frame, consumed)) = frame::parse_frame(&self.read_buf) else {
                if n == 0 {
                    return Ok(false); // no new data and no complete frame yet
                }
                continue; // got more bytes, but still not a complete frame -- read more
            };

            if frame.header.frame_type == FrameType::Settings && frame.header.flags & frame::FLAG_ACK == 0 {
                let payload = frame.payload.to_vec();
                self.apply_settings(&payload);
                frame::write_settings_ack(&mut self.write_buf);
                self.flush_write_buf()?;
                self.read_buf.drain(..consumed);
                return Ok(true);
            }

            // Anything else (a stray WINDOW_UPDATE, etc.) is read and
            // discarded the same way a blocking implementation would
            // skip past it one frame at a time, up to a bound.
            self.read_buf.drain(..consumed);
            skipped += 1;
            if skipped >= MAX_SKIPPED_FRAMES {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too many non-SETTINGS frames before initial SETTINGS"));
            }
        }
    }

    fn apply_settings(&mut self, payload: &[u8]) {
        for chunk in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            match id {
                0x3 => self.peer_max_concurrent_streams = value, // SETTINGS_MAX_CONCURRENT_STREAMS
                0x4 => {
                    // SETTINGS_INITIAL_WINDOW_SIZE
                    if value <= 0x7fff_ffff {
                        self.stream_init_window = value as i32;
                        for stream in self.streams.values_mut() {
                            stream.send_window = i64::from(self.stream_init_window);
                        }
                    }
                }
                0x5 => {
                    // SETTINGS_MAX_FRAME_SIZE
                    if (frame::DEFAULT_MAX_FRAME_SIZE..=frame::ABSOLUTE_MAX_FRAME_SIZE).contains(&value) {
                        self.peer_max_frame_size = value;
                    }
                }
                _ => {}
            }
        }
    }
}

impl H2Client {
    pub fn has_capacity(&self) -> bool {
        (self.streams.len() as u32) < self.peer_max_concurrent_streams
    }

    /// Opens a new stream and writes its HEADERS (+ DATA, if `body`
    /// is non-empty) frames. `headers` is the complete, final header
    /// list -- pseudo-headers (`:method`, `:path`, `:scheme`,
    /// `:authority`) included -- already assembled by the caller (see
    /// `core::proxy`, which is where X-Forwarded-For/Via construction
    /// and hop-by-hop filtering happen; this method has no policy of
    /// its own about what belongs in the header list).
    ///
    /// Returns the new stream's id, or `None` if the connection is
    /// already at its peer-advertised concurrent stream limit.
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

    /// Bytes ready to write to the transport -- callers drain this
    /// (via `flush_write_buf`, or their own equivalent write loop)
    /// whenever the connection's fd reports writable.
    pub fn take_write_buf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.write_buf)
    }

    /// Attempts to write everything currently queued. Public wrapper
    /// around the internal helper of the same name used during
    /// connection establishment -- exposed so a caller's normal
    /// request/response traffic can use the identical drain logic
    /// (partial-write-aware, WouldBlock-tolerant) rather than
    /// reimplementing it.
    pub fn flush(&mut self) -> std::io::Result<bool> {
        self.flush_write_buf()
    }
}

/// Writes a HEADERS frame (plus CONTINUATION frames if the encoded
/// header block is larger than one frame's worth) -- identical
/// framing logic to the server side's equivalent in
/// `http::h2::stream`, just not shared as a function between the two
/// modules since it's a handful of lines and pulling it into a third,
/// shared-but-tiny module didn't seem worth the indirection.
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

impl H2Client {
    /// Reads and processes as many frames as are currently available,
    /// returning every stream id whose response just became complete
    /// (headers decoded and END_STREAM seen) -- callers retrieve each
    /// one's `ClientResponse` via `take_response`.
    pub fn process_readable(&mut self) -> std::io::Result<Vec<u32>> {
        // advance_io first -- see advance_initial_settings_read's
        // comment on why read_plaintext alone can't observe new bytes
        // that haven't yet been pulled off the socket and decrypted.
        match self.tls.advance_io(&mut self.stream) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        loop {
            let mut chunk = [0u8; 8192];
            match self.tls.read_plaintext(&mut chunk) {
                Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed by peer")),
                Ok(n) => self.read_buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

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
            self.dispatch_frame(header, &payload_owned, &mut completed);
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
                // breaker logic (see `lb::upstream`) is responsible for
                // not reusing this client for new streams once it
                // notices this connection won't accept more.
            }
            FrameType::Priority | FrameType::PushPromise | FrameType::Unknown(_) => {}
        }
    }

    fn handle_headers(&mut self, frame: &Frame<'_>, completed: &mut Vec<u32>) {
        let stream_id = frame.header.stream_id;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return; // response for a stream we don't know (already completed/removed) -- ignore
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

        // Replenish flow control immediately, mirroring
        // `http::h2::stream`'s policy on the server side -- see that
        // module's `handle_data` for why the simplest possible
        // give-back-what-was-spent approach is used rather than
        // batching.
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

    /// Takes ownership of a completed stream's response, removing it
    /// from the connection's stream table. Returns `None` if
    /// `stream_id` isn't a completed (or even a known) stream --
    /// callers should only call this for ids `process_readable` just
    /// reported.
    /// Returns every stream id that has had no I/O activity for at
    /// least `timeout` -- callers (see `core::proxy`) send a
    /// stream-level RST_STREAM and surface a 504 to whichever
    /// frontend request that stream was serving, then call
    /// `abandon_stream` to remove it from this connection's table.
    /// Applying this per-stream (rather than only being able to time
    /// out the whole shared H2 connection at once) means one slow
    /// upstream response doesn't force killing every other
    /// in-flight stream sharing the same connection.
    pub fn timed_out_streams(&self, timeout: std::time::Duration) -> Vec<u32> {
        let now = std::time::Instant::now();
        self.streams
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_io) >= timeout)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Sends RST_STREAM for `stream_id` and removes it from this
    /// connection's table -- used both for a timed-out stream (see
    /// `timed_out_streams`) and any other case where a caller needs to
    /// give up on a stream without waiting for its response.
    pub fn abandon_stream(&mut self, stream_id: u32) {
        if self.streams.remove(&stream_id).is_some() {
            frame::write_rst_stream(&mut self.write_buf, stream_id, 0x8); // CANCEL
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h2::stream::Connection as ServerConnection;
    use crate::net::tls::{TlsConnection as ServerTlsConn, TlsContext};
    use std::io::{Read as StdRead, Write as StdWrite};
    use std::net::TcpListener;
    use std::time::Duration;

    fn field(name: &str, value: &str) -> HeaderField {
        HeaderField {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    /// Generates a fresh self-signed certificate/key pair valid for
    /// `hostname`, in memory -- mirrors `net::tls`'s own private test
    /// helper of the same shape (that one isn't `pub`, so this module
    /// needs its own copy rather than reusing it directly).
    fn generate_test_identity(hostname: &str) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![hostname.to_string()]).expect("generate cert");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        (cert_der, key_der)
    }

    /// Spawns a minimal H2 server on its own thread using
    /// `http::h2::stream::Connection` (the real server-side
    /// implementation) plus a real TLS handshake -- this exercises an
    /// actual client<->server H2 conversation over TLS+ALPN rather
    /// than mocking either side, so a real interoperability bug
    /// between the two implementations would show up here rather than
    /// being hidden by both sides sharing the same (possibly
    /// incorrect) assumption.
    fn spawn_test_server(response_body: &'static [u8], response_status: u16) -> (u16, String, rustls::pki_types::CertificateDer<'static>) {
        let (cert_der, key_der) = generate_test_identity("localhost");
        let trust_anchor = cert_der.clone();
        let ctx = TlsContext::builder_from_der(vec![cert_der], key_der)
            .unwrap()
            .build()
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (raw_stream, _) = listener.accept().unwrap();
            raw_stream.set_nonblocking(true).unwrap();
            let mut mio_stream = mio::net::TcpStream::from_std(raw_stream);

            let mut tls = ServerTlsConn::new_server(&ctx).unwrap();
            loop {
                match tls.advance_io(&mut mio_stream) {
                    Ok(_) if !tls.is_handshaking() => break,
                    Ok(_) => std::thread::sleep(Duration::from_millis(5)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }

            let mut conn = ServerConnection::new(128, 4096);
            let initial = conn.initial_send();
            let _ = write_all_blocking(&mut tls, &mut mio_stream, &initial);

            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                if std::time::Instant::now() > deadline {
                    return;
                }
                // advance_io first -- read_plaintext alone only sees
                // bytes rustls has already decrypted, not new bytes
                // still sitting unread on the actual socket (same
                // reasoning as the client side's own read paths).
                // Without this, an Ok(0) from read_plaintext could be
                // misread as a real EOF when it's actually just
                // "nothing decrypted yet", tearing this thread (and
                // its socket) down while the client is still
                // legitimately connected.
                match tls.advance_io(&mut mio_stream) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => return,
                }
                let mut chunk = [0u8; 4096];
                match tls.read_plaintext(&mut chunk) {
                    Ok(0) => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Ok(n) => {
                        let result = conn.advance(&chunk[..n]);
                        let _ = write_all_blocking(&mut tls, &mut mio_stream, &result.to_send);
                        for stream_id in result.newly_ready_streams {
                            let out = conn.send_response(
                                stream_id,
                                response_status,
                                &[field("content-type", "text/plain")],
                                response_body.to_vec(),
                            );
                            let _ = write_all_blocking(&mut tls, &mut mio_stream, &out);
                            // Give the client a comfortable window to
                            // read this response before this thread
                            // (and, with it, the socket) potentially
                            // goes away -- avoids a benign test-only
                            // race where this thread's own teardown
                            // races the client's own read of bytes
                            // that were already successfully written.
                            std::thread::sleep(Duration::from_millis(200));
                        }
                        if result.connection_closed {
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });

        (port, "localhost".to_string(), trust_anchor)
    }

    fn write_all_blocking(tls: &mut ServerTlsConn, stream: &mut mio::net::TcpStream, data: &[u8]) -> std::io::Result<()> {
        let mut sent = 0;
        while sent < data.len() {
            match tls.write_plaintext(&data[sent..]) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
        // Flush rustls's outgoing buffer to the real socket -- write_plaintext
        // alone only queues into rustls's own buffer (see its doc comment
        // in net::tls). Retried in a loop since a single advance_io call
        // may only drain part of a large buffer under WouldBlock.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tls.advance_io(stream) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > deadline {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Drives an `H2Client` through connection establishment against a
    /// real listener, blocking (via short sleeps and repeated
    /// `advance()` calls) until `Ready` -- test-only convenience; real
    /// callers drive this from poller events instead.
    fn connect_and_wait_ready(port: u16, server_name: &str, trust_anchor: rustls::pki_types::CertificateDer<'static>) -> H2Client {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(trust_anchor).expect("add test trust anchor");
        let mut client = H2Client::connect_with_roots(addr, server_name, root_store).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match client.advance() {
                Ok(true) => return client,
                Ok(false) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("connection establishment failed: {e}"),
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for H2Client to become Ready, stuck in state {:?}", client.state);
            }
        }
    }

    fn wait_for_response(client: &mut H2Client, stream_id: u32) -> ClientResponse {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            client.flush().unwrap();
            match client.process_readable() {
                Ok(completed) if completed.contains(&stream_id) => {
                    return client.take_response(stream_id).unwrap();
                }
                Ok(_) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("process_readable failed: {e}"),
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for response on stream {stream_id}");
            }
        }
    }

    #[test]
    fn establishes_connection_and_completes_handshake() {
        let (port, name, trust_anchor) = spawn_test_server(b"hello", 200);
        let client = connect_and_wait_ready(port, &name, trust_anchor);
        assert_eq!(client.state, H2ClientState::Ready);
    }

    #[test]
    fn sends_request_and_receives_response() {
        let (port, name, trust_anchor) = spawn_test_server(b"hello from server", 200);
        let mut client = connect_and_wait_ready(port, &name, trust_anchor);

        let stream_id = client
            .open_stream(
                &[
                    field(":method", "GET"),
                    field(":scheme", "https"),
                    field(":path", "/"),
                    field(":authority", "localhost"),
                ],
                &[],
            )
            .unwrap();
        client.flush().unwrap();

        let response = wait_for_response(&mut client, stream_id);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello from server");
    }

    #[test]
    fn receives_correct_status_code() {
        let (port, name, trust_anchor) = spawn_test_server(b"not found", 404);
        let mut client = connect_and_wait_ready(port, &name, trust_anchor);

        let stream_id = client
            .open_stream(
                &[
                    field(":method", "GET"),
                    field(":scheme", "https"),
                    field(":path", "/missing"),
                    field(":authority", "localhost"),
                ],
                &[],
            )
            .unwrap();
        client.flush().unwrap();

        let response = wait_for_response(&mut client, stream_id);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn multiple_sequential_requests_on_same_connection() {
        let (port, name, trust_anchor) = spawn_test_server(b"response body", 200);
        let mut client = connect_and_wait_ready(port, &name, trust_anchor);

        for _ in 0..3 {
            let stream_id = client
                .open_stream(
                    &[
                        field(":method", "GET"),
                        field(":scheme", "https"),
                        field(":path", "/"),
                        field(":authority", "localhost"),
                    ],
                    &[],
                )
                .unwrap();
            client.flush().unwrap();
            let response = wait_for_response(&mut client, stream_id);
            assert_eq!(response.body, b"response body");
        }
    }

    #[test]
    fn response_headers_exclude_pseudo_headers() {
        let (port, name, trust_anchor) = spawn_test_server(b"x", 200);
        let mut client = connect_and_wait_ready(port, &name, trust_anchor);

        let stream_id = client
            .open_stream(
                &[
                    field(":method", "GET"),
                    field(":scheme", "https"),
                    field(":path", "/"),
                    field(":authority", "localhost"),
                ],
                &[],
            )
            .unwrap();
        client.flush().unwrap();

        let response = wait_for_response(&mut client, stream_id);
        assert!(response.headers.iter().all(|h| !h.name.starts_with(':')));
        assert!(response.headers.iter().any(|h| h.name == "content-type"));
    }

    #[test]
    fn has_capacity_reflects_peer_concurrent_stream_limit() {
        let (port, name, trust_anchor) = spawn_test_server(b"x", 200);
        let client = connect_and_wait_ready(port, &name, trust_anchor);
        assert!(client.has_capacity());
    }

    #[test]
    fn timed_out_streams_identifies_stale_streams() {
        let (port, name, trust_anchor) = spawn_test_server(b"slow", 200);
        let mut client = connect_and_wait_ready(port, &name, trust_anchor);

        let stream_id = client
            .open_stream(
                &[
                    field(":method", "GET"),
                    field(":scheme", "https"),
                    field(":path", "/"),
                    field(":authority", "localhost"),
                ],
                &[],
            )
            .unwrap();

        // Immediately after opening, nothing should be considered
        // timed out yet against a generous threshold.
        assert!(client.timed_out_streams(Duration::from_secs(10)).is_empty());

        // Against a threshold shorter than any real elapsed time, the
        // just-opened stream should be reported.
        std::thread::sleep(Duration::from_millis(20));
        let timed_out = client.timed_out_streams(Duration::from_millis(1));
        assert_eq!(timed_out, vec![stream_id]);
    }

    #[test]
    fn abandon_stream_removes_it_and_queues_rst_stream() {
        let (port, name, trust_anchor) = spawn_test_server(b"x", 200);
        let mut client = connect_and_wait_ready(port, &name, trust_anchor);

        let stream_id = client
            .open_stream(
                &[
                    field(":method", "GET"),
                    field(":scheme", "https"),
                    field(":path", "/"),
                    field(":authority", "localhost"),
                ],
                &[],
            )
            .unwrap();
        client.flush().unwrap();

        client.abandon_stream(stream_id);
        assert!(client.timed_out_streams(Duration::from_secs(0)).is_empty(), "abandoned stream should no longer be tracked");
        assert!(!client.write_buf.is_empty(), "abandoning a stream should queue an RST_STREAM frame");
    }

    #[test]
    fn connect_to_closed_port_eventually_fails() {
        // Bind and immediately drop, so nothing is listening.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut client = H2Client::connect(addr, "localhost").unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match client.advance() {
                Ok(true) => panic!("expected connection to a closed port to fail, not succeed"),
                Ok(false) => {
                    if std::time::Instant::now() > deadline {
                        panic!("timed out without ever seeing a connect failure");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    assert_eq!(client.state, H2ClientState::Failed);
                    return;
                }
            }
        }
    }
}
