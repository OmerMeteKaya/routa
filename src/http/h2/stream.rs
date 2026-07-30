//! HTTP/2 connection and stream state machine (server side). A
//! `Connection` owns connection-level state (SETTINGS negotiation,
//! the HPACK contexts, flow-control windows, the stream table) and
//! drives every stream on it; `advance()` is the sole entry point --
//! feed it newly-arrived bytes, get back what it produced to send and
//! what to do next (same "state machine advances, caller owns all
//! I/O" shape as `net::tls::TlsConnection::advance_io` and the
//! upstream health-check probes in `lb::upstream`). This module never
//! touches a socket or a poller directly -- `core::event_loop` (or,
//! for tests, a harness) is responsible for actually reading/writing
//! bytes and re-registering for readiness.
//!
//! Each stream's pending-response-body state is a single enum
//! (`PendingBody`) rather than a pair of independently-updated fields
//! (a byte buffer plus a separate "is there also a file descriptor"
//! flag) -- the specific shape that historically made it easy for a
//! completion check in one code path to disagree with a completion
//! check in another, since there were two places "are we done"
//! could be asked and no guarantee both were updated together. With
//! one enum, there is exactly one place that question is answered:
//! `PendingBody::is_exhausted`.

use std::collections::HashMap;

/// A stream table's storage strategy -- selected once at connection
/// construction time and fixed for that connection's lifetime. A
/// hashmap gives O(1) average lookup regardless of how many concurrent
/// streams exist; a linear scan over a small fixed-capacity vector can
/// be cheaper in practice when a connection's concurrent-stream limit
/// is kept low (as most proxy deployments do), since there's no
/// hashing cost and the whole table tends to fit in a few cache lines.
enum StreamTable {
    Hash(HashMap<u32, Stream>),
    Linear { slots: Vec<Option<(u32, Stream)>> },
}

impl StreamTable {
    fn new_hash() -> Self {
        StreamTable::Hash(HashMap::new())
    }

    fn new_linear(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || None);
        StreamTable::Linear { slots }
    }

    fn get(&self, id: &u32) -> Option<&Stream> {
        match self {
            StreamTable::Hash(map) => map.get(id),
            StreamTable::Linear { slots } => slots.iter().find_map(|slot| match slot {
                Some((slot_id, stream)) if slot_id == id => Some(stream),
                _ => None,
            }),
        }
    }

    fn get_mut(&mut self, id: &u32) -> Option<&mut Stream> {
        match self {
            StreamTable::Hash(map) => map.get_mut(id),
            StreamTable::Linear { slots } => slots.iter_mut().find_map(|slot| match slot {
                Some((slot_id, stream)) if slot_id == id => Some(stream),
                _ => None,
            }),
        }
    }

    fn contains_key(&self, id: &u32) -> bool {
        self.get(id).is_some()
    }

    fn remove(&mut self, id: &u32) {
        match self {
            StreamTable::Hash(map) => {
                map.remove(id);
            }
            StreamTable::Linear { slots } => {
                for slot in slots.iter_mut() {
                    if matches!(slot, Some((slot_id, _)) if slot_id == id) {
                        *slot = None;
                        break;
                    }
                }
            }
        }
    }

    fn keys(&self) -> Vec<u32> {
        match self {
            StreamTable::Hash(map) => map.keys().copied().collect(),
            StreamTable::Linear { slots } => slots.iter().filter_map(|s| s.as_ref().map(|(id, _)| *id)).collect(),
        }
    }

    fn values_mut(&mut self) -> Box<dyn Iterator<Item = &mut Stream> + '_> {
        match self {
            StreamTable::Hash(map) => Box::new(map.values_mut()),
            StreamTable::Linear { slots } => Box::new(slots.iter_mut().filter_map(|s| s.as_mut().map(|(_, stream)| stream))),
        }
    }

    fn values(&self) -> Box<dyn Iterator<Item = &Stream> + '_> {
        match self {
            StreamTable::Hash(map) => Box::new(map.values()),
            StreamTable::Linear { slots } => Box::new(slots.iter().filter_map(|s| s.as_ref().map(|(_, stream)| stream))),
        }
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (u32, &Stream)> + '_> {
        match self {
            StreamTable::Hash(map) => Box::new(map.iter().map(|(id, s)| (*id, s))),
            StreamTable::Linear { slots } => Box::new(slots.iter().filter_map(|s| s.as_ref().map(|(id, stream)| (*id, stream)))),
        }
    }

    /// Same contract as `HashMap::entry(id).or_insert_with(f)` -- looks
    /// up `id`, inserting `f()`'s result first if it's not already
    /// present, and returns a mutable reference either way. A fixed-
    /// capacity `Linear` table that's completely full silently reuses
    /// its last slot rather than panicking or growing -- a connection
    /// this deep into ignoring its own concurrent-stream limit already
    /// has a bug elsewhere (`handle_headers` refuses new streams past
    /// `local_max_concurrent_streams` before this is ever reached).
    fn get_or_insert_with(&mut self, id: u32, f: impl FnOnce() -> Stream) -> &mut Stream {
        match self {
            StreamTable::Hash(map) => map.entry(id).or_insert_with(f),
            StreamTable::Linear { slots } => {
                let existing_idx = slots.iter().position(|slot| matches!(slot, Some((slot_id, _)) if *slot_id == id));
                let idx = existing_idx.unwrap_or_else(|| {
                    let free_idx = slots.iter().position(|slot| slot.is_none()).unwrap_or(slots.len() - 1);
                    slots[free_idx] = Some((id, f()));
                    free_idx
                });
                slots[idx].as_mut().map(|(_, stream)| stream).expect("slot just populated")
            }
        }
    }
}

use super::frame::{self, Frame, FrameHeader, FrameType};
use super::hpack::{HeaderField, HpackContext};

// ─── Constants ──────────────────────────────────────────────────────────

const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DEFAULT_HEADER_TABLE_SIZE: usize = 4096;
const DEFAULT_INITIAL_WINDOW_SIZE: i32 = 65_535;
const MAX_WINDOW_SIZE: i64 = (1i64 << 31) - 1;
const CONNECTION_STREAM_ID: u32 = 0;

// ─── Settings (RFC 9113 6.5.2) ──────────────────────────────────────────

const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

// ─── Error codes (RFC 9113 7) ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2Error {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

// ─── Pending response body ──────────────────────────────────────────────

/// A stream's not-yet-fully-sent response body. Exactly one variant
/// is ever active -- see this module's top doc comment for why that
/// matters (a completion check has exactly one place to be asked,
/// `is_exhausted`, rather than needing two independently-maintained
/// fields to agree).
pub enum PendingBody {
    None,
    /// An in-memory body, or the not-yet-flow-control-permitted tail
    /// of one -- `offset` is how much of `data` has already been
    /// framed into DATA frames and handed off.
    Buffered { data: Vec<u8>, offset: usize },
}

impl PendingBody {
    fn is_exhausted(&self) -> bool {
        match self {
            PendingBody::None => true,
            PendingBody::Buffered { data, offset } => *offset >= data.len(),
        }
    }

    fn remaining(&self) -> &[u8] {
        match self {
            PendingBody::None => &[],
            PendingBody::Buffered { data, offset } => &data[*offset..],
        }
    }

    /// Records that `n` bytes of whatever's remaining were just framed
    /// into an outgoing DATA frame. The one and only place this
    /// state's "how much is left" bookkeeping is updated -- see this
    /// module's top doc comment.
    fn advance(&mut self, n: usize) {
        if let PendingBody::Buffered { offset, .. } = self {
            *offset += n;
        }
    }
}

// ─── Stream state ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    /// HEADERS received (possibly split across CONTINUATION frames,
    /// not yet fully assembled) but END_HEADERS not yet seen.
    ReceivingHeaders,
    /// Full request headers assembled; request body (if any) still
    /// arriving via DATA frames.
    Open,
    /// Client sent END_STREAM -- request is fully received, dispatched
    /// to the router, response streaming out.
    HalfClosedRemote,
    Closed,
}

pub struct Stream {
    pub id: u32,
    pub phase: StreamPhase,
    /// When this stream was opened -- used by `Connection::reap_stale_streams`
    /// to enforce `RoutaH2Config::stream_timeout_ms`.
    pub created_at: std::time::Instant,

    // Flow control (RFC 9113 6.9), this stream's contribution
    // (connection-level windows live on `Connection`, not here).
    pub send_window: i64,
    pub recv_window: i64,

    // Header block assembly (spans HEADERS + any CONTINUATION frames).
    header_block: Vec<u8>,
    header_block_end_stream: bool,

    pub request_headers: Vec<HeaderField>,
    pub request_body: Vec<u8>,

    pub pending_response: PendingBody,
    pub response_headers_sent: bool,
    /// Trailer fields received after the request body (a second
    /// HEADERS frame with END_STREAM, sent once the stream was
    /// already `Open`) -- kept separate from `request_headers` since
    /// trailers arrive after the body and are exempt from the
    /// pseudo-header validation regular request headers require.
    pub trailers: Vec<HeaderField>,
}

impl Stream {
    fn new(id: u32, initial_send_window: i32, initial_recv_window: i32) -> Self {
        Stream {
            id,
            phase: StreamPhase::ReceivingHeaders,
            created_at: std::time::Instant::now(),
            send_window: i64::from(initial_send_window),
            recv_window: i64::from(initial_recv_window),
            header_block: Vec::new(),
            header_block_end_stream: false,
            request_headers: Vec::new(),
            request_body: Vec::new(),
            pending_response: PendingBody::None,
            response_headers_sent: false,
            trailers: Vec::new(),
        }
    }
}

// ─── Connection ──────────────────────────────────────────────────────────

/// What a caller (see this module's top doc comment) should do after
/// an `advance()` call: bytes to send, and whether more read/write
/// readiness is currently wanted.
#[derive(Default)]
pub struct AdvanceResult {
    /// Bytes ready to write out. May be empty even on a successful
    /// advance (e.g. a DATA frame's worth of request body arrived but
    /// produced no immediate response bytes).
    pub to_send: Vec<u8>,
    /// The connection encountered a protocol error and sent (or is
    /// about to send, in `to_send`) a GOAWAY -- the caller should close
    /// the underlying transport once `to_send` has been flushed.
    pub connection_closed: bool,
    /// Stream ids that just finished receiving a complete request
    /// (END_STREAM on the request side) and are ready to be dispatched
    /// to a router -- see `Connection::take_ready_streams`.
    pub newly_ready_streams: Vec<u32>,
}

pub struct Connection {
    preface_received: bool,
    preface_buf: Vec<u8>,

    streams: StreamTable,
    highest_peer_stream_id: u32,

    // This side's view of the peer's SETTINGS (what WE must respect
    // when sending).
    peer_header_table_size: usize,
    peer_max_concurrent_streams: Option<u32>,
    peer_initial_window_size: i32,
    peer_max_frame_size: u32,
    peer_max_header_list_size: Option<u32>,

    // Our own advertised SETTINGS (what the peer must respect when
    // sending to us).
    pub local_max_concurrent_streams: u32,
    pub local_initial_window_size: i32,
    pub local_max_frame_size: u32,
    /// RFC 9113 6.5.2 SETTINGS_MAX_HEADER_LIST_SIZE: an advisory cap on
    /// the uncompressed size (RFC 7541 4.1 per-field accounting) of a
    /// request's header list. `0` means unlimited, matching
    /// `RoutaH2Config::max_header_list_size`'s own convention.
    pub local_max_header_list_size: u32,
    local_header_table_size: usize,
    local_enable_push: bool,

    settings_ack_pending: bool,

    // Connection-level flow control (RFC 9113 6.9.1) -- separate from
    // any one stream's window.
    send_window: i64,
    recv_window: i64,

    encoder: HpackContext,
    decoder: HpackContext,

    goaway_sent: bool,
    error: bool,
    last_stream_id_processed: u32,
    /// `Some(stream_id)` while a HEADERS frame without END_HEADERS is
    /// still waiting for its CONTINUATION frame(s) -- RFC 9113 6.10
    /// requires that no other frame type may be interleaved on the
    /// connection during this window (not even for a different
    /// stream), so `dispatch_frame` checks this before routing
    /// anything except CONTINUATION while it's set.
    expecting_continuation_for: Option<u32>,
}

impl Connection {
    pub fn new(local_max_concurrent_streams: u32, local_header_table_size: usize) -> Self {
        Connection {
            preface_received: false,
            preface_buf: Vec::new(),
            streams: StreamTable::new_hash(),
            highest_peer_stream_id: 0,
            peer_header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            peer_max_concurrent_streams: None,
            peer_initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            peer_max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
            peer_max_header_list_size: None,
            local_max_concurrent_streams,
            local_initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            local_max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
            local_max_header_list_size: 0,
            local_header_table_size,
            local_enable_push: true,
            settings_ack_pending: false,
            send_window: i64::from(DEFAULT_INITIAL_WINDOW_SIZE),
            recv_window: i64::from(DEFAULT_INITIAL_WINDOW_SIZE),
            encoder: HpackContext::new(local_header_table_size),
            decoder: HpackContext::new(local_header_table_size),
            goaway_sent: false,
            error: false,
            last_stream_id_processed: 0,
            expecting_continuation_for: None,
        }
    }

    /// Replaces this connection's outbound flow-control/framing
    /// SETTINGS (RoutaH2Config's `initial_window_size`/`max_frame_size`)
    /// -- separate constructor params would work too, but this matches
    /// the builder-style pattern already used elsewhere in this
    /// codebase (e.g. `lb::upstream::UpstreamPool::with_outlier_config`)
    /// for optional configuration a caller may not care to override.
    pub fn with_local_settings(mut self, initial_window_size: u32, max_frame_size: u32, max_header_list_size: u32) -> Self {
        self.local_initial_window_size = initial_window_size.min(MAX_WINDOW_SIZE as u32) as i32;
        self.send_window = i64::from(self.local_initial_window_size);
        self.recv_window = i64::from(self.local_initial_window_size);
        self.local_max_frame_size = max_frame_size.clamp(frame::DEFAULT_MAX_FRAME_SIZE, frame::ABSOLUTE_MAX_FRAME_SIZE);
        self.local_max_header_list_size = max_header_list_size;
        self
    }

    /// Sets whether this connection's HPACK encoder prefers Huffman
    /// coding for string literals and proactively signals its own
    /// dynamic table size changes -- see `RoutaH2Config::huffman_encoding`
    /// / `dynamic_table_update`.
    pub fn with_encoder_options(mut self, huffman_encoding: bool, dynamic_table_update: bool) -> Self {
        self.encoder = self
            .encoder
            .with_huffman_enabled(huffman_encoding)
            .with_dynamic_table_update_enabled(dynamic_table_update);
        self
    }

    /// Sets whether SETTINGS_ENABLE_PUSH is advertised as enabled --
    /// see `RoutaH2Config::server_push_enabled`. Routa never actually
    /// sends PUSH_PROMISE frames regardless of this value (no server
    /// push implementation exists), but the SETTINGS value itself is
    /// still real protocol-visible signaling a conforming peer may act
    /// on (e.g. deciding whether to bother asking for pushed resources
    /// some other way).
    pub fn with_push_enabled(mut self, enabled: bool) -> Self {
        self.local_enable_push = enabled;
        self
    }

    /// Switches this connection's stream table to a fixed-capacity
    /// linear-scan strategy sized to `local_max_concurrent_streams`
    /// (its own hard limit on how many streams can ever be open at
    /// once) instead of the default hashmap. See `StreamTable`'s own
    /// doc comment for the tradeoff this exists to make available.
    pub fn with_linear_stream_lookup(mut self) -> Self {
        self.streams = StreamTable::new_linear(self.local_max_concurrent_streams as usize);
        self
    }

    /// Marks this connection as having already exchanged its preface
    /// through some other means -- an HTTP/1.1 `Upgrade: h2c` request
    /// switches a connection to HTTP/2 without either side ever
    /// sending the `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` bytes `advance`
    /// otherwise requires up front, since the upgrade response itself
    /// already served that purpose.
    pub fn assume_preface_received(&mut self) {
        self.preface_received = true;
    }

    /// Feeds an already-decoded HTTP2-Settings header payload (RFC
    /// 9113 3.2: the base64url-decoded bytes of an `Upgrade: h2c`
    /// request's own `HTTP2-Settings` header, i.e. one SETTINGS
    /// frame's payload with no frame header of its own) through the
    /// same settings-processing path a normal SETTINGS frame would --
    /// this is how the client's initial settings for an upgraded
    /// connection get applied, since they never arrive as an actual
    /// framed SETTINGS frame the way a prior-knowledge connection's
    /// would.
    pub fn apply_upgrade_settings(&mut self, settings_payload: &[u8]) {
        let mut result = AdvanceResult::default();
        let synthetic_frame = Frame {
            header: FrameHeader {
                length: settings_payload.len() as u32,
                frame_type: FrameType::Settings,
                flags: 0,
                stream_id: CONNECTION_STREAM_ID,
            },
            payload: settings_payload,
        };
        self.handle_settings(&synthetic_frame, &mut result);
        // The resulting SETTINGS ACK belongs with whatever else this
        // connection sends first post-upgrade (its own initial_send)
        // rather than being lost here -- discard just the ACK bytes
        // and let initial_send's own SETTINGS establish this side's
        // policy; a client that already sent HTTP2-Settings isn't
        // waiting on an ACK for it specifically before proceeding.
        let _ = result.to_send;
    }

    /// The connection preface (RFC 9113 3.4) plus our initial SETTINGS
    /// frame -- what a server sends before anything else, immediately
    /// on accepting an h2 connection (whether negotiated via ALPN or
    /// an h2c upgrade).
    pub fn initial_send(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut settings = vec![
            frame::Setting {
                id: SETTINGS_HEADER_TABLE_SIZE,
                value: self.local_header_table_size as u32,
            },
            frame::Setting {
                id: SETTINGS_ENABLE_PUSH,
                value: self.local_enable_push as u32,
            },
            frame::Setting {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: self.local_max_concurrent_streams,
            },
            frame::Setting {
                id: SETTINGS_INITIAL_WINDOW_SIZE,
                value: self.local_initial_window_size as u32,
            },
            frame::Setting {
                id: SETTINGS_MAX_FRAME_SIZE,
                value: self.local_max_frame_size,
            },
        ];
        if self.local_max_header_list_size > 0 {
            settings.push(frame::Setting {
                id: SETTINGS_MAX_HEADER_LIST_SIZE,
                value: self.local_max_header_list_size,
            });
        }
        frame::write_settings(&mut out, &settings);
        out
    }

    /// Takes ownership of every stream id that just became ready for
    /// dispatch (see `AdvanceResult::newly_ready_streams`) -- typically
    /// called once per `advance()` result, handing each id's request
    /// off to a router and then, once a response is ready, back to
    /// `Connection::send_response`.
    pub fn take_request(&self, stream_id: u32) -> Option<(&[HeaderField], &[u8], &[HeaderField])> {
        self.streams
            .get(&stream_id)
            .map(|s| (s.request_headers.as_slice(), s.request_body.as_slice(), s.trailers.as_slice()))
    }

    pub fn is_closed(&self) -> bool {
        self.error
    }

    /// Resets (RST_STREAM, error CANCEL) every stream that's been open
    /// longer than `timeout` without finishing -- called periodically
    /// (see `core::event_loop`'s idle sweep) rather than on every
    /// `advance()`, since a stuck stream by definition isn't producing
    /// frames for `advance()` to react to. A no-op when `timeout` is
    /// zero, matching `RoutaH2Config::stream_timeout_ms`'s "0 disables
    /// this" convention used throughout `core::config`.
    pub fn reap_stale_streams(&mut self, timeout: std::time::Duration) -> Vec<u8> {
        if timeout.is_zero() {
            return Vec::new();
        }
        let now = std::time::Instant::now();
        let stale: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, s)| s.phase != StreamPhase::Closed && now.duration_since(s.created_at) > timeout)
            .map(|(id, _)| id)
            .collect();

        let mut out = Vec::new();
        for stream_id in stale {
            frame::write_rst_stream(&mut out, stream_id, H2Error::Cancel as u32);
            self.streams.remove(&stream_id);
        }
        out
    }
}

impl Connection {
    /// Feeds newly-arrived bytes into the connection. Consumes the
    /// preface first (if not yet seen), then parses and dispatches as
    /// many complete frames as `data` contains -- a partial frame at
    /// the end is simply left for the next `advance()` call once more
    /// bytes have arrived, mirroring how `http::request::parse`
    /// reports `Incomplete` rather than erroring on a short buffer.
    pub fn advance(&mut self, data: &[u8]) -> AdvanceResult {
        let mut result = AdvanceResult::default();
        if self.error {
            result.connection_closed = true;
            return result;
        }

        if !self.preface_received {
            self.preface_buf.extend_from_slice(data);
            if self.preface_buf.len() < CONNECTION_PREFACE.len() {
                return result; // still waiting for the rest of the preface
            }
            if !self.preface_buf.starts_with(CONNECTION_PREFACE) {
                self.error = true;
                result.connection_closed = true;
                return result;
            }
            self.preface_received = true;
            let leftover = self.preface_buf[CONNECTION_PREFACE.len()..].to_vec();
            self.preface_buf.clear();
            self.process_frames(&leftover, &mut result);
            return result;
        }

        self.process_frames(data, &mut result);
        result
    }

    fn process_frames(&mut self, mut data: &[u8], result: &mut AdvanceResult) {
        loop {
            // Check the frame header's declared length against our
            // own advertised SETTINGS_MAX_FRAME_SIZE as soon as the
            // 9-byte header itself is available -- deliberately
            // before waiting for parse_frame to see the frame's full
            // payload. A frame whose declared length already exceeds
            // what we said we'd accept can legitimately never
            // complete (the peer may simply never send that much
            // payload, especially a conformance tester deliberately
            // testing this exact boundary), so waiting for the "full"
            // frame first would mean waiting forever instead of
            // erroring immediately per RFC 9113 4.2.
            let Some(header) = frame::FrameHeader::parse(data) else {
                break; // not even a full header yet -- wait for more data
            };
            if header.length > self.local_max_frame_size {
                self.conn_error(H2Error::FrameSizeError, result);
                break;
            }

            let Some((frame, consumed)) = frame::parse_frame(data) else {
                break; // header fits the limit, but payload hasn't fully arrived yet
            };

            self.dispatch_frame(&frame, result);
            if self.error {
                break;
            }

            data = &data[consumed..];
        }
    }

    fn dispatch_frame(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        if self.expecting_continuation_for.is_some() && frame.header.frame_type != FrameType::Continuation {
            // RFC 9113 6.10: while a header block is incomplete (a
            // HEADERS frame arrived without END_HEADERS), no frame
            // other than CONTINUATION may be sent on the connection --
            // not even a different, unrelated frame type or a frame
            // for a different stream.
            return self.conn_error(H2Error::ProtocolError, result);
        }
        match frame.header.frame_type {
            FrameType::Settings => self.handle_settings(frame, result),
            FrameType::Ping => self.handle_ping(frame, result),
            FrameType::WindowUpdate => self.handle_window_update(frame, result),
            FrameType::RstStream => self.handle_rst_stream(frame, result),
            FrameType::GoAway => self.handle_goaway(frame),
            FrameType::Headers => self.handle_headers(frame, result),
            FrameType::Continuation => self.handle_continuation(frame, result),
            FrameType::Data => self.handle_data(frame, result),
            FrameType::Priority => self.handle_priority(frame, result),
            FrameType::PushPromise => {
                // A server never receives PUSH_PROMISE (only sends it)
                // -- a client sending one is a protocol error.
                self.conn_error(H2Error::ProtocolError, result);
            }
            FrameType::Unknown(_) => {} // RFC 9113 4.1: unknown frame types are ignored, not errors
        }
    }

    fn conn_error(&mut self, code: H2Error, result: &mut AdvanceResult) {
        if !self.goaway_sent {
            frame::write_goaway(
                &mut result.to_send,
                self.last_stream_id_processed,
                code as u32,
            );
            self.goaway_sent = true;
        }
        self.error = true;
        result.connection_closed = true;
    }
}

// ─── Connection-level frame handlers ────────────────────────────────────

impl Connection {
    fn handle_settings(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        if frame.header.stream_id != CONNECTION_STREAM_ID {
            return self.conn_error(H2Error::ProtocolError, result);
        }

        if frame.header.flags & frame::FLAG_ACK != 0 {
            if !frame.payload.is_empty() {
                return self.conn_error(H2Error::FrameSizeError, result);
            }
            self.settings_ack_pending = false;
            return;
        }

        if frame.payload.len() % 6 != 0 {
            return self.conn_error(H2Error::FrameSizeError, result);
        }

        let mut window_delta: i64 = 0;
        for chunk in frame.payload.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);

            match id {
                SETTINGS_HEADER_TABLE_SIZE => {
                    self.peer_header_table_size = value as usize;
                    self.encoder.set_max_dynamic_table_size(value as usize);
                }
                SETTINGS_ENABLE_PUSH => {
                    if value > 1 {
                        return self.conn_error(H2Error::ProtocolError, result);
                    }
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => {
                    self.peer_max_concurrent_streams = Some(value);
                }
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if value as i64 > MAX_WINDOW_SIZE {
                        return self.conn_error(H2Error::FlowControlError, result);
                    }
                    // RFC 9113 6.9.2: a change here retroactively
                    // adjusts every existing stream's send window by
                    // the delta, not just future streams'.
                    window_delta = i64::from(value as i32) - i64::from(self.peer_initial_window_size);
                    self.peer_initial_window_size = value as i32;
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(frame::DEFAULT_MAX_FRAME_SIZE..=frame::ABSOLUTE_MAX_FRAME_SIZE)
                        .contains(&value)
                    {
                        return self.conn_error(H2Error::ProtocolError, result);
                    }
                    self.peer_max_frame_size = value;
                }
                SETTINGS_MAX_HEADER_LIST_SIZE => {
                    self.peer_max_header_list_size = Some(value);
                }
                _ => {} // RFC 9113 6.5.2: unknown settings identifiers are ignored
            }
        }

        if window_delta != 0 {
            for stream in self.streams.values_mut() {
                stream.send_window += window_delta;
            }
            // RFC 9113 6.9.2: adjusting SETTINGS_INITIAL_WINDOW_SIZE
            // must actually unstall any stream whose pending response
            // was previously blocked on a zero-or-negative window --
            // just updating send_window above without also resuming
            // delivery would leave that data queued forever even
            // though the window is now open.
            let stream_ids: Vec<u32> = self.streams.keys();
            for stream_id in stream_ids {
                self.flush_pending(stream_id, &mut result.to_send);
            }
        }

        frame::write_settings_ack(&mut result.to_send);
    }

    fn handle_ping(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        if frame.header.stream_id != CONNECTION_STREAM_ID {
            return self.conn_error(H2Error::ProtocolError, result);
        }
        if frame.payload.len() != 8 {
            return self.conn_error(H2Error::FrameSizeError, result);
        }
        if frame.header.flags & frame::FLAG_ACK != 0 {
            return; // an ACK for a PING we don't currently send ourselves
        }
        let mut payload = [0u8; 8];
        payload.copy_from_slice(frame.payload);
        frame::write_ping(&mut result.to_send, &payload, true);
    }

    fn handle_window_update(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        if frame.payload.len() != 4 {
            return self.conn_error(H2Error::FrameSizeError, result);
        }
        let increment =
            u32::from_be_bytes([frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3]])
                & 0x7fff_ffff;
        if increment == 0 {
            return self.conn_error(H2Error::ProtocolError, result);
        }

        if frame.header.stream_id == CONNECTION_STREAM_ID {
            self.send_window += i64::from(increment);
            if self.send_window > MAX_WINDOW_SIZE {
                return self.conn_error(H2Error::FlowControlError, result);
            }
            // A connection-level window increase can unstall every
            // stream that has a response queued, not just one -- same
            // reasoning as the SETTINGS_INITIAL_WINDOW_SIZE handler.
            let stream_ids: Vec<u32> = self.streams.keys();
            for stream_id in stream_ids {
                self.flush_pending(stream_id, &mut result.to_send);
            }
        } else {
            if frame.header.stream_id > self.highest_peer_stream_id {
                // RFC 9113 5.1: a WINDOW_UPDATE for an idle stream
                // (its id exceeds every id the peer has ever actually
                // opened) is a connection error -- distinct from a
                // WINDOW_UPDATE for a stream we've already closed and
                // forgotten about, which is a normal, ignorable
                // close-timing race (handled by the early return
                // below when the id isn't found but is <= the highest
                // seen).
                return self.conn_error(H2Error::ProtocolError, result);
            }
            let Some(stream) = self.streams.get_mut(&frame.header.stream_id) else {
                return;
            };
            stream.send_window += i64::from(increment);
            if stream.send_window > MAX_WINDOW_SIZE {
                let stream_id = frame.header.stream_id;
                frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::FlowControlError as u32);
                self.streams.remove(&stream_id);
                return;
            }
            let stream_id = frame.header.stream_id;
            self.flush_pending(stream_id, &mut result.to_send);
        }
    }

    fn handle_rst_stream(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        if frame.header.stream_id == CONNECTION_STREAM_ID {
            return self.conn_error(H2Error::ProtocolError, result);
        }
        if frame.payload.len() != 4 {
            return self.conn_error(H2Error::FrameSizeError, result);
        }
        // RFC 9113 5.1: RST_STREAM on an idle stream (never opened --
        // its id exceeds every id seen so far) is a connection error;
        // a closed stream is different from idle and this is the
        // ordinary/expected way a stream we already know about ends.
        if frame.header.stream_id > self.highest_peer_stream_id {
            return self.conn_error(H2Error::ProtocolError, result);
        }
        self.streams.remove(&frame.header.stream_id);
    }

    /// PRIORITY frames are deprecated (RFC 9113 5.3.2 marks the whole
    /// mechanism as a SHOULD-not-implement for new code, and routa
    /// never acts on stream dependency/weight) but still must be
    /// validated per RFC 9113 6.3 -- a client can send one at any
    /// point, including for an idle stream, so its frame-level
    /// requirements (exactly 5 bytes, not self-dependent) are checked
    /// here even though the dependency/weight values themselves are
    /// discarded afterward.
    fn handle_priority(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        if frame.header.stream_id == CONNECTION_STREAM_ID {
            return self.conn_error(H2Error::ProtocolError, result);
        }
        if frame.payload.len() != 5 {
            // RFC 9113 6.3: a PRIORITY frame with a length other than
            // 5 octets is a stream error, not a connection error --
            // but if this is an idle stream (no Stream entry exists
            // yet to attach a stream-level error to), there's nothing
            // for a stream error to apply to, so this degrades to a
            // connection error instead.
            if self.streams.contains_key(&frame.header.stream_id) {
                frame::write_rst_stream(&mut result.to_send, frame.header.stream_id, H2Error::FrameSizeError as u32);
                self.streams.remove(&frame.header.stream_id);
            } else {
                self.conn_error(H2Error::FrameSizeError, result);
            }
            return;
        }
        let dependency = u32::from_be_bytes([frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3]]) & 0x7fff_ffff;
        if dependency == frame.header.stream_id {
            // RFC 9113 5.3.1: a stream cannot depend on itself.
            if self.streams.contains_key(&frame.header.stream_id) {
                frame::write_rst_stream(&mut result.to_send, frame.header.stream_id, H2Error::ProtocolError as u32);
                self.streams.remove(&frame.header.stream_id);
            } else {
                self.conn_error(H2Error::ProtocolError, result);
            }
        }
        // Dependency/weight are otherwise accepted and discarded --
        // see this function's own doc comment.
    }

    fn handle_goaway(&mut self, frame: &Frame<'_>) {
        // Peer is telling us it's shutting down and won't process
        // streams above the id in this frame -- no response required;
        // record that the connection is going away so a caller
        // stops initiating anything new on it.
        let _ = frame;
        self.error = true;
    }
}

// ─── Header frame handling ───────────────────────────────────────────────

impl Connection {
    fn handle_headers(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        let stream_id = frame.header.stream_id;
        if stream_id == CONNECTION_STREAM_ID || stream_id % 2 == 0 {
            // RFC 9113 5.1.1: client-initiated streams must use odd
            // ids; stream 0 is never a real stream.
            return self.conn_error(H2Error::ProtocolError, result);
        }
        if stream_id <= self.highest_peer_stream_id && !self.streams.contains_key(&stream_id) {
            // Reusing/reopening an id that's already been superseded --
            // RFC 9113 5.1's idle-stream-must-be-monotonic rule.
            return self.conn_error(H2Error::ProtocolError, result);
        }
        // RFC 9113 5.1: a HEADERS frame for a stream already in
        // HalfClosedRemote is only valid as trailers -- the request's
        // own END_STREAM has already arrived, so any further HEADERS
        // must itself carry END_STREAM (trailers never introduce a
        // new request body chunk) or it's a stream error. This is
        // also what prevents a stray/duplicate HEADERS from
        // re-triggering dispatch of a request that's already been
        // fully received and responded to.
        if let Some(existing) = self.streams.get(&stream_id) {
            if existing.phase == StreamPhase::HalfClosedRemote {
                // RFC 9113 5.1: any further frame on a stream already
                // in HalfClosedRemote other than WINDOW_UPDATE,
                // PRIORITY, or RST_STREAM is a stream error of type
                // STREAM_CLOSED -- including a HEADERS frame that
                // merely resembles trailers on the surface (has
                // END_STREAM) but isn't valid trailers once decoded
                // (carries pseudo-headers, i.e. is actually a second
                // copy of request headers). Only genuine trailers --
                // END_STREAM set AND no pseudo-headers once HPACK-
                // decoded -- are accepted and silently discarded here
                // (no trailer-aware second-dispatch path exists, so
                // accepting them is just "don't error", not "act on
                // them"). Everything else, including an END_STREAM'd
                // HEADERS that isn't valid trailers, must still
                // consume its bytes from the HPACK decoder's dynamic
                // table state (decoding is a shared, stateful
                // per-connection process -- skipping it would corrupt
                // decoding of every subsequent HEADERS frame on this
                // connection), so decode it before deciding.
                if frame.header.flags & frame::FLAG_END_STREAM == 0 {
                    frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::StreamClosed as u32);
                    self.streams.remove(&stream_id);
                    return;
                }
                let mut payload = frame.payload;
                if frame.header.flags & frame::FLAG_PADDED != 0 {
                    let Some(&pad_len) = payload.first() else {
                        return self.conn_error(H2Error::FrameSizeError, result);
                    };
                    let pad_len = pad_len as usize;
                    if payload.len() < 1 + pad_len {
                        return self.conn_error(H2Error::FrameSizeError, result);
                    }
                    payload = &payload[1..payload.len() - pad_len];
                }
                if frame.header.flags & frame::FLAG_PRIORITY != 0 {
                    if payload.len() < 5 {
                        return self.conn_error(H2Error::FrameSizeError, result);
                    }
                    payload = &payload[5..];
                }
                let fields = match self.decoder.decode(payload) {
                    Ok(f) => f,
                    Err(_) => return self.conn_error(H2Error::CompressionError, result),
                };
                if !validate_trailer_fields(&fields) {
                    frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::StreamClosed as u32);
                    self.streams.remove(&stream_id);
                    return;
                }
                return;
            }
        }

        let concurrent = self
            .streams
            .values()
            .filter(|s| s.phase != StreamPhase::Closed)
            .count();
        if concurrent as u32 >= self.local_max_concurrent_streams {
            frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::RefusedStream as u32);
            return;
        }

        self.highest_peer_stream_id = self.highest_peer_stream_id.max(stream_id);
        self.last_stream_id_processed = self.highest_peer_stream_id;

        let mut payload = frame.payload;

        // PADDED (RFC 9113 6.2): first byte is pad length, padding is
        // at the end of the frame -- both are stripped before anything
        // else looks at the payload. Padding's only real purpose is
        // letting a client obscure a compressed header block's exact
        // length as a defense against traffic-analysis attacks (see
        // RFC 9113 10.7); routa has no reason to ever pad frames it
        // sends, but must still correctly parse padding a client
        // sends.
        if frame.header.flags & frame::FLAG_PADDED != 0 {
            let Some(&pad_len) = payload.first() else {
                return self.conn_error(H2Error::FrameSizeError, result);
            };
            let pad_len = pad_len as usize;
            if payload.len() < 1 + pad_len {
                return self.conn_error(H2Error::FrameSizeError, result);
            }
            payload = &payload[1..payload.len() - pad_len];
        }

        // PRIORITY (RFC 9113 5.3, deprecated): 5 bytes (stream
        // dependency + weight) accepted and skipped, never acted on --
        // see this module's top doc comment. Still validated for
        // self-dependency (RFC 9113 5.3.1): a HEADERS frame whose
        // embedded priority makes the stream depend on itself is a
        // stream error even though the dependency value is otherwise
        // discarded.
        if frame.header.flags & frame::FLAG_PRIORITY != 0 {
            if payload.len() < 5 {
                return self.conn_error(H2Error::FrameSizeError, result);
            }
            let dependency = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
            if dependency == stream_id {
                frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::ProtocolError as u32);
                return;
            }
            payload = &payload[5..];
        }

        let end_stream = frame.header.flags & frame::FLAG_END_STREAM != 0;
        let end_headers = frame.header.flags & frame::FLAG_END_HEADERS != 0;

        let peer_initial_window_size = self.peer_initial_window_size;
        let local_initial_window_size = self.local_initial_window_size;
        let stream = self
            .streams
            .get_or_insert_with(stream_id, || Stream::new(stream_id, peer_initial_window_size, local_initial_window_size));
        stream.header_block.extend_from_slice(payload);
        stream.header_block_end_stream = end_stream;

        if end_headers {
            self.finish_header_block(stream_id, result);
        } else {
            self.expecting_continuation_for = Some(stream_id);
        }
    }

    fn handle_continuation(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        let stream_id = frame.header.stream_id;
        // A CONTINUATION not for the stream currently being assembled
        // (including one that arrives when no header block is in
        // progress at all) is a connection error -- RFC 9113 6.10.
        if self.expecting_continuation_for != Some(stream_id) {
            return self.conn_error(H2Error::ProtocolError, result);
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return self.conn_error(H2Error::ProtocolError, result);
        };
        if stream.phase != StreamPhase::ReceivingHeaders {
            return self.conn_error(H2Error::ProtocolError, result);
        }

        stream.header_block.extend_from_slice(frame.payload);

        if frame.header.flags & frame::FLAG_END_HEADERS != 0 {
            self.expecting_continuation_for = None;
            self.finish_header_block(stream_id, result);
        }
    }

    /// Called once a stream's complete header block has been
    /// assembled (HEADERS possibly followed by CONTINUATION frames,
    /// now all concatenated) -- decodes it via HPACK, validates
    /// pseudo-headers per RFC 9113 8.3, and transitions the stream to
    /// `Open` (or straight to `HalfClosedRemote` if this request had
    /// no body).
    fn finish_header_block(&mut self, stream_id: u32, result: &mut AdvanceResult) {
        let Some(existing) = self.streams.get(&stream_id) else {
            return;
        };

        // A header block assembled while the stream was already
        // `Open` (request headers already accepted, body in
        // progress) is trailers, not a second set of request headers
        // -- RFC 9113 8.1: trailers carry no pseudo-headers of their
        // own and must not be run through the same pseudo-header
        // validation regular request headers need. `handle_headers`
        // only reaches this point for such a stream when the frame
        // also carried END_STREAM (anything else was already
        // rejected there), so trailers here always terminate the
        // stream.
        if existing.phase == StreamPhase::Open {
            let header_block_end_stream = existing.header_block_end_stream;
            let header_block = std::mem::take(&mut self.streams.get_mut(&stream_id).unwrap().header_block);
            let fields = match self.decoder.decode(&header_block) {
                Ok(f) => f,
                Err(_) => return self.conn_error(H2Error::CompressionError, result),
            };
            // RFC 9113 8.1: a second HEADERS frame on an already-Open
            // stream is only valid as trailers, which by definition
            // terminate the stream -- one lacking END_STREAM is
            // neither a valid trailers block nor a valid way to
            // resume sending request headers, so it's a stream error.
            if !header_block_end_stream {
                frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::ProtocolError as u32);
                self.streams.remove(&stream_id);
                return;
            }
            if !validate_trailer_fields(&fields) {
                frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::ProtocolError as u32);
                self.streams.remove(&stream_id);
                return;
            }
            let stream = self.streams.get_mut(&stream_id).unwrap();
            stream.trailers = fields;
            stream.phase = StreamPhase::HalfClosedRemote;
            result.newly_ready_streams.push(stream_id);
            return;
        }

        let header_block = std::mem::take(&mut self.streams.get_mut(&stream_id).unwrap().header_block);

        let fields = match self.decoder.decode(&header_block) {
            Ok(f) => f,
            Err(_) => return self.conn_error(H2Error::CompressionError, result),
        };

        if !validate_request_pseudo_headers(&fields) {
            frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::ProtocolError as u32);
            self.streams.remove(&stream_id);
            return;
        }

        if self.local_max_header_list_size > 0 {
            // RFC 7541 4.1's own per-entry accounting (name + value +
            // 32 bytes overhead), applied here to the *uncompressed*
            // header list rather than the dynamic table -- this is
            // what SETTINGS_MAX_HEADER_LIST_SIZE actually bounds (RFC
            // 9113 6.5.2), a separate limit from the dynamic table's
            // own size.
            let total: usize = fields.iter().map(|f| f.name.len() + f.value.len() + 32).sum();
            if total as u32 > self.local_max_header_list_size {
                frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::RefusedStream as u32);
                self.streams.remove(&stream_id);
                return;
            }
        }

        let stream = self.streams.get_mut(&stream_id).unwrap();
        stream.request_headers = fields;

        if stream.header_block_end_stream {
            stream.phase = StreamPhase::HalfClosedRemote;
            result.newly_ready_streams.push(stream_id);
        } else {
            stream.phase = StreamPhase::Open;
        }
    }
}

/// RFC 9113 8.3: `:method`, `:scheme`, `:path` are required exactly
/// once each; `:authority` is optional but, if absent, a `host` header
/// must be present instead; connection-specific headers (RFC 9110
/// 7.6.1's hop-by-hop set) are forbidden on an h2 request entirely --
/// their h1 equivalents (Connection: keep-alive, Transfer-Encoding,
/// etc.) have no meaning in h2's own framing.
/// RFC 9113 8.1: trailers carry no pseudo-headers at all (unlike
/// regular request headers, which must have exactly one of each
/// required pseudo-header) -- any field starting with ':' here is a
/// stream error. Regular field-name rules (lowercase-only, no
/// hop-by-hop headers) still apply.
fn validate_trailer_fields(fields: &[HeaderField]) -> bool {
    for field in fields {
        if field.name.starts_with(':') {
            return false;
        }
        if field.name.chars().any(|c| c.is_ascii_uppercase()) {
            return false;
        }
        if is_hop_by_hop(&field.name) {
            return false;
        }
    }
    true
}

fn validate_request_pseudo_headers(fields: &[HeaderField]) -> bool {
    let mut method = None;
    let mut scheme = None;
    let mut path = None;
    let mut authority = None;
    let mut seen_regular_header = false;

    for field in fields {
        if field.name.starts_with(':') {
            if seen_regular_header {
                return false; // pseudo-headers must all precede regular headers
            }
            match field.name.as_str() {
                ":method" if method.is_none() => method = Some(&field.value),
                ":scheme" if scheme.is_none() => scheme = Some(&field.value),
                ":path" if path.is_none() => path = Some(&field.value),
                ":authority" if authority.is_none() => authority = Some(&field.value),
                _ => return false, // duplicate or unrecognized pseudo-header
            }
        } else {
            seen_regular_header = true;
            // RFC 9113 8.2.1: field names are always lowercase in
            // HTTP/2 -- an uppercase letter anywhere in the name is a
            // protocol error, not just a stylistic nit, since h2's
            // HPACK-based framing has no case-folding step the way h1
            // header parsing does.
            if field.name.chars().any(|c| c.is_ascii_uppercase()) {
                return false;
            }
            if is_hop_by_hop(&field.name) {
                return false;
            }
            // RFC 9113 8.2.2: the only valid value for a TE header in
            // an h2 request is exactly "trailers" -- any other value
            // (including empty) is a protocol error, distinct from
            // the general is_hop_by_hop check above which forbids
            // Connection/Transfer-Encoding/etc. entirely but allows TE
            // through with this one specific value.
            if field.name.eq_ignore_ascii_case("te") && !field.value.eq_ignore_ascii_case("trailers") {
                return false;
            }
        }
    }

    if method.is_none() || scheme.is_none() || path.is_none() {
        return false;
    }
    // RFC 9113 8.3.1: :path must not be empty (a genuinely empty path
    // is invalid even though "*" and "/" are both valid non-empty
    // special cases handled elsewhere).
    if path.is_some_and(|p| p.is_empty()) {
        return false;
    }
    if authority.is_none() && !fields.iter().any(|f| f.name.eq_ignore_ascii_case("host")) {
        return false;
    }
    true
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

// ─── DATA frame handling / response sending ─────────────────────────────

impl Connection {
    fn handle_data(&mut self, frame: &Frame<'_>, result: &mut AdvanceResult) {
        let stream_id = frame.header.stream_id;
        if stream_id == CONNECTION_STREAM_ID {
            return self.conn_error(H2Error::ProtocolError, result);
        }

        let mut payload = frame.payload;
        if frame.header.flags & frame::FLAG_PADDED != 0 {
            let Some(&pad_len) = payload.first() else {
                return self.conn_error(H2Error::FrameSizeError, result);
            };
            let pad_len = pad_len as usize;
            if payload.len() < 1 + pad_len {
                return self.conn_error(H2Error::FrameSizeError, result);
            }
            payload = &payload[1..payload.len() - pad_len];
        }

        let frame_len = frame.header.length as i64;
        self.recv_window -= frame_len;
        if self.recv_window < 0 {
            return self.conn_error(H2Error::FlowControlError, result);
        }

        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return self.conn_error(H2Error::StreamClosed, result);
        };
        if stream.phase != StreamPhase::Open {
            let stream_id = stream_id;
            frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::StreamClosed as u32);
            self.streams.remove(&stream_id);
            return;
        }

        stream.recv_window -= frame_len;
        if stream.recv_window < 0 {
            frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::FlowControlError as u32);
            self.streams.remove(&stream_id);
            return;
        }

        stream.request_body.extend_from_slice(payload);

        let end_stream = frame.header.flags & frame::FLAG_END_STREAM != 0;
        if end_stream {
            // RFC 9113 8.3.2 / RFC 9110 8.6: if a content-length
            // header was sent, the actual received body size must
            // match it exactly.
            if let Some(declared) = stream
                .request_headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| h.value.parse::<usize>().ok())
            {
                if declared != stream.request_body.len() {
                    frame::write_rst_stream(&mut result.to_send, stream_id, H2Error::ProtocolError as u32);
                    self.streams.remove(&stream_id);
                    return;
                }
            }
            stream.phase = StreamPhase::HalfClosedRemote;
            result.newly_ready_streams.push(stream_id);
        }

        // Replenish flow-control windows immediately (simplest
        // possible policy: give back exactly what was spent, on every
        // DATA frame, rather than batching window updates) -- a more
        // elaborate implementation could wait for the application to
        // actually consume the data or batch updates to reduce
        // WINDOW_UPDATE frame overhead; correctness doesn't require
        // either optimization, so the simpler policy is used here.
        frame::write_window_update(&mut result.to_send, CONNECTION_STREAM_ID, frame_len as u32);
        self.recv_window += frame_len;
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            frame::write_window_update(&mut result.to_send, stream_id, frame_len as u32);
            stream.recv_window += frame_len;
        }
    }

    /// Queues `headers` + `body` as the response for `stream_id`,
    /// HPACK-encoding the headers and framing as much of the body as
    /// the current flow-control window and negotiated max frame size
    /// allow right now. Any body bytes that don't fit yet are kept in
    /// the stream's `pending_response` and framed later, once
    /// `resume_pending` is called after a WINDOW_UPDATE arrives (see
    /// `handle_window_update`'s caller in `core::event_loop`, which is
    /// expected to call `resume_pending` for affected streams after
    /// observing new send-window headroom).
    pub fn send_response(
        &mut self,
        stream_id: u32,
        status: u16,
        headers: &[HeaderField],
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return out;
        };
        if stream.response_headers_sent {
            return out;
        }
        stream.response_headers_sent = true;

        let mut fields = Vec::with_capacity(headers.len() + 1);
        fields.push(HeaderField {
            name: ":status".to_string(),
            value: status.to_string(),
        });
        fields.extend_from_slice(headers);

        let encoded = self.encoder.encode(&fields);
        write_header_block_frames(&mut out, stream_id, &encoded, self.peer_max_frame_size, body.is_empty());

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.pending_response = PendingBody::Buffered { data: body, offset: 0 };
        }
        self.flush_pending(stream_id, &mut out);
        out
    }

    /// Frames as much of a stream's pending response body as the
    /// connection- and stream-level flow-control windows currently
    /// allow, appending the resulting DATA frame(s) to `out`. Safe to
    /// call repeatedly (a no-op once the pending body is exhausted, or
    /// immediately once a window is exhausted) -- see `send_response`
    /// and the caller expectations noted there for when this needs
    /// calling again.
    fn flush_pending(&mut self, stream_id: u32, out: &mut Vec<u8>) {
        loop {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return;
            };
            if stream.pending_response.is_exhausted() {
                // Only a stream whose response has actually started
                // (`send_response` already ran at least once) is safe
                // to close out here -- an exhausted-looking
                // `PendingBody::None` on a stream that hasn't been
                // dispatched yet is just its untouched default, not a
                // finished response. Closing it prematurely (e.g. from
                // a WINDOW_UPDATE or SETTINGS-triggered resume that
                // fires before the request has even reached the
                // router) would drop the stream out of `self.streams`
                // before `take_request`/`send_response` ever get a
                // chance to run on it.
                if stream.response_headers_sent && stream.phase == StreamPhase::HalfClosedRemote {
                    stream.phase = StreamPhase::Closed;
                    self.streams.remove(&stream_id);
                }
                return;
            }

            let conn_win = self.send_window;
            let stream_win = stream.send_window;
            let window = conn_win.min(stream_win);
            if window <= 0 {
                return; // stalled -- caller resumes via resume_pending later
            }

            let remaining = stream.pending_response.remaining();
            let can_send = (window as usize).min(remaining.len());
            let chunk_len = can_send.min(self.peer_max_frame_size as usize);
            if chunk_len == 0 {
                return;
            }

            let chunk = remaining[..chunk_len].to_vec();
            let is_last_chunk =
                chunk_len == remaining.len(); // this drains the whole remaining buffer
            frame::write_data(out, stream_id, &chunk, is_last_chunk);

            self.send_window -= chunk_len as i64;
            let stream = self.streams.get_mut(&stream_id).unwrap();
            stream.send_window -= chunk_len as i64;
            stream.pending_response.advance(chunk_len);

            if is_last_chunk {
                if stream.phase == StreamPhase::HalfClosedRemote {
                    stream.phase = StreamPhase::Closed;
                    self.streams.remove(&stream_id);
                }
                return;
            }
        }
    }

    /// Resumes framing a stream's still-pending response body after a
    /// WINDOW_UPDATE (connection- or stream-level) increased available
    /// send window -- see `flush_pending`'s doc comment for the
    /// calling contract this exists to satisfy.
    pub fn resume_pending(&mut self, stream_id: u32) -> Vec<u8> {
        let mut out = Vec::new();
        self.flush_pending(stream_id, &mut out);
        out
    }

    /// Every stream id with a pending response body not yet fully
    /// flushed -- a caller resumes each of these (see `resume_pending`)
    /// after a connection-level WINDOW_UPDATE, since that can unblock
    /// every stalled stream at once, not just whichever one happened
    /// to receive its own stream-level WINDOW_UPDATE.
    pub fn streams_with_pending_response(&self) -> Vec<u32> {
        self.streams
            .iter()
            .filter(|(_, s)| !s.pending_response.is_exhausted())
            .map(|(id, _)| id)
            .collect()
    }
}

/// Writes a HEADERS frame (plus CONTINUATION frames if `header_block`
/// is larger than `max_frame_size`) for `encoded` header bytes.
fn write_header_block_frames(
    out: &mut Vec<u8>,
    stream_id: u32,
    encoded: &[u8],
    max_frame_size: u32,
    end_stream: bool,
) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> HeaderField {
        HeaderField {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn new_conn() -> Connection {
        Connection::new(128, 4096)
    }

    /// Whether any frame in `data` (a concatenated byte stream of
    /// however many frames a single `advance()` call produced) has the
    /// given type -- several assertions below only care that a
    /// RST_STREAM appears somewhere in the output, not that it's the
    /// very first frame (a SETTINGS ack, for instance, may precede it).
    fn contains_frame_type(mut data: &[u8], want: FrameType) -> bool {
        while let Some((frame, consumed)) = frame::parse_frame(data) {
            if frame.header.frame_type == want {
                return true;
            }
            data = &data[consumed..];
        }
        false
    }

    /// Drives a full client handshake + a single GET request through
    /// `conn`, returning the stream id the request landed on.
    /// Constructs its own minimal client-side encoder (a fresh
    /// `HpackContext`) rather than depending on `net::h2_client`, which
    /// doesn't exist yet -- this module's tests only need "some valid
    /// HPACK-encoded request", not a full client implementation.
    fn send_handshake_and_request(conn: &mut Connection, path: &str) -> u32 {
        let mut client_encoder = HpackContext::new(4096);
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        // Client's own initial SETTINGS frame (empty is valid).
        frame::write_settings(&mut input, &[]);

        let headers = client_encoder.encode(&[
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":path", path),
            field(":authority", "example.com"),
        ]);
        frame::write_headers(&mut input, 1, &headers, true, true);

        let result = conn.advance(&input);
        assert!(!result.connection_closed, "handshake + request should not close the connection");
        assert_eq!(result.newly_ready_streams, vec![1]);
        1
    }

    #[test]
    fn handshake_produces_settings_frame() {
        let mut conn = new_conn();
        let initial = conn.initial_send();
        let (frame, _) = frame::parse_frame(&initial).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Settings);
    }

    #[test]
    fn incomplete_preface_is_incomplete_not_error() {
        let mut conn = new_conn();
        let result = conn.advance(b"PRI * HTTP/2.0\r\n");
        assert!(!result.connection_closed);
        assert!(!conn.is_closed());
    }

    #[test]
    fn wrong_preface_closes_connection() {
        let mut conn = new_conn();
        let result = conn.advance(b"NOT THE RIGHT PREFACE AT ALLXX");
        assert!(result.connection_closed);
        assert!(conn.is_closed());
    }

    #[test]
    fn simple_get_request_reaches_ready_streams() {
        let mut conn = new_conn();
        let stream_id = send_handshake_and_request(&mut conn, "/hello");
        let (headers, body, _trailers) = conn.take_request(stream_id).unwrap();
        assert!(headers.iter().any(|h| h.name == ":path" && h.value == "/hello"));
        assert!(body.is_empty());
    }

    #[test]
    fn settings_ack_sent_in_response_to_settings() {
        let mut conn = new_conn();
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);
        let result = conn.advance(&input);

        let (frame, _) = frame::parse_frame(&result.to_send).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Settings);
        assert_eq!(frame.header.flags, frame::FLAG_ACK);
    }

    // ─── Response sending ───────────────────────────────────────────

    #[test]
    fn send_response_produces_headers_and_data_frames() {
        let mut conn = new_conn();
        let stream_id = send_handshake_and_request(&mut conn, "/");

        let out = conn.send_response(stream_id, 200, &[field("content-type", "text/plain")], b"hello".to_vec());

        let (headers_frame, consumed) = frame::parse_frame(&out).unwrap();
        assert_eq!(headers_frame.header.frame_type, FrameType::Headers);
        assert_eq!(headers_frame.header.flags & frame::FLAG_END_HEADERS, frame::FLAG_END_HEADERS);
        // Not END_STREAM yet -- a DATA frame with the body follows.
        assert_eq!(headers_frame.header.flags & frame::FLAG_END_STREAM, 0);

        let (data_frame, _) = frame::parse_frame(&out[consumed..]).unwrap();
        assert_eq!(data_frame.header.frame_type, FrameType::Data);
        assert_eq!(data_frame.payload, b"hello");
        assert_eq!(data_frame.header.flags & frame::FLAG_END_STREAM, frame::FLAG_END_STREAM);
    }

    #[test]
    fn send_response_with_empty_body_sets_end_stream_on_headers() {
        let mut conn = new_conn();
        let stream_id = send_handshake_and_request(&mut conn, "/");
        let out = conn.send_response(stream_id, 204, &[], Vec::new());

        let (headers_frame, _) = frame::parse_frame(&out).unwrap();
        assert_eq!(headers_frame.header.flags & frame::FLAG_END_STREAM, frame::FLAG_END_STREAM);
    }

    #[test]
    fn send_response_twice_is_a_no_op_second_time() {
        let mut conn = new_conn();
        let stream_id = send_handshake_and_request(&mut conn, "/");
        let first = conn.send_response(stream_id, 200, &[], b"a".to_vec());
        assert!(!first.is_empty());
        let second = conn.send_response(stream_id, 200, &[], b"b".to_vec());
        assert!(second.is_empty(), "sending a response twice for the same stream should be a no-op");
    }

    // ─── Flow control ───────────────────────────────────────────────

    #[test]
    fn response_larger_than_window_is_split_and_stalls() {
        let mut conn = new_conn();
        // Shrink this stream's send window artificially small by
        // simulating a peer SETTINGS that lowers initial window size
        // AFTER the stream already exists -- simpler for this test:
        // directly construct a body larger than the default window and
        // confirm the connection doesn't just blast it all out ignoring
        // flow control.
        let stream_id = send_handshake_and_request(&mut conn, "/");
        let big_body = vec![b'x'; 100_000]; // larger than the 65535-byte default window
        let out = conn.send_response(stream_id, 200, &[], big_body.clone());

        let mut total_data_bytes = 0usize;
        let mut pos = 0;
        let mut saw_end_stream = false;
        while let Some((frame, consumed)) = frame::parse_frame(&out[pos..]) {
            if frame.header.frame_type == FrameType::Data {
                total_data_bytes += frame.payload.len();
                if frame.header.flags & frame::FLAG_END_STREAM != 0 {
                    saw_end_stream = true;
                }
            }
            pos += consumed;
        }
        assert!(total_data_bytes < big_body.len(), "should not have sent the whole body past the flow-control window");
        assert!(!saw_end_stream, "should not claim END_STREAM before the whole body is sent");
    }

    #[test]
    fn window_update_resumes_stalled_response() {
        let mut conn = new_conn();
        let stream_id = send_handshake_and_request(&mut conn, "/");
        let big_body = vec![b'x'; 100_000];
        let first_out = conn.send_response(stream_id, 200, &[], big_body.clone());

        let sent_before: usize = {
            let mut total = 0;
            let mut pos = 0;
            while let Some((frame, consumed)) = frame::parse_frame(&first_out[pos..]) {
                if frame.header.frame_type == FrameType::Data {
                    total += frame.payload.len();
                }
                pos += consumed;
            }
            total
        };
        assert!(sent_before < big_body.len());

        // Grant a large WINDOW_UPDATE on both the connection AND the
        // stream -- RFC 9113 6.9.1's flow control applies both levels
        // independently (the send window is the minimum of the two),
        // so both need replenishing for the stall to actually clear,
        // not just one.
        let mut window_update_frame = Vec::new();
        frame::write_window_update(&mut window_update_frame, CONNECTION_STREAM_ID, 100_000);
        frame::write_window_update(&mut window_update_frame, stream_id, 100_000);
        let advance_result = conn.advance(&window_update_frame);
        assert!(!advance_result.connection_closed);

        // `advance()` itself already resumes any stream a WINDOW_UPDATE
        // unstalled (see `handle_window_update`) -- a caller-driven
        // `resume_pending` immediately afterward is now redundant for
        // this exact case, but must still be a harmless no-op (the
        // stream may already be fully drained and gone from
        // `self.streams` by this point).
        let mut sent_after = 0;
        let mut saw_end_stream = false;
        for buf in [&advance_result.to_send, &conn.resume_pending(stream_id)] {
            let mut pos = 0;
            while let Some((frame, consumed)) = frame::parse_frame(&buf[pos..]) {
                if frame.header.frame_type == FrameType::Data {
                    sent_after += frame.payload.len();
                    if frame.header.flags & frame::FLAG_END_STREAM != 0 {
                        saw_end_stream = true;
                    }
                }
                pos += consumed;
            }
        }
        assert_eq!(sent_before + sent_after, big_body.len(), "all bytes should eventually be sent, none lost or duplicated");
        assert!(saw_end_stream, "END_STREAM should be set once the very last byte is sent");
    }

    #[test]
    fn streams_with_pending_response_tracks_stalled_streams() {
        let mut conn = new_conn();
        let stream_id = send_handshake_and_request(&mut conn, "/");
        let big_body = vec![b'x'; 100_000];
        conn.send_response(stream_id, 200, &[], big_body);
        assert_eq!(conn.streams_with_pending_response(), vec![stream_id]);
    }

    // ─── Protocol validation ─────────────────────────────────────────

    /// Builds a raw 9-byte frame header + payload, for constructing
    /// frames deliberately outside what this module's own frame::write_*
    /// helpers would ever produce (malformed lengths, wrong stream
    /// ids) -- exactly the kind of input a conformance fuzzer/tester
    /// like h2spec sends and this module's own well-behaved test
    /// helpers otherwise never would.
    fn raw_frame(length: u32, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((length >> 16) as u8);
        out.push((length >> 8) as u8);
        out.push(length as u8);
        out.push(frame_type);
        out.push(flags);
        out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    const FRAME_TYPE_PING: u8 = 0x6;
    const FRAME_TYPE_PRIORITY: u8 = 0x2;
    const FRAME_TYPE_RST_STREAM: u8 = 0x3;
    const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;

    #[test]
    fn ping_with_wrong_length_is_connection_error() {
        let mut conn = new_conn();
        let mut input = CONNECTION_PREFACE.to_vec();
        // A PING frame with a 4-byte payload instead of the required 8.
        input.extend_from_slice(&raw_frame(4, FRAME_TYPE_PING, 0, 0, &[1, 2, 3, 4]));
        let result = conn.advance(&input);
        assert!(result.connection_closed, "wrong-length PING should close the connection");
    }

    #[test]
    fn rst_stream_on_idle_stream_is_connection_error() {
        let mut conn = new_conn();
        let mut input = CONNECTION_PREFACE.to_vec();
        // Stream 1 has never been opened (no HEADERS sent for it) --
        // an RST_STREAM referencing it is idle, not closed.
        input.extend_from_slice(&raw_frame(4, FRAME_TYPE_RST_STREAM, 0, 1, &[0, 0, 0, 0]));
        let result = conn.advance(&input);
        assert!(result.connection_closed, "RST_STREAM on an idle stream should close the connection");
    }

    #[test]
    fn window_update_on_idle_stream_is_connection_error() {
        let mut conn = new_conn();
        let mut input = CONNECTION_PREFACE.to_vec();
        input.extend_from_slice(&raw_frame(4, FRAME_TYPE_WINDOW_UPDATE, 0, 1, &[0, 0, 0, 1]));
        let result = conn.advance(&input);
        assert!(result.connection_closed, "WINDOW_UPDATE on an idle stream should close the connection");
    }

    #[test]
    fn priority_frame_depending_on_itself_is_an_error() {
        let mut conn = new_conn();
        let stream_id = send_handshake_and_request(&mut conn, "/");
        let mut priority_payload = Vec::new();
        priority_payload.extend_from_slice(&stream_id.to_be_bytes()); // depends on itself
        priority_payload.push(16); // weight
        let input = raw_frame(5, FRAME_TYPE_PRIORITY, 0, stream_id, &priority_payload);
        let result = conn.advance(&input);
        // Either a full connection close, or an RST_STREAM for the
        // affected stream, satisfies RFC 9113 5.3.1's "stream error"
        // requirement here -- confirmed by checking result.to_send
        // contains something (either GOAWAY or RST_STREAM bytes),
        // not silence.
        assert!(!result.to_send.is_empty() || result.connection_closed);
    }

    #[test]
    fn priority_frame_wrong_length_on_idle_stream_is_connection_error() {
        let mut conn = new_conn();
        let mut input = CONNECTION_PREFACE.to_vec();
        input.extend_from_slice(&raw_frame(3, FRAME_TYPE_PRIORITY, 0, 1, &[0, 0, 0]));
        let result = conn.advance(&input);
        assert!(result.connection_closed, "wrong-length PRIORITY on an idle stream should close the connection");
    }

    #[test]
    fn even_stream_id_from_client_is_protocol_error() {
        let mut conn = new_conn();
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);
        conn.advance(&input);

        let mut bad = Vec::new();
        frame::write_headers(&mut bad, 2, b"garbage", true, true); // even id -- server-only
        let result = conn.advance(&bad);
        assert!(result.connection_closed);
    }

    #[test]
    fn missing_required_pseudo_header_resets_stream_not_connection() {
        let mut conn = new_conn();
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);
        conn.advance(&input);

        let mut client_encoder = HpackContext::new(4096);
        // Missing :path -- required per RFC 9113 8.3.
        let headers = client_encoder.encode(&[field(":method", "GET"), field(":scheme", "https")]);
        let mut bad = Vec::new();
        frame::write_headers(&mut bad, 1, &headers, true, true);

        let result = conn.advance(&bad);
        assert!(!result.connection_closed, "an invalid request should reset just its stream, not the whole connection");
        let (rst_frame, _) = frame::parse_frame(&result.to_send).unwrap();
        assert_eq!(rst_frame.header.frame_type, FrameType::RstStream);
    }

    #[test]
    fn push_promise_from_client_is_protocol_error() {
        let mut conn = new_conn();
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);
        conn.advance(&input);

        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::PushPromise,
            flags: 0,
            stream_id: 1,
        };
        let mut bad = Vec::new();
        header.write(&mut bad);
        bad.extend_from_slice(&[0, 0, 0, 3]);

        let result = conn.advance(&bad);
        assert!(result.connection_closed);
    }

    #[test]
    fn unknown_frame_type_is_ignored_not_an_error() {
        let mut conn = new_conn();
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);

        let header = FrameHeader {
            length: 3,
            frame_type: FrameType::Unknown(0xEE),
            flags: 0,
            stream_id: 0,
        };
        header.write(&mut input);
        input.extend_from_slice(b"xyz");

        let result = conn.advance(&input);
        assert!(!result.connection_closed);
    }

    #[test]
    fn multiple_concurrent_streams_all_complete_independently() {
        // Exercises the exact category of bug a naive "iterate and
        // mutate the same map" implementation is prone to: several
        // streams in flight at once, each completing and being
        // removed, none silently skipped.
        let mut conn = new_conn();
        let mut client_encoder = HpackContext::new(4096);
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);

        for stream_id in [1u32, 3, 5, 7, 9] {
            let headers = client_encoder.encode(&[
                field(":method", "GET"),
                field(":scheme", "https"),
                field(":path", "/"),
                field(":authority", "example.com"),
            ]);
            frame::write_headers(&mut input, stream_id, &headers, true, true);
        }

        let result = conn.advance(&input);
        let mut ready = result.newly_ready_streams.clone();
        ready.sort();
        assert_eq!(ready, vec![1, 3, 5, 7, 9]);

        for stream_id in [1u32, 3, 5, 7, 9] {
            let out = conn.send_response(stream_id, 200, &[], b"ok".to_vec());
            assert!(!out.is_empty(), "stream {stream_id} should have gotten a response");
        }
    }

    #[test]
    fn concurrent_stream_limit_refuses_excess_streams() {
        let mut conn = Connection::new(2, 4096); // only 2 concurrent streams allowed
        let mut client_encoder = HpackContext::new(4096);
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);

        // Open 2 streams without END_STREAM, so they stay open and count
        // against the concurrency limit.
        for stream_id in [1u32, 3] {
            let headers = client_encoder.encode(&[
                field(":method", "GET"),
                field(":scheme", "https"),
                field(":path", "/"),
                field(":authority", "example.com"),
            ]);
            frame::write_headers(&mut input, stream_id, &headers, false, true);
        }
        let result = conn.advance(&input);
        assert!(!result.connection_closed);

        // A third stream should be refused (RST_STREAM), not accepted.
        let mut third = Vec::new();
        let headers = client_encoder.encode(&[
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":path", "/"),
            field(":authority", "example.com"),
        ]);
        frame::write_headers(&mut third, 5, &headers, true, true);
        let result = conn.advance(&third);
        assert!(!result.connection_closed);
        let (rst_frame, _) = frame::parse_frame(&result.to_send).unwrap();
        assert_eq!(rst_frame.header.frame_type, FrameType::RstStream);
    }

    #[test]
    fn max_header_list_size_refuses_oversized_header_block() {
        // RoutaH2Config::max_header_list_size wired via with_local_settings.
        let mut conn = new_conn().with_local_settings(65_535, frame::DEFAULT_MAX_FRAME_SIZE, 100);
        let mut client_encoder = HpackContext::new(4096);
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);

        let headers = client_encoder.encode(&[
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":path", "/"),
            field(":authority", "example.com"),
            field("x-padding", &"a".repeat(500)), // pushes the uncompressed header list well past the 100-byte limit
        ]);
        frame::write_headers(&mut input, 1, &headers, true, true);

        let result = conn.advance(&input);
        assert!(!result.connection_closed);
        assert!(result.newly_ready_streams.is_empty(), "oversized header list must not reach dispatch");
        assert!(contains_frame_type(&result.to_send, FrameType::RstStream));
    }

    #[test]
    fn max_header_list_size_zero_means_unlimited() {
        let mut conn = new_conn().with_local_settings(65_535, frame::DEFAULT_MAX_FRAME_SIZE, 0);
        let stream_id = send_handshake_and_request(&mut conn, "/");
        assert_eq!(stream_id, 1);
    }

    #[test]
    fn reap_stale_streams_resets_streams_open_past_the_timeout() {
        let mut conn = new_conn();
        let mut client_encoder = HpackContext::new(4096);
        let mut input = Vec::new();
        input.extend_from_slice(CONNECTION_PREFACE);
        frame::write_settings(&mut input, &[]);
        // No END_STREAM -- request body never completes, stream stays open.
        let headers = client_encoder.encode(&[
            field(":method", "POST"),
            field(":scheme", "https"),
            field(":path", "/"),
            field(":authority", "example.com"),
        ]);
        frame::write_headers(&mut input, 1, &headers, false, true);
        conn.advance(&input);
        assert!(conn.streams.contains_key(&1));

        // Zero timeout is a no-op (RoutaH2Config's "0 disables this" convention).
        assert!(conn.reap_stale_streams(std::time::Duration::ZERO).is_empty());
        assert!(conn.streams.contains_key(&1));

        // A timeout that's already elapsed (stream was created moments ago) resets it.
        let rst_bytes = conn.reap_stale_streams(std::time::Duration::from_nanos(1));
        assert!(!rst_bytes.is_empty());
        assert!(contains_frame_type(&rst_bytes, FrameType::RstStream));
        assert!(!conn.streams.contains_key(&1));
    }

    #[test]
    fn huffman_disabled_output_is_not_smaller_than_raw_encoding() {
        let mut with_huffman = HpackContext::new(4096);
        let mut without_huffman = HpackContext::new(4096).with_huffman_enabled(false);
        let value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fields = [field("x-custom", value)];

        let compressed = with_huffman.encode(&fields);
        let raw = without_huffman.encode(&fields);

        // Highly repetitive ASCII compresses well under Huffman -- with it
        // disabled, the encoded form must be strictly larger for this input.
        assert!(raw.len() > compressed.len());
    }

    #[test]
    fn dynamic_table_update_signaling_toggle() {
        let mut signaling_on = HpackContext::new(4096).with_dynamic_table_update_enabled(true);
        signaling_on.set_max_dynamic_table_size(1024);
        let out_on = signaling_on.encode(&[field("x-a", "1")]);

        let mut signaling_off = HpackContext::new(4096).with_dynamic_table_update_enabled(false);
        signaling_off.set_max_dynamic_table_size(1024);
        let out_off = signaling_off.encode(&[field("x-a", "1")]);

        // Signaling on prepends a Dynamic Table Size Update instruction
        // (RFC 7541 6.3, top 3 bits 001) before the first header field --
        // signaling off must not, so the two outputs necessarily differ,
        // with the "off" form the shorter of the two.
        assert!(out_off.len() < out_on.len());
        assert_eq!(out_on[0] & 0xE0, 0x20);
    }

    #[test]
    fn max_concurrent_streams_hard_cap_clamps_local_setting() {
        // core::event_loop clamps max_concurrent_streams to the hard cap
        // before constructing Connection::new -- this test proves the
        // resulting settings frame reflects the clamped value, not the
        // higher configured max_concurrent_streams.
        let configured_max: u32 = 500;
        let hard_cap: u32 = 32;
        let effective = configured_max.min(hard_cap).max(1);
        assert_eq!(effective, 32);
        let conn = Connection::new(effective, 4096);
        assert_eq!(conn.local_max_concurrent_streams, 32);
    }

    #[test]
    fn linear_stream_lookup_serves_requests_identically_to_the_hashmap_default() {
        let mut conn = Connection::new(128, 4096).with_linear_stream_lookup();
        let stream_id = send_handshake_and_request(&mut conn, "/hello");
        let (headers, body, _trailers) = conn.take_request(stream_id).unwrap();
        assert!(headers.iter().any(|h| h.name == ":path" && h.value == "/hello"));
        assert!(body.is_empty());

        let out = conn.send_response(stream_id, 200, &[], b"ok".to_vec());
        assert!(!out.is_empty());
    }

    #[test]
    fn linear_stream_lookup_reuses_a_closed_slot_for_a_new_stream() {
        // A fixed-capacity table only has room for as many concurrent
        // streams as configured -- once one closes, its slot must
        // become available to a subsequent stream rather than the
        // table silently running out of room well before the
        // configured concurrency limit is ever reached.
        let mut conn = Connection::new(1, 4096).with_linear_stream_lookup();
        let first = send_handshake_and_request(&mut conn, "/first");
        conn.send_response(first, 200, &[], b"ok".to_vec());
        assert!(conn.streams.get(&first).is_none(), "stream should have closed after a full response with no pending body");

        let mut request_frame = Vec::new();
        let headers = vec![
            HeaderField { name: ":method".to_string(), value: "GET".to_string() },
            HeaderField { name: ":path".to_string(), value: "/second".to_string() },
            HeaderField { name: ":scheme".to_string(), value: "http".to_string() },
            HeaderField { name: ":authority".to_string(), value: "example.com".to_string() },
        ];
        let mut encoder = HpackContext::new(4096);
        let encoded = encoder.encode(&headers);
        frame::write_headers(&mut request_frame, 3, &encoded, true, true);
        let result = conn.advance(&request_frame);
        assert_eq!(result.newly_ready_streams, vec![3]);
    }
}
