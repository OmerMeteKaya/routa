//! The application-protocol state a connection is running, independent
//! of which I/O backend (`mio_conn`, `uring_conn`) is driving its
//! transport. Unlike a `NULL`-checked field per protocol,
//! `ConnectionProtocol` makes "this connection is exactly one of
//! H1/H2/WS at a time" a fact the type system enforces -- there's no
//! state where, say, both an H2 session and a WebSocket upgrade could
//! coexist on the same connection without a match arm somewhere having
//! to decide which one is real.
//!
//! Every type here operates purely on buffers and its own internal
//! state machine -- none of them touch a socket, a poller, or anything
//! else that differs between a readiness-based and a completion-based
//! I/O backend. That's what makes them shareable: whichever backend is
//! compiled in supplies the bytes (via whatever mechanism its own I/O
//! model uses) and drains the write buffer to the real transport, but
//! the parsing/framing/protocol logic itself is identical either way.

use std::time::Instant;

use crate::util::buf::Buf;

/// Which application protocol is currently running over a connection's
/// transport. `Handshaking` covers both "TCP just accepted, protocol
/// not yet known" and "TLS handshake / ALPN not yet resolved" -- in
/// both cases nothing protocol-specific has decided what this
/// connection is yet.
pub enum ConnectionProtocol {
    /// Transport is up, but no application protocol has been
    /// determined yet (TLS handshake in progress, or plain TCP whose
    /// first bytes haven't been inspected to distinguish HTTP/1.1 from
    /// an h2c upgrade request).
    Handshaking,
    Http1(Http1Connection),
    Http2(Http2Connection),
    WebSocket(WsConnection),
}

/// HTTP/1.1 connection state: what's been read but not yet parsed into
/// a complete request, and what's been produced but not yet flushed to
/// the transport. Actual request/response parsing lives in
/// `http::request`/`http::response`; this only holds the buffers they
/// operate on plus the keep-alive bookkeeping that spans requests on
/// the same connection.
pub struct Http1Connection {
    pub read_buf: Buf,
    pub write_buf: Buf,
    pub keep_alive: bool,
    /// Set when request parsing begins, cleared when the response is
    /// fully written -- `None` means no request is currently in
    /// flight, used to enforce `request_timeout_ms`.
    pub request_started_at: Option<Instant>,
    /// A file-backed response body still being sent via `sendfile(2)`
    /// -- `None` once fully drained (or if this response's body was
    /// an ordinary in-memory buffer instead, queued into `write_buf`
    /// like any other response).
    pub pending_file: Option<PendingFileSend>,
    /// Set once a `100 Continue` interim response has been sent for
    /// the request currently being received -- since `http::request::parse`
    /// is stateless and reports `ParseOutcome::NeedsContinue` on every
    /// call while a request's body is still incomplete, this flag is
    /// what stops the event loop from queuing a fresh `100 Continue`
    /// on every single read event for the same request. Reset to
    /// `false` once that request finishes parsing (alongside
    /// `request_started_at`).
    pub continue_sent: bool,
}

/// A response body queued to be sent via `sendfile(2)` once the
/// preceding headers (in `Http1Connection::write_buf`) have fully
/// drained -- see each backend's own flush logic, the only place this
/// is actually acted on.
pub struct PendingFileSend {
    pub file: std::fs::File,
    pub offset: u64,
    pub remaining: u64,
}

impl Http1Connection {
    pub fn new() -> Self {
        Http1Connection {
            read_buf: Buf::new(),
            write_buf: Buf::new(),
            keep_alive: true,
            pending_file: None,
            continue_sent: false,
            request_started_at: None,
        }
    }
}

impl Default for Http1Connection {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP/2 session state on this connection -- delegates all actual
/// protocol logic to `http::h2::stream::Connection`; this wrapper only
/// adds the write buffer a caller drains to the transport (the H2
/// Connection itself never touches I/O directly -- see its own doc
/// comment).
pub struct Http2Connection {
    pub inner: crate::http::h2::stream::Connection,
    pub write_buf: Buf,
    pub created_at: Instant,
}

/// The subset of `core::config::RoutaH2Config` a new `Http2Connection`
/// needs -- computed once per worker (see each backend's own worker
/// setup) rather than re-read from the full server config on every
/// accepted H2 connection.
#[derive(Debug, Clone, Copy)]
pub struct Http2Settings {
    pub max_concurrent_streams: u32,
    pub header_table_size: usize,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub huffman_encoding: bool,
    pub dynamic_table_update: bool,
    pub server_push_enabled: bool,
    pub stream_timeout: std::time::Duration,
    pub keepalive_timeout: std::time::Duration,
    pub stream_lookup: crate::core::config::H2StreamLookup,
    /// Whether to advertise and accept RFC 8441 Extended CONNECT
    /// (`SETTINGS_ENABLE_CONNECT_PROTOCOL`) -- piggybacks on `h2.enabled
    /// && ws.enabled` rather than its own config field, since
    /// WebSocket-over-H2 is the same WebSocket feature tunneled over a
    /// different transport, not a separate thing a user would want to
    /// enable independently of either.
    pub connect_protocol_enabled: bool,
}

impl Http2Connection {
    pub fn new(settings: &Http2Settings) -> Self {
        let local_max_concurrent_streams = settings.max_concurrent_streams;
        let mut inner = crate::http::h2::stream::Connection::new(local_max_concurrent_streams, settings.header_table_size)
            .with_local_settings(settings.initial_window_size, settings.max_frame_size, settings.max_header_list_size)
            .with_encoder_options(settings.huffman_encoding, settings.dynamic_table_update)
            .with_push_enabled(settings.server_push_enabled)
            .with_connect_protocol_enabled(settings.connect_protocol_enabled);
        if settings.stream_lookup == crate::core::config::H2StreamLookup::Linear {
            inner = inner.with_linear_stream_lookup();
        }
        let mut write_buf = Buf::new();
        write_buf.push(&inner.initial_send());
        Http2Connection {
            inner,
            write_buf,
            created_at: Instant::now(),
        }
    }
}

/// The subset of `core::config::WsConfig` needed once a connection has
/// already been accepted and is running the WS protocol state machine
/// -- computed once per worker, same rationale as `Http2Settings`.
#[derive(Debug, Clone, Copy)]
pub struct WsSettings {
    pub max_frame_size: u64,
    pub max_message_size: u64,
    pub require_masking: bool,
    pub compression_level: u32,
    pub compression_threshold: usize,
    pub write_queue_max_bytes: u64,
    pub idle_timeout: Option<std::time::Duration>,
    pub ping_interval: std::time::Duration,
    pub ping_timeout: std::time::Duration,
    pub max_ping_misses: u32,
    pub read_buf_size: usize,
    pub write_buf_size: usize,
}

/// WebSocket connection state on this connection -- delegates all
/// actual protocol logic to `http::ws::WsConnection`; this wrapper
/// only adds the write buffer a caller drains to the transport, same
/// division of responsibility as Http2Connection above.
pub struct WsConnection {
    pub inner: crate::http::ws::WsConnection,
    pub write_buf: Buf,
    /// The path this connection originally upgraded on -- looked back
    /// up against `Router::dispatch_websocket` for every received
    /// message, rather than resolving and caching a handler reference
    /// once, since a request-scoped router lookup is already cheap
    /// (a linear scan over however many WS routes exist, typically
    /// few) and keeping just the path avoids this struct needing a
    /// lifetime or an `Arc` cycle back into the router that registered
    /// it.
    pub upgrade_path: String,
    /// `WsSettings::write_queue_max_bytes` for the connection this
    /// belongs to -- each backend checks `write_buf`'s length against
    /// this after every push to enforce `WsConfig::write_queue_max`
    /// backpressure.
    pub write_queue_max_bytes: u64,
    /// Ping/pong keepalive bookkeeping (`WsConfig::ping_interval_ms`
    /// / `ping_timeout_ms` / `max_ping_misses`), driven by each
    /// backend's own periodic sweep.
    pub last_pong_at: Instant,
    pub last_ping_sent: Option<Instant>,
    pub ping_misses: u32,
}

impl WsConnection {
    pub fn new(pmd: Option<crate::http::ws::PmdContext>, max_message_size: usize) -> Self {
        WsConnection {
            inner: crate::http::ws::WsConnection::new(pmd, max_message_size),
            write_buf: Buf::new(),
            write_queue_max_bytes: u64::MAX,
            last_pong_at: Instant::now(),
            last_ping_sent: None,
            ping_misses: 0,
            upgrade_path: String::new(),
        }
    }

    pub fn with_upgrade_path(mut self, path: String) -> Self {
        self.upgrade_path = path;
        self
    }

    pub fn with_settings(pmd: Option<crate::http::ws::PmdContext>, settings: &WsSettings) -> Self {
        WsConnection {
            inner: crate::http::ws::WsConnection::with_read_buf_capacity(
                pmd,
                settings.max_message_size as usize,
                settings.max_frame_size,
                settings.require_masking,
                settings.read_buf_size,
            ),
            write_buf: Buf::with_capacity(settings.write_buf_size),
            write_queue_max_bytes: settings.write_queue_max_bytes,
            last_pong_at: Instant::now(),
            last_ping_sent: None,
            ping_misses: 0,
            upgrade_path: String::new(),
        }
    }
}
