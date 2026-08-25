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
    /// An *upstream* connection speaking H2 as a client -- distinct
    /// from `Http2` (which is `http::h2::stream::Connection`, a
    /// server-side state machine: different stream-id allocation,
    /// different frame-validation rules, no request parsing at all --
    /// see `net::uring_h2_client`'s own top doc comment for the full
    /// rationale for keeping the two separate types entirely rather
    /// than adding a client/server role flag to one shared type).
    /// Only ever constructed by uring_backend, once ALPN negotiates
    /// "h2" on a TLS-enabled upstream node's connection -- mio_backend
    /// has no equivalent variant to reach here at all, since its own
    /// H2 upstream support (`core::proxy::H2PoolRegistry`) is built
    /// entirely around `net::h2_client::H2Client` instead, outside
    /// this enum altogether.
    UpstreamH2(crate::net::uring_h2_client::UringH2Client),
}

/// HTTP/1.1 connection state: what's been read but not yet parsed into
/// a complete request, and what's been produced but not yet flushed to
/// the transport. Actual request/response parsing lives in
/// `http::request`/`http::response`; this only holds the buffers they
/// operate on plus the keep-alive bookkeeping that spans requests on
/// the same connection.
/// Everything a downstream connection needs to remember while its
/// current request has been forwarded upstream and might need to be
/// retried against a different node -- see `Http1Connection::waiting_for_upstream`'s
/// own doc comment for why this lives here rather than being
/// re-derived. `attempts_so_far` is what turns a single connect/send/recv
/// failure into an actual retry loop (mirroring mio_backend's own
/// synchronous `for attempt in 0..max_attempts` in `core::proxy::forward`)
/// rather than the first failure always producing a 502: a backend's
/// own failure-handling code checks this against
/// `pending.config`-derived retry bounds (`core::proxy::ProxyConfig`
/// doesn't carry `max_retries` itself -- see `ProxyPending`'s own
/// fields -- so this is checked against `pending.lb.config.max_retries`)
/// before giving up and finally producing an error response.
pub struct ProxyAttemptState {
    pub upstream_slab_index: usize,
    pub upstream_generation: u32,
    pub keep_alive: bool,
    pub attempts_so_far: u32,
    pub pending: crate::core::proxy::ProxyPending,
    pub original_request: Box<crate::http::request::HttpRequest>,
}

pub struct Http1Connection {
    pub read_buf: Buf,
    pub write_buf: Buf,
    pub keep_alive: bool,
    /// `false` while this connection is still a plaintext connection
    /// accumulating bytes to check against the H2 connection preface
    /// (see `decide_plaintext_protocol`) -- `Http1Connection` is reused
    /// as scratch storage for that check itself (rather than adding a
    /// separate buffer to `Connection`), so this flag is what tells a
    /// backend's protocol-selection code whether a `ConnectionProtocol::Http1`
    /// it's looking at genuinely means "confirmed HTTP/1.1" or "still
    /// deciding" -- `NeedMoreData` must not be mistaken for the
    /// former, or the preface check silently never runs again on a
    /// later call. Always `true` for a TLS connection (ALPN already
    /// decided unambiguously, see each backend's own handshake
    /// handling) and for a plaintext connection once
    /// `decide_plaintext_protocol` has actually returned `Http1`.
    pub protocol_confirmed: bool,
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
    /// `Some((upstream_slab_index, upstream_generation))` while this
    /// downstream connection's current request has been forwarded to
    /// an upstream connection and is waiting for that upstream's
    /// response -- see `core::conn::uring_conn::ConnectionRole::Upstream`'s
    /// own doc comment for the pairing's ABA-safety role. `process_http1_read_buf`
    /// itself never sets or reads this (proxying is driven by the
    /// backend event loop, one layer above the protocol state
    /// machines this module holds) -- it exists here purely so a
    /// downstream connection's own `Http1Connection` can carry this
    /// bookkeeping across the (possibly several) event loop passes
    /// between "request fully parsed, forwarded upstream" and
    /// "upstream response arrived, ready to flush back to the
    /// client", the same way `pending_file` already carries
    /// in-progress sendfile state across passes for a different kind
    /// of multi-step response. `None` outside of proxying (the
    /// overwhelming majority of connections, and the only case
    /// mio_backend's own equivalent Http1Connection usage needs to
    /// consider today, since core::proxy's mio path doesn't route
    /// through this at all -- see that module's own doc comment).
    pub waiting_for_upstream: Option<ProxyAttemptState>,
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
            protocol_confirmed: true,
            waiting_for_upstream: None,
        }
    }

    /// A scratch `Http1Connection` for accumulating a plaintext
    /// connection's not-yet-classified bytes -- see
    /// `protocol_confirmed`'s own doc comment. Only ever used as an
    /// intermediate state before `decide_plaintext_protocol` resolves
    /// it one way or the other.
    pub fn new_unconfirmed() -> Self {
        Http1Connection {
            protocol_confirmed: false,
            ..Self::new()
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

/// The literal client connection preface RFC 9113 3.4 defines --
/// exactly 24 bytes, sent by a client that already knows (without an
/// HTTP/1.1 Upgrade negotiation) that it's speaking directly to an H2
/// server. h2spec's default test mode -- and any HTTP/2 client that
/// isn't going through the h2c Upgrade dance -- connects this way,
/// distinct from (and in addition to) the h2c Upgrade path
/// `process_http1_read_buf` already handles.
pub const H2_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Checks whether `buf` (a connection's accumulated but not-yet-parsed
/// bytes) begins with the literal H2 connection preface -- see
/// `H2_CONNECTION_PREFACE`'s own doc comment. Only ever meaningful to
/// check on a connection still in `ConnectionProtocol::Handshaking`,
/// before anything has committed to treating its bytes as HTTP/1.1;
/// once even a single byte has been fed to `http::request::parse` as
/// part of that protocol, this check no longer applies.
pub fn starts_with_h2_connection_preface(buf: &[u8]) -> bool {
    buf.len() >= H2_CONNECTION_PREFACE.len() && &buf[..H2_CONNECTION_PREFACE.len()] == H2_CONNECTION_PREFACE
}

/// What a plaintext connection still in `ConnectionProtocol::Handshaking`
/// should become, given the bytes accumulated on it so far -- called
/// once enough bytes have arrived to decide, rather than committing to
/// HTTP/1.1 immediately the way a connection would if this check
/// didn't exist. Only meaningful for plaintext connections: a TLS
/// connection's protocol is already decided by ALPN (see each
/// backend's own handshake-completion handling) before any
/// application data is available to check this way at all.
pub enum PlaintextProtocolDecision {
    /// Not enough bytes yet to tell -- keep accumulating and call this
    /// again once more arrive.
    NeedMoreData,
    /// The H2 connection preface was found -- this connection is
    /// prior-knowledge HTTP/2 (RFC 9113 3.4), never HTTP/1.1 at all.
    Http2PriorKnowledge,
    /// No H2 preface within the bytes seen so far, and what's arrived
    /// never matched a prefix of it either -- ordinary HTTP/1.1 (the
    /// caller should hand these bytes to `Http1Connection::read_buf`
    /// and proceed with `process_http1_read_buf` as usual).
    Http1,
    /// What's arrived so far matched a genuine prefix of the H2
    /// connection preface (at minimum, starts with the literal `"PRI"`
    /// that no ordinary HTTP/1.1 request line begins with -- no valid
    /// method starts that way) but then diverged from it before the
    /// full 24 bytes matched -- a malformed attempt at prior-knowledge
    /// H2, not a real HTTP/1.1 request that happens to start
    /// similarly. RFC 9113 3.4 requires treating this as a connection
    /// error (PROTOCOL_ERROR), not silently reinterpreting it as
    /// HTTP/1.1 -- h2spec's own "sends invalid connection preface"
    /// test case exists specifically to check this.
    InvalidH2Preface,
}

/// Decides `buf`'s protocol per `PlaintextProtocolDecision`'s own doc
/// comment. Deliberately waits for a full `H2_CONNECTION_PREFACE`
/// worth of bytes before concluding `Http1` -- a partial prefix that
/// matches the preface so far (e.g. just `b"PRI "`) is genuinely
/// ambiguous and must not be misread as an HTTP/1.1 request line this
/// early.
pub fn decide_plaintext_protocol(buf: &[u8]) -> PlaintextProtocolDecision {
    // The shortest unambiguous marker that a client is genuinely
    // attempting prior-knowledge H2 rather than an HTTP/1.1 request
    // that merely happens to start similarly: no HTTP method is or
    // ever will be named "PRI" (RFC 9110 9.1 registers methods as
    // all-uppercase tokens followed by a space and a request-target --
    // "PRI * HTTP/2.0" itself deliberately reuses that shape so a
    // preface sent to an HTTP/1.1-only server is at least harmless).
    // Checking against this fixed 3-byte marker first, before the
    // full-prefix comparison below, means "PRI" alone is already
    // enough to commit to treating any further divergence as a
    // malformed H2 attempt rather than plain HTTP/1.1 -- exactly the
    // distinction RFC 9113 3.4 and h2spec's "sends invalid connection
    // preface" test case both depend on.
    const PRI_MARKER: &[u8] = b"PRI";

    if buf.len() < H2_CONNECTION_PREFACE.len() {
        // Not enough bytes yet to know for certain either way -- but
        // only genuinely still ambiguous if what HAS arrived is a
        // prefix consistent with the full preface (including, in
        // particular, being consistent with "PRI" for however many of
        // those first 3 bytes have arrived so far -- a partial buffer
        // shorter than 3 bytes is still fully consistent with "PRI",
        // it just hasn't arrived yet). A byte that already disagrees
        // with the preface at its own position -- including within
        // the first 3 bytes -- means this can only be HTTP/1.1.
        if buf.iter().zip(H2_CONNECTION_PREFACE.iter()).all(|(a, b)| a == b) {
            return PlaintextProtocolDecision::NeedMoreData;
        }
        // Diverged from the preface already -- but only treat this as
        // a malformed H2 attempt (InvalidH2Preface) rather than
        // ordinary HTTP/1.1 if enough bytes have arrived to know the
        // divergence happened at or after the "PRI" marker itself
        // (RFC 9110 9.1: no HTTP method is or ever will be named
        // "PRI", so once those 3 bytes are confirmed, any further
        // mismatch is a broken H2 attempt, not a real request line).
        // If the divergence is within the first 3 bytes, it's
        // unambiguously not even attempting "PRI" -- ordinary
        // HTTP/1.1.
        let diverged_within_first_three = buf.len() < PRI_MARKER.len()
            || buf[..PRI_MARKER.len()] != *PRI_MARKER;
        if diverged_within_first_three {
            return PlaintextProtocolDecision::Http1;
        }
        return PlaintextProtocolDecision::InvalidH2Preface;
    }

    if starts_with_h2_connection_preface(buf) {
        return PlaintextProtocolDecision::Http2PriorKnowledge;
    }
    let starts_with_pri_marker = &buf[..PRI_MARKER.len()] == PRI_MARKER;
    if starts_with_pri_marker {
        PlaintextProtocolDecision::InvalidH2Preface
    } else {
        PlaintextProtocolDecision::Http1
    }
}

// ─── HTTP/1.1 request processing (backend-agnostic) ─────────────────────

/// What the caller needs to do next after `process_http1_read_buf`
/// advances an `Http1Connection`'s state as far as it currently can.
/// None of these variants involve this module doing any I/O itself --
/// see this module's own doc comment -- they only describe what's now
/// sitting in `write_buf` (or which protocol the connection just
/// switched to) so each backend can drive its own transport
/// accordingly (a synchronous write for `mio_backend`, a `Send` SQE
/// submission for `uring_backend`).
pub enum Http1Outcome {
    /// No complete request is available yet -- nothing was queued into
    /// `write_buf`, no I/O is needed, just wait for more bytes to
    /// arrive and call this again.
    NeedsMoreData,
    /// A response is queued in `write_buf`; once the caller has
    /// flushed it, this connection should be closed (a malformed
    /// request, or a request whose response set `Connection: close`).
    FlushThenClose,
    /// A response is queued in `write_buf`; once the caller has
    /// flushed it, driving this connection should continue normally --
    /// `read_buf` may already hold a further pipelined request.
    FlushThenContinue,
    /// The connection has just switched to
    /// `ConnectionProtocol::Http2` (an h2c upgrade) -- the `101`
    /// response is already queued in what was `Http1Connection::write_buf`
    /// and must be flushed to the transport before the caller drives
    /// any `Http2` state at all, since the switch already replaced
    /// this connection's `protocol` by the time this returns.
    SwitchedToHttp2,
    /// The matched route is a proxy route -- see
    /// `http::response::HttpResponse::proxy_pending`'s own doc comment
    /// for why this function returns this instead of the real
    /// response itself. Nothing was queued into `write_buf`, and this
    /// connection's `Http1Connection` state (specifically its
    /// `read_buf`, which may already hold a further pipelined request)
    /// is left exactly as it was when this call started -- the caller
    /// is responsible for driving the actual proxy request (opening
    /// an upstream connection, forwarding it, and eventually producing
    /// a real response to flush back), then re-entering ordinary
    /// dispatch once that's done, the same way it would after any
    /// other asynchronous step this function itself can't perform
    /// (this function's own doc comment on why it does no I/O applies
    /// here too -- a backend's async connect/send/recv cycle has no
    /// business inside protocol-parsing code that's shared, unchanged,
    /// with mio_backend, which drives proxying through its own
    /// completely separate, synchronous code path instead -- see
    /// `core::proxy`'s own doc comment).
    ProxyPending(crate::core::proxy::ProxyPending, Box<crate::http::request::HttpRequest>),
    /// The matched route is a static-file route whose cache-miss path
    /// needs an asynchronous OPENAT+STATX round-trip -- see
    /// `crate::http::static_files::FileCachePending`'s own doc
    /// comment. Same shape and rationale as `ProxyPending` just above:
    /// nothing was queued into `write_buf`, and this connection's
    /// `read_buf` is left untouched; the caller drives the actual
    /// stat (or, for a backend with no async story of its own, calls
    /// `static_files::finish_after_stat` synchronously right away)
    /// and re-enters ordinary dispatch once a real response exists.
    FileCachePending(crate::http::static_files::FileCachePending, Box<crate::http::request::HttpRequest>),
    /// The connection has just switched to
    /// `ConnectionProtocol::WebSocket` -- same flush-before-anything-else
    /// requirement as `SwitchedToHttp2` above.
    SwitchedToWebSocket,
}

/// Reads `Sec-WebSocket-Extensions` back off the handshake response
/// (rather than the original request) so the negotiated parameters
/// this connection actually uses match exactly what was sent to the
/// client -- see `http::middleware`'s WS upgrade handler (wherever
/// that's registered) for where the response's own PMD negotiation
/// happens.
fn negotiate_pmd_from_response(response: &crate::http::response::HttpResponse, compression_level: u32) -> Option<crate::http::ws::PmdContext> {
    let ext = response.get_header("Sec-WebSocket-Extensions")?;
    if !ext.contains("permessage-deflate") {
        return None;
    }
    let params = crate::http::ws::PmdParams {
        server_no_context_takeover: ext.contains("server_no_context_takeover"),
        client_no_context_takeover: ext.contains("client_no_context_takeover"),
    };
    Some(crate::http::ws::PmdContext::with_compression_level(params, compression_level))
}

/// Serializes `response` into `h1.write_buf` (headers plus body, or
/// just headers with the body deferred to `PendingFileSend` if it was
/// file-backed). Only the file-body deferral shape (`PendingFileSend`)
/// is backend-agnostic here -- actually sending that file's bytes is
/// transport-specific and left to each backend's own flush logic.
pub fn queue_http1_response(h1: &mut Http1Connection, mut response: crate::http::response::HttpResponse) {
    let file_body = response.file_body.take();

    let mut serialized = crate::util::buf::Buf::new();
    response.serialize(&mut serialized); // body is empty when file_body was Some, so this only writes headers
    h1.write_buf.push(serialized.as_slice());

    if let Some(fb) = file_body {
        h1.pending_file = Some(PendingFileSend {
            file: fb.file,
            offset: fb.offset,
            remaining: fb.len,
        });
    }
}

/// The subset of a worker's per-connection context `process_http1_read_buf`
/// needs -- computed once per worker (see each backend's own setup,
/// mirroring `Http2Settings`/`WsSettings`) rather than threaded through
/// as a long parameter list. Deliberately excludes anything
/// transport-specific (no poller, no fd, no ring): this function's
/// whole point is not needing to know which backend is calling it.
pub struct Http1DispatchContext<'a> {
    pub server: &'a crate::core::server::RoutaServer,
    pub max_request_size: usize,
    pub h2_settings: &'a Http2Settings,
    pub ws_settings: &'a WsSettings,
    pub h2c_upgrade_enabled: bool,
    pub ws_enabled: bool,
    pub ws_max_connections: usize,
    pub ws_permessage_deflate: bool,
    pub remote_addr: std::net::IpAddr,
}

/// Advances an HTTP/1.1 connection's state as far as the bytes
/// currently sitting in its `read_buf` allow: parses as many complete
/// requests as are available, dispatches each through the server's
/// middleware chain, and queues the serialized response(s) into
/// `write_buf` -- switching `*protocol` to `Http2` or `WebSocket`
/// in-place if a request warranted it (h2c upgrade, or an accepted
/// WebSocket `Upgrade`). Does no I/O itself -- see `Http1Outcome`'s own
/// doc comment for what the caller does with its result.
///
/// Takes `&mut ConnectionProtocol` rather than `&mut Http1Connection`
/// directly because an h2c upgrade needs to replace the variant itself
/// partway through (the same thing mio_backend's original drive_http1
/// did in place) -- callers are expected to have already confirmed
/// `*protocol` is `ConnectionProtocol::Http1(_)` before calling this,
/// the same precondition `drive_http1` always had.
pub fn process_http1_read_buf(protocol: &mut ConnectionProtocol, ctx: &Http1DispatchContext) -> Http1Outcome {
    loop {
        let (parse_outcome, _request_started_at) = {
            let ConnectionProtocol::Http1(h1) = protocol else {
                unreachable!("process_http1_read_buf requires protocol to already be Http1")
            };
            (crate::http::request::parse(&h1.read_buf, ctx.max_request_size), h1.request_started_at)
        };

        match parse_outcome {
            crate::http::request::ParseOutcome::Incomplete => return Http1Outcome::NeedsMoreData,

            crate::http::request::ParseOutcome::NeedsContinue { method, path, headers } => {
                let already_sent = {
                    let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                    h1.continue_sent
                };
                if !already_sent {
                    let probe_request = crate::http::request::HttpRequest {
                        method,
                        remote_addr: Some(ctx.remote_addr),
                        path: path.clone(),
                        query: None,
                        query_params: Vec::new(),
                        version_major: 1,
                        version_minor: 1,
                        headers: headers.clone(),
                        body: Vec::new(),
                        keep_alive: true,
                        trailers: Vec::new(),
                    };
                    let route_exists = !matches!(
                        ctx.server.router.dispatch(&probe_request),
                        crate::http::router::Dispatch::NotFound | crate::http::router::Dispatch::MethodNotAllowed { .. }
                    );
                    let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                    if route_exists {
                        h1.write_buf.push(b"HTTP/1.1 100 Continue");
                        h1.write_buf.push(&[13, 10, 13, 10]);
                        h1.continue_sent = true;
                        // NeedsContinue is reported again on every
                        // call until the body finishes arriving -- the
                        // 100 Continue above only needs to be queued
                        // once (continue_sent guards that), and no
                        // response is complete yet, so this isn't a
                        // flush point: wait for more data exactly like
                        // the Incomplete case.
                        return Http1Outcome::NeedsMoreData;
                    } else {
                        let mut resp = ctx.server.middleware_chain.execute(&probe_request);
                        resp.set_header("Connection", "close");
                        queue_http1_response(h1, resp);
                        return Http1Outcome::FlushThenClose;
                    }
                }
                return Http1Outcome::NeedsMoreData;
            }

            crate::http::request::ParseOutcome::Invalid(_) => {
                let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                let mut resp = crate::http::response::HttpResponse::new(400, "Bad Request");
                resp.set_header("Connection", "close");
                queue_http1_response(h1, resp);
                return Http1Outcome::FlushThenClose;
            }

            crate::http::request::ParseOutcome::Complete { mut request, consumed } => {
                request.remote_addr = Some(ctx.remote_addr);

                {
                    let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                    h1.read_buf.consume(consumed);
                    h1.request_started_at = None;
                    h1.continue_sent = false;
                }

                if ctx.h2c_upgrade_enabled && crate::http::h2::is_h2c_upgrade_request(&request) {
                    let settings_payload = crate::http::h2::decode_http2_settings_header(&request).unwrap_or_default();
                    let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                    let mut resp = crate::http::response::HttpResponse::new(101, "Switching Protocols");
                    resp.set_header("Connection", "Upgrade");
                    resp.set_header("Upgrade", "h2c");
                    queue_http1_response(h1, resp);
                    // As with the WebSocket upgrade path above, the 101
                    // response was just serialized into what's about
                    // to become the *old* protocol variant's write_buf
                    // -- extracting its bytes before replacing
                    // *protocol is required, since Http2Connection::new
                    // starts with its own write_buf containing only
                    // the H2 connection preface's initial_send(), not
                    // this response.
                    let pending_101_response = h1.write_buf.as_slice().to_vec();

                    // Http2Connection::new already queues the H2
                    // connection preface's own initial_send() into its
                    // fresh write_buf -- the 101 response must precede
                    // that on the wire (the client is still expecting
                    // an HTTP/1.1-shaped response to its Upgrade
                    // request before it starts reading H2 frames), so
                    // it's built as a separate buffer here and placed
                    // in front of what new() already produced, rather
                    // than appending after it (which would send the H2
                    // preface first) or calling initial_send() again
                    // (which would send it twice).
                    let mut h2 = Http2Connection::new(ctx.h2_settings);
                    h2.inner.assume_preface_received();
                    h2.inner.apply_upgrade_settings(&settings_payload);
                    let mut write_buf_with_101_first = crate::util::buf::Buf::new();
                    write_buf_with_101_first.push(&pending_101_response);
                    write_buf_with_101_first.push(h2.write_buf.as_slice());
                    h2.write_buf = write_buf_with_101_first;
                    *protocol = ConnectionProtocol::Http2(h2);
                    return Http1Outcome::SwitchedToHttp2;
                }

                let is_upgrade = crate::http::ws::is_upgrade_request(&request);
                let request_body_len = request.body.len();
                let method_str = format!("{:?}", request.method).to_uppercase();
                let route = request.path.clone();
                ctx.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).inc();
                let dispatch_start = std::time::Instant::now();
                let mut response = ctx.server.middleware_chain.execute(&request);
                if let Some(pending) = response.proxy_pending.take() {
                    // No metrics recorded here -- there's no real
                    // response yet to record a status/duration/body
                    // size for; the caller's own eventual real
                    // forward() attempt is what actually produces
                    // those, the same as mio_backend's own drive_http1
                    // only records metrics after its (synchronous)
                    // forward() call returns.
                    ctx.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).dec();
                    return Http1Outcome::ProxyPending(pending, Box::new(request));
                }
                if let Some(pending) = response.file_cache_pending.take() {
                    // Same rationale as the proxy_pending arm just
                    // above -- no real response exists yet to record
                    // metrics for.
                    ctx.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).dec();
                    return Http1Outcome::FileCachePending(pending, Box::new(request));
                }
                let duration_secs = dispatch_start.elapsed().as_secs_f64();
                ctx.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).dec();
                ctx.server.metrics.record_request(
                    &method_str,
                    &route,
                    response.status,
                    duration_secs,
                    request_body_len,
                    response.body().len(),
                );
                if !response.early_hints.is_empty() {
                    let mut early_hints_response = String::from("HTTP/1.1 103 Early Hints\r\n");
                    for (name, value) in &response.early_hints {
                        early_hints_response.push_str(name);
                        early_hints_response.push_str(": ");
                        early_hints_response.push_str(value);
                        early_hints_response.push_str("\r\n");
                    }
                    early_hints_response.push_str("\r\n");
                    let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                    h1.write_buf.push(early_hints_response.as_bytes());
                }
                if request.method == crate::http::request::HttpMethod::Head {
                    response.strip_body_for_head();
                }

                if is_upgrade && response.status == 101 {
                    let over_capacity = ctx.server.ws_active_connections.load(std::sync::atomic::Ordering::Relaxed) >= ctx.ws_max_connections;
                    if !ctx.ws_enabled || over_capacity {
                        let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                        let mut resp = crate::http::response::HttpResponse::new(503, "Service Unavailable");
                        resp.set_header("Connection", "close");
                        resp.set_body(b"WebSocket unavailable\n".to_vec());
                        queue_http1_response(h1, resp);
                        return Http1Outcome::FlushThenClose;
                    }

                    let pmd = if ctx.ws_permessage_deflate {
                        negotiate_pmd_from_response(&response, ctx.ws_settings.compression_level)
                    } else {
                        None
                    };
                    let upgrade_path = request.path.clone();
                    let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                    queue_http1_response(h1, response);
                    // The 101 response was just serialized into what's
                    // about to become the *old* protocol variant's
                    // write_buf -- extracting its bytes before
                    // replacing *protocol below is required, not
                    // optional: WsConnection::with_settings starts
                    // with a fresh, empty write_buf of its own, so
                    // without this the 101 response would simply be
                    // dropped along with the Http1Connection it was
                    // queued into, and the client would see nothing
                    // come back for its upgrade request at all.
                    let pending_101_response = h1.write_buf.as_slice().to_vec();

                    let mut ws = WsConnection::with_settings(pmd, ctx.ws_settings).with_upgrade_path(upgrade_path);
                    ws.write_buf.push(&pending_101_response);
                    *protocol = ConnectionProtocol::WebSocket(ws);
                    ctx.server.ws_active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Http1Outcome::SwitchedToWebSocket;
                }

                let keep_alive = request.keep_alive && response.get_header("Connection").map(|v| !v.eq_ignore_ascii_case("close")).unwrap_or(true);
                // HttpResponse::serialize defaults to writing
                // Connection: close whenever no route handler set
                // this header explicitly (see its own doc comment) --
                // without setting it here, a keep_alive=true response
                // from a handler that never touches this header (the
                // overwhelming majority) would tell the client the
                // connection is closing while this backend actually
                // keeps it open, a real client-visible protocol
                // violation a read-until-EOF client (or a pipelined
                // request waiting on this connection's own second
                // response) would misinterpret as "nothing more is
                // coming".
                if response.get_header("Connection").is_none() {
                    response.set_header("Connection", if keep_alive { "keep-alive" } else { "close" });
                }
                let ConnectionProtocol::Http1(h1) = protocol else { unreachable!() };
                queue_http1_response(h1, response);
                h1.keep_alive = keep_alive;

                if !keep_alive {
                    return Http1Outcome::FlushThenClose;
                }
                return Http1Outcome::FlushThenContinue;
            }
        }
    }
}

// ─── WebSocket message processing (backend-agnostic) ────────────────────

/// The subset of a worker's per-connection context `process_websocket_input`
/// needs -- mirrors `Http1DispatchContext`, but WebSocket only ever
/// needs the router (for `dispatch_websocket`) and the configured
/// compression threshold, since everything else (frame limits,
/// masking requirements, ping/pong timers) already lives inside
/// `WsConnection::inner`'s own state, set once at upgrade time.
pub struct WsDispatchContext<'a> {
    pub router: &'a crate::http::router::Router,
    pub compression_threshold: usize,
}

/// What happened as a result of feeding newly-arrived bytes through a
/// WebSocket connection's frame parser -- mirrors `Http1Outcome`'s role
/// (see its own doc comment): describes what's now sitting in
/// `write_buf` and whether the connection should close, without this
/// function performing any I/O itself.
pub enum WebSocketOutcome {
    /// Bytes were queued into `write_buf` (an auto-pong, a
    /// close-handshake echo, or an application-level reply) and should
    /// be flushed; the connection stays open afterward.
    FlushThenContinue,
    /// A protocol error occurred, or the write queue exceeded
    /// `WsSettings::write_queue_max_bytes` -- whatever is in
    /// `write_buf` (if anything) should still be flushed, but the
    /// connection should then be closed.
    FlushThenClose,
    /// The close handshake has completed on both sides
    /// (`WsConnection::is_closed`) -- if anything is queued in
    /// `write_buf` (this side's own close-frame echo), it should be
    /// flushed, and the connection closed immediately afterward. Kept
    /// distinct from `FlushThenClose` (a protocol error or
    /// backpressure limit) since this is the ordinary, successful end
    /// of a WebSocket connection's life, not a fault -- callers may
    /// want to log or account for these differently.
    ClosedFlushThenClose,
    /// Nothing was produced and nothing needs to happen -- equivalent
    /// to `Http1Outcome::NeedsMoreData`, though for WebSocket this
    /// also covers the ordinary case of a frame that produced no
    /// reply (e.g. a received application message with no registered
    /// handler for this connection's route).
    NoActionNeeded,
}

/// Advances a WebSocket connection's frame parser with `input`,
/// dispatches any complete application messages through the server's
/// registered WS route handler, and queues whatever needs to go back
/// out (automatic pings/pongs, close-handshake echoes, handler
/// replies) into `ws.write_buf`. Does no I/O itself -- see
/// `WebSocketOutcome`'s own doc comment for what the caller does with
/// its result.
///
/// Takes `&mut ConnectionProtocol` for the same reason
/// `process_http1_read_buf` does -- callers are expected to have
/// already confirmed `*protocol` is `ConnectionProtocol::WebSocket(_)`.
/// Unlike HTTP/1.1, a WebSocket connection never switches to a
/// different `ConnectionProtocol` variant once upgraded, so this
/// never needs to replace `*protocol` the way an h2c upgrade does.
pub fn process_websocket_input(protocol: &mut ConnectionProtocol, input: &[u8], ctx: &WsDispatchContext) -> WebSocketOutcome {
    let ConnectionProtocol::WebSocket(ws) = protocol else {
        unreachable!("process_websocket_input requires protocol to already be WebSocket")
    };

    if input.is_empty() {
        return WebSocketOutcome::NoActionNeeded;
    }

    let advance_result = ws.inner.advance(input);

    let mut outgoing_messages = Vec::new();
    for event in &advance_result.events {
        if let crate::http::ws::WsEvent::Message(msg) = event {
            if let Some(handler) = ctx.router.dispatch_websocket(&ws.upgrade_path) {
                if let Some(reply) = handler(msg) {
                    outgoing_messages.push(reply);
                }
            }
        }
    }

    ws.write_buf.push(&advance_result.to_send);
    for reply in outgoing_messages {
        let framed = match reply {
            crate::http::ws::WsMessage::Text(text) => ws.inner.send_text(&text, ctx.compression_threshold),
            crate::http::ws::WsMessage::Binary(data) => ws.inner.send_binary(&data, ctx.compression_threshold),
        };
        ws.write_buf.push(&framed);
    }

    if advance_result.pong_received {
        ws.last_pong_at = Instant::now();
        ws.last_ping_sent = None;
        ws.ping_misses = 0;
    }

    let over_backpressure_limit = ws.write_buf.as_slice().len() as u64 > ws.write_queue_max_bytes;

    if advance_result.protocol_error || over_backpressure_limit {
        return WebSocketOutcome::FlushThenClose;
    }
    if ws.inner.is_closed() {
        return WebSocketOutcome::ClosedFlushThenClose;
    }
    if !ws.write_buf.is_empty() {
        return WebSocketOutcome::FlushThenContinue;
    }
    WebSocketOutcome::NoActionNeeded
}

// ─── HTTP/2 request/stream processing (backend-agnostic) ────────────────

/// The subset of a worker's per-connection context `process_http2_input`
/// needs -- mirrors `Http1DispatchContext`'s role for HTTP/1.1.
pub struct Http2DispatchContext<'a> {
    pub server: &'a crate::core::server::RoutaServer,
    pub ws_settings: &'a WsSettings,
    pub ws_enabled: bool,
    pub ws_max_connections: usize,
    pub ws_permessage_deflate: bool,
    pub remote_addr: std::net::IpAddr,
}

/// What happened as a result of advancing an HTTP/2 connection's state
/// machine with newly-arrived bytes -- mirrors `Http1Outcome`'s role
/// (see its own doc comment). Unlike HTTP/1.1, H2 never switches
/// `ConnectionProtocol` variants (there's no analogous upgrade path
/// once a connection is already speaking H2), so this only ever
/// describes whether to keep going or close.
pub enum Http2Outcome {
    /// Bytes are queued in `Http2Connection::write_buf` (stream
    /// responses, WS-tunnel DATA frames, or protocol-level frames like
    /// SETTINGS acks) and should be flushed; the connection stays open
    /// afterward.
    FlushThenContinue,
    /// The H2 connection itself has ended (a GOAWAY was sent/received,
    /// or a fatal connection-level error occurred) -- whatever is
    /// queued in `write_buf` should still be flushed, then the
    /// connection closed.
    FlushThenClose,
}

/// Builds an `HttpRequest` from an H2 stream's decoded pseudo-headers
/// plus regular headers -- the inverse of how `net::h2_client` builds
/// the pseudo-header list on the sending side. Returns `None` if the
/// required pseudo-headers are missing (already validated once by
/// `http::h2::stream::Connection::finish_header_block`, so this should
/// never actually happen for a stream that reached
/// `newly_ready_streams` -- defensive rather than load-bearing).
fn build_request_from_h2_headers(
    headers: &[crate::http::h2::hpack::HeaderField],
    body: &[u8],
    trailers: &[crate::http::h2::hpack::HeaderField],
    remote_ip: std::net::IpAddr,
) -> Option<crate::http::request::HttpRequest> {
    let method_str = headers.iter().find(|h| h.name == ":method")?.value.as_str();
    let method = match method_str {
        "GET" => crate::http::request::HttpMethod::Get,
        "POST" => crate::http::request::HttpMethod::Post,
        "PUT" => crate::http::request::HttpMethod::Put,
        "DELETE" => crate::http::request::HttpMethod::Delete,
        "HEAD" => crate::http::request::HttpMethod::Head,
        "PATCH" => crate::http::request::HttpMethod::Patch,
        "OPTIONS" => crate::http::request::HttpMethod::Options,
        "TRACE" => crate::http::request::HttpMethod::Trace,
        "CONNECT" => crate::http::request::HttpMethod::Connect,
        _ => return None,
    };
    let raw_path = headers.iter().find(|h| h.name == ":path")?.value.clone();
    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (raw_path, None),
    };
    let query_params = query
        .as_deref()
        .map(|q| {
            q.split('&')
                .filter_map(|pair| pair.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let regular_headers = headers
        .iter()
        .filter(|h| !h.name.starts_with(':'))
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();

    Some(crate::http::request::HttpRequest {
        method,
        remote_addr: Some(remote_ip),
        path,
        query,
        query_params,
        version_major: 2,
        version_minor: 0,
        headers: regular_headers,
        body: body.to_vec(),
        keep_alive: true, // meaningless for H2 (multiplexed streams, no per-request Connection semantics) -- true is the harmless default
        trailers: trailers.iter().map(|h| (h.name.clone(), h.value.clone())).collect(),
    })
}

/// Splits an `HttpResponse` into the pieces `http::h2::stream::Connection::send_response`
/// needs (status separately from headers, since H2 sends `:status` as
/// its own pseudo-header rather than a regular one).
fn split_response_for_h2(response: crate::http::response::HttpResponse) -> (u16, Vec<crate::http::h2::hpack::HeaderField>, Vec<u8>) {
    let status = response.status;
    let body = response.body().to_vec();
    let headers = response
        .headers()
        .map(|(name, value)| crate::http::h2::hpack::HeaderField {
            name: name.to_string(),
            value: value.to_string(),
        })
        .collect();
    (status, headers, body)
}

/// Feeds newly-arrived bytes on a WS-tunnel H2 stream through its
/// `WsConnection`, dispatches any resulting application messages to
/// the same `Router::dispatch_websocket` handler the HTTP/1.1 upgrade
/// path uses, and queues whatever needs to go back out (auto
/// PONGs/close-echoes plus any framed reply) as H2 DATA on the same
/// stream. Tears the tunnel down (`finish_ws_tunnel`, decrementing
/// `ws_active_connections`) once the WebSocket connection's own close
/// handshake has completed on both sides.
fn process_ws_tunnel_input(h2: &mut Http2Connection, ws_active_connections: &std::sync::atomic::AtomicUsize, ws_settings: &WsSettings, router: &crate::http::router::Router, stream_id: u32, input: Vec<u8>) {
    if input.is_empty() {
        return;
    }
    let path = h2.inner.stream_path(stream_id).map(|p| p.to_string());

    let Some(ws) = h2.inner.ws_tunnel_mut(stream_id) else {
        return;
    };
    let advance_result = ws.advance(&input);
    let is_closed = ws.is_closed();

    // Each received application message is looked up against the
    // registered WS routes and handed to whatever matched -- same
    // "unanswered, not torn down" behavior as `process_websocket_input`
    // for a tunnel with no matching handler (there always is one here,
    // since new-tunnel handling already rejected any path without a
    // match before ever calling `accept_ws_tunnel`, but the lookup is
    // repeated per-message rather than cached for the same reason
    // `process_websocket_input` repeats it: a request-scoped router
    // lookup is already cheap).
    let mut outgoing = advance_result.to_send;
    for event in &advance_result.events {
        if let crate::http::ws::WsEvent::Message(msg) = event {
            let Some(path) = &path else { continue };
            let reply = router.dispatch_websocket(path).and_then(|handler| handler(msg));
            if let Some(reply) = reply {
                let Some(ws) = h2.inner.ws_tunnel_mut(stream_id) else {
                    continue;
                };
                let framed = match reply {
                    crate::http::ws::WsMessage::Text(text) => ws.send_text(&text, ws_settings.compression_threshold),
                    crate::http::ws::WsMessage::Binary(data) => ws.send_binary(&data, ws_settings.compression_threshold),
                };
                outgoing.extend(framed);
            }
        }
    }

    let out = h2.inner.queue_ws_tunnel_data(stream_id, outgoing);
    h2.write_buf.push(&out);

    if is_closed {
        let out = h2.inner.finish_ws_tunnel(stream_id);
        h2.write_buf.push(&out);
        ws_active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Advances an HTTP/2 connection's state as far as `incoming`'s bytes
/// allow: parses frames, dispatches every newly-ready stream's request
/// through the server's middleware chain, handles RFC 8441 Extended
/// CONNECT (WebSocket-over-H2) tunnel setup/teardown/message
/// forwarding, and queues every response back onto `Http2Connection::write_buf`.
/// Does no I/O itself -- see `Http2Outcome`'s own doc comment for what
/// the caller does with its result.
///
/// Takes `&mut ConnectionProtocol` for the same reason
/// `process_http1_read_buf` does -- callers are expected to have
/// already confirmed `*protocol` is `ConnectionProtocol::Http2(_)`.
pub fn process_http2_input(protocol: &mut ConnectionProtocol, incoming: &[u8], ctx: &Http2DispatchContext) -> Http2Outcome {
    let ConnectionProtocol::Http2(h2) = protocol else {
        unreachable!("process_http2_input requires protocol to already be Http2")
    };

    let advance_result = h2.inner.advance(incoming);
    h2.write_buf.push(&advance_result.to_send);

    for stream_id in advance_result.newly_ready_streams {
        let request = h2
            .inner
            .take_request(stream_id)
            .and_then(|(headers, body, trailers)| build_request_from_h2_headers(headers, body, trailers, ctx.remote_addr));

        let Some(request) = request else {
            let out = h2.inner.send_response(stream_id, 400, &[], b"Bad Request\n".to_vec());
            h2.write_buf.push(&out);
            continue;
        };

        let method_str = format!("{:?}", request.method).to_uppercase();
        let route = request.path.clone();
        let request_body_len = request.body.len();
        ctx.server.metrics.http.requests_in_flight.with_label_values(&["http2"]).inc();
        let dispatch_start = std::time::Instant::now();
        let response = ctx.server.middleware_chain.execute(&request);
        let duration_secs = dispatch_start.elapsed().as_secs_f64();
        ctx.server.metrics.http.requests_in_flight.with_label_values(&["http2"]).dec();
        ctx.server.metrics.record_request(&method_str, &route, response.status, duration_secs, request_body_len, response.body().len());
        let early_hints: Vec<crate::http::h2::hpack::HeaderField> = response
            .early_hints
            .iter()
            .map(|(name, value)| crate::http::h2::hpack::HeaderField { name: name.clone(), value: value.clone() })
            .collect();
        let (status, headers, body) = split_response_for_h2(response);

        if !early_hints.is_empty() {
            let hints_out = h2.inner.send_informational_response(stream_id, 103, &early_hints);
            h2.write_buf.push(&hints_out);
        }
        let out = h2.inner.send_response(stream_id, status, &headers, body);
        h2.write_buf.push(&out);
    }

    for stream_id in advance_result.new_ws_tunnel_streams {
        let path = h2.inner.stream_path(stream_id).map(|p| p.to_string());
        let Some(path) = path else { continue };
        let route_matched = ctx.server.router.dispatch_websocket(&path).is_some();
        let over_capacity = ctx.server.ws_active_connections.load(std::sync::atomic::Ordering::Relaxed) >= ctx.ws_max_connections;

        if !route_matched {
            let out = h2.inner.reject_ws_tunnel(stream_id, 404, b"Not Found\n".to_vec());
            h2.write_buf.push(&out);
            continue;
        }
        if !ctx.ws_enabled || over_capacity {
            let out = h2.inner.reject_ws_tunnel(stream_id, 503, b"WebSocket unavailable\n".to_vec());
            h2.write_buf.push(&out);
            continue;
        }

        let pmd = if ctx.ws_permessage_deflate {
            let ext_header = h2.inner.stream_header(stream_id, "sec-websocket-extensions");
            crate::http::ws::negotiate_pmd(ext_header)
        } else {
            None
        };
        let accept_headers: Vec<crate::http::h2::hpack::HeaderField> = pmd
            .as_ref()
            .map(|params| {
                vec![crate::http::h2::hpack::HeaderField {
                    name: "sec-websocket-extensions".to_string(),
                    value: crate::http::ws::pmd_response_extension_header(params),
                }]
            })
            .unwrap_or_default();
        let pmd_context = pmd.map(|params| crate::http::ws::PmdContext::with_compression_level(params, ctx.ws_settings.compression_level));
        let ws_tunnel = crate::http::ws::WsConnection::with_read_buf_capacity(
            pmd_context,
            ctx.ws_settings.max_message_size as usize,
            ctx.ws_settings.max_frame_size,
            ctx.ws_settings.require_masking,
            ctx.ws_settings.read_buf_size,
        );
        let (out, buffered_input) = h2.inner.accept_ws_tunnel(stream_id, ws_tunnel, &accept_headers);
        h2.write_buf.push(&out);
        ctx.server.ws_active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !buffered_input.is_empty() {
            process_ws_tunnel_input(h2, &ctx.server.ws_active_connections, ctx.ws_settings, &ctx.server.router, stream_id, buffered_input);
        }
    }

    let ws_tunnel_streams_with_input = h2.inner.ws_tunnel_streams_with_input();
    for stream_id in ws_tunnel_streams_with_input {
        let input = h2.inner.take_ws_tunnel_input(stream_id);
        process_ws_tunnel_input(h2, &ctx.server.ws_active_connections, ctx.ws_settings, &ctx.server.router, stream_id, input);
    }

    if advance_result.connection_closed {
        Http2Outcome::FlushThenClose
    } else {
        Http2Outcome::FlushThenContinue
    }
}

#[cfg(test)]
mod plaintext_protocol_decision_tests {
    use super::*;

    #[test]
    fn empty_buffer_needs_more_data_not_an_early_http1_decision() {
        // The exact bug found via h2spec: an empty buffer (nothing
        // read yet) must never be decided as Http1 just because it's
        // shorter than the "PRI" marker -- it's still fully
        // consistent with a preface that hasn't arrived yet.
        assert!(matches!(decide_plaintext_protocol(b""), PlaintextProtocolDecision::NeedMoreData));
    }

    #[test]
    fn partial_pri_prefix_needs_more_data() {
        assert!(matches!(decide_plaintext_protocol(b"P"), PlaintextProtocolDecision::NeedMoreData));
        assert!(matches!(decide_plaintext_protocol(b"PR"), PlaintextProtocolDecision::NeedMoreData));
        assert!(matches!(decide_plaintext_protocol(b"PRI"), PlaintextProtocolDecision::NeedMoreData));
        assert!(matches!(decide_plaintext_protocol(b"PRI "), PlaintextProtocolDecision::NeedMoreData));
    }

    #[test]
    fn ordinary_http1_request_line_is_recognized_immediately() {
        assert!(matches!(decide_plaintext_protocol(b"GET / HTTP/1.1\r\n"), PlaintextProtocolDecision::Http1));
        assert!(matches!(decide_plaintext_protocol(b"G"), PlaintextProtocolDecision::Http1));
        assert!(matches!(decide_plaintext_protocol(b"P"), PlaintextProtocolDecision::NeedMoreData)); // "PUT" also starts with P -- ambiguous with "PRI" until more arrives
        assert!(matches!(decide_plaintext_protocol(b"PU"), PlaintextProtocolDecision::Http1)); // "PU" already disagrees with "PR"
    }

    #[test]
    fn full_valid_preface_is_recognized() {
        assert!(matches!(decide_plaintext_protocol(H2_CONNECTION_PREFACE), PlaintextProtocolDecision::Http2PriorKnowledge));
    }

    #[test]
    fn full_valid_preface_with_trailing_data_is_recognized() {
        let mut buf = H2_CONNECTION_PREFACE.to_vec();
        buf.extend_from_slice(b"extra data past the preface");
        assert!(matches!(decide_plaintext_protocol(&buf), PlaintextProtocolDecision::Http2PriorKnowledge));
    }

    #[test]
    fn malformed_preface_attempt_is_invalid_not_http1() {
        // Starts with "PRI" (committing to an H2 attempt) but diverges
        // before the full 24-byte preface.
        assert!(matches!(decide_plaintext_protocol(b"PRI * HTTP/1.1\r\n\r\n"), PlaintextProtocolDecision::InvalidH2Preface));
    }

    #[test]
    fn malformed_preface_attempt_detected_incrementally() {
        // Byte-by-byte, feeding one more byte at a time until the
        // divergence point is reached -- must stay NeedMoreData right
        // up until the point of divergence, then immediately report
        // InvalidH2Preface, never Http1.
        let malformed = b"PRI * HTTP/1.1\r\n\r\n"; // diverges from the real preface's "HTTP/2.0" at the '1' (real preface has '2' there), 0-indexed position 11, i.e. the divergence is already present at len 12
        for len in 1..=malformed.len() {
            let prefix = &malformed[..len];
            let decision = decide_plaintext_protocol(prefix);
            if len < 12 {
                assert!(
                    matches!(decision, PlaintextProtocolDecision::NeedMoreData),
                    "expected NeedMoreData at len={len}, prefix={prefix:?}"
                );
            } else {
                assert!(
                    matches!(decision, PlaintextProtocolDecision::InvalidH2Preface),
                    "expected InvalidH2Preface at len={len}, prefix={prefix:?}"
                );
            }
        }
    }
}
