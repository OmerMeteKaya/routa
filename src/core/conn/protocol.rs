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
fn queue_http1_response(h1: &mut Http1Connection, mut response: crate::http::response::HttpResponse) {
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

                    let mut h2 = Http2Connection::new(ctx.h2_settings);
                    h2.inner.assume_preface_received();
                    h2.inner.apply_upgrade_settings(&settings_payload);
                    h2.write_buf.push(&h2.inner.initial_send());
                    *protocol = ConnectionProtocol::Http2(h2);
                    return Http1Outcome::SwitchedToHttp2;
                }

                let is_upgrade = crate::http::ws::is_upgrade_request(&request);
                let request_body_len = request.body.len();
                let method_str = format!("{:?}", request.method).to_uppercase();
                let route = request.path.clone();
                ctx.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).inc();
                let dispatch_start = std::time::Instant::now();
                let response = ctx.server.middleware_chain.execute(&request);
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

                let mut response = response;
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

                    *protocol = ConnectionProtocol::WebSocket(WsConnection::with_settings(pmd, ctx.ws_settings).with_upgrade_path(upgrade_path));
                    ctx.server.ws_active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Http1Outcome::SwitchedToWebSocket;
                }

                let keep_alive = request.keep_alive && response.get_header("Connection").map(|v| !v.eq_ignore_ascii_case("close")).unwrap_or(true);
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
