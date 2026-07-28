//! The per-worker event loop: accepts connections, drives each one's
//! TLS handshake and application-protocol state machine (HTTP/1.1,
//! HTTP/2, WebSocket), and dispatches complete requests through a
//! `RoutaServer`'s middleware chain and router.
//!
//! Protocol selection happens once, right after a connection's
//! transport is ready to carry plaintext: a TLS connection's
//! negotiated ALPN protocol decides between HTTP/1.1 and HTTP/2 (an
//! ALPN value of `"h2"` selects HTTP/2, anything else -- including no
//! ALPN negotiation at all, e.g. a plaintext connection -- selects
//! HTTP/1.1). WebSocket is reached only via an HTTP/1.1 `Upgrade`
//! request the router matched, never chosen up front the way H1/H2
//! are.
//!
//! Every protocol handler here follows the same shape: advance a
//! state machine with newly-read bytes, get back bytes to write and
//! zero or more complete requests to dispatch, write the produced
//! bytes, dispatch each request through the server's middleware chain,
//! encode the resulting response back into the protocol's own framing,
//! and queue that for writing too. None of the protocol state machines
//! (`http::h2::stream::Connection`, `http::ws::WsConnection`,
//! `http::request::parse`) touch a socket themselves -- this module is
//! the only place actual I/O happens, exactly the same "state machine
//! advances, caller owns I/O" division used throughout this codebase.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mio::net::TcpListener;
use slab::Slab;

use crate::core::conn::{Connection, ConnectionProtocol, Http1Connection, Http2Connection, Transport, WsConnection};
use crate::core::server::RoutaServer;
use crate::core::worker::{ShutdownSignal, WorkerBody, WorkerPool};
use crate::net::poller::{EventPoller, Interests, MioPoller, PollKey};
use crate::net::socket::bind_reuseport;
use crate::net::tls::TlsConnection;

const DEFAULT_MAX_REQUEST_SIZE: usize = 0; // 0 = unlimited, matches http::request::parse's convention
const POLL_TIMEOUT: Duration = Duration::from_millis(200);
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

pub struct EventLoopWorker {
    port: u16,
    server: Arc<RoutaServer>,
    max_request_size: usize,
    keepalive_timeout: Duration,
    request_timeout: Duration,
}

impl EventLoopWorker {
    pub fn new(port: u16, server: Arc<RoutaServer>) -> Self {
        let keepalive_timeout = Duration::from_millis(server.config.keepalive_timeout_ms.max(0) as u64);
        let request_timeout = Duration::from_millis(server.config.request_timeout_ms.max(0) as u64);
        let max_request_size = if server.config.max_request_size > 0 {
            server.config.max_request_size as usize
        } else {
            DEFAULT_MAX_REQUEST_SIZE
        };
        EventLoopWorker {
            port,
            server,
            max_request_size,
            keepalive_timeout,
            request_timeout,
        }
    }
}

impl WorkerBody for EventLoopWorker {
    fn run(&self, _worker_id: usize, shutdown: &ShutdownSignal) {
        let mut listener = match bind_reuseport(self.port, 1024) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(port = self.port, error = %e, "worker failed to bind listener");
                return; // worker pool's reconciler observes this thread exiting and restarts it
            }
        };
        let mut poller = match MioPoller::new(1024) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "worker failed to create poller");
                return;
            }
        };
        // Registered with a sentinel key far outside any range
        // `connections`'s own Slab<Connection> will ever hand out
        // (its keys start at 0 and grow from there) -- register_with_key
        // doesn't reserve a slot in the poller's own internal slab the
        // way register() does (see its own doc comment), so the
        // listener's key and a connection's key must be guaranteed to
        // never collide some other way. Without this, the listener
        // and the very first accepted connection would both end up
        // with key/Token 0, and mio would conflate their readiness
        // events.
        let listener_key = PollKey::from_slab_index(usize::MAX);
        if poller.register_with_key(&mut listener, listener_key, Interests::READABLE).is_err() {
            return;
        }

        let mut connections: Slab<Connection> = Slab::new();
        let mut last_idle_sweep = Instant::now();

        while !shutdown.is_set() {
            let events = match poller.poll(Some(POLL_TIMEOUT)) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for (key, readiness) in events {
                if key == listener_key {
                    accept_all(self, &mut listener, &mut poller, &mut connections);
                    continue;
                }
                handle_connection_event(self, &mut poller, &mut connections, key, readiness);
            }

            if last_idle_sweep.elapsed() >= IDLE_SWEEP_INTERVAL {
                last_idle_sweep = Instant::now();
                reap_idle_connections(self, &mut poller, &mut connections);
            }
        }
    }
}

fn accept_all(worker: &EventLoopWorker, listener: &mut TcpListener, poller: &mut MioPoller, connections: &mut Slab<Connection>) {
    loop {
        match listener.accept() {
            Ok((mut stream, remote_addr)) => {
                let entry = connections.vacant_entry();
                let key = PollKey::from_slab_index(entry.key());
                if poller.register_with_key(&mut stream, key, Interests::READABLE_WRITABLE).is_err() {
                    continue;
                }

                let transport = match &worker.server.tls_context {
                    Some(tls_ctx) => match TlsConnection::new_server(tls_ctx) {
                        Ok(tls) => Transport::Tls { stream, tls: Box::new(tls) },
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to create TLS session for accepted connection");
                            continue; // drop this connection, its slot is simply not populated
                        }
                    },
                    None => Transport::Plain(stream),
                };

                let conn = Connection::new(entry.key() as u64, key, transport, remote_addr);
                entry.insert(conn);

                worker.server.metrics.connection.connections_accepted_total.inc();
                worker.server.metrics.connection.connections_active.inc();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn handle_connection_event(
    worker: &EventLoopWorker,
    poller: &mut MioPoller,
    connections: &mut Slab<Connection>,
    key: PollKey,
    _readiness: crate::net::poller::Readiness,
) {
    let idx = key.slab_index();
    if !connections.contains(idx) {
        return; // stale event for an already-removed connection
    }

    connections[idx].touch();

    // Drive the TLS handshake (a no-op immediately returning "not
    // handshaking" for a plaintext connection) before anything
    // protocol-specific -- no application data can be trusted until
    // this completes.
    if let Transport::Tls { .. } = &connections[idx].transport {
        if tls_is_handshaking(&connections[idx].transport) {
            match advance_tls_handshake(&mut connections[idx].transport) {
                Ok(true) => {} // handshake just completed -- fall through to protocol selection below
                Ok(false) => return, // still handshaking, wait for the next readiness event
                Err(_) => {
                    worker.server.metrics.connection.tls_handshakes_total.with_label_values(&["failure"]).inc();
                    close_connection(worker, poller, connections, idx);
                    return;
                }
            }
        }
    }

    if matches!(connections[idx].protocol, ConnectionProtocol::Handshaking) {
        if let Transport::Tls { .. } = &connections[idx].transport {
            worker.server.metrics.connection.tls_handshakes_total.with_label_values(&["success"]).inc();
        }
        let is_h2 = matches!(&connections[idx].transport, Transport::Tls { tls, .. } if tls.alpn_protocol() == Some(b"h2".as_slice()));
        connections[idx].protocol = if is_h2 {
            worker.server.metrics.connection.protocol_selected_total.with_label_values(&["http2"]).inc();
            ConnectionProtocol::Http2(Http2Connection::new(128, 4096))
        } else {
            worker.server.metrics.connection.protocol_selected_total.with_label_values(&["http1"]).inc();
            ConnectionProtocol::Http1(Http1Connection::new())
        };
    }

    let result = match &mut connections[idx].protocol {
        ConnectionProtocol::Handshaking => Ok(()), // TLS handshake still in progress (plaintext connections never linger here)
        ConnectionProtocol::Http1(_) => drive_http1(worker, connections, idx),
        ConnectionProtocol::Http2(_) => drive_http2(worker, connections, idx),
        ConnectionProtocol::WebSocket(_) => drive_websocket(connections, idx),
    };

    if result.is_err() || connections[idx].closing {
        close_connection(worker, poller, connections, idx);
    }
}

fn tls_is_handshaking(transport: &Transport) -> bool {
    match transport {
        Transport::Tls { tls, .. } => tls.is_handshaking(),
        Transport::Plain(_) => false,
    }
}

/// Advances a TLS handshake by one step. Returns `Ok(true)` once the
/// handshake has just completed (this specific call is the one that
/// finished it), `Ok(false)` if still in progress.
fn advance_tls_handshake(transport: &mut Transport) -> std::io::Result<bool> {
    let Transport::Tls { stream, tls } = transport else {
        return Ok(true);
    };
    let was_handshaking = tls.is_handshaking();
    match tls.advance_io(stream) {
        Ok(advance) => {
            if advance.peer_closed {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "peer closed during handshake"));
            }
            Ok(was_handshaking && !tls.is_handshaking())
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e),
    }
}

fn close_connection(worker: &EventLoopWorker, poller: &mut MioPoller, connections: &mut Slab<Connection>, idx: usize) {
    if connections.contains(idx) {
        let mut conn = connections.remove(idx);
        let key = conn.poll_key;
        match &mut conn.transport {
            Transport::Plain(stream) => {
                let _ = poller.deregister(stream, key);
            }
            Transport::Tls { stream, .. } => {
                let _ = poller.deregister(stream, key);
            }
        }
        worker.server.metrics.connection.connections_closed_total.inc();
        worker.server.metrics.connection.connections_active.dec();
    }
}

/// Reads available bytes, parses as many complete HTTP/1.1 requests
/// as the buffer contains, dispatches each through the server's
/// middleware chain, and queues the serialized response(s) for
/// writing -- then attempts to flush the write buffer. A request whose
/// `Upgrade: websocket` header the router's handler accepted (by
/// returning a `101` response) transitions this connection to
/// `ConnectionProtocol::WebSocket` for everything from that point
/// onward, on the same underlying transport.
fn drive_http1(worker: &EventLoopWorker, connections: &mut Slab<Connection>, idx: usize) -> std::io::Result<()> {
    read_into_transport(connections, idx, |conn| {
        let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
            unreachable!("drive_http1 is only called when protocol is Http1")
        };
        &mut h1.read_buf
    })?;

    loop {
        let (parse_outcome, request_started_at) = {
            let ConnectionProtocol::Http1(h1) = &connections[idx].protocol else {
                unreachable!()
            };
            (crate::http::request::parse(&h1.read_buf, worker.max_request_size), h1.request_started_at)
        };

        match parse_outcome {
            crate::http::request::ParseOutcome::Incomplete => break,
            crate::http::request::ParseOutcome::NeedsContinue { method, path, headers } => {
                let already_sent = {
                    let ConnectionProtocol::Http1(h1) = &connections[idx].protocol else {
                        unreachable!()
                    };
                    h1.continue_sent
                };
                if !already_sent {
                    let probe_request = crate::http::request::HttpRequest {
                        method,
                        remote_addr: Some(connections[idx].remote_addr.ip()),
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
                        worker.server.router.dispatch(&probe_request),
                        crate::http::router::Dispatch::NotFound | crate::http::router::Dispatch::MethodNotAllowed { .. }
                    );
                    if route_exists {
                        let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else {
                            unreachable!()
                        };
                        h1.write_buf.push(b"HTTP/1.1 100 Continue");
                        h1.write_buf.push(&[13, 10, 13, 10]);
                        h1.continue_sent = true;
                    } else {
                        let mut resp = worker.server.middleware_chain.execute(&probe_request);
                        resp.set_header("Connection", "close");
                        queue_http1_response(connections, idx, resp);
                        connections[idx].closing = true;
                        flush_transport(connections, idx)?;
                        return Ok(());
                    }
                }
                break;
            }
            crate::http::request::ParseOutcome::Invalid(_) => {
                let mut resp = crate::http::response::HttpResponse::new(400, "Bad Request");
                resp.set_header("Connection", "close");
                queue_http1_response(connections, idx, resp);
                connections[idx].closing = true;
                // queue_http1_response only queues bytes into the
                // connection's write_buf -- flush_transport is what
                // actually writes them to the socket. Without this,
                // the 400 response sat in write_buf forever: this
                // early-return path never reached the flush_transport
                // call at the bottom of the normal (valid-request)
                // loop below, so a malformed request produced no
                // observable response at all, just a silently closed
                // connection.
                flush_transport(connections, idx)?;
                return Ok(());
            }
            crate::http::request::ParseOutcome::Complete { mut request, consumed } => {
                let _ = request_started_at;
                request.remote_addr = Some(connections[idx].remote_addr.ip());

                let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else {
                    unreachable!()
                };
                h1.read_buf.consume(consumed);
                h1.request_started_at = None; // request is now fully parsed -- see the timeout sweep, which only fires while this is Some
                h1.continue_sent = false; // ready for the next request on this (keep-alive) connection to potentially need its own 100 Continue

                let is_upgrade = crate::http::ws::is_upgrade_request(&request);
                let request_body_len = request.body.len();
                let method_str = format!("{:?}", request.method).to_uppercase();
                let route = request.path.clone();
                worker.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).inc();
                let dispatch_start = Instant::now();
                let response = worker.server.middleware_chain.execute(&request);
                let duration_secs = dispatch_start.elapsed().as_secs_f64();
                worker.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).dec();
                worker.server.metrics.record_request(
                    &method_str,
                    &route,
                    response.status,
                    duration_secs,
                    request_body_len,
                    response.body().len(),
                );

                let mut response = response;
                if request.method == crate::http::request::HttpMethod::Head {
                    // RFC 9110 9.3.2: a HEAD response reports the same
                    // headers a GET would (Content-Length included),
                    // but must never actually send a body -- applied
                    // here uniformly to whatever the route/proxy
                    // produced. Metrics above already recorded this
                    // response's real body length before it's stripped.
                    response.strip_body_for_head();
                }
                if is_upgrade && response.status == 101 {
                    let pmd = negotiate_pmd_from_response(&response);
                    queue_http1_response(connections, idx, response);
                    connections[idx].protocol = ConnectionProtocol::WebSocket(WsConnection::new(pmd, 16 * 1024 * 1024));
                    flush_transport(connections, idx)?;
                    return Ok(());
                }

                let keep_alive = request.keep_alive && response.get_header("Connection").map(|v| !v.eq_ignore_ascii_case("close")).unwrap_or(true);
                queue_http1_response(connections, idx, response);

                let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else {
                    unreachable!()
                };
                h1.keep_alive = keep_alive;
                if !keep_alive {
                    connections[idx].closing = true;
                }
            }
        }
    }

    flush_transport(connections, idx)?;
    if connections[idx].closing {
        // Only actually close once the response has had a chance to
        // flush -- if flush_transport above left bytes still queued
        // (WouldBlock), a subsequent writable event drains the rest
        // and closing still applies once that finishes.
        let ConnectionProtocol::Http1(h1) = &connections[idx].protocol else {
            unreachable!()
        };
        if h1.write_buf.as_slice().is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "connection closing"));
        }
    }
    Ok(())
}

fn queue_http1_response(connections: &mut Slab<Connection>, idx: usize, mut response: crate::http::response::HttpResponse) {
    let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else {
        return;
    };
    let file_body = response.file_body.take();

    let mut serialized = crate::util::buf::Buf::new();
    response.serialize(&mut serialized); // body is empty when file_body was Some, so this only writes headers
    h1.write_buf.push(serialized.as_slice());

    if let Some(fb) = file_body {
        h1.pending_file = Some(crate::core::conn::PendingFileSend {
            file: fb.file,
            offset: fb.offset,
            remaining: fb.len,
        });
    }
}

/// Reads `Sec-WebSocket-Extensions` back off the handshake response
/// (rather than the original request) so the negotiated parameters
/// this connection actually uses match exactly what was sent to the
/// client -- see `http::middleware`'s WS upgrade handler (wherever
/// that's registered) for where the response's own PMD negotiation
/// happens.
fn negotiate_pmd_from_response(response: &crate::http::response::HttpResponse) -> Option<crate::http::ws::PmdContext> {
    let ext = response.get_header("Sec-WebSocket-Extensions")?;
    if !ext.contains("permessage-deflate") {
        return None;
    }
    let params = crate::http::ws::PmdParams {
        server_no_context_takeover: ext.contains("server_no_context_takeover"),
        client_no_context_takeover: ext.contains("client_no_context_takeover"),
    };
    Some(crate::http::ws::PmdContext::new(params))
}

/// Reads as much as is currently available from `connections[idx]`'s
/// transport into whichever buffer `select_buf` picks out of its
/// protocol state, looping until `WouldBlock`. `select_buf` is a
/// closure rather than a fixed field access since which buffer to
/// read into depends on which `ConnectionProtocol` variant is active.
fn read_into_transport(
    connections: &mut Slab<Connection>,
    idx: usize,
    select_buf: impl Fn(&mut Connection) -> &mut crate::util::buf::Buf,
) -> std::io::Result<()> {
    loop {
        let conn = &mut connections[idx];
        let mut chunk = [0u8; 16384];
        let read_result = match &mut conn.transport {
            Transport::Plain(stream) => stream.read(&mut chunk),
            Transport::Tls { tls, .. } => tls.read_plaintext(&mut chunk),
        };
        match read_result {
            Ok(0) => {
                conn.closing = true;
                return Ok(());
            }
            Ok(n) => {
                select_buf(conn).push(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

/// Reads as much as is available directly into a caller-supplied byte
/// buffer -- used by protocols (H2, WS) whose own state machine
/// `advance()` call takes a `&[u8]` directly rather than exposing a
/// persistent read buffer the way `Http1Connection` does.
fn read_transport_bytes(connections: &mut Slab<Connection>, idx: usize) -> std::io::Result<Vec<u8>> {
    let mut collected = Vec::new();
    loop {
        let conn = &mut connections[idx];

        // For a TLS transport, read_plaintext only surfaces bytes
        // rustls has already decrypted -- advance_io is what actually
        // reads new TLS records (or notices the underlying TCP
        // connection reached EOF) off the real socket. Without this,
        // an abruptly-closed TCP connection (no TLS close_notify sent
        // -- common; see rustls's own docs on this) would never
        // surface as anything other than WouldBlock from
        // read_plaintext, since rustls has no new record to decrypt
        // and no reason to believe the connection ended. The result
        // was an infinite busy-loop: mio's level-triggered epoll kept
        // reporting the socket readable (a closed peer is always
        // "readable" in that sense), and this function kept reporting
        // "nothing new" back up to the caller instead of ever
        // detecting the close.
        if let Transport::Tls { stream, tls } = &mut conn.transport {
            match tls.advance_io(stream) {
                Ok(advance) if advance.peer_closed => {
                    conn.closing = true;
                    return Ok(collected);
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }

        let mut chunk = [0u8; 16384];
        let read_result = match &mut conn.transport {
            Transport::Plain(stream) => stream.read(&mut chunk),
            Transport::Tls { tls, .. } => tls.read_plaintext(&mut chunk),
        };
        match read_result {
            Ok(0) => {
                conn.closing = true;
                return Ok(collected);
            }
            Ok(n) => collected.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(collected),
            Err(e) => return Err(e),
        }
    }
}

/// Flushes whichever write buffer the active protocol has queued,
/// writing as much as the transport currently accepts. Leftover bytes
/// (on `WouldBlock`) stay in the buffer for the next writable-readiness
/// event to resume -- this never blocks waiting for the transport to
/// drain.
fn flush_transport(connections: &mut Slab<Connection>, idx: usize) -> std::io::Result<()> {
    loop {
        let conn = &mut connections[idx];
        let pending: &[u8] = match &conn.protocol {
            ConnectionProtocol::Http1(h1) => h1.write_buf.as_slice(),
            ConnectionProtocol::Http2(h2) => h2.write_buf.as_slice(),
            ConnectionProtocol::WebSocket(ws) => ws.write_buf.as_slice(),
            ConnectionProtocol::Handshaking => &[],
        };
        if pending.is_empty() {
            break;
        }

        let write_result = match &mut conn.transport {
            Transport::Plain(stream) => stream.write(pending),
            Transport::Tls { tls, .. } => tls.write_plaintext(pending),
        };
        match write_result {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write returned 0")),
            Ok(n) => {
                match &mut conn.protocol {
                    ConnectionProtocol::Http1(h1) => h1.write_buf.consume(n),
                    ConnectionProtocol::Http2(h2) => h2.write_buf.consume(n),
                    ConnectionProtocol::WebSocket(ws) => ws.write_buf.consume(n),
                    ConnectionProtocol::Handshaking => {}
                }
                // For a TLS transport, write_plaintext only queues into
                // rustls's own outgoing buffer -- advance_io flushes
                // that to the real socket (see net::tls's own doc
                // comment on write_plaintext).
                if let Transport::Tls { stream, tls } = &mut conn.transport {
                    match tls.advance_io(stream) {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e),
        }
    }

    flush_pending_file(connections, idx)
}

/// Sends a queued file-backed response body (see `PendingFileSend`),
/// preferring `sendfile(2)` on a plaintext transport (kernel-space
/// file-to-socket copy, no userspace buffer) and falling back to an
/// ordinary read-then-write on a TLS transport (which must encrypt in
/// userspace before any byte reaches the kernel, so there's no file
/// descriptor for the kernel to copy directly from). Only reached
/// once `flush_transport`'s own header write_buf has fully drained --
/// the headers must precede the body on the wire.
fn flush_pending_file(connections: &mut Slab<Connection>, idx: usize) -> std::io::Result<()> {
    loop {
        let conn = &mut connections[idx];
        let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
            return Ok(()); // only H1 currently supports a file-backed body (see PendingFileSend's doc comment)
        };
        let Some(pending) = &mut h1.pending_file else {
            return Ok(());
        };
        if pending.remaining == 0 {
            h1.pending_file = None;
            return Ok(());
        }

        match &mut conn.transport {
            Transport::Plain(stream) => {
                let socket_fd = std::os::unix::io::AsRawFd::as_raw_fd(stream);
                let want = pending.remaining.min(4 * 1024 * 1024) as usize; // cap per-call size, same rationale as any other chunked transfer in this codebase
                match crate::net::socket::sendfile(&pending.file, socket_fd, &mut pending.offset, want) {
                    Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "sendfile returned 0")),
                    Ok(n) => {
                        pending.remaining -= n as u64;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            Transport::Tls { tls, .. } => {
                // TLS fallback: read a chunk from the file, encrypt +
                // write it like any other TLS response body -- no
                // sendfile possible here (see this function's own doc
                // comment).
                use std::io::{Read, Seek, SeekFrom};
                let want = pending.remaining.min(65536) as usize;
                let mut buf = vec![0u8; want];
                pending.file.seek(SeekFrom::Start(pending.offset))?;
                let n = pending.file.read(&mut buf)?;
                if n == 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "file ended before pending_file.remaining reached 0"));
                }
                match tls.write_plaintext(&buf[..n]) {
                    Ok(written) => {
                        pending.offset += written as u64;
                        pending.remaining -= written as u64;
                        // Any bytes read but not accepted by write_plaintext
                        // this call are simply re-read next time (offset
                        // wasn't advanced past them) -- correctness over
                        // squeezing out every read syscall here.
                        if written < n {
                            pending.remaining += (n - written) as u64;
                            pending.offset -= (n - written) as u64;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Reads available bytes, advances the connection's H2 state machine,
/// dispatches every newly-ready stream (request fully received) through
/// the server's middleware chain, and encodes each response back onto
/// the same stream via `send_response` -- multiplexing however many
/// requests happen to be in flight on this one connection.
fn drive_http2(worker: &EventLoopWorker, connections: &mut Slab<Connection>, idx: usize) -> std::io::Result<()> {
    let incoming = read_transport_bytes(connections, idx)?;

    let advance_result = {
        let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
            unreachable!("drive_http2 is only called when protocol is Http2")
        };
        h2.inner.advance(&incoming)
    };

    let remote_ip = connections[idx].remote_addr.ip();

    {
        let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
            unreachable!()
        };
        h2.write_buf.push(&advance_result.to_send);
    }

    for stream_id in advance_result.newly_ready_streams {
        let request = {
            let ConnectionProtocol::Http2(h2) = &connections[idx].protocol else {
                unreachable!()
            };
            let Some((headers, body, trailers)) = h2.inner.take_request(stream_id) else {
                continue;
            };
            build_request_from_h2_headers(headers, body, trailers, remote_ip)
        };
        let Some(request) = request else {
            let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
                unreachable!()
            };
            let out = h2.inner.send_response(stream_id, 400, &[], b"Bad Request\n".to_vec());
            h2.write_buf.push(&out);
            continue;
        };

        let method_str = format!("{:?}", request.method).to_uppercase();
        let route = request.path.clone();
        let request_body_len = request.body.len();
        worker.server.metrics.http.requests_in_flight.with_label_values(&["http2"]).inc();
        let dispatch_start = Instant::now();
        let response = worker.server.middleware_chain.execute(&request);
        let duration_secs = dispatch_start.elapsed().as_secs_f64();
        worker.server.metrics.http.requests_in_flight.with_label_values(&["http2"]).dec();
        worker.server.metrics.record_request(&method_str, &route, response.status, duration_secs, request_body_len, response.body().len());
        let (status, headers, body) = split_response_for_h2(response);

        let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
            unreachable!()
        };
        let out = h2.inner.send_response(stream_id, status, &headers, body);
        h2.write_buf.push(&out);
    }

    if advance_result.connection_closed {
        connections[idx].closing = true;
    }

    flush_transport(connections, idx)?;
    let _ = worker;
    Ok(())
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

/// Reads available bytes and advances the connection's WebSocket
/// frame parser, queuing whatever it produced (automatic PONGs,
/// close-handshake echoes) for writing. Actual application messages
/// (`WsEvent::Message`) aren't dispatched anywhere yet -- there's no
/// registered WS message handler at this layer today (the router's
/// job ends at the `101` upgrade response); a future addition wiring
/// a per-route WS handler would consume `advance_result.events` here
/// instead of this function currently discarding them.
fn drive_websocket(connections: &mut Slab<Connection>, idx: usize) -> std::io::Result<()> {
    let incoming = read_transport_bytes(connections, idx)?;

    let advance_result = {
        let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else {
            unreachable!("drive_websocket is only called when protocol is WebSocket")
        };
        ws.inner.advance(&incoming)
    };

    {
        let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else {
            unreachable!()
        };
        ws.write_buf.push(&advance_result.to_send);
    }

    if advance_result.protocol_error {
        connections[idx].closing = true;
    }

    flush_transport(connections, idx)?;
    Ok(())
}

/// Closes every connection that's exceeded `worker`'s configured
/// keepalive or request timeout -- called periodically (see
/// `EventLoopWorker::run`'s `IDLE_SWEEP_INTERVAL`), not on every
/// readiness event, since an idle connection by definition isn't
/// producing readiness events for this to react to otherwise.
fn reap_idle_connections(worker: &EventLoopWorker, poller: &mut MioPoller, connections: &mut Slab<Connection>) {
    let now = Instant::now();
    let stale: Vec<usize> = connections
        .iter()
        .filter_map(|(idx, conn)| {
            let request_in_flight_too_long = match &conn.protocol {
                ConnectionProtocol::Http1(h1) => h1
                    .request_started_at
                    .is_some_and(|started| now.duration_since(started) > worker.request_timeout),
                _ => false,
            };
            let idle_too_long = now.duration_since(conn.last_active_at) > worker.keepalive_timeout;
            if request_in_flight_too_long || idle_too_long {
                Some(idx)
            } else {
                None
            }
        })
        .collect();

    for idx in stale {
        close_connection(worker, poller, connections, idx);
    }
}

/// Starts `n_workers` worker threads, each running its own
/// `EventLoopWorker` bound (via `SO_REUSEPORT`) to `port` -- the
/// top-level entry point `main`/`core::server` calls once a
/// `RoutaServer` has been fully assembled.
pub fn run(server: Arc<RoutaServer>, port: u16, n_workers: usize) -> WorkerPool {
    let worker = EventLoopWorker::new(port, server);
    WorkerPool::spawn(n_workers, worker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::RoutaConfig;
    use std::io::{Read as StdRead, Write as StdWrite};
    use std::net::TcpStream as StdTcpStream;

    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    fn start_test_server(mut config: RoutaConfig, port: u16) -> WorkerPool {
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        run(server, port, 1)
    }

    fn http_get(port: u16, path: &str) -> (u16, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(mut stream) => {
                    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
                    stream.write_all(request.as_bytes()).unwrap();
                    let mut buf = Vec::new();
                    stream.read_to_end(&mut buf).unwrap();
                    let headers_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let header_str = String::from_utf8_lossy(&buf[..headers_end]);
                    let status: u16 = header_str.lines().next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
                    let body = buf[headers_end + 4..].to_vec();
                    return (status, body);
                }
                Err(_) => {
                    if Instant::now() > deadline {
                        panic!("timed out waiting for test server to accept connections");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    #[test]
    fn serves_static_file_over_real_tcp_connection() {
        let dir = std::env::temp_dir().join(format!(
            "routa_event_loop_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hello.txt"), b"hello from event loop").unwrap();

        let mut config = RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        let port = free_port();
        let _pool = start_test_server(config, port);

        let (status, body) = http_get(port, "/hello.txt");
        assert_eq!(status, 200);
        assert_eq!(body, b"hello from event loop");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn serves_large_file_via_sendfile_path() {
        // A file at or above FileCache's default mmap_threshold takes
        // the FileBody/sendfile path (see http::static_files::serve
        // and core::event_loop's flush_pending_file) instead of the
        // mmap'd in-memory path -- this proves that path actually
        // delivers correct bytes over a real TCP connection, not just
        // that the file descriptor/range were computed correctly (see
        // static_files's own unit test for that narrower check).
        let dir = std::env::temp_dir().join(format!(
            "routa_event_loop_sendfile_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Larger than any reasonable mmap threshold, and large enough
        // that a bug truncating or corrupting the sendfile transfer
        // partway through would be obvious rather than accidentally
        // still passing on a tiny file.
        let large_content = "0123456789".repeat(200_000); // 2,000,000 bytes
        std::fs::write(dir.join("large.bin"), large_content.as_bytes()).unwrap();

        let mut config = RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        let port = free_port();
        let _pool = start_test_server(config, port);

        let (status, body) = http_get(port, "/large.bin");
        assert_eq!(status, 200);
        assert_eq!(body.len(), large_content.len());
        assert_eq!(body, large_content.as_bytes());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn returns_404_for_unmatched_path() {
        let config = RoutaConfig::default();
        let port = free_port();
        let _pool = start_test_server(config, port);

        let (status, _body) = http_get(port, "/does-not-exist");
        assert_eq!(status, 404);
    }

    #[test]
    fn keep_alive_connection_serves_multiple_requests() {
        let dir = std::env::temp_dir().join(format!(
            "routa_event_loop_ka_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"first").unwrap();
        std::fs::write(dir.join("b.txt"), b"second").unwrap();

        let mut config = RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        let port = free_port();
        let _pool = start_test_server(config, port);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) => {
                    if Instant::now() > deadline {
                        panic!("timed out connecting");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };

        stream.write_all(b"GET /a.txt HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let first_response = String::from_utf8_lossy(&buf[..n]);
        assert!(first_response.contains("first"));

        // Same connection, second request -- proves keep-alive actually
        // kept the connection (and this worker's Http1Connection state
        // for it) alive rather than requiring a fresh TCP connection.
        stream.write_all(b"GET /b.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut buf2 = Vec::new();
        stream.read_to_end(&mut buf2).unwrap();
        let second_response = String::from_utf8_lossy(&buf2);
        assert!(second_response.contains("second"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn proxies_to_real_upstream_over_real_tcp_connection() {
        let upstream_port = free_port();
        std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind(("127.0.0.1", upstream_port)).unwrap();
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 4096];
                        let _ = stream.read(&mut buf);
                        let mut response = Vec::new();
                        response.extend_from_slice(b"HTTP/1.1 200 OK");
                        response.extend_from_slice(&[13, 10]);
                        response.extend_from_slice(b"Content-Length: 15");
                        response.extend_from_slice(&[13, 10]);
                        response.extend_from_slice(&[13, 10]);
                        response.extend_from_slice(b"from upstream!");
                        response.extend_from_slice(&[13, 10]);
                        let _ = stream.write_all(&response);
                    }
                    Err(_) => break,
                }
            }
        });
        std::thread::sleep(Duration::from_millis(50));

        let mut config = RoutaConfig::default();
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "test".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig {
                host: "127.0.0.1".to_string(),
                port: upstream_port,
                weight: 1,
                use_tls: false,
            }],
            ..Default::default()
        });
        let port = free_port();
        let _pool = start_test_server(config, port);

        let (status, body) = http_get(port, "/api/anything");
        assert_eq!(status, 200);
        assert_eq!(String::from_utf8_lossy(&body).trim_end(), "from upstream!");
    }
}
