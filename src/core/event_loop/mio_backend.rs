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

use crate::core::conn::{Connection, ConnectionProtocol, Http1Connection, Http2Connection, Http2Settings, Transport, WsConnection, WsSettings};
use crate::core::server::RoutaServer;
use crate::core::worker::{ShutdownSignal, WorkerBody, WorkerPool};
use crate::net::poller::{EventPoller, Interests, MioPoller, PollKey};
use crate::net::socket::bind_reuseport;
use crate::net::tls::TlsConnection;

const DEFAULT_MAX_REQUEST_SIZE: usize = 0; // 0 = unlimited, matches http::request::parse's convention
const POLL_TIMEOUT: Duration = Duration::from_millis(200);
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
const MEMORY_CHECK_INTERVAL: Duration = Duration::from_secs(5);

pub struct EventLoopWorker {
    port: u16,
    server: Arc<RoutaServer>,
    max_request_size: usize,
    keepalive_timeout: Duration,
    request_timeout: Duration,
    h2_settings: Http2Settings,
    ws_enabled: bool,
    ws_max_connections: usize,
    ws_permessage_deflate: bool,
    ws_settings: WsSettings,
    backlog: i32,
    max_connections: i64,
    socket_recv_buf_size: i32,
    socket_send_buf_size: i32,
    shutdown_timeout: Duration,
    cpu_affinity_enabled: bool,
    cpu_affinity_start_core: usize,
    numa_aware_enabled: bool,
    h2c_upgrade_enabled: bool,
    n_workers: usize,
    memory_soft_limit_mb: i64,
    memory_hard_limit_mb: i64,
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
        let h2 = &server.config.h2;
        let h2_settings = Http2Settings {
            max_concurrent_streams: h2.max_concurrent_streams.min(h2.max_concurrent_streams_hard_cap).max(1),
            header_table_size: h2.header_table_size as usize,
            initial_window_size: h2.initial_window_size,
            max_frame_size: h2.max_frame_size,
            max_header_list_size: h2.max_header_list_size,
            huffman_encoding: h2.huffman_encoding,
            dynamic_table_update: h2.dynamic_table_update,
            server_push_enabled: h2.server_push_enabled,
            stream_timeout: Duration::from_millis(h2.stream_timeout_ms.max(0) as u64),
            keepalive_timeout: Duration::from_millis(h2.keepalive_timeout_ms.max(0) as u64),
            stream_lookup: h2.stream_lookup,
            connect_protocol_enabled: h2.enabled && server.config.ws.enabled,
        };
        let ws = &server.config.ws;
        let ws_settings = WsSettings {
            max_frame_size: ws.max_frame_size,
            max_message_size: ws.max_message_size,
            require_masking: ws.require_masking,
            compression_level: ws.compression_level.clamp(0, 9) as u32,
            compression_threshold: ws.compression_threshold.max(0) as usize,
            write_queue_max_bytes: if ws.write_queue_max > 0 {
                ws.write_buf_size.max(1).saturating_mul(ws.write_queue_max.max(0) as u64)
            } else {
                u64::MAX
            },
            idle_timeout: if ws.idle_timeout_ms > 0 {
                Some(Duration::from_millis(ws.idle_timeout_ms as u64))
            } else {
                None
            },
            ping_interval: Duration::from_millis(ws.ping_interval_ms.max(0) as u64),
            ping_timeout: Duration::from_millis(ws.ping_timeout_ms.max(0) as u64),
            max_ping_misses: ws.max_ping_misses.max(0) as u32,
            read_buf_size: ws.read_buf_size.max(0) as usize,
            write_buf_size: ws.write_buf_size.max(0) as usize,
        };
        let ws_enabled = ws.enabled;
        let ws_max_connections = ws.max_connections.max(0) as usize;
        let ws_permessage_deflate = ws.permessage_deflate;
        let backlog = server.config.backlog.max(1);
        let max_connections = server.config.max_connections.max(0) as i64;
        let socket_recv_buf_size = server.config.socket_recv_buf_size;
        let socket_send_buf_size = server.config.socket_send_buf_size;
        let shutdown_timeout = Duration::from_millis(server.config.shutdown_timeout_ms.max(0) as u64);
        let cpu_affinity_enabled = server.config.cpu_affinity_enabled;
        let cpu_affinity_start_core = server.config.cpu_affinity_start_core.max(0) as usize;
        let numa_aware_enabled = server.config.numa_aware_enabled;
        let h2c_upgrade_enabled = server.config.h2.h2c_upgrade_enabled;
        let n_workers = server.config.n_workers.max(1) as usize;
        let memory_soft_limit_mb = server.config.memory_soft_limit_mb.max(0) as i64;
        let memory_hard_limit_mb = server.config.memory_hard_limit_mb.max(0) as i64;
        EventLoopWorker {
            port,
            server,
            max_request_size,
            keepalive_timeout,
            request_timeout,
            h2_settings,
            ws_enabled,
            ws_max_connections,
            ws_permessage_deflate,
            ws_settings,
            backlog,
            max_connections,
            socket_recv_buf_size,
            socket_send_buf_size,
            shutdown_timeout,
            cpu_affinity_enabled,
            cpu_affinity_start_core,
            numa_aware_enabled,
            n_workers,
            h2c_upgrade_enabled,
            memory_soft_limit_mb,
            memory_hard_limit_mb,
        }
    }
}

impl WorkerBody for EventLoopWorker {
    fn run(&self, worker_id: usize, shutdown: &ShutdownSignal) {
        if self.cpu_affinity_enabled {
            let topology = if self.numa_aware_enabled {
                crate::net::socket::numa_topology()
            } else {
                None
            };
            let assignment = crate::net::socket::numa_aware_core_assignment(
                self.n_workers,
                self.cpu_affinity_start_core,
                topology.as_deref(),
            );
            let core = assignment.get(worker_id).copied().unwrap_or(self.cpu_affinity_start_core + worker_id);
            if let Err(e) = crate::net::socket::pin_current_thread_to_core(core) {
                tracing::warn!(worker_id, core, error = %e, "failed to set CPU affinity for worker thread");
            }
        }

        let mut listener = match bind_reuseport(self.port, self.backlog) {
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

        // A distinct sentinel from listener_key -- see WsRegistry::new's
        // own doc comment on why its waker needs a key the poll loop
        // can recognize as "drain the broadcast queue", not a real
        // connection or the listener.
        let ws_registry_key = PollKey::from_slab_index(usize::MAX - 1);
        let mut ws_registry = match crate::http::ws::WsRegistry::new(poller.registry(), ws_registry_key) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "worker failed to create WS broadcast registry");
                return;
            }
        };

        let mut connections: Slab<Connection> = Slab::new();
        // Event-driven upstream connection state -- see
        // core::event_loop::mio_upstream's own module doc comment for
        // why this is a completely separate Slab/key-map from
        // `connections` above rather than folding upstream connections
        // into that same Slab. Keyed by mio's own PollKey (from
        // UpstreamConnection::start's own poller.register call) so an
        // incoming readiness event can be routed to the right entry
        // the same way `connections`'s own poll_key does for
        // downstream connections.
        let mut upstream_connections: Slab<crate::core::event_loop::mio_upstream::UpstreamConnection> = Slab::new();
        let mut upstream_poll_keys: std::collections::HashMap<PollKey, usize> = std::collections::HashMap::new();
        let mut last_idle_sweep = Instant::now();
        let mut last_memory_check = Instant::now();
        // Set the moment `shutdown.is_set()` first becomes true --
        // `RoutaConfig::shutdown_timeout_ms` bounds how long this
        // worker keeps draining in-flight connections after that,
        // rather than the previous behavior of dropping every
        // connection immediately as soon as the shutdown signal fired.
        let mut draining_since: Option<Instant> = None;

        loop {
            if shutdown.is_set() && draining_since.is_none() {
                draining_since = Some(Instant::now());
            }
            if let Some(started) = draining_since {
                if connections.is_empty() || started.elapsed() >= self.shutdown_timeout {
                    break;
                }
            }

            let events = match poller.poll(Some(POLL_TIMEOUT)) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for (key, readiness) in events {
                if upstream_poll_keys.contains_key(&key) {
                }
                if key == listener_key {
                    // Stop accepting new connections as soon as a
                    // shutdown has been requested -- only already-open
                    // connections get the grace period.
                    if draining_since.is_none() {
                        accept_all(self, &mut listener, &mut poller, &mut connections);
                    }
                    continue;
                }
                if key == ws_registry_key {
                    dispatch_ws_broadcast(&mut ws_registry, &mut connections);
                    continue;
                }
                if let Some(&upstream_idx) = upstream_poll_keys.get(&key) {
                    handle_upstream_event(self, &mut poller, &mut connections, &mut upstream_connections, &mut upstream_poll_keys, upstream_idx);
                    continue;
                }
                handle_connection_event(self, &mut poller, &mut connections, &mut upstream_connections, &mut upstream_poll_keys, key, readiness);
            }

            // Upstream connections have no fixed per-request timeout
            // check the poller itself can drive for us (unlike a
            // socket becoming readable/writable, "this connect/read
            // has taken too long" is purely a wall-clock condition) --
            // swept alongside the loop's own other periodic
            // maintenance rather than needing a separate timer.
            if last_idle_sweep.elapsed() >= IDLE_SWEEP_INTERVAL {
                reap_timed_out_upstream_connections(self, &mut poller, &mut connections, &mut upstream_connections, &mut upstream_poll_keys);
            }

            if last_idle_sweep.elapsed() >= IDLE_SWEEP_INTERVAL {
                last_idle_sweep = Instant::now();
                reap_idle_connections(self, &mut poller, &mut connections);
                reap_stale_h2_streams(&mut connections, self.h2_settings.stream_timeout);
                ping_sweep_ws_connections(self, &mut poller, &mut connections);
                sync_ws_registry(&mut ws_registry, &connections);
                for pool in &self.server.pools {
                    for node in pool.lb.pool.nodes().iter() {
                        node.reap_idle(pool.idle_timeout);
                    }
                }
            }

            // Only worker 0 samples RSS (a process-wide, not per-worker,
            // quantity -- every worker re-measuring it would be
            // redundant work for the same answer) -- see
            // `RoutaConfig::memory_soft_limit_mb`/`memory_hard_limit_mb`.
            if worker_id == 0 && (self.memory_soft_limit_mb > 0 || self.memory_hard_limit_mb > 0) && last_memory_check.elapsed() >= MEMORY_CHECK_INTERVAL {
                last_memory_check = Instant::now();
                self.server.metrics.process.refresh_rss();
                let rss_mb = (self.server.metrics.process.rss_bytes.get() / (1024.0 * 1024.0)) as i64;

                let over_soft = self.memory_soft_limit_mb > 0 && rss_mb >= self.memory_soft_limit_mb;
                self.server.memory_over_soft_limit.store(over_soft, std::sync::atomic::Ordering::Relaxed);

                if self.memory_hard_limit_mb > 0 && rss_mb >= self.memory_hard_limit_mb && !shutdown.is_set() {
                    tracing::error!(rss_mb, hard_limit_mb = self.memory_hard_limit_mb, "memory_hard_limit_mb exceeded, initiating graceful shutdown");
                    shutdown.signal();
                }
            }
        }
    }
}

/// Drives one upstream connection one step further in response to a
/// readiness event, and, once it resolves (successfully or not),
/// flushes the result to whichever downstream connection was waiting
/// on it -- the mio_backend counterpart to uring_backend's own
/// OP_TAG_RECV upstream-response handling, using
/// UpstreamConnection::advance's identical "state machine advances,
/// caller owns all I/O" contract instead of a completion queue.
fn handle_upstream_event(
    worker: &EventLoopWorker,
    poller: &mut MioPoller,
    connections: &mut Slab<Connection>,
    upstream_connections: &mut Slab<crate::core::event_loop::mio_upstream::UpstreamConnection>,
    upstream_poll_keys: &mut std::collections::HashMap<PollKey, usize>,
    upstream_idx: usize,
) {
    if !upstream_connections.contains(upstream_idx) {
        return;
    }
    let step = match upstream_connections[upstream_idx].advance() {
        Ok(step) => step,
        Err(_) => crate::core::event_loop::mio_upstream::UpstreamStep::Failed,
    };
    match step {
        crate::core::event_loop::mio_upstream::UpstreamStep::Pending => {}
        crate::core::event_loop::mio_upstream::UpstreamStep::Done(response) => {
            let upstream = upstream_connections.remove(upstream_idx);
            upstream_poll_keys.remove(&upstream.poll_key);
            let _ = poller.deregister(&mut { upstream.stream }, upstream.poll_key);
            if response.status < 500 {
                upstream.node.record_success(&upstream.pool);
            } else {
                upstream.node.record_failure(&upstream.pool);
            }
            flush_upstream_result_to_downstream(worker, poller, connections, upstream.downstream_slab_index, upstream.downstream_conn_id, Some(response), Some(&upstream.node));
            // Mirrors handle_connection_event's own identical
            // check/close right after driving a downstream
            // connection's protocol state machine (see that
            // function's own if result.is_err() || connections[idx].closing)
            // -- flush_upstream_result_to_downstream may have just set
            // closing = true (Connection: close on either the original
            // request or the response), and nothing else in this
            // event-driven upstream path otherwise ever reaches that
            // check, since this call arrived via an upstream
            // connection's own readiness event, not a downstream
            // one's.
            if connections.contains(upstream.downstream_slab_index) && connections[upstream.downstream_slab_index].id == upstream.downstream_conn_id && connections[upstream.downstream_slab_index].closing {
                close_connection(worker, poller, connections, upstream.downstream_slab_index);
            }
        }
        crate::core::event_loop::mio_upstream::UpstreamStep::Failed => {
            let upstream = upstream_connections.remove(upstream_idx);
            upstream_poll_keys.remove(&upstream.poll_key);
            let _ = poller.deregister(&mut { upstream.stream }, upstream.poll_key);
            upstream.node.record_failure(&upstream.pool);
            flush_upstream_result_to_downstream(worker, poller, connections, upstream.downstream_slab_index, upstream.downstream_conn_id, None, None);
        }
    }
}

/// Delivers an upstream request's outcome to the downstream connection
/// that was waiting on it -- `Some(response)` flushes it as the proxied
/// response; `None` means the upstream attempt failed, and this reads
/// the downstream's own `Http1Connection::waiting_for_upstream` to
/// decide whether to retry a different node or give up with a 502
/// (mirrors uring_backend's own retry_or_fail_proxy_attempt).
fn flush_upstream_result_to_downstream(
    worker: &EventLoopWorker,
    poller: &mut MioPoller,
    connections: &mut Slab<Connection>,
    downstream_slab_index: usize,
    downstream_conn_id: crate::core::conn::ConnId,
    response: Option<crate::http::response::HttpResponse>,
    node: Option<&Arc<crate::lb::upstream::UpstreamNode>>,
) {
    if !connections.contains(downstream_slab_index) {
        return;
    }
    let conn = &mut connections[downstream_slab_index];
    if conn.id != downstream_conn_id {
        return;
    }
    let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
        return;
    };
    let Some(attempt_state) = h1.waiting_for_upstream.take() else {
        return;
    };
    match response {
        Some(resp) => {
            let keep_alive = attempt_state.keep_alive;
            let mut resp = resp;
            if let Some(node) = node {
                let incoming_sticky = attempt_state
                    .original_request
                    .get_header(&crate::core::proxy::sticky_cookie_header_name(&attempt_state.pending.lb));
                crate::core::proxy::apply_sticky_cookie(&mut resp, &attempt_state.pending.lb, node, incoming_sticky);
            }
            crate::core::conn::protocol::queue_http1_response(h1, resp);
            h1.keep_alive = keep_alive;
            if !keep_alive {
                // Mirrors the ordinary (non-proxied) response path's
                // own identical closing = true -- without this, a
                // Connection: close request proxied through this
                // event-driven path would queue and flush its
                // response correctly but never actually close the
                // TCP connection afterward, leaving a client using
                // read-until-EOF (the standard way to consume a
                // Connection: close response) waiting indefinitely
                // for a FIN that was never coming.
                connections[downstream_slab_index].closing = true;
            }
            let _ = flush_transport(connections, downstream_slab_index);
        }
        None => {
            retry_or_fail_proxy_attempt_mio(worker, poller, connections, downstream_slab_index, downstream_conn_id, attempt_state);
        }
    }
}

/// Picks a different upstream node and starts a fresh
/// UpstreamConnection against it, or gives up with a 502 if the
/// attempt limit (`LbPoolConfig::lb_max_attempts`, via `pending.config`)
/// has been reached or no other node is available -- the mio_backend
/// counterpart to uring_backend's own retry_or_fail_proxy_attempt,
/// using UpstreamConnection::start instead of a raw Connect SQE.
fn retry_or_fail_proxy_attempt_mio(
    worker: &EventLoopWorker,
    poller: &mut MioPoller,
    connections: &mut Slab<Connection>,
    downstream_slab_index: usize,
    downstream_conn_id: crate::core::conn::ConnId,
    mut attempt_state: crate::core::conn::protocol::ProxyAttemptState,
) {
    attempt_state.attempts_so_far += 1;
    let max_attempts = 1 + attempt_state.pending.lb.config.max_retries.max(0) as u32;
    let node = if attempt_state.attempts_so_far < max_attempts {
        attempt_state.pending.lb.pick_node_sticky(None, None)
    } else {
        None
    };
    let Some(node) = node else {
        flush_502_to_downstream(connections, downstream_slab_index, downstream_conn_id);
        return;
    };
    let client_addr = attempt_state.original_request.remote_addr;
    let headers = crate::core::proxy::build_upstream_headers(&attempt_state.original_request, client_addr, &attempt_state.pending.config.proxy_identity);
    let mut upstream_req = (*attempt_state.original_request).clone();
    upstream_req.headers = headers.into_iter().map(|h| (h.name, h.value)).collect();
    let request_bytes = upstream_req.serialize();
    let pool = std::sync::Arc::clone(&attempt_state.pending.lb.pool);
    match crate::core::event_loop::mio_upstream::UpstreamConnection::start(
        poller,
        std::sync::Arc::clone(&node),
        pool,
        request_bytes,
        downstream_slab_index,
        downstream_conn_id,
        attempt_state.pending.config.connect_timeout,
    ) {
        Ok(_upstream_conn) => {
            // The caller (handle_upstream_event's own Failed arm) is
            // responsible for re-inserting attempt_state as this
            // downstream connection's own waiting_for_upstream --
            // done by its own caller site rather than here, since this
            // function only decides whether a retry is possible at
            // all, not how it's threaded back into the downstream's
            // own state (mirrors uring_backend's own split between
            // deciding and threading state back).
            if !connections.contains(downstream_slab_index) {
                return;
            }
            let conn = &mut connections[downstream_slab_index];
            if conn.id != downstream_conn_id {
                return;
            }
            if let ConnectionProtocol::Http1(h1) = &mut conn.protocol {
                h1.waiting_for_upstream = Some(attempt_state);
            }
            let _ = worker;
        }
        Err(_) => {
            flush_502_to_downstream(connections, downstream_slab_index, downstream_conn_id);
        }
    }
}

/// Sends a 502 Bad Gateway to a downstream connection that was waiting
/// on a proxied response -- shared terminal case for both an exhausted
/// retry budget and a failed retry attempt itself.
fn flush_502_to_downstream(connections: &mut Slab<Connection>, downstream_slab_index: usize, downstream_conn_id: crate::core::conn::ConnId) {
    if !connections.contains(downstream_slab_index) {
        return;
    }
    let conn = &mut connections[downstream_slab_index];
    if conn.id != downstream_conn_id {
        return;
    }
    let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
        return;
    };
    let mut resp = crate::http::response::HttpResponse::new(502, "Bad Gateway");
    resp.set_body(b"Bad Gateway\n".to_vec());
    crate::core::conn::protocol::queue_http1_response(h1, resp);
    let _ = flush_transport(connections, downstream_slab_index);
}

/// Sweeps `upstream_connections` for any whose own deadline (set from
/// `UpstreamConnection::start`'s own connect_timeout parameter -- see
/// that field's own doc comment) has passed without resolving,
/// treating each as a failed attempt the same way a real connection
/// error would be -- mio has no equivalent to io_uring's own
/// LinkTimeout SQE (see uring_backend's own push_link_timeout), so
/// this periodic wall-clock sweep is this backend's substitute.
fn reap_timed_out_upstream_connections(
    worker: &EventLoopWorker,
    poller: &mut MioPoller,
    connections: &mut Slab<Connection>,
    upstream_connections: &mut Slab<crate::core::event_loop::mio_upstream::UpstreamConnection>,
    upstream_poll_keys: &mut std::collections::HashMap<PollKey, usize>,
) {
    let now = Instant::now();
    let timed_out: Vec<usize> = upstream_connections
        .iter()
        .filter(|(_, u)| now >= u.deadline)
        .map(|(idx, _)| idx)
        .collect();
    for idx in timed_out {
        if !upstream_connections.contains(idx) {
            continue;
        }
        let upstream = upstream_connections.remove(idx);
        upstream_poll_keys.remove(&upstream.poll_key);
        let _ = poller.deregister(&mut { upstream.stream }, upstream.poll_key);
        upstream.node.record_failure(&upstream.pool);
        flush_upstream_result_to_downstream(worker, poller, connections, upstream.downstream_slab_index, upstream.downstream_conn_id, None, None);
    }
}

fn accept_all(worker: &EventLoopWorker, listener: &mut TcpListener, poller: &mut MioPoller, connections: &mut Slab<Connection>) {
    loop {
        match listener.accept() {
            Ok((mut stream, remote_addr)) => {
                // RoutaConfig::max_connections (0 = unlimited) caps
                // total open connections across every worker --
                // `connections_active` is one shared `IntGauge` (see
                // `util::metrics::Metrics`, constructed once and held
                // behind an `Arc`), so this reads the true cluster-wide
                // count rather than just this worker's own slab size.
                if worker.max_connections > 0 && worker.server.metrics.connection.connections_active.get() >= worker.max_connections {
                    continue; // drop this connection immediately -- at capacity
                }
                if worker.server.memory_over_soft_limit.load(std::sync::atomic::Ordering::Relaxed) {
                    continue; // drop this connection immediately -- memory_soft_limit_mb exceeded
                }

                let _ = crate::net::socket::apply_buffer_sizes(
                    socket2::SockRef::from(&stream),
                    worker.socket_recv_buf_size,
                    worker.socket_send_buf_size,
                );

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
    upstream_connections: &mut Slab<crate::core::event_loop::mio_upstream::UpstreamConnection>,
    upstream_poll_keys: &mut std::collections::HashMap<PollKey, usize>,
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

    let still_deciding_protocol = matches!(connections[idx].protocol, ConnectionProtocol::Handshaking)
       || matches!(&connections[idx].protocol, ConnectionProtocol::Http1(h1) if !h1.protocol_confirmed);
    if still_deciding_protocol {
       if connections[idx].is_tls() {
          if let Transport::Tls { tls, .. } = &connections[idx].transport {
             worker.server.metrics.connection.tls_handshakes_total.with_label_values(&["success"]).inc();
             let duration_secs = connections[idx].created_at.elapsed().as_secs_f64();
             let tls_version = tls.protocol_version_label();
             worker.server.metrics.connection.tls_handshake_duration_seconds.with_label_values(&[tls_version]).observe(duration_secs);
          }
          let is_h2 = matches!(&connections[idx].transport, Transport::Tls { tls, .. } if tls.alpn_protocol() == Some(b"h2".as_slice()));
          connections[idx].protocol = if is_h2 {
             worker.server.metrics.connection.protocol_selected_total.with_label_values(&["http2"]).inc();
             ConnectionProtocol::Http2(Http2Connection::new(&worker.h2_settings))
          } else {
             worker.server.metrics.connection.protocol_selected_total.with_label_values(&["http1"]).inc();
             ConnectionProtocol::Http1(Http1Connection::new())
          };
       } else {
          // A plaintext connection has no ALPN to consult -- reads
          // whatever's available and checks it against the H2
          // connection preface (RFC 9113 3.4) before committing to
          // HTTP/1.1, so a prior-knowledge H2 client (h2spec's
          // default test mode, and any HTTP/2 client that skips the
          // h2c Upgrade dance) is recognized rather than having its
          // preface bytes misparsed as a malformed HTTP/1.1 request
          // line. Reuses a scratch Http1Connection purely as a place
          // to accumulate these bytes across calls until enough have
          // arrived to decide -- if the decision comes back Http1,
          // this same buffer becomes that connection's real
          // read_buf, so nothing already read is lost or re-read.
          if !matches!(connections[idx].protocol, ConnectionProtocol::Http1(_)) {
             connections[idx].protocol = ConnectionProtocol::Http1(Http1Connection::new_unconfirmed());
          }
          if read_into_transport(connections, idx, |conn| {
             let ConnectionProtocol::Http1(h1) = &mut conn.protocol else { unreachable!() };
             &mut h1.read_buf
          })
          .is_err()
          {
             close_connection(worker, poller, connections, idx);
             return;
          }
          let decision = {
             let ConnectionProtocol::Http1(h1) = &connections[idx].protocol else { unreachable!() };
             crate::core::conn::protocol::decide_plaintext_protocol(h1.read_buf.as_slice())
          };
          match decision {
             crate::core::conn::protocol::PlaintextProtocolDecision::NeedMoreData => return, // wait for the next readiness event
             crate::core::conn::protocol::PlaintextProtocolDecision::Http1 => {
                worker.server.metrics.connection.protocol_selected_total.with_label_values(&["http1"]).inc();
                let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else { unreachable!() };
                h1.protocol_confirmed = true;
             }
             crate::core::conn::protocol::PlaintextProtocolDecision::InvalidH2Preface => {
                // RFC 9113 3.4: a client that starts the H2 connection
                // preface but sends something other than the exact 24
                // expected bytes has committed to prior-knowledge H2,
                // badly -- this must be rejected as a connection error
                // (PROTOCOL_ERROR), not silently reinterpreted as
                // HTTP/1.1 the way a genuinely unrelated malformed
                // request would be.
                const PROTOCOL_ERROR: u32 = 0x1;
                let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else { unreachable!() };
                let mut goaway = Vec::new();
                crate::http::h2::frame::write_goaway(&mut goaway, 0, PROTOCOL_ERROR);
                h1.write_buf.push(&goaway);
                connections[idx].closing = true;
                // Best-effort flush -- if it fails, close_connection
                // below still runs and tears the connection down
                // either way, same as every other error path in this
                // function.
                let _ = flush_transport(connections, idx);
                close_connection(worker, poller, connections, idx);
                return;
             }
             crate::core::conn::protocol::PlaintextProtocolDecision::Http2PriorKnowledge => {
                worker.server.metrics.connection.protocol_selected_total.with_label_values(&["http2"]).inc();
                let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else { unreachable!() };
                // Consume exactly the preface's own bytes -- any
                // further bytes already read past it (a client's own
                // initial SETTINGS frame, pipelined immediately after
                // the preface) are real H2 protocol data and must be
                // handed to the new Http2Connection's own advance(),
                // not discarded.
                h1.read_buf.consume(crate::core::conn::protocol::H2_CONNECTION_PREFACE.len());
                let leftover = h1.read_buf.as_slice().to_vec();
                let mut h2 = Http2Connection::new(&worker.h2_settings);
                h2.inner.assume_preface_received();
                connections[idx].protocol = ConnectionProtocol::Http2(h2);
                if !leftover.is_empty() {
                   let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else { unreachable!() };
                   let advance_result = h2.inner.advance(&leftover);
                   h2.write_buf.push(&advance_result.to_send);
                   // Only the connection-preface bytes themselves were
                   // consumed above -- any newly-ready streams or WS
                   // tunnels this leftover data produced are handled by
                   // drive_http2's own next pass over this connection
                   // (triggered by this function falling through to
                   // the normal protocol-dispatch match below), not
                   // re-implemented here.
                }
             }
          }
       }
    }


    let result = match &mut connections[idx].protocol {
        ConnectionProtocol::Handshaking => Ok(()), // TLS handshake in progress, or a plaintext connection still waiting for enough bytes to decide HTTP/1.1 vs. H2 prior-knowledge (see the block above)
        ConnectionProtocol::Http1(_) => drive_http1(worker, poller, connections, upstream_connections, upstream_poll_keys, idx),
        ConnectionProtocol::Http2(_) => drive_http2(worker, connections, idx),
        ConnectionProtocol::WebSocket(_) => drive_websocket(worker, connections, idx),
        ConnectionProtocol::UpstreamH2(_) => unreachable!("mio_backend never constructs ConnectionProtocol::UpstreamH2 -- see that variant's own doc comment"),
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
        if matches!(conn.protocol, ConnectionProtocol::WebSocket(_)) {
            worker.server.ws_active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
fn drive_http1(
    worker: &EventLoopWorker,
    poller: &mut MioPoller,
    connections: &mut Slab<Connection>,
    upstream_connections: &mut Slab<crate::core::event_loop::mio_upstream::UpstreamConnection>,
    upstream_poll_keys: &mut std::collections::HashMap<PollKey, usize>,
    idx: usize,
) -> std::io::Result<()> {
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

                if worker.h2c_upgrade_enabled && crate::http::h2::is_h2c_upgrade_request(&request) {
                    let settings_payload = crate::http::h2::decode_http2_settings_header(&request).unwrap_or_default();
                    let mut resp = crate::http::response::HttpResponse::new(101, "Switching Protocols");
                    resp.set_header("Connection", "Upgrade");
                    resp.set_header("Upgrade", "h2c");
                    queue_http1_response(connections, idx, resp);
                    flush_transport(connections, idx)?;
                    let mut h2 = crate::core::conn::Http2Connection::new(&worker.h2_settings);
                    h2.inner.assume_preface_received();
                    h2.inner.apply_upgrade_settings(&settings_payload);
                    connections[idx].protocol = ConnectionProtocol::Http2(h2);
                    return drive_http2(worker, connections, idx);
                }

                let is_upgrade = crate::http::ws::is_upgrade_request(&request);
                let request_body_len = request.body.len();
                let method_str = format!("{:?}", request.method).to_uppercase();
                let route = request.path.clone();
                worker.server.metrics.http.requests_in_flight.with_label_values(&["http1"]).inc();
                let dispatch_start = Instant::now();
                let response = worker.server.middleware_chain.execute(&request);
                // A route handler that matched a proxy route
                // deliberately does no I/O itself (see
                // `HttpResponse::proxy_pending`'s own doc comment) --
                // the actual forwarding, synchronously, on this same
                // thread, is this backend's job, called from here
                // rather than from inside the route handler. This
                // matches this backend's own prior behavior exactly
                // (forward() used to be called directly from the
                // route handler, blocking this same call stack either
                // way) -- only *where* forward() is invoked from
                // changed, not its own synchronous nature or anything
                // about what it does.
                if let Some(pending) = response.proxy_pending.clone() {
                    // Event-driven path (see
                    // core::event_loop::mio_upstream's own module doc
                    // comment): pick a node the same way
                    // core::proxy::forward's own pick_node_sticky call
                    // does, open a real non-blocking connection to it
                    // via UpstreamConnection::start, and return here
                    // immediately -- this connection's own
                    // Http1Connection::waiting_for_upstream is what
                    // marks it as "response pending" so nothing else
                    // (a keep-alive pipelined request behind this one,
                    // for instance) tries to act on it until
                    // handle_upstream_event's own flush_upstream_result_to_downstream
                    // resolves it, mirroring uring_backend's identical
                    // ProxyPending arm.
                    let Some(node) = pending.lb.pick_node_sticky(None, None) else {
                        let mut resp = crate::http::response::HttpResponse::new(503, "Service Unavailable");
                        resp.set_body(b"Service Unavailable\n".to_vec());
                        let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else { unreachable!() };
                        crate::core::conn::protocol::queue_http1_response(h1, resp);
                        return flush_transport(connections, idx);
                    };
                    let client_addr = request.remote_addr;
                    let headers = crate::core::proxy::build_upstream_headers(&request, client_addr, &pending.config.proxy_identity);
                    let mut upstream_req = request.clone();
                    upstream_req.headers = headers.into_iter().map(|h| (h.name, h.value)).collect();
                    let request_bytes = upstream_req.serialize();
                    // request.keep_alive is what actually reflects
                    // this specific request's own Connection header
                    // (see the ordinary, non-proxied response path's
                    // own identical keep_alive computation a little
                    // further down in this same function) --
                    // h1.keep_alive itself hasn't been updated for
                    // this request yet at this point, so reading it
                    // here would use whatever value the *previous*
                    // request on this same keep-alive connection left
                    // behind.
                    let keep_alive_for_attempt = request.keep_alive;
                    let downstream_conn_id = connections[idx].id;
                    let pool = std::sync::Arc::clone(&pending.lb.pool);
                    match crate::core::event_loop::mio_upstream::UpstreamConnection::start(
                        poller,
                        std::sync::Arc::clone(&node),
                        pool,
                        request_bytes,
                        idx,
                        downstream_conn_id,
                        pending.config.connect_timeout,
                    ) {
                        Ok(upstream_conn) => {
                            let key = upstream_conn.poll_key;
                            let slot = upstream_connections.insert(upstream_conn);
                            upstream_poll_keys.insert(key, slot);
                            let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else { unreachable!() };
                            h1.waiting_for_upstream = Some(crate::core::conn::protocol::ProxyAttemptState {
                                upstream_slab_index: slot,
                                upstream_generation: 0,
                                keep_alive: keep_alive_for_attempt,
                                attempts_so_far: 1,
                                pending,
                                original_request: Box::new(request.clone()),
                            });
                            return Ok(());
                        }
                        Err(_) => {
                            let mut resp = crate::http::response::HttpResponse::new(502, "Bad Gateway");
                            resp.set_body(b"Bad Gateway\n".to_vec());
                            let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else { unreachable!() };
                            crate::core::conn::protocol::queue_http1_response(h1, resp);
                            return flush_transport(connections, idx);
                        }
                    }
                }
                let response = response;
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
                if !response.early_hints.is_empty() {
                    let mut early_hints_response = String::from("HTTP/1.1 103 Early Hints\r\n");
                    for (name, value) in &response.early_hints {
                        early_hints_response.push_str(name);
                        early_hints_response.push_str(": ");
                        early_hints_response.push_str(value);
                        early_hints_response.push_str("\r\n");
                    }
                    early_hints_response.push_str("\r\n");
                    let ConnectionProtocol::Http1(h1) = &mut connections[idx].protocol else {
                        unreachable!()
                    };
                    h1.write_buf.push(early_hints_response.as_bytes());
                }
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
                    // WsConfig::enabled / max_connections are enforced
                    // here rather than earlier: only a request the
                    // application handler already accepted as a valid
                    // upgrade (101) is a candidate at all, so there's
                    // no reason to reject anything before that's known.
                    let over_capacity = worker.server.ws_active_connections.load(std::sync::atomic::Ordering::Relaxed) >= worker.ws_max_connections;
                    if !worker.ws_enabled || over_capacity {
                        let mut resp = crate::http::response::HttpResponse::new(503, "Service Unavailable");
                        resp.set_header("Connection", "close");
                        resp.set_body(b"WebSocket unavailable\n".to_vec());
                        queue_http1_response(connections, idx, resp);
                        connections[idx].closing = true;
                        flush_transport(connections, idx)?;
                        return Ok(());
                    }

                    let pmd = if worker.ws_permessage_deflate {
                        negotiate_pmd_from_response(&response, worker.ws_settings.compression_level)
                    } else {
                        None
                    };
                    let upgrade_path = request.path.clone();
                    queue_http1_response(connections, idx, response);
                    // The 101 response was just queued into this
                    // connection's Http1 write_buf -- flushed here,
                    // before the protocol switch below replaces the
                    // Http1 state (and its write_buf) with a fresh
                    // WsConnection, since nothing carries pending
                    // bytes across that replacement otherwise.
                    flush_transport(connections, idx)?;
                    connections[idx].protocol = ConnectionProtocol::WebSocket(
                        WsConnection::with_settings(pmd, &worker.ws_settings).with_upgrade_path(upgrade_path),
                    );
                    worker.server.ws_active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            ConnectionProtocol::UpstreamH2(_) => unreachable!("mio_backend never constructs ConnectionProtocol::UpstreamH2"),
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
                    ConnectionProtocol::UpstreamH2(_) => unreachable!("mio_backend never constructs ConnectionProtocol::UpstreamH2"),
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
        let early_hints: Vec<crate::http::h2::hpack::HeaderField> = response
            .early_hints
            .iter()
            .map(|(name, value)| crate::http::h2::hpack::HeaderField { name: name.clone(), value: value.clone() })
            .collect();
        let (status, headers, body) = split_response_for_h2(response);

        let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
            unreachable!()
        };
        if !early_hints.is_empty() {
            let hints_out = h2.inner.send_informational_response(stream_id, 103, &early_hints);
            h2.write_buf.push(&hints_out);
        }
        let out = h2.inner.send_response(stream_id, status, &headers, body);
        h2.write_buf.push(&out);
    }

    // RFC 8441 Extended CONNECT: each candidate is looked up against
    // the same registered WS routes the HTTP/1.1 upgrade path uses
    // (`Router::dispatch_websocket`) -- this lookup, and the
    // WsConfig::enabled/max_connections gate below it, can only happen
    // here rather than inside `http::h2::stream`, since that module has
    // no access to a `Router` or to `worker`'s shared WS accounting.
    for stream_id in advance_result.new_ws_tunnel_streams {
        let path = {
            let ConnectionProtocol::Http2(h2) = &connections[idx].protocol else {
                unreachable!()
            };
            h2.inner.stream_path(stream_id).map(|p| p.to_string())
        };
        let Some(path) = path else { continue };
        let route_matched = worker.server.router.dispatch_websocket(&path).is_some();
        let over_capacity = worker.server.ws_active_connections.load(std::sync::atomic::Ordering::Relaxed) >= worker.ws_max_connections;

        let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
            unreachable!()
        };
        if !route_matched {
            // Same "unmatched path" response an ordinary request gets
            // (see `core::server::dispatch`'s `Dispatch::NotFound` arm)
            // -- Extended CONNECT is matched by path against the WS
            // route table exactly like a normal request is matched
            // against the regular route table, so an unmatched path
            // means the same thing either way.
            let out = h2.inner.reject_ws_tunnel(stream_id, 404, b"Not Found\n".to_vec());
            h2.write_buf.push(&out);
            continue;
        }
        if !worker.ws_enabled || over_capacity {
            let out = h2.inner.reject_ws_tunnel(stream_id, 503, b"WebSocket unavailable\n".to_vec());
            h2.write_buf.push(&out);
            continue;
        }

        let pmd = if worker.ws_permessage_deflate {
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
        let pmd_context = pmd.map(|params| crate::http::ws::PmdContext::with_compression_level(params, worker.ws_settings.compression_level));
        let ws_tunnel = crate::http::ws::WsConnection::with_read_buf_capacity(
            pmd_context,
            worker.ws_settings.max_message_size as usize,
            worker.ws_settings.max_frame_size,
            worker.ws_settings.require_masking,
            worker.ws_settings.read_buf_size,
        );
        let (out, buffered_input) = h2.inner.accept_ws_tunnel(stream_id, ws_tunnel, &accept_headers);
        h2.write_buf.push(&out);
        worker.server.ws_active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !buffered_input.is_empty() {
            drive_ws_tunnel_input(worker, connections, idx, stream_id, buffered_input);
        }
    }

    let ws_tunnel_streams_with_input = {
        let ConnectionProtocol::Http2(h2) = &connections[idx].protocol else {
            unreachable!()
        };
        h2.inner.ws_tunnel_streams_with_input()
    };
    for stream_id in ws_tunnel_streams_with_input {
        let input = {
            let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
                unreachable!()
            };
            h2.inner.take_ws_tunnel_input(stream_id)
        };
        drive_ws_tunnel_input(worker, connections, idx, stream_id, input);
    }

    if advance_result.connection_closed {
        connections[idx].closing = true;
    }

    flush_transport(connections, idx)?;
    let _ = worker;
    Ok(())
}

/// Feeds newly-arrived bytes on a WS-tunnel H2 stream through its
/// `WsConnection`, dispatches any resulting application messages to the
/// same `Router::dispatch_websocket` handler `drive_websocket` uses for
/// the HTTP/1.1 upgrade path, and queues whatever needs to go back out
/// (auto PONGs/close-echoes plus any framed reply) as H2 DATA on the
/// same stream -- respecting its own flow control via
/// `queue_ws_tunnel_data`. Tears the tunnel down (`finish_ws_tunnel`,
/// decrementing `ws_active_connections`) once the WebSocket
/// connection's own close handshake has completed on both sides.
fn drive_ws_tunnel_input(worker: &EventLoopWorker, connections: &mut Slab<Connection>, idx: usize, stream_id: u32, input: Vec<u8>) {
    if input.is_empty() {
        return;
    }
    let path = {
        let ConnectionProtocol::Http2(h2) = &connections[idx].protocol else {
            unreachable!()
        };
        h2.inner.stream_path(stream_id).map(|p| p.to_string())
    };

    let (advance_result, is_closed) = {
        let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
            unreachable!()
        };
        let Some(ws) = h2.inner.ws_tunnel_mut(stream_id) else {
            return;
        };
        let advance_result = ws.advance(&input);
        let is_closed = ws.is_closed();
        (advance_result, is_closed)
    };

    // Each received application message is looked up against the
    // registered WS routes and handed to whatever matched -- same
    // "unanswered, not torn down" behavior as `drive_websocket` for a
    // tunnel with no matching handler (there always is one here, since
    // `new_ws_tunnel_streams` handling above already rejected any path
    // without a match before ever calling `accept_ws_tunnel`, but the
    // lookup is repeated per-message rather than cached for the same
    // reason `drive_websocket` repeats it: a request-scoped lookup is
    // already cheap, and avoids this function needing to carry a
    // handler reference across calls).
    let mut outgoing = advance_result.to_send;
    for event in &advance_result.events {
        if let crate::http::ws::WsEvent::Message(msg) = event {
            let Some(path) = &path else { continue };
            let reply = worker.server.router.dispatch_websocket(path).and_then(|handler| handler(msg));
            if let Some(reply) = reply {
                let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
                    unreachable!()
                };
                let Some(ws) = h2.inner.ws_tunnel_mut(stream_id) else {
                    continue;
                };
                let framed = match reply {
                    crate::http::ws::WsMessage::Text(text) => ws.send_text(&text, worker.ws_settings.compression_threshold),
                    crate::http::ws::WsMessage::Binary(data) => ws.send_binary(&data, worker.ws_settings.compression_threshold),
                };
                outgoing.extend(framed);
            }
        }
    }

    let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
        unreachable!()
    };
    let out = h2.inner.queue_ws_tunnel_data(stream_id, outgoing);
    h2.write_buf.push(&out);

    if is_closed {
        let out = h2.inner.finish_ws_tunnel(stream_id);
        h2.write_buf.push(&out);
        worker.server.ws_active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
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
fn drive_websocket(worker: &EventLoopWorker, connections: &mut Slab<Connection>, idx: usize) -> std::io::Result<()> {
    let incoming = read_transport_bytes(connections, idx)?;

    let advance_result = {
        let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else {
            unreachable!("drive_websocket is only called when protocol is WebSocket")
        };
        ws.inner.advance(&incoming)
    };

    let upgrade_path = {
        let ConnectionProtocol::WebSocket(ws) = &connections[idx].protocol else {
            unreachable!()
        };
        ws.upgrade_path.clone()
    };
    // Each received application message is looked up against the
    // registered WS routes and handed to whatever matched -- a
    // connection with no matching route simply has its messages go
    // unanswered rather than the connection being torn down, since
    // receiving messages nobody asked for isn't itself a protocol
    // violation.
    let mut outgoing_messages = Vec::new();
    for event in &advance_result.events {
        if let crate::http::ws::WsEvent::Message(msg) = event {
            if let Some(handler) = worker.server.router.dispatch_websocket(&upgrade_path) {
                if let Some(reply) = handler(msg) {
                    outgoing_messages.push(reply);
                }
            }
        }
    }

    {
        let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else {
            unreachable!()
        };
        ws.write_buf.push(&advance_result.to_send);
        for reply in outgoing_messages {
            let framed = match reply {
                crate::http::ws::WsMessage::Text(text) => ws.inner.send_text(&text, worker.ws_settings.compression_threshold),
                crate::http::ws::WsMessage::Binary(data) => ws.inner.send_binary(&data, worker.ws_settings.compression_threshold),
            };
            ws.write_buf.push(&framed);
        }
        if advance_result.pong_received {
            ws.last_pong_at = Instant::now();
            ws.last_ping_sent = None;
            ws.ping_misses = 0;
        }
        if ws.write_buf.as_slice().len() as u64 > ws.write_queue_max_bytes {
            // WsConfig::write_queue_max backpressure: the peer isn't
            // reading fast enough to keep this connection's queued
            // outbound bytes under the configured ceiling -- torn down
            // rather than left to grow the write buffer unbounded.
            connections[idx].closing = true;
        }
    }

    if advance_result.protocol_error {
        connections[idx].closing = true;
    }

    flush_transport(connections, idx)?;
    Ok(())
}

/// Sends a PING to every WebSocket connection that's gone
/// `ping_interval` since its last PONG (or, if a PING is already
/// outstanding, `ping_timeout` since that PING was sent), and closes
/// any connection that's accumulated `max_ping_misses` such misses in
/// a row -- called periodically (see `EventLoopWorker::run`'s idle
/// sweep) rather than reactively, since a connection that's stopped
/// responding by definition isn't producing readiness events for this
/// to react to otherwise.
/// Keeps a worker's `WsRegistry` (used purely for cross-connection
/// broadcast, see `WsRegistry`'s own doc comment) in step with which
/// connections are actually WebSocket connections right now --
/// registering newly-upgraded ones and dropping closed ones. Run from
/// the same periodic sweep as ping/idle timeout checks rather than at
/// the exact moment a connection upgrades or closes, trading a small,
/// bounded registration delay for not needing to thread the registry
/// through every code path that can create or close a connection.
fn sync_ws_registry(ws_registry: &mut crate::http::ws::WsRegistry, connections: &Slab<Connection>) {
    let live_ws_ids: std::collections::HashSet<u64> = connections
        .iter()
        .filter(|(_, c)| matches!(c.protocol, ConnectionProtocol::WebSocket(_)))
        .map(|(_, c)| c.id)
        .collect();
    for id in ws_registry.ids() {
        if !live_ws_ids.contains(&id) {
            ws_registry.remove(id);
        }
    }
    for &id in &live_ws_ids {
        if !ws_registry.contains(id) {
            ws_registry.add(id);
        }
    }
}

/// Drains a worker's WS broadcast queue and writes the resulting
/// bytes to every currently-open WebSocket connection's write buffer,
/// flushing each one immediately -- called when `ws_registry_key`
/// reports readiness (see `WsRegistry::new`'s doc comment on its
/// waker).
fn dispatch_ws_broadcast(ws_registry: &mut crate::http::ws::WsRegistry, connections: &mut Slab<Connection>) {
    let framed = ws_registry.dispatch_broadcast();
    if framed.is_empty() {
        return;
    }
    for (_, conn) in connections.iter_mut() {
        if let ConnectionProtocol::WebSocket(ws) = &mut conn.protocol {
            ws.write_buf.push(&framed);
        }
    }
    let ws_idxs: Vec<usize> = connections
        .iter()
        .filter(|(_, c)| matches!(c.protocol, ConnectionProtocol::WebSocket(_)))
        .map(|(idx, _)| idx)
        .collect();
    for idx in ws_idxs {
        let _ = flush_transport(connections, idx);
    }
}

fn ping_sweep_ws_connections(worker: &EventLoopWorker, poller: &mut MioPoller, connections: &mut Slab<Connection>) {
    if worker.ws_settings.ping_interval.is_zero() {
        return;
    }
    let now = Instant::now();
    let idxs: Vec<usize> = connections
        .iter()
        .filter(|(_, c)| matches!(c.protocol, ConnectionProtocol::WebSocket(_)))
        .map(|(idx, _)| idx)
        .collect();

    let mut to_close = Vec::new();
    for idx in idxs {
        let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else {
            continue;
        };
        match ws.last_ping_sent {
            Some(sent_at) => {
                if now.duration_since(sent_at) >= worker.ws_settings.ping_timeout {
                    ws.ping_misses += 1;
                    if ws.ping_misses >= worker.ws_settings.max_ping_misses.max(1) {
                        to_close.push(idx);
                        continue;
                    }
                    let ping_bytes = ws.inner.ping(&[]);
                    ws.write_buf.push(&ping_bytes);
                    ws.last_ping_sent = Some(now);
                }
            }
            None => {
                if now.duration_since(ws.last_pong_at) >= worker.ws_settings.ping_interval {
                    let ping_bytes = ws.inner.ping(&[]);
                    ws.write_buf.push(&ping_bytes);
                    ws.last_ping_sent = Some(now);
                }
            }
        }
        let _ = flush_transport(connections, idx);
    }

    for idx in to_close {
        close_connection(worker, poller, connections, idx);
    }
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
            // An H2 connection has its own idle ceiling
            // (`RoutaH2Config::keepalive_timeout_ms`) rather than
            // sharing H1's `keepalive_timeout_ms` -- a multiplexed
            // connection with streams in flight is a different notion
            // of "idle" than a plain H1 keep-alive connection between
            // requests.
            let keepalive_timeout = match &conn.protocol {
                ConnectionProtocol::Http2(_) => worker.h2_settings.keepalive_timeout,
                // WsConfig::idle_timeout_ms = 0 (the default) means "no
                // WS-specific ceiling" -- such a connection still falls
                // back to the ordinary H1 keepalive_timeout_ms, same as
                // before this field existed.
                ConnectionProtocol::WebSocket(_) => worker.ws_settings.idle_timeout.unwrap_or(worker.keepalive_timeout),
                _ => worker.keepalive_timeout,
            };
            let idle_too_long = now.duration_since(conn.last_active_at) > keepalive_timeout;
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

/// Resets any H2 stream that's been open longer than
/// `RoutaH2Config::stream_timeout_ms` without completing -- see
/// `http::h2::stream::Connection::reap_stale_streams`. Unlike a whole
/// connection's idle timeout (`reap_idle_connections`), this can fire
/// on an otherwise-active, healthy connection: a stuck stream shouldn't
/// need its whole multiplexed connection to go idle before it's
/// cleaned up.
fn reap_stale_h2_streams(connections: &mut Slab<Connection>, stream_timeout: Duration) {
    if stream_timeout.is_zero() {
        return;
    }
    let idxs: Vec<usize> = connections
        .iter()
        .filter(|(_, c)| matches!(c.protocol, ConnectionProtocol::Http2(_)))
        .map(|(idx, _)| idx)
        .collect();
    for idx in idxs {
        let ConnectionProtocol::Http2(h2) = &mut connections[idx].protocol else {
            continue;
        };
        let rst_bytes = h2.inner.reap_stale_streams(stream_timeout);
        if !rst_bytes.is_empty() {
            h2.write_buf.push(&rst_bytes);
            let _ = flush_transport(connections, idx);
        }
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
    fn early_hints_103_precedes_the_real_response_over_http1() {
        let config = RoutaConfig::default();
        let mut server = RoutaServer::from_config(config).unwrap();
        let mut router = crate::http::router::Router::new();
        router.add(
            "/hints",
            &[crate::http::request::HttpMethod::Get],
            |_req, _params| {
                let mut resp = crate::http::response::HttpResponse::new(200, "OK");
                resp.add_early_hint_link("</style.css>; rel=preload; as=style");
                resp.set_body(b"done".to_vec());
                resp
            },
        );
        let router = Arc::new(router);
        server.router = Arc::clone(&router);
        server.middleware_chain = Arc::new(
            crate::http::middleware::ChainBuilder::new().build(move |req| crate::core::server::dispatch(&router, req)),
        );
        let server = Arc::new(server);
        let port = free_port();
        let _pool = run(server, port, 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("could not connect to test server: {e}"),
            }
        };
        stream.write_all(b"GET /hints HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();

        let mut buf = Vec::new();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);

        let hints_pos = text.find("103 Early Hints").expect("expected a 103 Early Hints status line");
        let ok_pos = text.find("200 OK").expect("expected the real 200 response to follow");
        assert!(hints_pos < ok_pos, "103 must arrive before the real response");
        assert!(text.contains("Link: </style.css>; rel=preload; as=style"));
        assert!(text.ends_with("done"));
    }

    #[test]
    fn h2c_upgrade_switches_a_plaintext_connection_to_http2() {
        let mut config = RoutaConfig::default();
        config.h2.h2c_upgrade_enabled = true;
        let port = free_port();
        let _pool = start_test_server(config, port);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("could not connect to test server: {e}"),
            }
        };

        let settings_header = "AAAAAA";
        let request = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: {settings_header}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();

        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut status_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut status_line).unwrap();
        assert!(status_line.starts_with("HTTP/1.1 101"), "expected 101 Switching Protocols, got: {status_line}");
        loop {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }

        let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        stream.write_all(&preface).unwrap();

        let mut response_header = [0u8; 9];
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        std::io::Read::read_exact(&mut reader, &mut response_header).unwrap();
        let frame_type = response_header[3];
        assert_eq!(frame_type, 0x4, "expected a SETTINGS frame as the first bytes back over the upgraded connection");
    }

    /// Reads exactly one H2 frame (header + payload) off `reader` --
    /// the test-side equivalent of `frame::parse_frame`, but reading
    /// from a live socket a byte at a time instead of an
    /// already-buffered slice.
    fn read_one_h2_frame(reader: &mut impl std::io::BufRead) -> (u8, u8, Vec<u8>) {
        let mut header = [0u8; 9];
        std::io::Read::read_exact(reader, &mut header).unwrap();
        let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let frame_type = header[3];
        let flags = header[4];
        let mut payload = vec![0u8; len];
        std::io::Read::read_exact(reader, &mut payload).unwrap();
        (frame_type, flags, payload)
    }

    /// Reads frames until a HEADERS frame (type `0x1`) arrives,
    /// skipping anything else (a SETTINGS ACK for the client's own
    /// preface SETTINGS frame, WINDOW_UPDATEs, etc.) -- returns the
    /// decoded `:status` value and whether END_STREAM was set.
    fn read_h2_status_headers(reader: &mut impl std::io::BufRead, decoder: &mut crate::http::h2::hpack::HpackContext) -> (String, bool) {
        let (status, end_stream, _fields) = read_h2_response_headers(reader, decoder);
        (status, end_stream)
    }

    /// Same as `read_h2_status_headers`, but also returns every
    /// decoded header field -- for callers that need to inspect
    /// something beyond `:status` (e.g. a negotiated
    /// `sec-websocket-extensions` value).
    fn read_h2_response_headers(
        reader: &mut impl std::io::BufRead,
        decoder: &mut crate::http::h2::hpack::HpackContext,
    ) -> (String, bool, Vec<crate::http::h2::hpack::HeaderField>) {
        loop {
            let (frame_type, flags, payload) = read_one_h2_frame(reader);
            if frame_type != 0x1 {
                continue;
            }
            let fields = decoder.decode(&payload).unwrap();
            let status = fields.iter().find(|h| h.name == ":status").unwrap().value.clone();
            return (status, flags & 0x1 != 0, fields);
        }
    }

    /// Reads frames until a DATA frame (type `0x0`) arrives, skipping
    /// anything else -- returns its payload.
    fn read_h2_data_payload(reader: &mut impl std::io::BufRead) -> Vec<u8> {
        loop {
            let (frame_type, _flags, payload) = read_one_h2_frame(reader);
            if frame_type != 0x0 {
                continue;
            }
            return payload;
        }
    }

    /// A minimal masked client-to-server WebSocket TEXT frame (RFC
    /// 6455 5.2) carrying `text` -- small-payload-only (no extended
    /// length), which is all this test needs.
    fn build_masked_ws_text_frame(text: &str) -> Vec<u8> {
        let payload = text.as_bytes();
        assert!(payload.len() < 126);
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let masked: Vec<u8> = payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
        let mut frame = vec![0x81u8, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend_from_slice(&masked);
        frame
    }

    /// Parses a minimal unmasked server-to-client WebSocket frame (RFC
    /// 6455 5.2: a server must never mask its own frames) -- returns
    /// its opcode and payload. Small-payload-only, same limitation as
    /// `build_masked_ws_text_frame`.
    fn parse_unmasked_ws_frame(data: &[u8]) -> (u8, Vec<u8>) {
        let opcode = data[0] & 0x0f;
        assert_eq!(data[1] & 0x80, 0, "a server must never mask its own WebSocket frames");
        let len = (data[1] & 0x7f) as usize;
        (opcode, data[2..2 + len].to_vec())
    }

    #[test]
    fn extended_connect_websocket_tunnel_end_to_end_over_real_tcp() {
        let mut config = RoutaConfig::default();
        config.h2.h2c_upgrade_enabled = true;
        config.ws.enabled = true;
        let mut server = RoutaServer::from_config(config).unwrap();
        let mut router = crate::http::router::Router::new();
        router.add_websocket_route("/ws", |msg| match msg {
            crate::http::ws::WsMessage::Text(text) if text == "ping" => Some(crate::http::ws::WsMessage::Text("pong".to_string())),
            _ => None,
        });
        server.router = Arc::new(router);
        let server = Arc::new(server);
        let port = free_port();
        let _pool = run(server, port, 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("could not connect to test server: {e}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        // h2c upgrade dance -- same as
        // `h2c_upgrade_switches_a_plaintext_connection_to_http2`.
        // An empty HTTP2-Settings value base64url-decodes to zero
        // bytes -- a validly-shaped (empty) SETTINGS payload. Unlike
        // the placeholder "AAAAAA" used elsewhere in this test module,
        // which decodes to 4 bytes (not a multiple of 6) and silently
        // poisons the connection's error state via
        // `apply_upgrade_settings`, this test continues the exchange
        // far enough afterward that such poisoning would be observed.
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n";
        stream.write_all(request.as_bytes()).unwrap();

        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut status_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut status_line).unwrap();
        assert!(status_line.starts_with("HTTP/1.1 101"));
        loop {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }

        // `assume_preface_received` (used by the h2c-upgrade path this
        // test drives through) means the server does not expect the
        // client to resend the literal "PRI * HTTP/2.0..." connection
        // preface on this connection -- the HTTP/1.1 request that
        // upgraded it already served that purpose. Only the client's
        // own (empty) SETTINGS frame follows.
        stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();

        // The server's initial SETTINGS frame must advertise
        // SETTINGS_ENABLE_CONNECT_PROTOCOL now that both h2 and ws are
        // enabled.
        let (frame_type, _flags, settings_payload) = read_one_h2_frame(&mut reader);
        assert_eq!(frame_type, 0x4, "expected a SETTINGS frame");
        let has_connect_setting = settings_payload.chunks_exact(6).any(|c| u16::from_be_bytes([c[0], c[1]]) == 0x8);
        assert!(has_connect_setting, "server must advertise SETTINGS_ENABLE_CONNECT_PROTOCOL");

        // A real Extended CONNECT request for the registered WS route.
        let mut client_encoder = crate::http::h2::hpack::HpackContext::new(4096);
        let hf = |name: &str, value: &str| crate::http::h2::hpack::HeaderField {
            name: name.to_string(),
            value: value.to_string(),
        };
        let header_block = client_encoder.encode(&[
            hf(":method", "CONNECT"),
            hf(":protocol", "websocket"),
            hf(":scheme", "http"),
            hf(":path", "/ws"),
            hf(":authority", "localhost"),
        ]);
        let mut headers_frame = Vec::new();
        crate::http::h2::frame::write_headers(&mut headers_frame, 1, &header_block, false, true);
        stream.write_all(&headers_frame).unwrap();

        let mut server_decoder = crate::http::h2::hpack::HpackContext::new(4096);
        let (status, end_stream) = read_h2_status_headers(&mut reader, &mut server_decoder);
        assert_eq!(status, "200");
        assert!(!end_stream, "an accepted WS tunnel's 200 response must not end the stream");

        // A real WebSocket TEXT frame, sent as H2 DATA on the tunnel.
        let ws_frame = build_masked_ws_text_frame("ping");
        let mut data_frame = Vec::new();
        crate::http::h2::frame::write_data(&mut data_frame, 1, &ws_frame, false);
        stream.write_all(&data_frame).unwrap();

        // The registered handler's reply ("pong"), framed by the real
        // `WsConnection` and carried back as H2 DATA on the same
        // stream.
        let reply_payload = read_h2_data_payload(&mut reader);
        let (opcode, payload) = parse_unmasked_ws_frame(&reply_payload);
        assert_eq!(opcode, 0x1, "expected a text frame");
        assert_eq!(payload, b"pong");
    }

    #[test]
    fn extended_connect_negotiates_permessage_deflate_from_the_request_header() {
        let mut config = RoutaConfig::default();
        config.h2.h2c_upgrade_enabled = true;
        config.ws.enabled = true;
        config.ws.permessage_deflate = true;
        let mut server = RoutaServer::from_config(config).unwrap();
        let mut router = crate::http::router::Router::new();
        router.add_websocket_route("/ws", |_msg| None);
        server.router = Arc::new(router);
        let server = Arc::new(server);
        let port = free_port();
        let _pool = run(server, port, 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("could not connect to test server: {e}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n";
        stream.write_all(request.as_bytes()).unwrap();
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut status_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut status_line).unwrap();
        assert!(status_line.starts_with("HTTP/1.1 101"));
        loop {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }
        stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
        let (frame_type, _flags, _settings_payload) = read_one_h2_frame(&mut reader);
        assert_eq!(frame_type, 0x4, "expected a SETTINGS frame");

        let mut client_encoder = crate::http::h2::hpack::HpackContext::new(4096);
        let hf = |name: &str, value: &str| crate::http::h2::hpack::HeaderField {
            name: name.to_string(),
            value: value.to_string(),
        };
        let header_block = client_encoder.encode(&[
            hf(":method", "CONNECT"),
            hf(":protocol", "websocket"),
            hf(":scheme", "http"),
            hf(":path", "/ws"),
            hf(":authority", "localhost"),
            hf("sec-websocket-extensions", "permessage-deflate; client_no_context_takeover"),
        ]);
        let mut headers_frame = Vec::new();
        crate::http::h2::frame::write_headers(&mut headers_frame, 1, &header_block, false, true);
        stream.write_all(&headers_frame).unwrap();

        let mut server_decoder = crate::http::h2::hpack::HpackContext::new(4096);
        let (status, end_stream, fields) = read_h2_response_headers(&mut reader, &mut server_decoder);
        assert_eq!(status, "200");
        assert!(!end_stream);
        let ext = fields
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("sec-websocket-extensions"))
            .expect("server should have accepted permessage-deflate and echoed the extension header");
        assert!(ext.value.contains("permessage-deflate"));
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

    // ─── WsConfig wiring ──────────────────────────────────────────────

    /// Builds a real accepted TCP connection pair (registered with
    /// `poller`), wrapped as a `Connection` already in
    /// `ConnectionProtocol::WebSocket` state -- lets these tests drive
    /// the periodic sweeps directly without needing a full router/
    /// middleware-chain WS upgrade handshake, which nothing in this
    /// codebase's config (only a caller embedding routa as a library
    /// registers WS routes) exercises end-to-end today.
    fn insert_test_ws_connection(poller: &mut MioPoller, connections: &mut Slab<Connection>, ws: crate::core::conn::WsConnection) -> (usize, StdTcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = StdTcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        server_stream.set_nonblocking(true).unwrap();
        let mut mio_stream = mio::net::TcpStream::from_std(server_stream);

        let entry = connections.vacant_entry();
        let key = PollKey::from_slab_index(entry.key());
        poller.register_with_key(&mut mio_stream, key, Interests::READABLE_WRITABLE).unwrap();

        let mut conn = Connection::new(entry.key() as u64, key, Transport::Plain(mio_stream), client.local_addr().unwrap());
        conn.protocol = ConnectionProtocol::WebSocket(ws);
        let idx = entry.key();
        entry.insert(conn);
        (idx, client)
    }

    #[test]
    fn real_http1_upgrade_handshake_reaches_the_client_over_a_real_tcp_socket() {
        // Exercises the actual HTTP/1.1 Upgrade path end to end (a
        // route handler returning 101, drive_http1 switching the
        // connection's protocol) rather than
        // insert_test_ws_connection's shortcut of constructing an
        // already-WebSocket connection directly -- the two exercise
        // different code, and only this one proves the 101 response
        // itself actually reaches the client before the connection's
        // protocol state is replaced.
        let mut config = RoutaConfig::default();
        config.ws.enabled = true;
        let mut server = RoutaServer::from_config(config).unwrap();
        let mut router = crate::http::router::Router::new();
        router.add("/ws", &[crate::http::request::HttpMethod::Get], |req, _params| {
            crate::http::ws::build_handshake_response(req, None)
        });
        router.add_websocket_route("/ws", |msg| Some(msg.clone()));
        let router = Arc::new(router);
        server.router = Arc::clone(&router);
        server.middleware_chain = Arc::new(crate::http::middleware::ChainBuilder::new().build(move |req| {
            match router.dispatch(req) {
                crate::http::router::Dispatch::Matched { handler, params } => handler(req, &params),
                crate::http::router::Dispatch::MethodNotAllowed { .. } => crate::http::response::HttpResponse::new(405, "Method Not Allowed"),
                crate::http::router::Dispatch::NotFound => crate::http::response::HttpResponse::new(404, "Not Found"),
            }
        }));
        let server = Arc::new(server);
        let port = free_port();
        let _pool = run(server, port, 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("could not connect to test server: {e}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let request = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        stream.write_all(request.as_bytes()).unwrap();

        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).expect("the 101 handshake response must reach the client");
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.starts_with("HTTP/1.1 101"), "expected a 101 response, got: {response}");
        assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    }

    #[test]
    fn ws_message_handler_registered_on_router_receives_and_replies_to_a_real_message() {
        let config = RoutaConfig::default();
        let mut server = RoutaServer::from_config(config).unwrap();
        // The router built inside from_config is already shared with
        // the middleware chain's dispatch closure by this point, so
        // it can't be mutated through server.router directly (its
        // strong count is already > 1) -- build a fresh Router with
        // the same WS route instead and swap it in before anything
        // else gets a chance to clone the Arc.
        let mut router = crate::http::router::Router::new();
        router.add_websocket_route("/echo", |msg| match msg {
            crate::http::ws::WsMessage::Text(text) => Some(crate::http::ws::WsMessage::Text(format!("echo:{text}"))),
            crate::http::ws::WsMessage::Binary(data) => Some(crate::http::ws::WsMessage::Binary(data.clone())),
        });
        server.router = Arc::new(router);
        let server = Arc::new(server);
        let worker = EventLoopWorker::new(free_port(), Arc::clone(&server));

        let mut poller = MioPoller::new(16).unwrap();
        let mut connections: Slab<Connection> = Slab::new();
        let mut ws = crate::core::conn::WsConnection::with_settings(None, &worker.ws_settings);
        ws.upgrade_path = "/echo".to_string();
        let (idx, mut client) = insert_test_ws_connection(&mut poller, &mut connections, ws);

        // A masked text frame carrying "hi" -- client-to-server frames
        // must be masked per RFC 6455 5.1.
        let mut frame = vec![0x81u8, 0x82, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(b"hi");
        client.write_all(&frame).unwrap();

        drive_websocket(&worker, &mut connections, idx).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut response = [0u8; 32];
        let n = client.read(&mut response).unwrap();
        let payload_len = (response[1] & 0x7f) as usize;
        let payload = &response[2..2 + payload_len];
        assert_eq!(payload, b"echo:hi", "handler's reply should have reached the real client socket, got {} bytes", n);
    }

    #[test]
    fn broadcast_message_reaches_a_real_registered_ws_connection() {
        let mut config = RoutaConfig::default();
        config.ws.enabled = true;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);

        let mut poller = MioPoller::new(16).unwrap();
        let ws_registry_key = PollKey::from_slab_index(usize::MAX - 1);
        let mut ws_registry = crate::http::ws::WsRegistry::new(poller.registry(), ws_registry_key).unwrap();

        let mut connections: Slab<Connection> = Slab::new();
        let ws = crate::core::conn::WsConnection::with_settings(None, &worker.ws_settings);
        let (idx, mut client) = insert_test_ws_connection(&mut poller, &mut connections, ws);

        sync_ws_registry(&mut ws_registry, &connections);
        assert_eq!(ws_registry.len(), 1, "the one open WS connection should have been registered");

        let sender = ws_registry.sender();
        let msg = crate::http::ws::BroadcastMessage {
            data: b"hello everyone".to_vec(),
            opcode: crate::http::ws::Opcode::Text,
        };
        sender.send(msg).unwrap();

        dispatch_ws_broadcast(&mut ws_registry, &mut connections);
        let _ = idx;

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        assert!(n > 0, "the broadcast message should have reached the real client socket");
        // A text frame's payload starts after the 2-byte header for a
        // short (< 126 byte) unmasked server-to-client frame.
        assert_eq!(&buf[2..n], b"hello everyone");
    }

    #[test]
    fn ping_sweep_sends_ping_after_interval() {
        let mut config = RoutaConfig::default();
        config.ws.ping_interval_ms = 50;
        config.ws.ping_timeout_ms = 5_000;
        config.ws.max_ping_misses = 3;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);

        let mut poller = MioPoller::new(16).unwrap();
        let mut connections: Slab<Connection> = Slab::new();
        let ws = crate::core::conn::WsConnection::with_settings(None, &worker.ws_settings);
        let (idx, mut client) = insert_test_ws_connection(&mut poller, &mut connections, ws);

        // last_pong_at defaults to "now" (connection just created), so
        // nothing should be due yet.
        ping_sweep_ws_connections(&worker, &mut poller, &mut connections);
        let ConnectionProtocol::WebSocket(ws) = &connections[idx].protocol else { unreachable!() };
        assert!(ws.last_ping_sent.is_none());

        // Backdate last_pong_at past ping_interval and sweep again.
        let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else { unreachable!() };
        ws.last_pong_at = Instant::now() - Duration::from_millis(100);
        ping_sweep_ws_connections(&worker, &mut poller, &mut connections);

        assert!(connections.contains(idx), "should not be closed yet, just pinged");
        let ConnectionProtocol::WebSocket(ws) = &connections[idx].protocol else { unreachable!() };
        assert!(ws.last_ping_sent.is_some());

        // The PING frame should have actually reached the client socket.
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0] & 0x0f, 0x9); // opcode 0x9 = PING
    }

    #[test]
    fn ping_sweep_closes_connection_after_max_misses() {
        let mut config = RoutaConfig::default();
        config.ws.ping_interval_ms = 10;
        config.ws.ping_timeout_ms = 10;
        config.ws.max_ping_misses = 2;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);

        let mut poller = MioPoller::new(16).unwrap();
        let mut connections: Slab<Connection> = Slab::new();
        let ws = crate::core::conn::WsConnection::with_settings(None, &worker.ws_settings);
        let (idx, _client) = insert_test_ws_connection(&mut poller, &mut connections, ws);

        {
            let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else { unreachable!() };
            ws.last_pong_at = Instant::now() - Duration::from_secs(1);
        }

        // Each sweep call either sends a ping or, once ping_timeout has
        // elapsed since the last one with no pong, counts a miss --
        // repeated sweeps (with a short sleep to cross ping_timeout)
        // simulate the periodic sweep firing on an unresponsive peer.
        for _ in 0..10 {
            if !connections.contains(idx) {
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
            ping_sweep_ws_connections(&worker, &mut poller, &mut connections);
        }

        assert!(!connections.contains(idx), "connection should be closed after exceeding max_ping_misses");
    }

    #[test]
    fn write_queue_max_backpressure_closes_slow_consumer() {
        let mut config = RoutaConfig::default();
        config.ws.write_buf_size = 16;
        config.ws.write_queue_max = 1; // effective cap: 16 bytes
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);
        assert_eq!(worker.ws_settings.write_queue_max_bytes, 16);

        let mut poller = MioPoller::new(16).unwrap();
        let mut connections: Slab<Connection> = Slab::new();
        let ws = crate::core::conn::WsConnection::with_settings(None, &worker.ws_settings);
        let (idx, _client) = insert_test_ws_connection(&mut poller, &mut connections, ws);

        // Simulate a large backlog of unflushed outbound bytes (as if
        // the peer stopped reading) directly, then drive one more pass
        // through drive_websocket's backpressure check via a manual
        // push + the same threshold comparison it performs.
        {
            let ConnectionProtocol::WebSocket(ws) = &mut connections[idx].protocol else { unreachable!() };
            ws.write_buf.push(&[0u8; 100]);
            assert!(ws.write_buf.as_slice().len() as u64 > ws.write_queue_max_bytes);
        }
        let _ = drive_websocket(&worker, &mut connections, idx);
        assert!(connections[idx].closing, "backpressure should mark the connection for closing");
    }

    #[test]
    fn ws_disabled_rejects_upgrade_with_503() {
        let mut config = RoutaConfig::default();
        config.ws.enabled = false;
        // No actual WS route is registered (see insert_test_ws_connection's
        // doc comment on why), so this only exercises the config
        // plumbing (worker.ws_enabled reads false), not the full
        // request-to-101 path -- that gate is proven directly here
        // instead of through a real socket round trip.
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);
        assert!(!worker.ws_enabled);
    }

    #[test]
    fn ws_max_connections_is_read_from_config() {
        let mut config = RoutaConfig::default();
        config.ws.max_connections = 3;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);
        assert_eq!(worker.ws_max_connections, 3);
    }

    #[test]
    fn ws_idle_timeout_overrides_generic_keepalive_for_ws_connections() {
        let mut config = RoutaConfig::default();
        config.keepalive_timeout_ms = 60_000;
        config.ws.idle_timeout_ms = 50;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);

        let mut poller = MioPoller::new(16).unwrap();
        let mut connections: Slab<Connection> = Slab::new();
        let ws = crate::core::conn::WsConnection::with_settings(None, &worker.ws_settings);
        let (idx, _client) = insert_test_ws_connection(&mut poller, &mut connections, ws);
        connections[idx].last_active_at = Instant::now() - Duration::from_millis(200);

        reap_idle_connections(&worker, &mut poller, &mut connections);
        assert!(!connections.contains(idx), "WS-specific idle_timeout_ms should have closed this connection despite the much larger generic keepalive_timeout_ms");
    }

    // ─── General RoutaConfig fields ────────────────────────────────────

    #[test]
    fn tls_handshake_duration_is_observed_on_a_real_handshake() {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use rustls::pki_types::CertificateDer;

        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        let dir = std::env::temp_dir().join(format!(
            "routa_event_loop_tls_metric_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();

        let mut config = RoutaConfig::default();
        config.tls_enabled = true;
        config.tls_cert = cert_path.to_str().unwrap().to_string();
        config.tls_key = key_path.to_str().unwrap().to_string();
        let port = free_port();
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let _pool = run(Arc::clone(&server), port, 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut client_sock = loop {
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
        client_sock.set_nonblocking(true).unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).unwrap();
        let mut client_conn =
            crate::net::tls::TlsConnection::new_client_with_roots("localhost", vec![b"http/1.1".to_vec()], root_store).unwrap();

        let handshake_deadline = Instant::now() + Duration::from_secs(5);
        while client_conn.is_handshaking() {
            let _ = client_conn.advance_io(&mut client_sock);
            if Instant::now() > handshake_deadline {
                panic!("client TLS handshake never completed");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Give the server side a moment to also observe completion and
        // record the metric.
        std::thread::sleep(Duration::from_millis(100));

        let text = String::from_utf8(server.metrics.prometheus_text()).unwrap();
        assert!(text.contains("routa_tls_handshake_duration_seconds"), "expected the histogram to be present:\n{text}");
        assert!(
            text.contains("routa_tls_handshake_duration_seconds_count{tls_version=\"TLSv1.3\"} 1"),
            "expected exactly one TLSv1.3 handshake observed:\n{text}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backlog_socket_buffers_and_shutdown_timeout_are_read_from_config() {
        let mut config = RoutaConfig::default();
        config.backlog = 512;
        config.socket_recv_buf_size = 65_536;
        config.socket_send_buf_size = 32_768;
        config.shutdown_timeout_ms = 7_000;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);

        assert_eq!(worker.backlog, 512);
        assert_eq!(worker.socket_recv_buf_size, 65_536);
        assert_eq!(worker.socket_send_buf_size, 32_768);
        assert_eq!(worker.shutdown_timeout, Duration::from_millis(7_000));
    }

    #[test]
    fn max_connections_zero_means_unlimited() {
        let config = RoutaConfig::default(); // max_connections default is nonzero -- test the actual 0 case
        let mut config = config;
        config.max_connections = 0;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);
        assert_eq!(worker.max_connections, 0);
    }

    /// A real proxied request through a sticky-session-enabled pool,
    /// driven through mio_upstream's event-driven path -- proves the
    /// response actually carries a Set-Cookie identifying the node it
    /// was routed to, mirroring uring_backend's own
    /// proxy_sets_a_sticky_cookie_on_first_response.
    #[test]
    fn proxy_sets_a_sticky_cookie_on_first_response() {
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind real upstream listener");
        let upstream_port = upstream_listener.local_addr().expect("upstream addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let body = b"sticky!";
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        let mut config = RoutaConfig::default();
        let port = free_port();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            sticky_session_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: false }],
            ..Default::default()
        });
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(port, Arc::clone(&server));
        let shutdown = ShutdownSignal::new();
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::spawn(move || worker.run(0, &shutdown_for_thread));

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
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("set read timeout");

        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write proxied request");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200, got: {response_text:?}");
        assert!(response_text.contains("Set-Cookie: routa_sticky="), "expected a sticky Set-Cookie header, got: {response_text:?}");
        assert!(response_text.ends_with("sticky!"), "expected the upstream's body, got: {response_text:?}");

        shutdown.signal();
        handle.join().unwrap();
    }

    #[test]
    fn shutdown_timeout_keeps_in_flight_connection_alive_briefly_after_signal() {
        let mut config = RoutaConfig::default();
        config.shutdown_timeout_ms = 300;
        let port = free_port();
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(port, Arc::clone(&server));
        let shutdown = ShutdownSignal::new();
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::spawn(move || worker.run(0, &shutdown_for_thread));

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
        // Leave the connection open (no request sent) and signal
        // shutdown -- with a 300ms shutdown_timeout_ms, the worker's
        // run() loop must still be alive shortly after, and only exit
        // once that grace period elapses (this open, idle connection
        // never empties `connections` on its own).
        shutdown.signal();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!handle.is_finished(), "worker should still be draining well within shutdown_timeout_ms");

        std::thread::sleep(Duration::from_millis(400));
        assert!(handle.is_finished(), "worker should have exited once shutdown_timeout_ms elapsed");
        drop(stream);
        handle.join().unwrap();
    }

    #[test]
    fn ws_buffer_sizes_are_read_from_config() {
        let mut config = RoutaConfig::default();
        config.ws.read_buf_size = 4096;
        config.ws.write_buf_size = 8192;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);
        assert_eq!(worker.ws_settings.read_buf_size, 4096);
        assert_eq!(worker.ws_settings.write_buf_size, 8192);
    }

    #[test]
    fn cpu_affinity_settings_are_read_from_config() {
        let mut config = RoutaConfig::default();
        config.cpu_affinity_enabled = true;
        config.cpu_affinity_start_core = 2;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);
        assert!(worker.cpu_affinity_enabled);
        assert_eq!(worker.cpu_affinity_start_core, 2);
    }

    #[test]
    fn memory_limits_are_read_from_config() {
        let mut config = RoutaConfig::default();
        config.memory_soft_limit_mb = 512;
        config.memory_hard_limit_mb = 1024;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let worker = EventLoopWorker::new(free_port(), server);
        assert_eq!(worker.memory_soft_limit_mb, 512);
        assert_eq!(worker.memory_hard_limit_mb, 1024);
    }

    #[test]
    fn memory_over_soft_limit_flag_blocks_new_connections() {
        // Directly exercises accept_all's gate on the shared flag, since
        // actually driving RSS past a configured threshold in a unit
        // test isn't practical/deterministic -- the periodic sampling
        // loop that sets this flag (core::event_loop::EventLoopWorker::run)
        // is covered by memory_limits_are_read_from_config for the
        // config plumbing into that loop's threshold comparison.
        let mut config = RoutaConfig::default();
        config.memory_soft_limit_mb = 1;
        let port = free_port();
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        server.memory_over_soft_limit.store(true, std::sync::atomic::Ordering::Relaxed);
        let _pool = run(server.clone(), port, 1);

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
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        assert!(buf.is_empty(), "connection should be dropped immediately while over the soft memory limit, got {} bytes", buf.len());
    }

    #[test]
    fn max_connections_limit_rejects_connections_past_capacity() {
        let mut config = RoutaConfig::default();
        config.max_connections = 1;
        let port = free_port();
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).unwrap());
        let _pool = run(server.clone(), port, 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        let _first = loop {
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
        // Give the worker a moment to actually register the first
        // connection (accept_all runs on the poller thread, not
        // synchronously with connect()) before the metric it checks
        // reflects it.
        let metric_deadline = Instant::now() + Duration::from_secs(2);
        while server.metrics.connection.connections_active.get() < 1 {
            if Instant::now() > metric_deadline {
                panic!("first connection never became active");
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // A second connection should be accepted at the TCP level (the
        // listener's backlog doesn't know about max_connections) but
        // immediately dropped by the worker without ever being served.
        let mut second = StdTcpStream::connect(("127.0.0.1", port)).unwrap();
        second.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        second.write_all(request.as_bytes()).unwrap();
        let mut buf = Vec::new();
        let _ = second.read_to_end(&mut buf);
        assert!(buf.is_empty(), "over-capacity connection should be dropped without any response, got {} bytes", buf.len());
    }
}
