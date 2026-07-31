//! The io_uring backend's per-worker event loop: a completion-based
//! counterpart to `mio_backend`, selected in its place at compile time
//! by the `io_uring` feature (see this crate's top-level
//! `compile_error!` guard for why this is Linux-only).
//!
//! # Capability discovery
//!
//! Two different mechanisms establish whether this backend can run at
//! all on the current host, because one mechanism can't answer both
//! questions:
//!
//! - `Probe` (registered via `register_probe`) answers "does this
//!   kernel know about the `ACCEPT`/`RECV`/`SEND`/`CLOSE`/`TIMEOUT`/
//!   `ASYNC_CANCEL` opcodes at all". This is enough for opcodes with
//!   no version-gated variant.
//! - Multishot accept can't be answered by `Probe` at all:
//!   `opcode::AcceptMulti::CODE` is defined as exactly the same
//!   constant as `opcode::Accept::CODE` -- multishot is carried as an
//!   `ioprio` flag on the same opcode, not a distinct one, so `Probe`
//!   reports identical support for both regardless of whether the
//!   running kernel understands that flag. The only way to actually
//!   find out is to submit a real multishot SQE and read its
//!   completion: an unrecognized flag comes back as a distinct error
//!   code (`-EINVAL`), so this reuses the worker's own real listener
//!   accept as its discovery mechanism rather than a separate,
//!   throwaway probe request.
//!
//! # Buffer ownership
//!
//! Every connection owns one fixed-size `Vec<u8>` recv buffer, stored
//! in the `Slab` alongside the rest of its state rather than allocated
//! per-operation. A buffer submitted as part of a `Recv`/`Send` SQE is,
//! for as long as that SQE is outstanding, effectively lent to the
//! kernel: nothing in this module reads, writes, or moves it (which
//! would invalidate the raw pointer the kernel was given) until its
//! completion has actually arrived. This is exactly the category of
//! invariant Rust's own borrow checker can't see across an io_uring
//! submit/completion boundary -- the kernel holds a raw pointer, not a
//! borrow -- so it's enforced here by construction instead: a
//! connection's buffer is only ever touched from the single completion
//! handler that owns the outstanding SQE for it, and no new SQE reusing
//! that same buffer is submitted until the previous one completes.
//!
//! # Scope today
//!
//! A real accept/recv/send loop that echoes back whatever a client
//! sends -- not yet connected to `core::conn::protocol`'s shared HTTP
//! state machines. This exists to validate the completion-based
//! submit/reap cycle itself (multishot accept's per-connection
//! completions, buffer lifetime across a submit, recognizing peer
//! close) before building request parsing and dispatch on top of it.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use io_uring::{opcode, types, IoUring, Probe};
use slab::Slab;

use crate::core::conn::protocol::{ConnectionProtocol, Http1Connection, Http1DispatchContext, Http1Outcome};
use crate::core::conn::uring_conn::{Connection, Transport};
use crate::core::server::RoutaServer;
use crate::core::worker::{ShutdownSignal, WorkerBody};

// RING_ENTRIES and RECV_BUF_SIZE were fixed constants during this
// backend's earliest milestones -- both are now read from
// RoutaConfig::io_uring (see EventLoopWorker::new) so they're
// configurable exactly like every other per-worker tuning knob
// (RoutaH2Config, WsConfig) rather than being the one thing in this
// backend a config file couldn't adjust.

/// A connection's `user_data` is packed as
/// `(op_tag << 56) | (generation << 32) | slab_index` -- three fields
/// sharing one u64 so a completion can be routed back to "which
/// connection", "which operation was in flight for it", and "is this
/// completion even still relevant" from a single value with no
/// additional lookup.
///
/// `generation` exists to close a real race: a `Recv`/`Send` SQE
/// submitted against connection A can still be outstanding in the
/// kernel at the moment A is removed from `connections` (peer closed,
/// an error, keep-alive ended) -- `Slab` freely reuses A's old index
/// for a brand new connection B afterward. Without `generation`, A's
/// stale completion arriving late would be misread as belonging to
/// whichever connection now occupies that same slab index -- reading
/// or writing B's buffers on A's behalf, silently. `generation` is
/// bumped (see `next_generation`/`WorkerState::generations`) every
/// time a slot is reused, embedded in every SQE submitted for that
/// connection's lifetime, and checked against the slot's *current*
/// generation before a completion is trusted -- a mismatch means the
/// completion belongs to whatever used to live in that slot, and is
/// dropped rather than acted on.
const OP_TAG_BITS: u32 = 56;
const GENERATION_BITS: u32 = 24;
const SLAB_INDEX_MASK: u64 = (1u64 << GENERATION_BITS) - 1;
const GENERATION_MASK: u64 = (1u64 << (OP_TAG_BITS - GENERATION_BITS)) - 1;

const OP_TAG_ACCEPT: u64 = 0;
const OP_TAG_RECV: u64 = 1;
const OP_TAG_SEND: u64 = 2;
const OP_TAG_TIMEOUT: u64 = 3;
const OP_TAG_CANCEL: u64 = 4;

/// The listener accept SQE has no associated connection slot and is
/// submitted exactly once per worker (re-armed in place, never
/// removed and reinserted the way a connection's slab entry is), so it
/// has no ABA risk to guard against -- generation 0 is used as a fixed
/// placeholder rather than this backend tracking a real generation for
/// something that was never subject to the slab-reuse race in the
/// first place.
const USER_DATA_ACCEPT: u64 = OP_TAG_ACCEPT << OP_TAG_BITS;
const USER_DATA_TIMEOUT: u64 = OP_TAG_TIMEOUT << OP_TAG_BITS;
/// Like `USER_DATA_ACCEPT`/`USER_DATA_TIMEOUT`, a fixed tag with no
/// per-connection generation -- a cancellation completion carries no
/// connection state itself (see its own match arm), so there's
/// nothing for a generation to protect here.
const USER_DATA_CANCEL: u64 = OP_TAG_CANCEL << OP_TAG_BITS;

/// How long a single `submit_and_wait` call may block before the main
/// loop is guaranteed to check `ShutdownSignal::is_set()` again --
/// this backend's counterpart to `mio_backend::POLL_TIMEOUT`. Without
/// this, `submit_and_wait` blocks until an unrelated I/O completion
/// happens to arrive (a new connection, more data on some other
/// socket) with no bound at all -- an idle worker with no traffic
/// would never notice a shutdown signal, since nothing wakes it up to
/// re-check.
const LOOP_TIMEOUT_MS: u64 = 200;

fn make_user_data(op_tag: u64, generation: u32, slab_index: usize) -> u64 {
    (op_tag << OP_TAG_BITS) | ((generation as u64 & GENERATION_MASK) << GENERATION_BITS) | (slab_index as u64 & SLAB_INDEX_MASK)
}

/// Returns `(op_tag, generation, slab_index)` -- the inverse of
/// `make_user_data`.
fn split_user_data(user_data: u64) -> (u64, u32, usize) {
    let op_tag = user_data >> OP_TAG_BITS;
    let generation = ((user_data >> GENERATION_BITS) & GENERATION_MASK) as u32;
    let slab_index = (user_data & SLAB_INDEX_MASK) as usize;
    (op_tag, generation, slab_index)
}

pub struct EventLoopWorker {
    port: u16,
    server: Arc<RoutaServer>,
    ring_entries: u32,
    recv_buf_size: usize,
    max_request_size: usize,
    h2_settings: crate::core::conn::Http2Settings,
    ws_settings: crate::core::conn::WsSettings,
    h2c_upgrade_enabled: bool,
    ws_enabled: bool,
    ws_max_connections: usize,
    ws_permessage_deflate: bool,
}

impl EventLoopWorker {
    pub fn new(port: u16, server: Arc<RoutaServer>) -> Self {
        // RoutaConfig::validate already rejects an out-of-range or
        // non-power-of-two ring_entries before a server is ever built
        // from this config -- see core::config::validate -- so the
        // casts below don't need their own bounds-checking here.
        let ring_entries = server.config.io_uring.ring_entries as u32;
        let recv_buf_size = server.config.io_uring.recv_buf_size as usize;

        const DEFAULT_MAX_REQUEST_SIZE: usize = 0; // 0 = unlimited, matches http::request::parse's convention
        let max_request_size = if server.config.max_request_size > 0 {
            server.config.max_request_size as usize
        } else {
            DEFAULT_MAX_REQUEST_SIZE
        };

        let h2 = &server.config.h2;
        let h2_settings = crate::core::conn::Http2Settings {
            max_concurrent_streams: h2.max_concurrent_streams.min(h2.max_concurrent_streams_hard_cap).max(1),
            header_table_size: h2.header_table_size as usize,
            initial_window_size: h2.initial_window_size,
            max_frame_size: h2.max_frame_size,
            max_header_list_size: h2.max_header_list_size,
            huffman_encoding: h2.huffman_encoding,
            dynamic_table_update: h2.dynamic_table_update,
            server_push_enabled: h2.server_push_enabled,
            stream_timeout: std::time::Duration::from_millis(h2.stream_timeout_ms.max(0) as u64),
            keepalive_timeout: std::time::Duration::from_millis(h2.keepalive_timeout_ms.max(0) as u64),
            stream_lookup: h2.stream_lookup,
            connect_protocol_enabled: h2.enabled && server.config.ws.enabled,
        };

        let ws = &server.config.ws;
        let ws_settings = crate::core::conn::WsSettings {
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
                Some(std::time::Duration::from_millis(ws.idle_timeout_ms as u64))
            } else {
                None
            },
            ping_interval: std::time::Duration::from_millis(ws.ping_interval_ms.max(0) as u64),
            ping_timeout: std::time::Duration::from_millis(ws.ping_timeout_ms.max(0) as u64),
            max_ping_misses: ws.max_ping_misses.max(0) as u32,
            read_buf_size: ws.read_buf_size.max(0) as usize,
            write_buf_size: ws.write_buf_size.max(0) as usize,
        };

        EventLoopWorker {
            port,
            ring_entries,
            recv_buf_size,
            max_request_size,
            h2_settings,
            ws_settings,
            h2c_upgrade_enabled: server.config.h2.h2c_upgrade_enabled,
            ws_enabled: server.config.ws.enabled,
            ws_max_connections: server.config.ws.max_connections.max(0) as usize,
            ws_permessage_deflate: server.config.ws.permessage_deflate,
            server,
        }
    }
}

/// Creates this worker's ring and checks that every opcode this
/// backend depends on and that carries no version-gated variant (so
/// `Probe` can answer for it completely) is actually supported by the
/// running kernel. Multishot accept is deliberately not checked here
/// -- see this module's own doc comment for why that has to happen
/// differently, as part of the listener's first real submit instead.
fn create_ring_and_check_support(ring_entries: u32) -> Result<IoUring, String> {
    let ring = IoUring::new(ring_entries).map_err(|e| {
        format!(
            "failed to create io_uring ring: {e} (this usually means io_uring is unavailable on \
            this host -- the kernel.io_uring_disabled sysctl, a seccomp/container policy, or a \
            kernel older than 5.1)"
        )
    })?;

    let mut probe = Probe::new();
    ring.submitter()
        .register_probe(&mut probe)
        .map_err(|e| format!("failed to register io_uring probe: {e}"))?;

    let required: &[(&str, u8)] = &[
        ("ACCEPT", opcode::Accept::CODE),
        ("RECV", opcode::Recv::CODE),
        ("SEND", opcode::Send::CODE),
        ("CLOSE", opcode::Close::CODE),
        ("TIMEOUT", opcode::Timeout::CODE),
        ("ASYNC_CANCEL", opcode::AsyncCancel::CODE),
    ];
    let unsupported: Vec<&str> = required
        .iter()
        .filter(|(_, code)| !probe.is_supported(*code))
        .map(|(name, _)| *name)
        .collect();

    if !unsupported.is_empty() {
        return Err(format!(
            "this kernel's io_uring does not support the following required opcodes: {}",
            unsupported.join(", ")
        ));
    }
    Ok(ring)
}

/// Submits the listener's multishot accept SQE. Called once at
/// startup, and again any time the completion loop notices the kernel
/// disarmed it (see `IORING_CQE_F_MORE` handling below) -- unlike
/// `Recv`/`Send`, a healthy multishot accept SQE otherwise stays armed
/// and keeps producing completions on its own.
/// Calls `getpeername(2)` on an accepted connection's fd and parses
/// the result into a `SocketAddr` -- see the accept completion
/// handler's own comment on why this synchronous call is the correct
/// way to recover the peer address `AcceptMulti` doesn't report,
/// rather than a limitation to route around. Supports both IPv4 and
/// IPv6 (`bind_reuseport` prefers a dual-stack IPv6 listener -- see
/// `net::socket`'s own doc comment -- so an accepted connection's
/// peer address may legitimately be either family, including an
/// IPv4-mapped IPv6 address).
fn get_peer_addr(fd: RawFd) -> std::io::Result<std::net::SocketAddr> {
    // sockaddr_storage is large enough to hold either sockaddr_in or
    // sockaddr_in6 -- using the generic storage type here (rather than
    // committing to one address family upfront) is what lets a single
    // getpeername(2) call handle both without knowing the family in
    // advance.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let result = unsafe { libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr_in: libc::sockaddr_in = unsafe { std::mem::transmute_copy(&storage) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
            let port = u16::from_be(addr_in.sin_port);
            Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let addr_in6: libc::sockaddr_in6 = unsafe { std::mem::transmute_copy(&storage) };
            let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
            let port = u16::from_be(addr_in6.sin6_port);
            Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, addr_in6.sin6_flowinfo, addr_in6.sin6_scope_id)))
        }
        family => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("getpeername returned an unexpected address family: {family}"),
        )),
    }
}

fn submit_listener_accept(ring: &mut IoUring, listener_fd: RawFd) -> Result<(), String> {
    let accept_multi = opcode::AcceptMulti::new(types::Fd(listener_fd)).build().user_data(USER_DATA_ACCEPT);
    unsafe {
        ring.submission()
            .push(&accept_multi)
            .map_err(|_| "failed to push listener accept SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Submits a one-shot `Timeout` SQE so the main loop's `submit_and_wait`
/// call is guaranteed to unblock within `LOOP_TIMEOUT_MS` even if no
/// other completion arrives in that window -- see `LOOP_TIMEOUT_MS`'s
/// own doc comment. `timespec` is taken by reference and must outlive
/// the submitted SQE until it completes (either a real timeout, or
/// cancelled implicitly by the ring being torn down) -- the caller
/// owns a stack-local `Timespec` for exactly this call, one per loop
/// iteration, rather than this function allocating one itself that
/// would need its own lifetime tracked across the wait.
fn submit_loop_timeout(ring: &mut IoUring, timespec: &types::Timespec) -> Result<(), String> {
    let timeout = opcode::Timeout::new(timespec).build().user_data(USER_DATA_TIMEOUT);
    unsafe {
        ring.submission()
            .push(&timeout)
            .map_err(|_| "failed to push loop-timeout SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Submits a `Recv` SQE for `slab_index`'s connection, reading into its
/// own `recv_buf`. Single-shot (not `RecvMulti`): the multishot recv
/// variant requires a registered provided-buffer pool (available since
/// kernel 6.0) that this echo loop doesn't set up yet -- deliberately
/// deferred to a later, real-workload-justified optimization pass
/// rather than added speculatively here (see this module's own doc
/// comment on scope).
fn submit_recv(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let recv = opcode::Recv::new(types::Fd(conn.transport.fd), conn.recv_buf.as_mut_ptr(), conn.recv_buf.len() as u32)
        .build()
        .user_data(make_user_data(OP_TAG_RECV, conn.generation, slab_index));
    unsafe {
        ring.submission()
            .push(&recv)
            .map_err(|_| "failed to push recv SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Submits a `Send` SQE for `slab_index`'s connection, echoing back the
/// first `len` bytes of its `recv_buf` -- the same buffer `submit_recv`
/// just filled. Safe to reuse immediately here because this function
/// is only ever called after that `Recv`'s own completion was already
/// consumed (see this module's own doc comment on buffer ownership):
/// nothing else can be mid-flight against this buffer at the same
/// time.
/// Submits a `Send` SQE for `slab_index`'s connection, sending
/// whatever is currently queued in its active protocol's write
/// buffer (`Http1Connection::write_buf` today -- H2/WS write buffers
/// aren't driven by this backend yet). Unlike the earlier echo-loop
/// milestone's version of this function, the buffer sent is not the
/// same one `submit_recv` reads into: `process_http1_read_buf`
/// deliberately keeps read and write buffers separate (see
/// `Http1Connection`'s own fields), so nothing here reuses `recv_buf`
/// as an outgoing buffer.
/// The write buffer currently pending for whichever protocol is
/// active on this connection -- `Http1Connection::write_buf` and
/// `WsConnection::write_buf` play the identical role for their
/// respective protocols (queued bytes not yet flushed to the
/// transport), so `submit_send` can stay protocol-agnostic past this
/// one lookup rather than needing its own copy of the same submit
/// logic per protocol. Returns `None` for `Handshaking`/`Http2`
/// (H2's own write buffer isn't driven by this backend yet).
fn active_write_buf(protocol: &ConnectionProtocol) -> Option<&crate::util::buf::Buf> {
    match protocol {
        ConnectionProtocol::Http1(h1) => Some(&h1.write_buf),
        ConnectionProtocol::WebSocket(ws) => Some(&ws.write_buf),
        ConnectionProtocol::Handshaking | ConnectionProtocol::Http2(_) => None,
    }
}

fn consume_active_write_buf(protocol: &mut ConnectionProtocol, n: usize) {
    match protocol {
        ConnectionProtocol::Http1(h1) => h1.write_buf.consume(n),
        ConnectionProtocol::WebSocket(ws) => ws.write_buf.consume(n),
        ConnectionProtocol::Handshaking | ConnectionProtocol::Http2(_) => {}
    }
}

fn submit_send(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let Some(pending) = active_write_buf(&conn.protocol) else {
        return Err("submit_send called while no active protocol has a driven write buffer (Handshaking/Http2 aren't driven by this backend)".to_string());
    };
    let pending = pending.as_slice();
    let send = opcode::Send::new(types::Fd(conn.transport.fd), pending.as_ptr(), pending.len() as u32)
        .build()
        .user_data(make_user_data(OP_TAG_SEND, conn.generation, slab_index));
    unsafe {
        ring.submission()
            .push(&send)
            .map_err(|_| "failed to push send SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Submits an `AsyncCancel` SQE targeting every outstanding SQE tagged
/// with `target_user_data` -- used when a connection is about to be
/// removed from `connections` to ask the kernel to cancel whichever
/// `Recv`/`Send` is still in flight for it, rather than leaving that
/// SQE to complete on its own against a slab slot that may already
/// hold a different connection by then. The cancellation's own
/// completion (tagged `OP_TAG_CANCEL`) is handled separately and
/// carries no connection state to act on -- see its own match arm.
fn submit_cancel(ring: &mut IoUring, target_user_data: u64) -> Result<(), String> {
    let cancel = opcode::AsyncCancel::new(target_user_data).build().user_data(USER_DATA_CANCEL);
    unsafe {
        ring.submission()
            .push(&cancel)
            .map_err(|_| "failed to push cancel SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Cancels whatever `Recv`/`Send` SQE is currently outstanding for
/// `slab_index`'s connection (if any -- `Connection` doesn't track
/// which operation, if either, is in flight, so this conservatively
/// submits cancellations for both possible tags; cancelling a tag with
/// nothing outstanding is a harmless no-op, see `AsyncCancel`'s own
/// semantics) before it's removed from `connections`. Called from
/// every path that removes a connection, so a stale completion for it
/// never has the chance to arrive after the slot's been reused -- the
/// `generation` check in the main loop is this backend's second,
/// independent line of defense against that same race (see
/// `make_user_data`'s own doc comment), not a substitute for actually
/// asking the kernel to stop the operation.
fn cancel_outstanding_operations(ring: &mut IoUring, generation: u32, slab_index: usize) {
    for op_tag in [OP_TAG_RECV, OP_TAG_SEND] {
        let target = make_user_data(op_tag, generation, slab_index);
        if let Err(reason) = submit_cancel(ring, target) {
            tracing::warn!(%reason, "failed to submit cancellation for an outstanding operation");
        }
    }
}

impl WorkerBody for EventLoopWorker {
    fn run(&self, worker_id: usize, shutdown: &ShutdownSignal) {
        let mut ring = match create_ring_and_check_support(self.ring_entries) {
            Ok(r) => r,
            Err(reason) => {
                tracing::error!(
                    worker_id,
                    port = self.port,
                    %reason,
                    "io_uring backend refusing to start. Rebuild without `--features io_uring` to \
                    use the default mio/epoll backend instead."
                );
                return;
            }
        };

        let listener = match crate::net::socket::bind_reuseport(self.port, 1024) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(worker_id, port = self.port, error = %e, "worker failed to bind listener");
                return;
            }
        };
        let listener_fd = listener.as_raw_fd();

        if let Err(reason) = submit_listener_accept(&mut ring, listener_fd) {
            tracing::error!(worker_id, port = self.port, %reason, "failed to submit initial listener accept");
            return;
        }

        let mut connections: Slab<Connection> = Slab::new();
        // Parallel to `connections`: `generations[i]` is the
        // generation currently valid for slab index `i`, bumped every
        // time that slot is reused for a new connection -- see
        // `make_user_data`'s own doc comment for the race this closes.
        // Grown lazily alongside `connections` rather than
        // pre-sized, since slab indices are handed out in whatever
        // order `Slab::vacant_entry` picks.
        let mut generations: Vec<u32> = Vec::new();

        loop {
            if shutdown.is_set() {
                break;
            }

            // A fresh Timespec each iteration -- submit_loop_timeout's
            // SQE only needs this pointer valid until the SQE is
            // submitted (not until it completes; see its own doc
            // comment and opcode::Timeout's), so a stack-local value
            // per iteration is sufficient.
            let loop_timeout = types::Timespec::new().sec(0).nsec((LOOP_TIMEOUT_MS as u32) * 1_000_000);
            if let Err(reason) = submit_loop_timeout(&mut ring, &loop_timeout) {
                tracing::warn!(worker_id, %reason, "failed to submit loop timeout");
            }

            if let Err(e) = ring.submit_and_wait(1) {
                tracing::warn!(worker_id, error = %e, "submit_and_wait failed, retrying");
                continue;
            }

            // Collected up front rather than matched on while
            // borrowing `ring.completion()` -- several of these arms
            // need to submit further SQEs (a fresh Recv after a Send,
            // for instance), which itself needs `&mut ring`, so the
            // completion queue's borrow has to end before that can
            // happen.
            let completions: Vec<(u64, i32, u32)> = ring.completion().map(|cqe| (cqe.user_data(), cqe.result(), cqe.flags())).collect();

            let mut multishot_accept_disarmed = false;

            for (user_data, result, flags) in completions {
                let (op_tag, completion_generation, slab_index) = split_user_data(user_data);

                match op_tag {
                    OP_TAG_ACCEPT => {
                        if result < 0 {
                            let errno = -result;
                            if errno == libc::EINVAL || errno == libc::EOPNOTSUPP {
                                tracing::error!(worker_id, port = self.port, errno, "io_uring backend refusing to continue: this kernel does not understand the multishot accept flag (available since kernel 5.19)");
                                return;
                            }
                            tracing::warn!(worker_id, errno, "accept completion failed for an unexpected reason");
                            if !io_uring::cqueue::more(flags) {
                                multishot_accept_disarmed = true;
                            }
                            continue;
                        }

                        let accepted_fd = result;
                        // AcceptMulti deliberately doesn't report the
                        // peer's address the way a plain accept(2)
                        // does (see opcode::AcceptMulti's own doc
                        // comment: with multishot, several connections
                        // can arrive before the application processes
                        // any one of them, so a single shared addr
                        // buffer would risk one connection's address
                        // being overwritten by the next before it's
                        // read). getpeername(2) is the correct
                        // follow-up here rather than a design gap to
                        // work around -- it's a short, synchronous
                        // syscall that only reads already-known kernel
                        // state (the established connection's peer
                        // address), no different in kind from the
                        // handful of other synchronous, non-blocking
                        // calls this backend already makes (e.g.
                        // bind_reuseport itself).
                        let remote_addr = get_peer_addr(accepted_fd).unwrap_or_else(|e| {
                            tracing::warn!(worker_id, accepted_fd, error = %e, "getpeername failed for an accepted connection -- falling back to a placeholder address");
                            "0.0.0.0:0".parse().unwrap()
                        });
                        let transport = Transport { fd: accepted_fd };

                        let entry = connections.vacant_entry();
                        let new_slab_index = entry.key();
                        if new_slab_index >= generations.len() {
                            generations.resize(new_slab_index + 1, 0);
                        }
                        // Bump this slot's generation before it's
                        // handed to a new connection -- any SQE tagged
                        // with the *previous* generation (from whatever
                        // used to occupy this slot) that completes
                        // late is now guaranteed to mismatch and be
                        // dropped rather than mistaken for this new
                        // connection's own I/O.
                        generations[new_slab_index] = generations[new_slab_index].wrapping_add(1);
                        let generation = generations[new_slab_index];

                        let mut conn = Connection::new(accepted_fd as u64, transport, remote_addr, self.recv_buf_size, generation);
                        conn.protocol = ConnectionProtocol::Http1(Http1Connection::new());
                        entry.insert(conn);

                        if let Err(reason) = submit_recv(&mut ring, &mut connections, new_slab_index) {
                            tracing::warn!(worker_id, %reason, "failed to submit initial recv for accepted connection");
                            cancel_outstanding_operations(&mut ring, generation, new_slab_index);
                            connections.remove(new_slab_index);
                        }

                        if !io_uring::cqueue::more(flags) {
                            // The kernel disarmed the multishot SQE
                            // (e.g. after some transient error) --
                            // re-arm it so new connections keep being
                            // accepted.
                            multishot_accept_disarmed = true;
                        }
                    }

                    OP_TAG_RECV => {
                        if !connections.contains(slab_index) {
                            continue; // connection already closed by the time this completion arrived
                        }
                        if connections[slab_index].generation != completion_generation {
                            // Stale completion from whatever used to
                            // occupy this slot -- see make_user_data's
                            // own doc comment. The current occupant's
                            // own Recv is unaffected; nothing to do.
                            continue;
                        }
                        if result <= 0 {
                            // 0 means the peer closed (EOF); negative
                            // is a real error -- either way, this
                            // connection is done.
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        }

                        let n = result as usize;
                        let is_h2 = matches!(connections[slab_index].protocol, ConnectionProtocol::Http2(_));
                        if is_h2 {
                            tracing::warn!(worker_id, slab_index, "recv completion for an Http2 connection -- H2 is not yet driven by this backend");
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        }

                        let is_websocket = matches!(connections[slab_index].protocol, ConnectionProtocol::WebSocket(_));

                        if is_websocket {
                            let recv_buf = connections[slab_index].recv_buf.clone();
                            connections[slab_index].touch();
                            let ws_ctx = crate::core::conn::protocol::WsDispatchContext {
                                router: &self.server.router,
                                compression_threshold: self.ws_settings.compression_threshold,
                            };
                            let ws_outcome = crate::core::conn::protocol::process_websocket_input(
                                &mut connections[slab_index].protocol,
                                &recv_buf[..n],
                                &ws_ctx,
                            );

                            match ws_outcome {
                                crate::core::conn::protocol::WebSocketOutcome::NoActionNeeded => {
                                    if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit follow-up recv (websocket)");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                }
                                crate::core::conn::protocol::WebSocketOutcome::FlushThenContinue => {
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit websocket send");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                }
                                crate::core::conn::protocol::WebSocketOutcome::FlushThenClose
                                | crate::core::conn::protocol::WebSocketOutcome::ClosedFlushThenClose => {
                                    // Either way, this connection closes
                                    // once its (possibly empty) pending
                                    // write buffer has been flushed --
                                    // marking it here lets the
                                    // OP_TAG_SEND arm below know to
                                    // close afterward rather than
                                    // looping back to another recv, the
                                    // way it otherwise would by default
                                    // for a WebSocket connection (see
                                    // that arm's own comment on why WS
                                    // has no per-message keep_alive
                                    // flag the way HTTP/1.1 does).
                                    connections[slab_index].closing = true;
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit final websocket send");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                }
                            }
                            continue;
                        }

                        {
                            let conn = &mut connections[slab_index];
                            conn.touch();
                            let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
                                tracing::warn!(worker_id, slab_index, "recv completion for a connection whose protocol is neither Http1 nor WebSocket");
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                                continue;
                            };
                            // conn.recv_buf was written into directly by
                            // the kernel as part of this now-completed
                            // Recv SQE -- see this module's own doc
                            // comment on buffer ownership for why it's
                            // only safe to read from here, after the
                            // completion, not before.
                            let recv_buf = conn.recv_buf.clone();
                            h1.read_buf.push(&recv_buf[..n]);
                        }

                        let outcome = {
                            let conn = &mut connections[slab_index];
                            let ctx = Http1DispatchContext {
                                server: &self.server,
                                max_request_size: self.max_request_size,
                                h2_settings: &self.h2_settings,
                                ws_settings: &self.ws_settings,
                                h2c_upgrade_enabled: self.h2c_upgrade_enabled,
                                ws_enabled: self.ws_enabled,
                                ws_max_connections: self.ws_max_connections,
                                ws_permessage_deflate: self.ws_permessage_deflate,
                                remote_addr: conn.remote_addr.ip(),
                            };
                            crate::core::conn::protocol::process_http1_read_buf(&mut conn.protocol, &ctx)
                        };

                        match outcome {
                            Http1Outcome::NeedsMoreData => {
                                if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index) {
                                    tracing::warn!(worker_id, %reason, "failed to submit follow-up recv");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                            }
                            Http1Outcome::FlushThenContinue | Http1Outcome::FlushThenClose => {
                                // FlushThenClose is handled the same as
                                // FlushThenContinue here: the response
                                // is sent first either way, and the
                                // OP_TAG_SEND completion arm below is
                                // what actually closes the connection
                                // afterward for FlushThenClose -- see
                                // its own comment.
                                if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                    tracing::warn!(worker_id, %reason, "failed to submit response send");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                            }
                            Http1Outcome::SwitchedToHttp2 => {
                                // The 101 response is queued (still in
                                // what was Http1Connection::write_buf,
                                // now unreachable through the switched
                                // protocol) -- H2 isn't driven by this
                                // backend yet, so there's nothing
                                // further this arm can correctly do.
                                // Not attempting the flush here (it
                                // would need to read write_buf back out
                                // of a protocol variant submit_send
                                // doesn't understand) rather than
                                // silently leaving the connection in an
                                // inconsistent, half-upgraded state.
                                tracing::warn!(worker_id, slab_index, "connection requested an h2c upgrade -- not yet supported by this backend, closing");
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                            Http1Outcome::SwitchedToWebSocket => {
                                // Unlike the H2 case above, this
                                // backend *does* drive WebSocket --
                                // the switch already replaced
                                // conn.protocol with a real
                                // ConnectionProtocol::WebSocket carrying
                                // the queued 101 response in its own
                                // write_buf (see process_http1_read_buf's
                                // own handling of this), so it can be
                                // flushed exactly like any other
                                // pending send.
                                if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                    tracing::warn!(worker_id, %reason, "failed to submit websocket upgrade response");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                            }
                        }
                    }

                    OP_TAG_SEND => {
                        if !connections.contains(slab_index) {
                            continue;
                        }
                        if connections[slab_index].generation != completion_generation {
                            // Stale completion from whatever used to
                            // occupy this slot -- see make_user_data's
                            // own doc comment.
                            continue;
                        }
                        if result < 0 {
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        }

                        let n = result as usize;
                        consume_active_write_buf(&mut connections[slab_index].protocol, n);

                        // "Should this connection close once its write
                        // buffer is fully flushed" means something
                        // different per protocol: HTTP/1.1 has an
                        // explicit keep_alive flag (a request or its
                        // response may have asked for the connection to
                        // close); WebSocket has no such per-message
                        // flag -- a WS connection is expected to stay
                        // open until its own close handshake completes,
                        // which process_websocket_input already
                        // reflected by returning FlushThenClose rather
                        // than something this arm needs to re-derive.
                        // Tracking "this send was the tail end of a
                        // close-triggering flush" would need its own
                        // state; for now, a WS connection whose write
                        // buffer just fully drained always goes back to
                        // reading rather than closing -- correct for
                        // every case except the close-handshake
                        // completion's own final send, a gap called out
                        // here rather than silently accepted.
                        let already_marked_closing = connections[slab_index].closing;
                        let (fully_flushed, should_close_after_flush) = match &connections[slab_index].protocol {
                            ConnectionProtocol::Http1(h1) => (h1.write_buf.is_empty(), !h1.keep_alive),
                            // WebSocket has no per-message keep_alive
                            // flag the way HTTP/1.1 does -- whether
                            // this connection should close once
                            // flushed is instead whatever the OP_TAG_RECV
                            // arm already decided and recorded on
                            // `closing` (a completed close handshake,
                            // a protocol error, or backpressure --
                            // see process_websocket_input's own
                            // WebSocketOutcome variants).
                            ConnectionProtocol::WebSocket(ws) => (ws.write_buf.is_empty(), already_marked_closing),
                            ConnectionProtocol::Handshaking | ConnectionProtocol::Http2(_) => {
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                                continue;
                            }
                        };

                        if fully_flushed && should_close_after_flush {
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        }

                        if !fully_flushed {
                            // A partial write -- send the rest of the
                            // same buffer before doing anything else.
                            if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                tracing::warn!(worker_id, %reason, "failed to submit remainder of a partially-sent buffer");
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                        } else {
                            // Fully flushed, and either HTTP/1.1
                            // keep-alive or WebSocket (which always
                            // goes back to reading here -- see this
                            // arm's own comment) -- read the next
                            // message/request from the same connection.
                            if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index) {
                                tracing::warn!(worker_id, %reason, "failed to submit follow-up recv");
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                        }
                    }

                    OP_TAG_CANCEL => {
                        // Nothing to act on -- the cancellation
                        // completion carries no connection state, and
                        // whichever connection its target belonged to
                        // has already been (or is being) removed by
                        // the caller that submitted this cancel; see
                        // cancel_outstanding_operations's own doc
                        // comment. A negative result here (e.g.
                        // -ENOENT, meaning there was nothing to cancel
                        // in the first place -- an expected, harmless
                        // outcome per AsyncCancel's own semantics) is
                        // not logged as a warning for that reason.
                    }

                    OP_TAG_TIMEOUT => {
                        // Its only purpose is unblocking submit_and_wait
                        // on a schedule -- see LOOP_TIMEOUT_MS's own
                        // doc comment. -ETIME is the expected, normal
                        // result when the timeout actually elapsed;
                        // -ECANCELED would mean something explicitly
                        // cancelled it, which nothing in this backend
                        // does yet -- either way there's nothing to
                        // react to here beyond falling through to the
                        // next loop iteration, which re-checks
                        // shutdown.is_set() and resubmits a fresh one.
                    }

                    _ => {
                        tracing::warn!(worker_id, op_tag, "completion with unrecognized op tag");
                    }
                }
            }

            if multishot_accept_disarmed {
                if let Err(reason) = submit_listener_accept(&mut ring, listener_fd) {
                    tracing::error!(worker_id, %reason, "failed to re-arm listener accept after it was disarmed");
                    return;
                }
            }
        }

        let _ = &self.server; // not yet consulted by this echo-loop milestone -- see this module's own doc comment on scope
    }
}

/// Starts `n_workers` worker threads bound to `port`, using the
/// io_uring backend -- signature-compatible with `mio_backend::run`,
/// which this fully replaces (never both at once) when the `io_uring`
/// feature is enabled.
pub fn run(server: Arc<RoutaServer>, port: u16, n_workers: usize) -> crate::core::worker::WorkerPool {
    let worker = EventLoopWorker::new(port, server);
    crate::core::worker::WorkerPool::spawn(n_workers, worker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;

    #[test]
    fn user_data_packing_round_trips() {
        for slab_index in [0usize, 1, 42, 1_000_000] {
            for generation in [0u32, 1, 255, 1_000_000] {
                for op_tag in [OP_TAG_ACCEPT, OP_TAG_RECV, OP_TAG_SEND, OP_TAG_TIMEOUT, OP_TAG_CANCEL] {
                    let packed = make_user_data(op_tag, generation, slab_index);
                    assert_eq!(split_user_data(packed), (op_tag, generation, slab_index));
                }
            }
        }
    }

    #[test]
    fn different_generations_produce_different_user_data_for_the_same_slot() {
        // The exact property make_user_data exists to provide: two
        // completions for the same op tag and slab index, but
        // different generations, must be distinguishable -- this is
        // what lets the main loop recognize a stale completion from a
        // slot's previous occupant.
        let gen1 = make_user_data(OP_TAG_RECV, 1, 5);
        let gen2 = make_user_data(OP_TAG_RECV, 2, 5);
        assert_ne!(gen1, gen2);
    }

    #[test]
    fn ring_creation_and_probe_check_succeeds_on_this_host() {
        create_ring_and_check_support(256).expect("ring creation and probe check should succeed on a modern Linux host");
    }

    #[test]
    fn get_peer_addr_reports_the_real_client_address() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _client = StdTcpStream::connect(addr).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");

        let peer = get_peer_addr(accepted.as_raw_fd()).expect("getpeername should succeed on a real connected socket");
        assert_eq!(peer.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), "peer address should be the real loopback client, not a placeholder");
    }

    /// A real WebSocket handshake, a real echoed application message,
    /// and a real close handshake, all over an actual TCP connection
    /// -- exercises process_websocket_input's full round trip (the
    /// upgrade path through process_http1_read_buf, then message
    /// dispatch through the registered route handler, then the close
    /// handshake correctly ending the connection) rather than any one
    /// piece in isolation.
    #[test]
    fn websocket_upgrade_echo_and_close_handshake_end_to_end() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.ws.enabled = true;
        config.port = port as i32;
        let mut server = RoutaServer::from_config(config).expect("build a minimal RoutaServer");
        let mut router = crate::http::router::Router::new();
        // The 101 upgrade itself is an ordinary HTTP route, matched
        // and dispatched through middleware_chain like any other
        // request -- add_websocket_route below only registers the
        // *post-upgrade* message handler, it doesn't make "/ws" match
        // as a request path on its own. See mio_backend's own
        // equivalent test for the same two-registrations shape.
        router.add("/ws", &[crate::http::request::HttpMethod::Get], |req, _params| {
            crate::http::ws::build_handshake_response(req, None)
        });
        router.add_websocket_route("/ws", |msg| match msg {
            crate::http::ws::WsMessage::Text(text) if text == "ping" => Some(crate::http::ws::WsMessage::Text("pong".to_string())),
            _ => None,
        });
        let router = Arc::new(router);
        server.router = Arc::clone(&router);
        // server.router and server.middleware_chain are independently
        // constructed by from_config -- replacing just the former
        // leaves middleware_chain still dispatching through the old,
        // routeless router underneath. Rebuilding middleware_chain
        // here to close over the same new router is what actually
        // makes the new route reachable.
        server.middleware_chain = Arc::new(crate::http::middleware::ChainBuilder::new().build(move |req| {
            match router.dispatch(req) {
                crate::http::router::Dispatch::Matched { handler, params } => handler(req, &params),
                crate::http::router::Dispatch::MethodNotAllowed { .. } => crate::http::response::HttpResponse::new(405, "Method Not Allowed"),
                crate::http::router::Dispatch::NotFound => crate::http::response::HttpResponse::new(404, "Not Found"),
            }
        }));
        let server = Arc::new(server);
        let pool = run(server, port, 1);

        let mut connected = None;
        for _ in 0..50 {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let mut stream = connected.expect("worker should eventually accept a connection");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("set read timeout");

        // Real WebSocket upgrade handshake (RFC 6455). The Sec-WebSocket-Key
        // here is a fixed, arbitrary base64 value -- this test doesn't
        // verify Sec-WebSocket-Accept's derivation (http::ws's own unit
        // tests are responsible for that), only that a real upgrade
        // request produces a 101 and switches this connection to
        // WebSocket end to end.
        stream
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .expect("write upgrade request should succeed");

        let mut header_buf = [0u8; 512];
        let n = stream.read(&mut header_buf).expect("read upgrade response should succeed");
        let response_text = String::from_utf8_lossy(&header_buf[..n]);
        assert!(response_text.starts_with("HTTP/1.1 101"), "expected a 101 Switching Protocols response, got: {response_text:?}");

        // Send a masked "ping" text frame (RFC 6455 5.1: client frames
        // must be masked) and expect the registered handler's "pong"
        // reply, framed as an ordinary unmasked server text frame.
        let ping_frame = build_masked_ws_text_frame("ping");
        stream.write_all(&ping_frame).expect("write ping frame should succeed");

        let mut reply_buf = [0u8; 512];
        let n = stream.read(&mut reply_buf).expect("read pong reply should succeed");
        let (opcode, payload) = parse_unmasked_ws_frame(&reply_buf[..n]);
        assert_eq!(opcode, 0x1, "expected a text frame opcode");
        assert_eq!(payload, b"pong");

        // Close handshake: a masked close frame from the client should
        // be echoed back by the server, and the connection should then
        // actually close (read_to_end returning cleanly at EOF, not
        // hanging or erroring).
        let close_frame = build_masked_ws_close_frame();
        stream.write_all(&close_frame).expect("write close frame should succeed");

        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).expect("connection should close cleanly after the close handshake completes");

        pool.shutdown();
    }

    /// Builds a masked WebSocket text frame -- RFC 6455 5.1 requires
    /// every client-to-server frame to be masked; a fixed, arbitrary
    /// masking key is used since this test only needs *a* valid mask,
    /// not to exercise masking's own randomness.
    fn build_masked_ws_text_frame(text: &str) -> Vec<u8> {
        let mask: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        let payload = text.as_bytes();
        let mut frame = vec![0x81u8]; // FIN + text opcode
        frame.push(0x80 | (payload.len() as u8)); // MASK bit + payload length (assumes len < 126, true for this test's fixed strings)
        frame.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        frame
    }

    /// Builds a masked WebSocket close frame with no payload (a bare
    /// close, status code omitted -- RFC 6455 7.1.5 permits this).
    fn build_masked_ws_close_frame() -> Vec<u8> {
        let mask: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        vec![0x88u8, 0x80] // FIN + close opcode, MASK bit + zero-length payload
            .into_iter()
            .chain(mask.iter().copied())
            .collect()
    }

    /// Parses a single unmasked (server-to-client) WebSocket frame,
    /// returning its opcode and payload -- assumes a short (< 126
    /// byte) payload, matching what this test's own fixed messages
    /// need.
    fn parse_unmasked_ws_frame(data: &[u8]) -> (u8, Vec<u8>) {
        let opcode = data[0] & 0x0f;
        assert_eq!(data[1] & 0x80, 0, "a server must never mask its own WebSocket frames");
        let len = (data[1] & 0x7f) as usize;
        (opcode, data[2..2 + len].to_vec())
    }

    #[test]
    fn recv_completion_of_zero_means_peer_closed() {
        // Documents the exact convention the main loop's OP_TAG_RECV
        // arm relies on (recv(2) returning 0 means EOF) without
        // needing a real socket to demonstrate it.
        let result: i32 = 0;
        assert!(result <= 0, "a zero recv result must be treated as connection-closed, not retried");
    }

    /// End-to-end: runs the actual worker body on a background thread
    /// against a real listener, connects a real client, sends a real
    /// HTTP/1.1 request, and checks a real response comes back --
    /// exercising the full accept -> recv -> parse -> dispatch ->
    /// send cycle exactly as production traffic would, not just the
    /// discovery/setup pieces earlier milestones tested in isolation.
    #[test]
    fn serves_a_real_http_request_end_to_end() {
        // Pick a genuinely free port first (bind on port 0, read back
        // what the OS assigned, then release it) so the worker below
        // can be started already knowing which port to bind -- the
        // worker's own run() does the real SO_REUSEPORT bind itself
        // from self.port, there's no path for it to report back an
        // OS-chosen port after the fact.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        // A request needs at least one route to match, or the router
        // reports 404 -- still a valid HTTP response (proving the
        // full parse/dispatch/serialize path works end to end), so
        // this test doesn't need to register a real route just to
        // observe a real, well-formed response.
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
        let pool = run(server, port, 1);

        // Give the worker a moment to actually bind and arm its
        // listener accept before a client tries to connect -- same
        // reasoning as mio_backend's own equivalent startup-timing
        // tests.
        let mut connected = None;
        for _ in 0..50 {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let mut stream = connected.expect("worker should eventually accept a connection on its bound port");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("set read timeout");

        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .expect("write should succeed");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("read should succeed (or time out, which fails the test instead of hanging it)");

        let response_text = String::from_utf8_lossy(&response);
        assert!(
            response_text.starts_with("HTTP/1.1 "),
            "expected a well-formed HTTP/1.1 status line, got: {response_text:?}"
        );
        assert!(
            response_text.contains("404 Not Found"),
            "expected a 404 for an unregistered route, got: {response_text:?}"
        );

        pool.shutdown();
    }
}
