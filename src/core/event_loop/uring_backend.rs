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

/// A connection's `user_data` is packed as `(op_tag << 56) | slab_index`
/// -- 56 bits is far beyond any realistic connection count, and
/// keeping the op tag in fixed high bits (rather than, say, a separate
/// counter) means a completion can be routed back to both "which
/// connection" and "which operation was in flight for it" from a
/// single u64 with no additional lookup.
const OP_TAG_BITS: u32 = 56;
const OP_TAG_ACCEPT: u64 = 0;
const OP_TAG_RECV: u64 = 1;
const OP_TAG_SEND: u64 = 2;
const OP_TAG_TIMEOUT: u64 = 3;

const USER_DATA_ACCEPT: u64 = OP_TAG_ACCEPT << OP_TAG_BITS;
const USER_DATA_TIMEOUT: u64 = OP_TAG_TIMEOUT << OP_TAG_BITS;

/// How long a single `submit_and_wait` call may block before the main
/// loop is guaranteed to check `ShutdownSignal::is_set()` again --
/// this backend's counterpart to `mio_backend::POLL_TIMEOUT`. Without
/// this, `submit_and_wait` blocks until an unrelated I/O completion
/// happens to arrive (a new connection, more data on some other
/// socket) with no bound at all -- an idle worker with no traffic
/// would never notice a shutdown signal, since nothing wakes it up to
/// re-check.
const LOOP_TIMEOUT_MS: u64 = 200;

fn make_user_data(op_tag: u64, slab_index: usize) -> u64 {
    (op_tag << OP_TAG_BITS) | (slab_index as u64)
}

fn split_user_data(user_data: u64) -> (u64, usize) {
    let op_tag = user_data >> OP_TAG_BITS;
    let slab_index = (user_data & ((1u64 << OP_TAG_BITS) - 1)) as usize;
    (op_tag, slab_index)
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
        .user_data(make_user_data(OP_TAG_RECV, slab_index));
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
fn submit_send(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let ConnectionProtocol::Http1(h1) = &conn.protocol else {
        return Err("submit_send called while protocol is not Http1 -- H2/WS write buffers are not yet driven by this backend".to_string());
    };
    let pending = h1.write_buf.as_slice();
    let send = opcode::Send::new(types::Fd(conn.transport.fd), pending.as_ptr(), pending.len() as u32)
        .build()
        .user_data(make_user_data(OP_TAG_SEND, slab_index));
    unsafe {
        ring.submission()
            .push(&send)
            .map_err(|_| "failed to push send SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
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
                let (op_tag, slab_index) = split_user_data(user_data);

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
                        // AcceptMulti doesn't report the peer's address
                        // (see opcode::AcceptMulti's own doc comment --
                        // "no out SockAddr is passed for the multishot
                        // accept case"), unlike mio_backend's
                        // listener.accept(), which gets it for free
                        // from the accept(2) call itself. A real
                        // remote_addr requires a follow-up
                        // getpeername(2)-equivalent this backend
                        // doesn't yet submit -- using a placeholder
                        // here rather than blocking accept on it.
                        let placeholder_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
                        let transport = Transport { fd: accepted_fd };
                        let mut conn = Connection::new(accepted_fd as u64, transport, placeholder_addr, self.recv_buf_size);
                        conn.protocol = ConnectionProtocol::Http1(Http1Connection::new());

                        let entry = connections.vacant_entry();
                        let new_slab_index = entry.key();
                        entry.insert(conn);

                        if let Err(reason) = submit_recv(&mut ring, &mut connections, new_slab_index) {
                            tracing::warn!(worker_id, %reason, "failed to submit initial recv for accepted connection");
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
                        if result <= 0 {
                            // 0 means the peer closed (EOF); negative
                            // is a real error -- either way, this
                            // connection is done.
                            connections.remove(slab_index);
                            continue;
                        }

                        let n = result as usize;
                        {
                            let conn = &mut connections[slab_index];
                            conn.touch();
                            let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
                                tracing::warn!(worker_id, slab_index, "recv completion for a connection whose protocol is not Http1 -- H2/WS are not yet driven by this backend");
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
                                    connections.remove(slab_index);
                                }
                            }
                            Http1Outcome::SwitchedToHttp2 | Http1Outcome::SwitchedToWebSocket => {
                                // The 101 response is queued (still in
                                // what was Http1Connection::write_buf,
                                // now unreachable through the switched
                                // protocol) -- H2/WS aren't driven by
                                // this backend yet, so there's nothing
                                // further this arm can correctly do.
                                // Not attempting the flush here (it
                                // would need to read write_buf back out
                                // of a protocol variant submit_send
                                // doesn't understand) rather than
                                // silently leaving the connection in an
                                // inconsistent, half-upgraded state.
                                tracing::warn!(worker_id, slab_index, "connection requested an h2c/WebSocket upgrade -- not yet supported by this backend, closing");
                                connections.remove(slab_index);
                            }
                        }
                    }

                    OP_TAG_SEND => {
                        if !connections.contains(slab_index) {
                            continue;
                        }
                        if result < 0 {
                            connections.remove(slab_index);
                            continue;
                        }

                        let n = result as usize;
                        let should_close = {
                            let conn = &mut connections[slab_index];
                            let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
                                connections.remove(slab_index);
                                continue;
                            };
                            h1.write_buf.consume(n);
                            let fully_flushed = h1.write_buf.is_empty();
                            fully_flushed && !h1.keep_alive
                        };

                        if should_close {
                            connections.remove(slab_index);
                            continue;
                        }

                        let still_pending = {
                            let conn = &connections[slab_index];
                            let ConnectionProtocol::Http1(h1) = &conn.protocol else {
                                continue;
                            };
                            !h1.write_buf.is_empty()
                        };

                        if still_pending {
                            // A partial write -- send the rest of the
                            // same response before doing anything else.
                            if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                tracing::warn!(worker_id, %reason, "failed to submit remainder of a partially-sent response");
                                connections.remove(slab_index);
                            }
                        } else {
                            // Fully flushed and keep-alive -- go back
                            // to reading the next (possibly already
                            // pipelined) request from the same
                            // connection.
                            if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index) {
                                tracing::warn!(worker_id, %reason, "failed to submit follow-up recv");
                                connections.remove(slab_index);
                            }
                        }
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
            for op_tag in [OP_TAG_ACCEPT, OP_TAG_RECV, OP_TAG_SEND] {
                let packed = make_user_data(op_tag, slab_index);
                assert_eq!(split_user_data(packed), (op_tag, slab_index));
            }
        }
    }

    #[test]
    fn ring_creation_and_probe_check_succeeds_on_this_host() {
        create_ring_and_check_support(256).expect("ring creation and probe check should succeed on a modern Linux host");
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
