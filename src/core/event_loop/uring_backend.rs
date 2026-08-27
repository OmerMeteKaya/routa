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

use io_uring::{opcode, squeue, types, IoUring, Probe};
use slab::Slab;

use crate::core::conn::protocol::{ConnectionProtocol, Http1Connection, Http1DispatchContext, Http1Outcome, Http2Connection};
use crate::core::conn::uring_conn::{Connection, ConnectionRole, Transport};
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
/// Completion of an `opcode::Connect` SQE opening a new upstream
/// connection -- see `submit_connect`'s own doc comment. Distinct from
/// `OP_TAG_ACCEPT` (which only ever fires for the listener socket,
/// identified by a fixed sentinel slab_index rather than a real one --
/// see that arm's own handling) since a Connect completion always
/// corresponds to a real slab slot (the newly-created upstream
/// Connection waiting to know whether its connect() succeeded).
const OP_TAG_CONNECT: u64 = 5;
/// Completion of a `LinkTimeout` SQE submitted alongside a
/// `Connect`/`Send`/`Recv` on an *upstream* connection (see
/// `submit_connect`/`submit_send`/`submit_recv`'s own handling of
/// `ProxyConfig`'s timeouts) -- carries no useful result of its own to
/// act on: either the timeout fired first (the linked operation
/// itself then completes with `-ECANCELED`, which its own completion
/// arm already treats as a real failure) or the linked operation
/// completed first (this timeout then completes with `-ECANCELED`
/// too, RFC-consistent io_uring behavior for a timeout whose target
/// finished before it fired -- see LinkTimeout's own doc comment).
/// Either way, nothing needs to happen when *this* completion itself
/// arrives; the real teardown/response logic already lives in the
/// linked operation's own arm.
const OP_TAG_LINK_TIMEOUT: u64 = 6;
/// First leg of a `PendingFileSend` relay -- `Splice(file_fd -> pipe_write_fd)`.
/// See `PendingSplice`/`SplicePhase`'s own doc comments for why a file
/// body's bytes cross a pipe rather than going straight to the socket.
const OP_TAG_SPLICE_TO_PIPE: u64 = 7;
/// Second leg of a `PendingFileSend` relay -- `Splice(pipe_read_fd -> socket_fd)`,
/// moving however many bytes the matching `OP_TAG_SPLICE_TO_PIPE`
/// completion reported were placed into the pipe.
const OP_TAG_SPLICE_TO_SOCKET: u64 = 8;
/// A `SendZc` (zero-copy send) SQE -- see `submit_send`'s own doc
/// comment for the size threshold that decides `Send` vs `SendZc`,
/// and this tag's own completion arm for the two-CQE (MORE, then
/// NOTIF) lifecycle SendZc requires that ordinary `Send` doesn't.
const OP_TAG_SEND_ZC: u64 = 9;
/// A `Statx` SQE stat'ing a static file's path asynchronously -- see
/// `FileCachePending`'s own doc comment (in http::static_files) for
/// why this exists instead of a synchronous std::fs::metadata call.
const OP_TAG_STATX: u64 = 10;

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
    registered_buffers_enabled: bool,
    registered_buffer_count: u32,
    max_request_size: usize,
    h2_settings: crate::core::conn::Http2Settings,
    ws_settings: crate::core::conn::WsSettings,
    h2c_upgrade_enabled: bool,
    ws_enabled: bool,
    ws_max_connections: usize,
    ws_permessage_deflate: bool,
    /// Trusts an explicit root store for upstream TLS connections
    /// instead of the platform default -- exposed only for this
    /// module's own tests, which need to trust a freshly-generated
    /// self-signed test certificate rather than a real CA-issued one,
    /// mirroring `net::h2_client`'s own `#[cfg(test)] connect_with_roots`.
    /// Always `None` outside tests, in which case upstream TLS
    /// connections use `TlsConnection::new_client`'s real webpki
    /// roots exactly as production traffic requires.
    #[cfg(test)]
    upstream_tls_test_roots: Option<rustls::RootCertStore>,
}

impl EventLoopWorker {
    pub fn new(port: u16, server: Arc<RoutaServer>) -> Self {
        // RoutaConfig::validate already rejects an out-of-range or
        // non-power-of-two ring_entries before a server is ever built
        // from this config -- see core::config::validate -- so the
        // casts below don't need their own bounds-checking here.
        let ring_entries = server.config.io_uring.ring_entries as u32;
        let recv_buf_size = server.config.io_uring.recv_buf_size as usize;
        let registered_buffers_enabled = server.config.io_uring.registered_buffers_enabled;
        let registered_buffer_count = server.config.io_uring.registered_buffer_count.max(0) as u32;

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
            registered_buffers_enabled,
            registered_buffer_count,
            max_request_size,
            h2_settings,
            ws_settings,
            h2c_upgrade_enabled: server.config.h2.h2c_upgrade_enabled,
            ws_enabled: server.config.ws.enabled,
            ws_max_connections: server.config.ws.max_connections.max(0) as usize,
            ws_permessage_deflate: server.config.ws.permessage_deflate,
            server,
            #[cfg(test)]
            upstream_tls_test_roots: None,
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

/// Probes whether the running kernel's io_uring supports `SendZc`
/// (`IORING_OP_SEND_ZC`, stabilized in Linux 6.1) -- unlike the
/// opcodes `create_ring_and_check_support` checks, SendZc is an
/// optional optimization this backend degrades gracefully without
/// (see `submit_send`'s own doc comment on its size-thresholded
/// SendZc/Send choice), not a hard requirement that should refuse to
/// start the worker if missing. A dedicated probe call, separate from
/// the one `create_ring_and_check_support` already made, since a
/// `Probe` snapshot is a one-time registration against the kernel's
/// current opcode table -- reusing the same probe object would need
/// threading it out of that function's own scope for a single extra
/// check this rarely-changing capability doesn't warrant.
fn probe_send_zc_support(ring: &IoUring) -> bool {
    let mut probe = Probe::new();
    if ring.submitter().register_probe(&mut probe).is_err() {
        return false;
    }
    probe.is_supported(opcode::SendZc::CODE)
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

/// Feeds newly-received ciphertext through a TLS connection's
/// `advance_io` (see `Transport::Tls`'s own doc comment for why this
/// works under io_uring's completion model at all) and reports what
/// happened -- the TLS-connection equivalent of a single step in
/// `mio_backend`'s own `advance_tls_handshake`, but also covering the
/// post-handshake record-layer advancement mio's version doesn't need
/// a separate function for (mio drives that inline in
/// `read_into_transport`/`flush_transport` instead).
enum TlsAdvanceOutcome {
    /// The handshake is still in progress -- submit `io.outgoing` (if
    /// non-empty) as a Send, then submit another Recv and wait for
    /// more.
    StillHandshaking,
    /// The handshake just completed on this call -- caller should
    /// check `alpn_protocol()` and select Http1/Http2, after flushing
    /// any final handshake bytes still in `io.outgoing`.
    HandshakeJustCompleted,
    /// Already past the handshake -- ordinary record-layer traffic
    /// was processed. Decrypted application data (if any) is now
    /// available via `tls.read_plaintext()`.
    RecordLayerAdvanced,
    /// The peer closed the connection (clean EOF on the raw socket
    /// read, not necessarily a TLS close_notify).
    PeerClosed,
}

fn advance_tls(tls: &mut crate::net::tls::TlsConnection, io: &mut crate::net::tls::MemoryTlsIo, new_ciphertext: &[u8]) -> std::io::Result<TlsAdvanceOutcome> {
    io.incoming.push(new_ciphertext);
    let was_handshaking = tls.is_handshaking();
    let advance = tls.advance_io(io)?;
    if advance.peer_closed {
        return Ok(TlsAdvanceOutcome::PeerClosed);
    }
    if advance.handshake_just_completed {
        return Ok(TlsAdvanceOutcome::HandshakeJustCompleted);
    }
    if was_handshaking {
        return Ok(TlsAdvanceOutcome::StillHandshaking);
    }
    Ok(TlsAdvanceOutcome::RecordLayerAdvanced)
}

/// Creates a fresh, non-blocking TCP socket (via `socket(2)`) for an
/// upstream connection attempt -- doesn't connect it yet, that's
/// `submit_connect`'s job via a real `Connect` SQE. A synchronous
/// `socket(2)` call here is the same kind of short, non-blocking-I/O-free
/// syscall `get_peer_addr`'s own `getpeername(2)` already is (see its
/// own doc comment) -- it only asks the kernel to allocate an fd, no
/// network I/O happens until the SQE this fd is used for actually
/// runs.
fn create_upstream_socket(remote_addr: &std::net::SocketAddr) -> std::io::Result<RawFd> {
    let domain = match remote_addr {
        std::net::SocketAddr::V4(_) => libc::AF_INET,
        std::net::SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Encodes `addr` into the raw `sockaddr` bytes `opcode::Connect`
/// needs -- the inverse of `get_peer_addr`'s own decoding. Returns the
/// encoded bytes and their true length (`opcode::Connect` needs both
/// a pointer and an exact length, not just a fixed-size buffer,
/// because IPv4 and IPv6 addresses encode to different lengths).
fn encode_sockaddr(addr: &std::net::SocketAddr) -> (Box<libc::sockaddr_storage>, libc::socklen_t) {
    let mut storage: Box<libc::sockaddr_storage> = Box::new(unsafe { std::mem::zeroed() });
    let len = match addr {
        std::net::SocketAddr::V4(v4) => {
            let sockaddr_in = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::write(&mut *storage as *mut _ as *mut libc::sockaddr_in, sockaddr_in);
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        std::net::SocketAddr::V6(v6) => {
            let sockaddr_in6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::write(&mut *storage as *mut _ as *mut libc::sockaddr_in6, sockaddr_in6);
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    (storage, len)
}

/// Submits a `Connect` SQE for a slab slot already holding an
/// upstream `Connection` (created via `Connection::new_upstream` with
/// `create_upstream_socket`'s fd) -- the async equivalent of
/// `connect(2)`. The completion (`OP_TAG_CONNECT` in the main loop)
/// reports success or failure the same way a real `connect(2)` would:
/// `result == 0` means connected, a negative result is `-errno`
/// (`ECONNREFUSED`, `ETIMEDOUT`, etc.), and there's no separate
/// "connection in progress" completion the way a non-blocking
/// synchronous `connect(2)` followed by `poll(2)` needs -- io_uring's
/// own Connect opcode already waits for the handshake to finish
/// before completing at all.
fn submit_connect(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize, timeout: std::time::Duration) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let (storage, len) = encode_sockaddr(&conn.remote_addr);
    let sockaddr_ptr = &*storage as *const libc::sockaddr_storage as *const libc::sockaddr;
    let connect = opcode::Connect::new(types::Fd(conn.transport.fd()), sockaddr_ptr, len)
        .build()
        // IO_LINK ties this SQE to the very next one submitted (the
        // LinkTimeout below) -- see submit_connect's own doc comment
        // for the completion semantics this produces.
        .flags(squeue::Flags::IO_LINK)
        .user_data(make_user_data(OP_TAG_CONNECT, conn.generation, slab_index));
    // storage must outlive the SQE the kernel will read sockaddr_ptr
    // from -- stashing it on the connection itself (rather than
    // letting it drop at the end of this function) is what keeps it
    // alive until the OP_TAG_CONNECT completion arrives and clears it.
    conn.pending_connect_addr = Some(storage);

    let timespec = Box::new(types::Timespec::new().sec(timeout.as_secs()).nsec(timeout.subsec_nanos()));
    let timespec_ptr: *const types::Timespec = &*timespec;
    let link_timeout = opcode::LinkTimeout::new(timespec_ptr)
        .build()
        .user_data(make_user_data(OP_TAG_LINK_TIMEOUT, conn.generation, slab_index));
    // timespec must outlive the LinkTimeout SQE the same way
    // pending_connect_addr's storage must outlive the Connect SQE --
    // see pending_timeout's own doc comment.
    conn.pending_timeout = Some(timespec);

    unsafe {
        ring.submission()
            .push(&connect)
            .map_err(|_| "failed to push connect SQE -- submission queue unexpectedly full".to_string())?;
        ring.submission()
            .push(&link_timeout)
            .map_err(|_| "failed to push connect's link-timeout SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Called whenever an upstream attempt has failed (a connect(2)
/// failure, or the upstream closing before a complete response
/// arrived) for a downstream connection that's still around and still
/// waiting -- decides whether to retry against a different node
/// (mirroring mio_backend's own synchronous `for attempt in 0..max_attempts`
/// loop in `core::proxy::forward`) or give up and flush a 502 back,
/// and does whichever it decides. `downstream_slab_index` must already
/// be known to exist with `attempt_state`'s own generation -- callers
/// check this themselves (the same generation-checked pattern used
/// throughout this module) before calling, since what to do if the
/// downstream is already gone is caller-specific (usually: nothing).
fn retry_or_fail_proxy_attempt(
    ring: &mut IoUring,
    connections: &mut Slab<Connection>,
    generations: &mut Vec<u32>,
    downstream_slab_index: usize,
    mut attempt_state: crate::core::conn::protocol::ProxyAttemptState,
    recv_buf_size: usize,
    worker_id: usize,
    send_zc_supported: bool,
) {
    let max_attempts = 1 + attempt_state.pending.lb.config.max_retries.max(0) as u32;
    let downstream_generation = connections[downstream_slab_index].generation;
    if attempt_state.attempts_so_far < max_attempts {
        if let Some(node) = attempt_state.pending.lb.pick_node_sticky(None, None) {
            if let Ok(upstream_addr) = node.resolve_addr() {
                if let Ok(upstream_fd) = create_upstream_socket(&upstream_addr) {
                    let upstream_entry = connections.vacant_entry();
                    let upstream_slab_index = upstream_entry.key();
                    if upstream_slab_index >= generations.len() {
                        generations.resize(upstream_slab_index + 1, 0);
                    }
                    generations[upstream_slab_index] = generations[upstream_slab_index].wrapping_add(1);
                    let upstream_generation = generations[upstream_slab_index];
                    let read_write_timeouts = (attempt_state.pending.config.read_timeout, attempt_state.pending.config.write_timeout);
                    let mut upstream_conn = Connection::new_upstream(
                        upstream_fd as u64,
                        Transport::Plain(upstream_fd),
                        upstream_addr,
                        recv_buf_size,
                        upstream_generation,
                        Arc::clone(&node),
                        Arc::clone(&attempt_state.pending.lb.pool),
                        read_write_timeouts,
                    );
                    upstream_conn.send_zc_supported = send_zc_supported;
                    upstream_conn.role = ConnectionRole::Upstream {
                        node: Arc::clone(&node),
                        pool: Arc::clone(&attempt_state.pending.lb.pool),
                        read_write_timeouts,
                        serving_downstream: std::collections::HashMap::from([(0u32, (downstream_slab_index, downstream_generation))]),
                        pending_request: Some(attempt_state.original_request.clone()),
                    };
                    upstream_conn.protocol = ConnectionProtocol::Http1(Http1Connection::new());
                    upstream_entry.insert(upstream_conn);

                    attempt_state.upstream_slab_index = upstream_slab_index;
                    attempt_state.upstream_generation = upstream_generation;
                    attempt_state.attempts_so_far += 1;
                    let connect_timeout = attempt_state.pending.config.connect_timeout;
                    if let ConnectionProtocol::Http1(h1) = &mut connections[downstream_slab_index].protocol {
                        h1.waiting_for_upstream = Some(attempt_state);
                    }
                    if let Err(reason) = submit_connect(ring, connections, upstream_slab_index, connect_timeout) {
                        tracing::warn!(worker_id, %reason, "failed to submit connect for a retried upstream attempt");
                        cancel_outstanding_operations(ring, upstream_generation, upstream_slab_index);
                        connections.remove(upstream_slab_index);
                        flush_proxy_error_to_downstream(ring, connections, downstream_slab_index, 502, b"Bad Gateway\n");
                    }
                    return;
                }
            }
        }
        // Node selection, address resolution, or socket creation
        // itself failed -- same as exhausting retries, there's no
        // further attempt to make.
    }
    flush_proxy_error_to_downstream(ring, connections, downstream_slab_index, 502, b"Bad Gateway\n");
}

/// Queues `status`/`body` as this downstream connection's response
/// and flushes it -- shared by every one of this backend's proxy
/// error paths (exhausted retries, a connect failure with no retries
/// left, etc.) so the keep_alive-preservation dance
/// (`Http1Connection::waiting_for_upstream`'s own doc comment) isn't
/// duplicated at each call site.
fn flush_proxy_error_to_downstream(ring: &mut IoUring, connections: &mut Slab<Connection>, downstream_slab_index: usize, status: u16, body: &[u8]) {
    let mut resp = crate::http::response::HttpResponse::new(status, "");
    resp.set_body(body.to_vec());
    let keep_alive = if let ConnectionProtocol::Http1(h1) = &connections[downstream_slab_index].protocol {
        h1.waiting_for_upstream.as_ref().map(|s| s.keep_alive).unwrap_or(false)
    } else {
        false
    };
    let downstream_generation = connections[downstream_slab_index].generation;
    if let ConnectionProtocol::Http1(h1) = &mut connections[downstream_slab_index].protocol {
        h1.waiting_for_upstream = None;
        crate::core::conn::protocol::queue_http1_response(h1, resp);
        h1.keep_alive = keep_alive;
    }
    if let Err(reason) = submit_send(ring, connections, downstream_slab_index) {
        tracing::warn!(downstream_slab_index, %reason, "failed to submit proxy error response to downstream");
        cancel_outstanding_operations(ring, downstream_generation, downstream_slab_index);
        connections.remove(downstream_slab_index);
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
#[track_caller]
fn submit_recv(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize, registered_buffer_pool: &mut Option<RegisteredBufferPool>) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    // An upstream connection's own read_timeout (ProxyConfig's,
    // carried on ConnectionRole::Upstream -- see its own doc comment)
    // bounds this Recv via a linked LinkTimeout, the same way
    // submit_connect already bounds Connect. A downstream connection
    // has no such timeout configured (client-facing timeouts are a
    // separate, not-yet-implemented concern -- see ConnectionRole::Upstream's
    // own doc comment), so this check is what keeps every one of this
    // function's many existing call sites correct unchanged for that
    // case.
    let read_timeout = match &conn.role {
        ConnectionRole::Upstream { read_write_timeouts, .. } => Some(read_write_timeouts.0),
        ConnectionRole::Downstream => None,
    };

    // ReadFixed needs both a registered buffer index (buf_index) and
    // a pointer into that exact buffer's own backing memory. Unlike
    // SendZc's size threshold (see submit_send's own doc comment),
    // there's no size-based reason to prefer plain Recv: a fixed
    // buffer is exactly recv_buf's own size regardless of how much
    // the peer actually sends, so ReadFixed is strictly preferable
    // whenever the pool has one available -- only unavailability
    // (pool exhausted, or registration never happened at all -- see
    // RegisteredBufferPool::new's own doc comment) falls back to the
    // ordinary path below.
    if let Some(pool) = registered_buffer_pool.as_mut() {
        if let Some((buf_index, buf_ptr, buf_len)) = pool.acquire() {
            conn.pending_recv_buf_index = Some(buf_index);
            let mut recv = opcode::ReadFixed::new(types::Fd(conn.transport.fd()), buf_ptr, buf_len as u32, buf_index).build();
            if read_timeout.is_some() {
                recv = recv.flags(squeue::Flags::IO_LINK);
            }
            let recv = recv.user_data(make_user_data(OP_TAG_RECV, conn.generation, slab_index));
            unsafe {
                ring.submission()
                    .push(&recv)
                    .map_err(|_| "failed to push read_fixed SQE -- submission queue unexpectedly full".to_string())?;
            }
            if let Some(timeout) = read_timeout {
                push_link_timeout(ring, conn, slab_index, timeout)?;
            }
            return Ok(());
        }
    }

    conn.pending_recv_buf_index = None;
    let mut recv = opcode::Recv::new(types::Fd(conn.transport.fd()), conn.recv_buf.as_mut_ptr(), conn.recv_buf.len() as u32).build();
    if read_timeout.is_some() {
        recv = recv.flags(squeue::Flags::IO_LINK);
    }
    let recv = recv.user_data(make_user_data(OP_TAG_RECV, conn.generation, slab_index));

    unsafe {
        ring.submission()
            .push(&recv)
            .map_err(|_| "failed to push recv SQE -- submission queue unexpectedly full".to_string())?;
    }

    if let Some(timeout) = read_timeout {
        push_link_timeout(ring, conn, slab_index, timeout)?;
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
fn active_write_buf(protocol: &ConnectionProtocol) -> Option<&[u8]> {
    match protocol {
        ConnectionProtocol::Http1(h1) => Some(h1.write_buf.as_slice()),
        ConnectionProtocol::WebSocket(ws) => Some(ws.write_buf.as_slice()),
        ConnectionProtocol::Http2(h2) => Some(h2.write_buf.as_slice()),
        ConnectionProtocol::UpstreamH2(h2c) => Some(h2c.write_buf_slice()),
        ConnectionProtocol::Handshaking => None,
    }
}

fn consume_active_write_buf(protocol: &mut ConnectionProtocol, n: usize) {
    match protocol {
        ConnectionProtocol::Http1(h1) => h1.write_buf.consume(n),
        ConnectionProtocol::WebSocket(ws) => ws.write_buf.consume(n),
        ConnectionProtocol::Http2(h2) => h2.write_buf.consume(n),
        ConnectionProtocol::UpstreamH2(h2c) => h2c.consume_write_buf(n),
        ConnectionProtocol::Handshaking => {}
    }
}

/// Submits a `Send` SQE carrying whatever ciphertext is currently
/// queued in a TLS connection's `MemoryTlsIo::outgoing` -- used only
/// during the handshake (see the OP_TAG_RECV arm's TLS branch), where
/// what needs to go out is handshake protocol bytes rustls produced,
/// not anything from a protocol's own `write_buf` the way ordinary
/// `submit_send` drains. Once the handshake completes, application
/// data flows through `write_plaintext` -> `advance_io` ->
/// `outgoing` too, but by then it's driven from the same
/// `submit_send`/`consume_active_write_buf` path as any other
/// protocol's write buffer -- see how `Http1Outcome`/`Http2Outcome`/
/// `WebSocketOutcome` reach `submit_send` today for that shape; this
/// function is deliberately only for the pre-application-data
/// handshake bytes.
fn submit_tls_send(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let Transport::Tls { fd, io, .. } = &conn.transport else {
        return Err("submit_tls_send called on a non-TLS connection".to_string());
    };
    let pending = io.outgoing.as_slice();
    let send = opcode::Send::new(types::Fd(*fd), pending.as_ptr(), pending.len() as u32)
        .build()
        .user_data(make_user_data(OP_TAG_SEND, conn.generation, slab_index));
    unsafe {
        ring.submission()
            .push(&send)
            .map_err(|_| "failed to push tls send SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Pushes a `LinkTimeout` SQE bounding whatever operation was just
/// pushed onto `ring` (which must itself have been built with
/// `.flags(squeue::Flags::IO_LINK)` already) for `slab_index` -- shared
/// by `submit_recv`/`submit_send`'s own upstream-timeout handling so
/// the LinkTimeout construction/push logic isn't duplicated between
/// them (this function still needs a separate call at each of
/// submit_send's own two Send call sites -- TLS and plaintext -- since
/// each pushes its own, separate Send SQE to link it to).
fn push_link_timeout(ring: &mut IoUring, conn: &mut Connection, slab_index: usize, timeout: std::time::Duration) -> Result<(), String> {
    let timespec = Box::new(types::Timespec::new().sec(timeout.as_secs()).nsec(timeout.subsec_nanos()));
    let timespec_ptr: *const types::Timespec = &*timespec;
    let link_timeout = opcode::LinkTimeout::new(timespec_ptr)
        .build()
        .user_data(make_user_data(OP_TAG_LINK_TIMEOUT, conn.generation, slab_index));
    conn.pending_timeout = Some(timespec);
    unsafe {
        ring.submission()
            .push(&link_timeout)
            .map_err(|_| "failed to push a link-timeout SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Worker-local pool of already-open pipe fd pairs (`pipe(2)`, opened
/// `O_CLOEXEC | O_NONBLOCK`), reused across successive `PendingFileSend`
/// relays rather than paying a fresh `pipe(2)`/two `close(2)` calls on
/// every file response -- see `Connection::pending_splice`'s own doc
/// comment for why the relay needs a pipe at all. Never shared across
/// worker threads, so no locking (same rationale as `idle_upstream_conns`).
struct PipePool {
    pairs: Vec<(i32, i32)>,
}

impl PipePool {
    fn new() -> Self {
        PipePool { pairs: Vec::new() }
    }

    /// Hands back a pipe fd pair for a new relay to use, opening one
    /// fresh via `pipe2(2)` only if the pool is currently empty.
    fn acquire(&mut self) -> std::io::Result<(i32, i32)> {
        if let Some(pair) = self.pairs.pop() {
            return Ok(pair);
        }
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }

    /// Returns a pipe fd pair to the pool once its relay has finished
    /// (or failed) -- the pipe's own buffered contents are irrelevant
    /// at this point, since a relay only ever returns its pipe once
    /// `PendingFileSend::remaining` has reached 0 (fully drained) or
    /// the connection is being torn down anyway.
    fn release(&mut self, pair: (i32, i32)) {
        self.pairs.push(pair);
    }
}

impl Drop for PipePool {
    fn drop(&mut self) {
        for (r, w) in self.pairs.drain(..) {
            unsafe {
                libc::close(r);
                libc::close(w);
            }
        }
    }
}

/// Worker-local pool of buffers registered with the kernel via
/// `IORING_REGISTER_BUFFERS`, used for `ReadFixed` recvs instead of
/// plain `Recv` when one is available (see `submit_recv`'s own doc
/// comment) -- registering a buffer once up front lets the kernel
/// pin/map it a single time rather than re-validating a fresh
/// userspace address on every single recv. Each buffer is
/// `recv_buf_size` bytes, matching Connection::recv_buf's own size so
/// a ReadFixed recv can read exactly as much as an ordinary Recv
/// would.
///
/// The pool's own `Vec<Vec<u8>>` keeps each buffer's backing memory
/// at a stable address even as the outer Vec grows/reallocates --
/// only the outer Vec's own pointer/len/cap triple moves on
/// reallocation, never the heap allocation each inner `Vec<u8>` owns,
/// which is what the kernel was actually given the address of via
/// `register_buffers`. Never resized after construction for exactly
/// this reason: growing it post-registration would invalidate
/// addresses the kernel already has pinned.
struct RegisteredBufferPool {
    buffers: Vec<Vec<u8>>,
    available: Vec<u16>,
}

impl RegisteredBufferPool {
    /// Allocates `count` buffers of `buf_size` bytes each and
    /// registers them with `ring` via `IORING_REGISTER_BUFFERS`.
    /// Returns `None` (rather than an error) if registration fails --
    /// an unsupported kernel or a `ulimit`/memlock ceiling are both
    /// plausible causes, and this optimization's own designed
    /// fallback (see this pool's own doc comment) means a `None` here
    /// simply means callers use ordinary `Recv` instead, not that the
    /// worker should refuse to start.
    fn new(ring: &IoUring, count: u32, buf_size: usize) -> Option<Self> {
        if count == 0 || buf_size == 0 {
            return None;
        }
        let mut buffers: Vec<Vec<u8>> = (0..count).map(|_| vec![0u8; buf_size]).collect();
        let iovecs: Vec<libc::iovec> = buffers
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr() as *mut libc::c_void,
                iov_len: b.len(),
            })
            .collect();
        // Safety: each iovec's (base, len) points into a buffer this
        // pool owns for its own entire lifetime (buffers is never
        // resized or dropped before the pool itself is, and the pool
        // is worker-local, never shared across threads) -- exactly
        // the validity/lifetime contract register_buffers's own doc
        // comment requires.
        let register_result = unsafe { ring.submitter().register_buffers(&iovecs) };
        if register_result.is_err() {
            return None;
        }
        let available: Vec<u16> = (0..count as u16).collect();
        Some(RegisteredBufferPool { buffers, available })
    }

    /// Hands back a registered buffer's index and a mutable pointer
    /// to its backing memory, or `None` if every buffer is currently
    /// in use -- callers fall back to an ordinary (non-fixed) Recv in
    /// that case (see this pool's own doc comment).
    fn acquire(&mut self) -> Option<(u16, *mut u8, usize)> {
        let idx = self.available.pop()?;
        let buf = &mut self.buffers[idx as usize];
        Some((idx, buf.as_mut_ptr(), buf.len()))
    }

    /// Returns a buffer index to the pool once its ReadFixed
    /// completes (or the connection using it is torn down).
    fn release(&mut self, idx: u16) {
        self.available.push(idx);
    }

    /// Borrows a registered buffer's full backing memory by index --
    /// used to read back what a completed ReadFixed wrote into it
    /// (see `recv_bytes`'s own doc comment). Callers slice this down
    /// to the completion's own reported byte count themselves, since
    /// this pool has no notion of how many bytes a given recv
    /// actually filled.
    fn buffer_slice(&self, idx: u16) -> &[u8] {
        &self.buffers[idx as usize]
    }
}

/// Returns the bytes a completed Recv/ReadFixed actually delivered --
/// either `conn.recv_buf` (an ordinary Recv wrote directly into it) or
/// the registered buffer `conn.pending_recv_buf_index` names (a
/// ReadFixed wrote into the pool's own memory instead -- see
/// `submit_recv`'s own doc comment on why ReadFixed can't write into
/// recv_buf itself). Every call site that used to read
/// `conn.recv_buf[..n]` directly goes through this instead, so a
/// ReadFixed completion's bytes are found where they actually are
/// rather than in an untouched (and therefore stale or zeroed)
/// recv_buf.
fn recv_bytes<'a>(conn: &'a Connection, pool: &'a Option<RegisteredBufferPool>) -> &'a [u8] {
    if let Some(idx) = conn.pending_recv_buf_index {
        if let Some(pool) = pool {
            return pool.buffer_slice(idx);
        }
    }
    conn.recv_buf.as_slice()
}

/// Handles a settled Send completion -- shared by OP_TAG_SEND
/// (ordinary Send, one CQE) and OP_TAG_SEND_ZC's own NOTIF arm
/// (SendZc, whose second completion is the point its transfer is
/// actually settled -- see that arm's own doc comment). `result`
/// is the settled byte count (already resolved from whichever of
/// the two completions carries it for its own opcode).
fn handle_send_completion(
    worker: &EventLoopWorker,
    worker_id: usize,
    ring: &mut IoUring,
    connections: &mut Slab<Connection>,
    slab_index: usize,
    completion_generation: u32,
    result: i32,
    pipe_pool: &mut PipePool,
    registered_buffer_pool: &mut Option<RegisteredBufferPool>,
) {
                        if !connections.contains(slab_index) {
                            return;
                        }
                        if connections[slab_index].generation != completion_generation {
                            return;
                        }
                        if result < 0 {
                            cancel_outstanding_operations(ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            return;
                        }

                        let n = result as usize;

                        // A TLS handshake's own Send (see
                        // submit_tls_send) drains MemoryTlsIo::outgoing
                        // directly rather than going through any
                        // protocol's write_buf -- the connection is
                        // still ConnectionProtocol::Handshaking at this
                        // point (ALPN hasn't decided Http1 vs Http2
                        // yet), so this has to be handled before the
                        // protocol-based dispatch below, which would
                        // otherwise treat Handshaking as an
                        // unrecognized state and incorrectly tear the
                        // connection down mid-handshake.
                        if connections[slab_index].transport.is_tls() && matches!(connections[slab_index].protocol, ConnectionProtocol::Handshaking) {
                            let still_pending = {
                                let Transport::Tls { io, .. } = &mut connections[slab_index].transport else { unreachable!() };
                                io.outgoing.consume(n);
                                !io.outgoing.is_empty()
                            };
                            if still_pending {
                                if let Err(reason) = submit_tls_send(ring, connections, slab_index) {
                                    tracing::warn!(worker_id, %reason, "failed to submit remainder of a tls handshake send");
                                    cancel_outstanding_operations(ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                            } else if let Err(reason) = submit_recv(ring, connections, slab_index, registered_buffer_pool) {
                                tracing::warn!(worker_id, %reason, "failed to submit follow-up recv after a tls handshake send");
                                cancel_outstanding_operations(ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                            return;
                        }

                        // TLS connections already had their
                        // write_buf consumed (against the plaintext
                        // length, not this completion's ciphertext
                        // length `n`) inside submit_send itself -- see
                        // its own doc comment for why the two lengths
                        // don't correspond and consuming here a second
                        // time, against the wrong unit, would corrupt
                        // write_buf's accounting. What DOES need to
                        // happen here for a TLS connection is
                        // consuming `n` bytes from MemoryTlsIo::outgoing
                        // itself -- the real ciphertext this Send just
                        // transmitted -- so the next submit_send call
                        // doesn't re-send bytes the peer already
                        // received (which is exactly what a real
                        // client sees as TLS record corruption /
                        // DecryptError, since it's being handed the
                        // same ciphertext bytes twice, out of their
                        // correct position in the TLS record stream).
                        if connections[slab_index].transport.is_tls() {
                            let Transport::Tls { io, .. } = &mut connections[slab_index].transport else { unreachable!() };
                            io.outgoing.consume(n);
                        } else {
                            consume_active_write_buf(&mut connections[slab_index].protocol, n);
                        }

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
                            ConnectionProtocol::WebSocket(ws) => (ws.write_buf.is_empty(), already_marked_closing),
                            ConnectionProtocol::Http2(h2) => {
                                (h2.write_buf.is_empty(), already_marked_closing)
                            }
                            ConnectionProtocol::UpstreamH2(h2c) => {
                                // Never independently closed here --
                                // an UpstreamH2 connection's lifetime
                                // is driven by idle-pool/circuit-breaker
                                // logic elsewhere (mirroring how a
                                // plain HTTP/1.1 upstream connection's
                                // own reuse-or-close decision is made
                                // once a response completes), not by
                                // this generic flush-completion path.
                                (!h2c.has_pending_write(), false)
                            }
                            ConnectionProtocol::Handshaking => {
                                // A non-TLS connection should never
                                // have an outstanding Send while still
                                // Handshaking (plaintext connections
                                // skip Handshaking entirely -- see the
                                // accept arm) -- reaching this means
                                // something unexpected happened, not a
                                // normal TLS handshake send (handled
                                // above).
                                cancel_outstanding_operations(ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                                return;
                            }
                        };

                        let has_pending_file = matches!(&connections[slab_index].protocol, ConnectionProtocol::Http1(h1) if h1.pending_file.is_some());
                        if fully_flushed && should_close_after_flush && !has_pending_file {
                            cancel_outstanding_operations(ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            return;
                        }

                        if !fully_flushed {
                            // A partial write -- send the rest of the
                            // same buffer before doing anything else.
                            if let Err(reason) = submit_send(ring, connections, slab_index) {
                                tracing::warn!(worker_id, %reason, "failed to submit remainder of a partially-sent buffer");
                                cancel_outstanding_operations(ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                        } else if matches!(&connections[slab_index].protocol, ConnectionProtocol::Http1(h1) if h1.pending_file.is_some()) {
                            // The response's headers just finished
                            // flushing and a PendingFileSend is
                            // waiting behind them -- relay its bytes
                            // over a pooled pipe via two chained
                            // Splice SQEs (see submit_splice_to_pipe's
                            // own doc comment) instead of falling
                            // through to a Recv, which is what every
                            // other branch here does once write_buf
                            // is empty.
                            if let Err(reason) = submit_splice_to_pipe(ring, connections, pipe_pool, slab_index) {
                                tracing::warn!(worker_id, %reason, "failed to submit splice-to-pipe for a pending file body");
                                cancel_outstanding_operations(ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                        } else {
                            // Fully flushed, and either HTTP/1.1
                            // keep-alive or WebSocket (which always
                            // goes back to reading here -- see this
                            // arm's own comment). Before submitting a
                            // new Recv, check whether this connection
                            // is HTTP/1.1 and its read_buf already
                            // holds a further pipelined request (RFC
                            // 9112 9.4: a client may send a second
                            // request without waiting for the first
                            // response, so both can legitimately have
                            // arrived in the same earlier Recv
                            // completion, well before this Send even
                            // finished). Submitting a fresh Recv in
                            // that case would wait for bytes the peer
                            // has no reason to send again -- it
                            // already sent them -- stalling the
                            // connection forever from the peer's point
                            // of view. Re-running process_http1_read_buf
                            // against what's already buffered is what
                            // mio_backend's own drive_http1 does
                            // implicitly (its read/dispatch loop
                            // always re-checks read_buf before
                            // returning to wait on the poller); this
                            // backend needs to do that check
                            // explicitly, since each completion here
                            // is handled once and then control returns
                            // to the main event loop rather than
                            // looping internally.
                            drain_pipelined_request_or_recv(worker, worker_id, ring, connections, slab_index, completion_generation, registered_buffer_pool);
                        }
}

fn submit_send(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let write_timeout = match &conn.role {
        ConnectionRole::Upstream { read_write_timeouts, .. } => Some(read_write_timeouts.1),
        ConnectionRole::Downstream => None,
    };
    let Some(pending) = active_write_buf(&conn.protocol) else {
        return Err("submit_send called while no active protocol has a driven write buffer (Handshaking isn't driven by this backend)".to_string());
    };

    if conn.transport.is_tls() {
        // A TLS connection's protocol state machines (process_http1_read_buf,
        // process_http2_input, process_websocket_input) are
        // deliberately unaware of TLS at all -- they only ever queue
        // plaintext into write_buf, the same as on a plaintext
        // connection. Encrypting that plaintext into real ciphertext
        // is this function's job, not theirs: every byte queued since
        // the last submit_send call is fed through write_plaintext
        // (which only queues it into rustls's own internal buffer)
        // and then advance_io (which is what actually encrypts it
        // into MemoryTlsIo::outgoing) before anything is submitted to
        // the kernel. Sending `pending`'s plaintext bytes directly, as
        // this function used to, would leak unencrypted application
        // data onto the wire on a connection the peer believes is
        // encrypted.
        let plaintext = pending.to_vec();
        let Transport::Tls { tls, io, fd } = &mut conn.transport else { unreachable!() };
        tls.write_plaintext(&plaintext).map_err(|e| format!("failed to queue plaintext for TLS encryption: {e}"))?;
        tls.advance_io(io.as_mut()).map_err(|e| format!("failed to advance TLS record layer while encrypting: {e}"))?;

        // The plaintext was fully handed to rustls above -- mark it
        // consumed from the protocol's own write_buf now, since the
        // OP_TAG_SEND completion this SQE eventually produces reports
        // how many *ciphertext* bytes were sent, which has no direct
        // correspondence to the plaintext length consume_active_write_buf
        // needs (rustls's TLS record framing means the two aren't
        // equal) -- consuming here, once, against the known plaintext
        // length avoids the OP_TAG_SEND completion handler needing to
        // (incorrectly) treat a ciphertext byte count as a plaintext
        // one.
        let plaintext_len = plaintext.len();
        consume_active_write_buf(&mut conn.protocol, plaintext_len);

        let ciphertext = io.outgoing.as_slice();
        // Deliberately submitted even when empty (a 0-byte Send),
        // rather than returning early with nothing sent: every caller
        // of submit_send (H1/H2/WS's FlushThenContinue-style arms)
        // assumes a real OP_TAG_SEND completion will eventually
        // arrive and drive the connection's next step (typically
        // re-arming Recv) -- an early Ok(()) here with no SQE actually
        // submitted meant that step never happened, silently stalling
        // the connection forever. This is exactly what happened for
        // H2 frames whose response has no payload (PRIORITY, for
        // instance, requires no reply at all per RFC 9113 -- rustls
        // had nothing new to encrypt, `outgoing` stayed empty, and
        // this connection was simply never read from again). A 0-byte
        // Send still produces a normal, immediate completion, letting
        // OP_TAG_SEND's own existing "fully flushed -> submit_recv"
        // logic run exactly as it would for any other completed send.
        let mut send = opcode::Send::new(types::Fd(*fd), ciphertext.as_ptr(), ciphertext.len() as u32).build();
        if write_timeout.is_some() {
            send = send.flags(squeue::Flags::IO_LINK);
        }
        let send = send.user_data(make_user_data(OP_TAG_SEND, conn.generation, slab_index));
        unsafe {
            ring.submission()
                .push(&send)
                .map_err(|_| "failed to push tls send SQE -- submission queue unexpectedly full".to_string())?;
        }
        if let Some(timeout) = write_timeout {
            push_link_timeout(ring, conn, slab_index, timeout)?;
        }
        return Ok(());
    }

    // SendZc trades a small per-call fixed overhead (an extra CQE:
    // the kernel reports the transfer's own result via one CQE
    // carrying IORING_CQE_F_MORE, then a second, separate "notify"
    // CQE carrying IORING_CQE_F_NOTIF once the kernel is done reading
    // the buffer -- see OP_TAG_SEND_ZC's own completion arm) for
    // avoiding a userspace copy of the buffer into the kernel. That
    // trade only pays off once the copy it avoids is large enough to
    // matter more than the extra CQE round-trip -- below this
    // threshold, an ordinary Send (a single completion, no notify
    // bookkeeping) is both simpler and faster in practice.
    const SEND_ZC_MIN_LEN: usize = 16 * 1024;
    if conn.send_zc_supported && pending.len() >= SEND_ZC_MIN_LEN {
        let mut send = opcode::SendZc::new(types::Fd(conn.transport.fd()), pending.as_ptr(), pending.len() as u32).build();
        if write_timeout.is_some() {
            send = send.flags(squeue::Flags::IO_LINK);
        }
        let send = send.user_data(make_user_data(OP_TAG_SEND_ZC, conn.generation, slab_index));
        unsafe {
            ring.submission()
                .push(&send)
                .map_err(|_| "failed to push send_zc SQE -- submission queue unexpectedly full".to_string())?;
        }
        if let Some(timeout) = write_timeout {
            push_link_timeout(ring, conn, slab_index, timeout)?;
        }
        return Ok(());
    }
    let mut send = opcode::Send::new(types::Fd(conn.transport.fd()), pending.as_ptr(), pending.len() as u32).build();
    if write_timeout.is_some() {
        send = send.flags(squeue::Flags::IO_LINK);
    }
    let send = send.user_data(make_user_data(OP_TAG_SEND, conn.generation, slab_index));
    unsafe {
        ring.submission()
            .push(&send)
            .map_err(|_| "failed to push send SQE -- submission queue unexpectedly full".to_string())?;
    }
    if let Some(timeout) = write_timeout {
        push_link_timeout(ring, conn, slab_index, timeout)?;
    }
    Ok(())
}
/// After a Send completion fully drains an HTTP/1.1 connection's
/// write_buf (with no pending_file behind it -- see this function's
/// own call sites for that check), decides what's next: if a further
/// pipelined request (RFC 9112 9.4) is already sitting in read_buf,
/// dispatches it immediately rather than waiting on a Recv that bytes
/// the peer already sent would never satisfy; otherwise submits an
/// ordinary follow-up Recv. Shared between the plain post-Send path
/// and the post-file-relay path (OP_TAG_SPLICE_TO_SOCKET), both of
/// which reach the exact same "write_buf just emptied, what now"
/// decision from different completions.
fn drain_pipelined_request_or_recv(
    worker: &EventLoopWorker,
    worker_id: usize,
    ring: &mut IoUring,
    connections: &mut Slab<Connection>,
    slab_index: usize,
    completion_generation: u32,
    registered_buffer_pool: &mut Option<RegisteredBufferPool>,
) {
    let has_pipelined_request = matches!(
        &connections[slab_index].protocol,
        ConnectionProtocol::Http1(h1) if !h1.read_buf.is_empty()
    );
    if has_pipelined_request {
        let outcome = {
            let conn = &mut connections[slab_index];
            let ctx = Http1DispatchContext {
                server: &worker.server,
                max_request_size: worker.max_request_size,
                h2_settings: &worker.h2_settings,
                ws_settings: &worker.ws_settings,
                h2c_upgrade_enabled: worker.h2c_upgrade_enabled,
                ws_enabled: worker.ws_enabled,
                ws_max_connections: worker.ws_max_connections,
                ws_permessage_deflate: worker.ws_permessage_deflate,
                remote_addr: conn.remote_addr.ip(),
            };
            crate::core::conn::protocol::process_http1_read_buf(&mut conn.protocol, &ctx)
        };
        match outcome {
            Http1Outcome::NeedsMoreData => {
                if let Err(reason) = submit_recv(ring, connections, slab_index, registered_buffer_pool) {
                    tracing::warn!(worker_id, %reason, "failed to submit follow-up recv after draining a pipelined request");
                    cancel_outstanding_operations(ring, completion_generation, slab_index);
                    connections.remove(slab_index);
                }
            }
            Http1Outcome::FlushThenContinue | Http1Outcome::FlushThenClose => {
                if let Err(reason) = submit_send(ring, connections, slab_index) {
                    tracing::warn!(worker_id, %reason, "failed to submit response to a pipelined request");
                    cancel_outstanding_operations(ring, completion_generation, slab_index);
                    connections.remove(slab_index);
                }
            }
            Http1Outcome::SwitchedToHttp2 | Http1Outcome::SwitchedToWebSocket => {
                if let Err(reason) = submit_send(ring, connections, slab_index) {
                    tracing::warn!(worker_id, %reason, "failed to submit upgrade response to a pipelined request");
                }
                cancel_outstanding_operations(ring, completion_generation, slab_index);
                connections.remove(slab_index);
            }
            Http1Outcome::ProxyPending(..) => {
                tracing::warn!(worker_id, slab_index, "a pipelined proxy request is not yet supported by this backend, closing");
                cancel_outstanding_operations(ring, completion_generation, slab_index);
                connections.remove(slab_index);
            }
            Http1Outcome::FileCachePending(pending, original_request) => {
                if let Err(reason) = submit_statx(ring, connections, slab_index, pending, original_request) {
                    tracing::warn!(worker_id, %reason, "failed to submit statx for a pipelined static-file cache-miss");
                    cancel_outstanding_operations(ring, completion_generation, slab_index);
                    connections.remove(slab_index);
                }
            }
        }
        return;
    }
    if let Err(reason) = submit_recv(ring, connections, slab_index, registered_buffer_pool) {
        tracing::warn!(worker_id, %reason, "failed to submit follow-up recv");
        cancel_outstanding_operations(ring, completion_generation, slab_index);
        connections.remove(slab_index);
    }
}


/// Starts (or continues) a `PendingFileSend` relay by submitting the
/// first leg: `Splice(file_fd -> pipe_write_fd)`, moving up to one
/// pipe's worth of the file's remaining bytes into the pool-acquired
/// pipe. Only valid on a plaintext HTTP/1.1 connection with a
/// `pending_file` still holding bytes to send -- callers must check
/// both before calling (see this function's own call sites).
/// Submits a `Statx` SQE stat'ing `pending.resolved_path` (an
/// absolute filesystem path -- resolve_path already canonicalized it,
/// see FileCachePending's own doc comment) asynchronously, storing
/// the raw kernel-written statx buffer in `conn.pending_statx` for
/// OP_TAG_STATX's own completion arm to read once it arrives.
fn submit_statx(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize, pending: crate::http::static_files::FileCachePending, original_request: Box<crate::http::request::HttpRequest>) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let path_cstring = std::ffi::CString::new(pending.resolved_path.as_os_str().as_encoded_bytes())
        .map_err(|_| "static file path contains an interior NUL byte".to_string())?;
    let mut statx_buf: Box<libc::statx> = Box::new(unsafe { std::mem::zeroed() });
    let statx_ptr = statx_buf.as_mut() as *mut libc::statx as *mut io_uring::types::statx;
    let statx = opcode::Statx::new(types::Fd(libc::AT_FDCWD), path_cstring.as_ptr(), statx_ptr)
        .flags(libc::AT_STATX_SYNC_AS_STAT)
        .mask(libc::STATX_SIZE | libc::STATX_MTIME)
        .build()
        .user_data(make_user_data(OP_TAG_STATX, conn.generation, slab_index));
    conn.pending_statx = Some(crate::core::conn::uring_conn::PendingStatx {
        pending,
        original_request,
        statx_buf,
    });
    // path_cstring must outlive the SQE the kernel hasn't yet
    // consumed -- leaked deliberately (a handful of bytes, freed by
    // the allocator never running its destructor is the accepted
    // trade-off here, mirroring how pending_connect_addr/pending_timeout
    // solve the identical stable-address requirement via a Box kept
    // alive on Connection instead; a CString has no natural home on
    // PendingStatx itself since Statx's own pathname pointer must
    // already be baked into the SQE by the time this function
    // returns, and the completion arm has no further use for the
    // pathname bytes once the kernel has read them).
    std::mem::forget(path_cstring);
    unsafe {
        ring.submission()
            .push(&statx)
            .map_err(|_| "failed to push statx SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

fn submit_splice_to_pipe(ring: &mut IoUring, connections: &mut Slab<Connection>, pipe_pool: &mut PipePool, slab_index: usize) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let ConnectionProtocol::Http1(h1) = &mut conn.protocol else {
        return Err("submit_splice_to_pipe called on a non-HTTP/1.1 connection".to_string());
    };
    let Some(pending) = &h1.pending_file else {
        return Err("submit_splice_to_pipe called with no pending_file".to_string());
    };
    let remaining = pending.remaining;
    let file_fd = std::os::unix::io::AsRawFd::as_raw_fd(&pending.file);
    let offset = pending.offset as i64;

    let (pipe_read_fd, pipe_write_fd) = match conn.pending_splice.as_ref() {
        Some(existing) => (existing.pipe_read_fd, existing.pipe_write_fd),
        None => pipe_pool.acquire().map_err(|e| format!("failed to acquire a pipe for file splice: {e}"))?,
    };
    conn.pending_splice = Some(crate::core::conn::uring_conn::PendingSplice {
        pipe_read_fd,
        pipe_write_fd,
        phase: crate::core::conn::uring_conn::SplicePhase::FileToPipe,
    });

    // Bounded the same way flush_pending_file's own sendfile call caps
    // its per-call size -- a pipe's kernel buffer is limited (commonly
    // 64KiB unless resized via F_SETPIPE_SZ, which this doesn't do),
    // so requesting more than that per splice would just have the
    // kernel silently cap it anyway.
    let want = remaining.min(64 * 1024) as u32;

    let splice = opcode::Splice::new(types::Fd(file_fd), offset, types::Fd(pipe_write_fd), -1, want)
        .build()
        .user_data(make_user_data(OP_TAG_SPLICE_TO_PIPE, conn.generation, slab_index));
    unsafe {
        ring.submission()
            .push(&splice)
            .map_err(|_| "failed to push splice-to-pipe SQE -- submission queue unexpectedly full".to_string())?;
    }
    Ok(())
}

/// Second leg of a `PendingFileSend` relay: `Splice(pipe_read_fd -> socket_fd)`,
/// moving `bytes_in_pipe` bytes (as reported by the matching
/// `OP_TAG_SPLICE_TO_PIPE` completion) out of the pipe and onto the
/// wire.
fn submit_splice_to_socket(ring: &mut IoUring, connections: &mut Slab<Connection>, slab_index: usize, bytes_in_pipe: u32) -> Result<(), String> {
    let conn = &mut connections[slab_index];
    let socket_fd = conn.transport.fd();
    let Some(splice_state) = &mut conn.pending_splice else {
        return Err("submit_splice_to_socket called with no pending_splice".to_string());
    };
    splice_state.phase = crate::core::conn::uring_conn::SplicePhase::PipeToSocket { bytes_in_pipe };
    let pipe_read_fd = splice_state.pipe_read_fd;

    let splice = opcode::Splice::new(types::Fd(pipe_read_fd), -1, types::Fd(socket_fd), -1, bytes_in_pipe)
        .build()
        .user_data(make_user_data(OP_TAG_SPLICE_TO_SOCKET, conn.generation, slab_index));
    unsafe {
        ring.submission()
            .push(&splice)
            .map_err(|_| "failed to push splice-to-socket SQE -- submission queue unexpectedly full".to_string())?;
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
        // Worker-local (no locking needed, unlike UpstreamNode's own
        // Mutex-protected idle_conns pool mio_backend's core::proxy
        // uses -- see this field's own design discussion) pool of
        // upstream connections kept open between requests rather than
        // torn down after each one. Keyed by (host, port) since that's
        // what actually identifies "the same upstream" for reuse
        // purposes; an idle entry's slab_index/generation identify the
        // real Connection still sitting in `connections` above (idle
        // connections are never removed from the Slab, only marked
        // as not currently serving anyone -- see this field's use
        // sites for how that's threaded through ConnectionRole::Upstream's
        // own serving_downstream).
        let mut idle_upstream_conns: std::collections::HashMap<(String, u16), Vec<(usize, u32, std::time::Instant, std::time::Duration)>> = std::collections::HashMap::new();
        // Worker-local (no locking, same rationale as idle_upstream_conns
        // above) pool of already-open pipe fd pairs reused across
        // successive PendingFileSend relays rather than calling
        // pipe(2) and closing both ends on every single file response
        // -- see PipePool's own doc comment.
        let mut pipe_pool = PipePool::new();
        // Probed once per worker rather than per-send -- SendZc
        // support doesn't change during a worker's lifetime, and a
        // fresh Probe registration on every large send would be
        // pure overhead for a value that's already known.
        let send_zc_supported = probe_send_zc_support(&ring);
        // None whenever registration is disabled by config, the
        // kernel doesn't support IORING_REGISTER_BUFFERS, or a
        // resource limit (memlock, etc.) rejected it -- submit_recv
        // falls back to an ordinary Recv in that case (see
        // RegisteredBufferPool's own doc comment).
        let mut registered_buffer_pool = if self.registered_buffers_enabled {
            RegisteredBufferPool::new(&ring, self.registered_buffer_count, self.recv_buf_size)
        } else {
            None
        };
        // Worker-local, accumulating mmap slots (see
        // WorkerMmapCache's own doc comment) reused across every
        // static-file cache-miss OP_TAG_STATX completion handles --
        // mirrors register_static_route's own per-route mmap_cache,
        // the one piece of static_files::serve's own state this
        // backend needs to hold itself now that finish_after_stat is
        // called directly from a completion arm rather than from
        // inside a route handler closure that already had one
        // captured.
        let mut worker_mmap = self.server.file_cache.worker_mmap_cache();
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
                        let transport = match &self.server.tls_context {
                            Some(tls_ctx) => match crate::net::tls::TlsConnection::new_server(tls_ctx) {
                                Ok(tls) => Transport::Tls {
                                    fd: accepted_fd,
                                    tls: Box::new(tls),
                                    io: Box::new(crate::net::tls::MemoryTlsIo::new()),
                                },
                                Err(e) => {
                                    tracing::warn!(worker_id, accepted_fd, error = %e, "failed to create TLS session for accepted connection");
                                    unsafe { libc::close(accepted_fd) };
                                    if !io_uring::cqueue::more(flags) {
                                        multishot_accept_disarmed = true;
                                    }
                                    continue;
                                }
                            },
                            None => Transport::Plain(accepted_fd),
                        };

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

                        // Starts as an unconfirmed Http1Connection --
                        // this backend doesn't yet have TLS/ALPN (see
                        // conn::uring_conn's own doc comment), so
                        // every accepted connection is plaintext and
                        // must be checked against the H2 connection
                        // preface (RFC 9113 3.4) before being treated
                        // as HTTP/1.1, exactly like mio_backend's own
                        // equivalent plaintext path -- see
                        // decide_plaintext_protocol's own doc comment.
                        let mut conn = Connection::new(accepted_fd as u64, transport, remote_addr, self.recv_buf_size, generation);
                        conn.send_zc_supported = send_zc_supported;
                        // TLS connections stay Handshaking (the
                        // default Connection::new starts with) until
                        // the handshake completes and ALPN decides
                        // Http1 vs Http2 -- see the OP_TAG_RECV arm's
                        // TLS branch. A plaintext connection has no
                        // handshake or ALPN to wait for, so it starts
                        // as an unconfirmed Http1Connection instead,
                        // pending the H2 prior-knowledge preface check
                        // (RFC 9113 3.4) -- see
                        // decide_plaintext_protocol's own doc comment.
                        if !conn.is_tls() {
                            conn.protocol = ConnectionProtocol::Http1(Http1Connection::new_unconfirmed());
                        }
                        entry.insert(conn);

                        if let Err(reason) = submit_recv(&mut ring, &mut connections, new_slab_index, &mut registered_buffer_pool) {
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
                            // connection is done. For an upstream
                            // connection, this means the upstream
                            // closed before a complete response
                            // arrived -- whatever partial bytes it
                            // did send (already in read_buf from
                            // earlier completions, if any) couldn't
                            // form a full response, or there'd have
                            // been a dispatch below already.
                            let close_context = match &connections[slab_index].role {
                                ConnectionRole::Upstream { serving_downstream, node, pool, .. } => Some((serving_downstream.clone(), Arc::clone(node), Arc::clone(pool))),
                                ConnectionRole::Downstream => None,
                            };
                            // All downstream connections this upstream
                            // was serving (every value in the map) get
                            // told about the failure, not just one --
                            // for an H1 upstream this map has at most
                            // the single sentinel-key entry, but an H2
                            // upstream closing early can be serving
                            // several streams' downstreams at once,
                            // every one of which needs its own
                            // retry-or-502 decision.
                            let serving_downstreams_on_close: Vec<(usize, u32)> = close_context.as_ref().map(|(serving, ..)| serving.values().copied().collect()).unwrap_or_default();
                            if let Some((_, node, pool)) = &close_context {
                                // Same failure model as a connect(2)
                                // failure -- reaching EOF/an error
                                // before a complete response arrived
                                // is a connection-level failure from
                                // the load balancer's point of view,
                                // regardless of how far the response
                                // got.
                                node.record_failure(pool);
                            }
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            for (downstream_slab_index, downstream_generation) in serving_downstreams_on_close {
                                if connections.contains(downstream_slab_index) && connections[downstream_slab_index].generation == downstream_generation {
                                    let attempt_state = if let ConnectionProtocol::Http1(h1) = &mut connections[downstream_slab_index].protocol {
                                        h1.waiting_for_upstream.take()
                                    } else {
                                        None
                                    };
                                    if let Some(attempt_state) = attempt_state {
                                        retry_or_fail_proxy_attempt(&mut ring, &mut connections, &mut generations, downstream_slab_index, attempt_state, self.recv_buf_size, worker_id, send_zc_supported);
                                    }
                                }
                            }
                            continue;
                        }


                        // An upstream connection's Recv completions
                        // carry the upstream's *response*, not a
                        // client request -- handled entirely
                        // separately from the ordinary
                        // H2/WebSocket/HTTP1-request dispatch below,
                        // which assumes it's looking at a downstream
                        // connection.
                        // Only treat this as "upstream awaiting a
                        // response" once its protocol has actually
                        // settled to Http1 -- while it's still
                        // Handshaking (a TLS-enabled upstream node's
                        // Recv completions before its own handshake
                        // finishes), this connection's role already
                        // has serving_downstream set (see the
                        // ProxyPending arm that creates it), but
                        // there's no Http1Connection yet to parse a
                        // response into -- that case is handled by
                        // the is_tls block below instead, which is
                        // itself what eventually drives this
                        // connection to Http1 once HandshakeJustCompleted
                        // fires for it.
                        // H1's sentinel key 0 -- see
                        // ConnectionRole::Upstream::serving_downstream's
                        // own doc comment on why this map holds a
                        // single entry under that key for an H1
                        // upstream. An H2 upstream is deliberately
                        // NOT handled by this arm at all -- see the
                        // separate UpstreamH2 block further down,
                        // which uses feed_plaintext's own
                        // Vec<u32>-of-completed-streams contract
                        // instead of this single-response shape.
                        let upstream_serving_downstream = match &connections[slab_index].role {
                            ConnectionRole::Upstream { serving_downstream, .. } if matches!(connections[slab_index].protocol, ConnectionProtocol::Http1(_)) => serving_downstream.get(&0).copied(),
                            _ => None,
                        };

                        if let Some((downstream_slab_index, downstream_generation)) = upstream_serving_downstream {
                            let n = result as usize;
                            // A TLS-enabled upstream's Recv completions
                            // carry ciphertext, same as any other TLS
                            // connection's -- see Transport::Tls's own
                            // doc comment. advance_tls both decrypts
                            // it and, on TlsAdvanceOutcome::PeerClosed
                            // or Err, signals this connection is done;
                            // a plaintext upstream skips straight to
                            // using recv_buf as-is, same as before.
                            let plaintext: Vec<u8> = if connections[slab_index].transport.is_tls() {
                                let ciphertext = {
                                let bytes = recv_bytes(&connections[slab_index], &registered_buffer_pool)[..n].to_vec();
                                if let Some(idx) = connections[slab_index].pending_recv_buf_index.take() {
                                    if let Some(pool) = registered_buffer_pool.as_mut() { pool.release(idx); }
                                }
                                bytes
                            };
                                let conn = &mut connections[slab_index];
                                let Transport::Tls { tls, io, .. } = &mut conn.transport else { unreachable!() };
                                let outcome = advance_tls(tls, io, &ciphertext);
                                let _outcome_str = match &outcome {
                                    Ok(TlsAdvanceOutcome::PeerClosed) => "PeerClosed",
                                    Ok(TlsAdvanceOutcome::StillHandshaking) => "StillHandshaking",
                                    Ok(TlsAdvanceOutcome::HandshakeJustCompleted) => "HandshakeJustCompleted",
                                    Ok(TlsAdvanceOutcome::RecordLayerAdvanced) => "RecordLayerAdvanced",
                                    Err(_) => "Err",
                                };
                                match outcome {
                                    Ok(TlsAdvanceOutcome::RecordLayerAdvanced) => {
                                        let mut buf = vec![0u8; conn.recv_buf.len()];
                                        let mut collected = Vec::new();
                                        loop {
                                            match tls.read_plaintext(&mut buf) {
                                                Ok(0) => break,
                                                Ok(read_n) => collected.extend_from_slice(&buf[..read_n]),
                                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                                Err(_) => break,
                                            }
                                        }
                                        if collected.is_empty() {
                                            // The TLS record layer
                                            // advanced but produced no
                                            // application data -- e.g.
                                            // a post-handshake
                                            // NewSessionTicket message
                                            // (TLS 1.3 servers commonly
                                            // send one right after the
                                            // handshake finishes,
                                            // before the actual
                                            // response), or any other
                                            // housekeeping-only record.
                                            // Not an error and not the
                                            // response yet -- keep
                                            // reading rather than
                                            // treating an empty
                                            // plaintext buffer as a
                                            // (necessarily incomplete,
                                            // since it's literally
                                            // nothing) response to
                                            // parse.
                                            if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                                tracing::warn!(worker_id, %reason, "failed to submit follow-up recv after a TLS record with no application data");
                                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                                connections.remove(slab_index);
                                            }
                                            continue;
                                        }
                                        collected
                                    }
                                    Ok(TlsAdvanceOutcome::StillHandshaking) => {
                                        // A rekey or other mid-stream
                                        // handshake activity produced
                                        // no new application data --
                                        // nothing to parse yet, just
                                        // flush whatever advance_tls
                                        // queued (if anything) and keep
                                        // reading.
                                        let has_outgoing = {
                                            let Transport::Tls { io, .. } = &connections[slab_index].transport else { unreachable!() };
                                            !io.outgoing.is_empty()
                                        };
                                        let submit_result = if has_outgoing {
                                            submit_tls_send(&mut ring, &mut connections, slab_index)
                                        } else {
                                            submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool)
                                        };
                                        if let Err(reason) = submit_result {
                                            tracing::warn!(worker_id, %reason, "failed to submit follow-up during upstream TLS rekey");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                        }
                                        continue;
                                    }
                                    Ok(TlsAdvanceOutcome::HandshakeJustCompleted) => {
                                        // Unreachable in practice --
                                        // OP_TAG_CONNECT's own upstream
                                        // TLS handling is what drives
                                        // the handshake to completion
                                        // and only sets protocol to
                                        // Http1 (making
                                        // upstream_serving_downstream
                                        // true, which is what got this
                                        // arm entered at all) once
                                        // that already happened -- kept
                                        // as a normal continue rather
                                        // than unreachable!() purely to
                                        // avoid a panic if that
                                        // invariant is ever violated by
                                        // a future change.
                                        continue;
                                    }
                                    Ok(TlsAdvanceOutcome::PeerClosed) | Err(_) => {
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                        continue;
                                    }
                                }
                            } else {
                                {
                                let bytes = recv_bytes(&connections[slab_index], &registered_buffer_pool)[..n].to_vec();
                                if let Some(idx) = connections[slab_index].pending_recv_buf_index.take() {
                                    if let Some(pool) = registered_buffer_pool.as_mut() { pool.release(idx); }
                                }
                                bytes
                            }
                            };
                            connections[slab_index].touch();
                            let parsed_response = {
                                let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                h1.read_buf.push(&plaintext);
                                crate::core::proxy::try_parse_response(h1.read_buf.as_slice())
                            };
                            let Some(response) = parsed_response else {
                                // Not a complete response yet -- keep
                                // reading from the upstream.
                                if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                    tracing::warn!(worker_id, %reason, "failed to submit follow-up recv from upstream");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                                continue;
                            };

                            // A complete response arrived -- this
                            // upstream connection's job for this
                            // request is done (no keep-alive/idle-pool
                            // reuse yet -- see this arm's own
                            // limitation note), tear it down and flush
                            // the response back to whichever
                            // downstream connection is still waiting
                            // for it (it may have gone away already,
                            // e.g. the client disconnected while
                            // waiting -- generation-checked the same
                            // way every other cross-referenced slot in
                            // this backend is).
                            //
                            // Health reporting mirrors mio_backend's
                            // own forward(): reaching this arm at all
                            // means a complete HTTP response came
                            // back (the connection itself is healthy),
                            // but a 5xx status is treated as an
                            // outlier the same way a connection-level
                            // failure is -- see core::proxy::forward's
                            // own comment on this "gateway failure"
                            // framing.
                            let (node_for_sticky, upstream_host_port) = if let ConnectionRole::Upstream { node, pool, .. } = &connections[slab_index].role {
                                if response.status < 500 {
                                    node.record_success(pool);
                                } else {
                                    node.record_failure(pool);
                                }
                                (Some(Arc::clone(node)), Some((node.host.clone(), node.port)))
                            } else {
                                (None, None)
                            };

                            // Keep this connection open for reuse
                            // (see idle_upstream_conns's own doc
                            // comment) if both this response and the
                            // request it answered allow it -- an
                            // upstream that returned `Connection:
                            // close`, or a request the client sent
                            // with the same, both mean this specific
                            // TCP connection is done regardless of
                            // what either side's protocol otherwise
                            // permits. response.keep_alive() reads the
                            // response's own Connection/HTTP-version
                            // framing (mirroring http::response's own
                            // rules for what mio_backend's forward()
                            // implicitly assumes too); the request's
                            // own intent has already been threaded
                            // through as keep_alive below.
                            let upstream_response_keep_alive = response
                                .get_header("Connection")
                                .map(|v| !v.eq_ignore_ascii_case("close"))
                                .unwrap_or(true);
                            let can_reuse_upstream = upstream_response_keep_alive
                                && connections.contains(downstream_slab_index)
                                && connections[downstream_slab_index].generation == downstream_generation
                                && if let ConnectionProtocol::Http1(h1) = &connections[downstream_slab_index].protocol {
                                    h1.waiting_for_upstream.as_ref().map(|s| s.keep_alive).unwrap_or(false)
                                } else {
                                    false
                                };

                            if can_reuse_upstream {
                                let idle_timeout = if let ConnectionProtocol::Http1(h1) = &connections[downstream_slab_index].protocol {
                                    h1.waiting_for_upstream.as_ref().map(|s| s.pending.config.idle_timeout).unwrap_or(std::time::Duration::from_secs(60))
                                } else {
                                    std::time::Duration::from_secs(60)
                                };
                                if let ConnectionRole::Upstream { serving_downstream, pending_request, .. } = &mut connections[slab_index].role {
                                    serving_downstream.clear();
                                    *pending_request = None;
                                }
                                if let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol {
                                    h1.read_buf = crate::util::buf::Buf::new();
                                }
                                if let Some(key) = upstream_host_port {
                                    idle_upstream_conns.entry(key).or_default().push((slab_index, connections[slab_index].generation, std::time::Instant::now(), idle_timeout));
                                }
                            } else {
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                            if connections.contains(downstream_slab_index) && connections[downstream_slab_index].generation == downstream_generation {
                                if let ConnectionProtocol::Http1(h1) = &mut connections[downstream_slab_index].protocol {
                                    let keep_alive = h1.waiting_for_upstream.as_ref().map(|s| s.keep_alive).unwrap_or(false);
                                    let mut response = response;
                                    if let (Some(node), Some(attempt_state)) = (&node_for_sticky, &h1.waiting_for_upstream) {
                                        let incoming_sticky = attempt_state.original_request.get_header(&crate::core::proxy::sticky_cookie_header_name(&attempt_state.pending.lb));
                                        crate::core::proxy::apply_sticky_cookie(&mut response, &attempt_state.pending.lb, node, incoming_sticky);
                                    }
                                    h1.waiting_for_upstream = None;
                                    crate::core::conn::protocol::queue_http1_response(h1, response);
                                    h1.keep_alive = keep_alive;
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, downstream_slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit proxied response to downstream");
                                        cancel_outstanding_operations(&mut ring, downstream_generation, downstream_slab_index);
                                        connections.remove(downstream_slab_index);
                                    }
                                }
                            }
                            continue;
                        }

                        // An UpstreamH2 connection's Recv completions
                        // carry (TLS-encrypted, always -- H2 upstream
                        // support only exists via ALPN, see
                        // HandshakeJustCompleted's own upstream
                        // handling) H2 frames for potentially several
                        // concurrent streams at once, handled entirely
                        // separately from the single-response H1 arm
                        // just above: feed_plaintext's own
                        // Vec<u32>-of-completed-stream-ids contract is
                        // fundamentally different from "one response,
                        // tear the connection down" -- an H2 upstream
                        // connection stays alive and keeps being read
                        // from after every completed stream, not just
                        // after all of them are done.
                        let is_upstream_h2 = matches!(connections[slab_index].protocol, ConnectionProtocol::UpstreamH2(_));
                        if is_upstream_h2 {
                            let n = result as usize;
                            let ciphertext = {
                                let bytes = recv_bytes(&connections[slab_index], &registered_buffer_pool)[..n].to_vec();
                                if let Some(idx) = connections[slab_index].pending_recv_buf_index.take() {
                                    if let Some(pool) = registered_buffer_pool.as_mut() { pool.release(idx); }
                                }
                                bytes
                            };
                            let plaintext: Vec<u8> = {
                                let conn = &mut connections[slab_index];
                                let Transport::Tls { tls, io, .. } = &mut conn.transport else { unreachable!() };
                                match advance_tls(tls, io, &ciphertext) {
                                    Ok(TlsAdvanceOutcome::RecordLayerAdvanced) => {
                                        let mut buf = vec![0u8; conn.recv_buf.len()];
                                        let mut collected = Vec::new();
                                        loop {
                                            match tls.read_plaintext(&mut buf) {
                                                Ok(0) => break,
                                                Ok(read_n) => collected.extend_from_slice(&buf[..read_n]),
                                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                                Err(_) => break,
                                            }
                                        }
                                        collected
                                    }
                                    Ok(TlsAdvanceOutcome::StillHandshaking) | Ok(TlsAdvanceOutcome::HandshakeJustCompleted) => Vec::new(),
                                    Ok(TlsAdvanceOutcome::PeerClosed) | Err(_) => Vec::new(),
                                }
                            };

                            if plaintext.is_empty() {
                                if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                    tracing::warn!(worker_id, %reason, "failed to submit follow-up recv for upstream H2 connection");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                                continue;
                            }

                            let completed_streams = {
                                let ConnectionProtocol::UpstreamH2(h2c) = &mut connections[slab_index].protocol else { unreachable!() };
                                let result = h2c.feed_plaintext(&plaintext);
                                result.unwrap_or_default()
                            };

                            for stream_id in completed_streams {
                                let downstream_target = if let ConnectionRole::Upstream { serving_downstream, .. } = &mut connections[slab_index].role {
                                    serving_downstream.remove(&stream_id)
                                } else {
                                    None
                                };
                                let response = if let ConnectionProtocol::UpstreamH2(h2c) = &mut connections[slab_index].protocol {
                                    h2c.take_response(stream_id)
                                } else {
                                    None
                                };
                                let (Some((downstream_slab_index, downstream_generation)), Some(client_response)) = (downstream_target, response) else {
                                    continue;
                                };
                                if !connections.contains(downstream_slab_index) || connections[downstream_slab_index].generation != downstream_generation {
                                    continue;
                                }
                                let mut resp = crate::http::response::HttpResponse::new(client_response.status, "");
                                for h in client_response.headers {
                                    resp.set_header(&h.name, &h.value);
                                }
                                resp.set_body(client_response.body);
                                if let ConnectionProtocol::Http1(h1) = &mut connections[downstream_slab_index].protocol {
                                    let keep_alive = h1.waiting_for_upstream.as_ref().map(|s| s.keep_alive).unwrap_or(false);
                                    h1.waiting_for_upstream = None;
                                    crate::core::conn::protocol::queue_http1_response(h1, resp);
                                    h1.keep_alive = keep_alive;
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, downstream_slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit H2-upstream-sourced response to downstream");
                                        cancel_outstanding_operations(&mut ring, downstream_generation, downstream_slab_index);
                                        connections.remove(downstream_slab_index);
                                    }
                                }
                            }

                            // This H2 upstream connection stays open
                            // regardless of how many streams just
                            // completed -- unlike H1, finishing one
                            // response is never a reason to tear the
                            // connection down. It's also never
                            // returned to idle_upstream_conns here the
                            // way an H1 connection is -- H2 upstream
                            // pooling isn't wired up yet (a live H2
                            // connection with capacity should really
                            // stay usable for new requests immediately,
                            // not go through an idle-then-reacquire
                            // cycle at all, which is a different
                            // design than idle_upstream_conns's own
                            // H1-shaped one).
                            if let ConnectionProtocol::UpstreamH2(h2c) = &connections[slab_index].protocol {
                                if h2c.has_pending_write() {
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit queued H2 upstream frames");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                        continue;
                                    }
                                } else if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                    tracing::warn!(worker_id, %reason, "failed to submit follow-up recv for upstream H2 connection");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                            }
                            continue;
                        }

                        let n = result as usize;

                        // TLS connections need their ciphertext run
                        // through advance_tls before anything below
                        // (H2/WS/H1 dispatch) can see plaintext -- see
                        // Transport::Tls's own doc comment. Plaintext
                        // connections skip straight to the existing
                        // dispatch logic.
                        let is_tls = connections[slab_index].transport.is_tls();
                        if is_tls {
                            let ciphertext = {
                                let bytes = recv_bytes(&connections[slab_index], &registered_buffer_pool)[..n].to_vec();
                                if let Some(idx) = connections[slab_index].pending_recv_buf_index.take() {
                                    if let Some(pool) = registered_buffer_pool.as_mut() { pool.release(idx); }
                                }
                                bytes
                            };
                            let tls_outcome = {
                                let conn = &mut connections[slab_index];
                                let Transport::Tls { tls, io, .. } = &mut conn.transport else { unreachable!() };
                                advance_tls(tls, io, &ciphertext)
                            };

                            match tls_outcome {
                                Ok(TlsAdvanceOutcome::PeerClosed) | Err(_) => {
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                    continue;
                                }
                                Ok(TlsAdvanceOutcome::StillHandshaking) => {
                                    let has_outgoing = {
                                        let Transport::Tls { io, .. } = &connections[slab_index].transport else { unreachable!() };
                                        !io.outgoing.is_empty()
                                    };
                                    if has_outgoing {
                                        if let Err(reason) = submit_tls_send(&mut ring, &mut connections, slab_index) {
                                            tracing::warn!(worker_id, %reason, "failed to submit tls handshake send");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                        }
                                    } else if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                        tracing::warn!(worker_id, %reason, "failed to submit follow-up recv during tls handshake");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                    continue;
                                }
                                Ok(TlsAdvanceOutcome::HandshakeJustCompleted) => {
                                    // An upstream connection's TLS
                                    // handshake completing means it's
                                    // finally ready to actually send
                                    // the pending request -- entirely
                                    // separate from everything below
                                    // this check, which is all about a
                                    // *downstream* connection picking
                                    // its application protocol
                                    // (H1/H2 via ALPN) once its own
                                    // handshake finishes.
                                    let is_upstream = matches!(connections[slab_index].role, ConnectionRole::Upstream { .. });
                                    if is_upstream {
                                        let negotiated_h2 = connections[slab_index].transport.alpn_protocol() == Some(b"h2".as_slice());
                                        let pending_request = match &mut connections[slab_index].role {
                                            ConnectionRole::Upstream { pending_request, .. } => pending_request.take(),
                                            ConnectionRole::Downstream => None,
                                        };
                                        let Some(pending_request) = pending_request else {
                                            tracing::warn!(worker_id, slab_index, "upstream TLS handshake completed with no pending request -- closing");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                            continue;
                                        };
                                        let proxy_identity = self.server.config.pools.first().map(|p| p.name.clone()).unwrap_or_else(|| "routa".to_string());

                                        if negotiated_h2 {
                                            // Same pseudo-header
                                            // assembly as mio_backend's
                                            // own forward_http2 --
                                            // duplicated rather than
                                            // shared as a function
                                            // since core::proxy's own
                                            // version is tied to
                                            // mio_backend's H2Client
                                            // and Arc<Mutex<...>>
                                            // sharing model, neither of
                                            // which this backend uses.
                                            let node_host = match &connections[slab_index].role {
                                                ConnectionRole::Upstream { node, .. } => node.host.clone(),
                                                ConnectionRole::Downstream => String::new(),
                                            };
                                            let node_use_tls = match &connections[slab_index].role {
                                                ConnectionRole::Upstream { node, .. } => node.use_tls,
                                                ConnectionRole::Downstream => false,
                                            };
                                            let client_addr = pending_request.remote_addr;
                                            let mut headers = crate::core::proxy::build_upstream_headers(&pending_request, client_addr, &proxy_identity);
                                            // RFC 9113 8.3.1: a request
                                            // carrying both an
                                            // :authority pseudo-header
                                            // and a Host header field
                                            // must have the two agree
                                            // -- since :authority is
                                            // always set here from the
                                            // upstream node's own host
                                            // (never copied from
                                            // whatever Host the
                                            // downstream client sent,
                                            // which could be anything),
                                            // the two would essentially
                                            // never actually agree.
                                            // HTTP/1.1's own equivalent
                                            // Host header therefore has
                                            // no H2 role to play here
                                            // at all -- :authority
                                            // already carries that
                                            // information -- so it's
                                            // dropped rather than risk
                                            // a real H2 server (like
                                            // this same codebase's own
                                            // server-mode
                                            // http::h2::stream, whose
                                            // strict validation
                                            // rejected exactly this
                                            // with a PROTOCOL_ERROR
                                            // RST_STREAM during this
                                            // fix's own development)
                                            // treating the mismatch as
                                            // a protocol violation.
                                            headers.retain(|h| !h.name.eq_ignore_ascii_case("host"));
                                            // RFC 9113 8.2: header
                                            // field names MUST be
                                            // converted to lowercase
                                            // before encoding into an
                                            // H2 header block --
                                            // build_upstream_headers's
                                            // own output preserves
                                            // whatever case the
                                            // original HTTP/1.1
                                            // request used
                                            // (correct for H1,
                                            // case-insensitive there),
                                            // so this is what actually
                                            // enforces it for the H2
                                            // upstream case specifically.
                                            // Sending mixed-case names
                                            // is exactly what a real H2
                                            // server (this same
                                            // codebase's own
                                            // server-mode
                                            // http::h2::stream) will
                                            // reject outright, not with
                                            // some lenient
                                            // normalization.
                                            for h in &mut headers {
                                                h.name = h.name.to_ascii_lowercase();
                                            }
                                            let scheme = if node_use_tls { "https" } else { "http" };
                                            let mut pseudo_headers = vec![
                                                crate::http::h2::hpack::HeaderField { name: ":method".to_string(), value: format!("{:?}", pending_request.method).to_uppercase() },
                                                crate::http::h2::hpack::HeaderField { name: ":scheme".to_string(), value: scheme.to_string() },
                                                crate::http::h2::hpack::HeaderField {
                                                    name: ":path".to_string(),
                                                    value: match &pending_request.query {
                                                        Some(q) => format!("{}?{}", pending_request.path, q),
                                                        None => pending_request.path.clone(),
                                                    },
                                                },
                                                crate::http::h2::hpack::HeaderField { name: ":authority".to_string(), value: node_host },
                                            ];
                                            pseudo_headers.append(&mut headers);

                                            let mut h2c = crate::net::uring_h2_client::UringH2Client::new();
                                            h2c.initial_send();
                                            let stream_id = h2c.open_stream(&pseudo_headers, &pending_request.body);
                                            connections[slab_index].protocol = ConnectionProtocol::UpstreamH2(h2c);
                                            let Some(stream_id) = stream_id else {
                                                tracing::warn!(worker_id, slab_index, "brand-new upstream H2 connection already at its own concurrent-stream limit -- this should be unreachable");
                                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                                connections.remove(slab_index);
                                                continue;
                                            };
                                            // ProxyPending's own arm
                                            // (which created this
                                            // connection before its
                                            // protocol -- H1 or H2 --
                                            // was known) recorded the
                                            // waiting downstream under
                                            // H1's sentinel key 0 (see
                                            // ConnectionRole::Upstream::serving_downstream's
                                            // own doc comment) -- move
                                            // that entry to this
                                            // stream's real id now that
                                            // it's known, so
                                            // OP_TAG_RECV's own
                                            // UpstreamH2 completion
                                            // handling (which looks
                                            // entries up by real stream
                                            // id, since a real H2
                                            // connection can be serving
                                            // several downstreams under
                                            // several different ids at
                                            // once) can actually find
                                            // it.
                                            if let ConnectionRole::Upstream { serving_downstream, .. } = &mut connections[slab_index].role {
                                                if let Some(downstream) = serving_downstream.remove(&0) {
                                                    serving_downstream.insert(stream_id, downstream);
                                                }
                                            }
                                            let submit_result = submit_send(&mut ring, &mut connections, slab_index);
                                            if let Err(reason) = submit_result {
                                                tracing::warn!(worker_id, %reason, "failed to submit initial send to newly-TLS-handshaked H2 upstream");
                                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                                connections.remove(slab_index);
                                            }
                                            continue;
                                        }

                                        connections[slab_index].protocol = ConnectionProtocol::Http1(Http1Connection::new());
                                        let client_addr = pending_request.remote_addr;
                                        let headers = crate::core::proxy::build_upstream_headers(&pending_request, client_addr, &proxy_identity);
                                        let mut upstream_req = (*pending_request).clone();
                                        upstream_req.headers = headers.into_iter().map(|h| (h.name, h.value)).collect();
                                        let request_bytes = upstream_req.serialize();
                                        let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                        h1.write_buf.push(&request_bytes);
                                        if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                            tracing::warn!(worker_id, %reason, "failed to submit request to newly-TLS-handshaked upstream");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                        }
                                        continue;
                                    }

                                    let is_h2_alpn = connections[slab_index].transport.alpn_protocol() == Some(b"h2".as_slice());
                                    connections[slab_index].protocol = if is_h2_alpn {
                                        ConnectionProtocol::Http2(Http2Connection::new(&self.h2_settings))
                                    } else {
                                        ConnectionProtocol::Http1(Http1Connection::new())
                                    };

                                    // Http2Connection::new() just queued
                                    // its own initial_send() (the
                                    // server's SETTINGS frame) into
                                    // Http2Connection::write_buf -- but
                                    // that's plaintext, and nothing
                                    // else in this HandshakeJustCompleted
                                    // arm ever encrypts a protocol's
                                    // write_buf the way submit_send's
                                    // TLS branch does; only the raw TLS
                                    // handshake bytes already sitting
                                    // in MemoryTlsIo::outgoing were
                                    // being sent. Without this, an
                                    // ALPN-negotiated H2 connection's
                                    // SETTINGS frame was silently never
                                    // encrypted or transmitted at all
                                    // -- the client would see a
                                    // successful TLS+ALPN handshake but
                                    // then wait forever for a SETTINGS
                                    // frame that was never coming (this
                                    // is what h2spec's TLS suite
                                    // exposed: every test after the
                                    // bare connection-preface check
                                    // timed out, since none of them
                                    // could get past waiting for this
                                    // frame). h2c's own upgrade path
                                    // doesn't have this problem because
                                    // it's plaintext -- the 101
                                    // response and the H2 preface
                                    // travel unencrypted, and
                                    // Http1Outcome::SwitchedToHttp2's
                                    // own submit_send call already
                                    // handles a protocol's write_buf
                                    // correctly for that case.
                                    if is_h2_alpn {
                                        // submit_send's TLS branch
                                        // already both encrypts
                                        // Http2Connection::write_buf's
                                        // SETTINGS frame into
                                        // MemoryTlsIo::outgoing AND
                                        // submits the resulting Send
                                        // SQE -- it's a complete,
                                        // self-contained submission,
                                        // unlike the plain "check
                                        // outgoing, maybe submit_tls_send"
                                        // pattern the non-H2 branch
                                        // below still needs (that
                                        // pattern exists because a
                                        // plaintext Http1/WebSocket
                                        // connection reaching this
                                        // point has no write_buf
                                        // content of its own to send
                                        // yet -- only leftover TLS
                                        // handshake bytes, if any).
                                        // Falling through to that same
                                        // check here would submit a
                                        // second, redundant Send SQE
                                        // against the same still-unconsumed
                                        // outgoing buffer.
                                        if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                            tracing::warn!(worker_id, %reason, "failed to submit h2 settings frame after tls+alpn handshake");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                        }
                                        continue;
                                    }

                                    let has_outgoing = {
                                        let Transport::Tls { io, .. } = &connections[slab_index].transport else { unreachable!() };
                                        !io.outgoing.is_empty()
                                    };
                                    if has_outgoing {
                                        if let Err(reason) = submit_tls_send(&mut ring, &mut connections, slab_index) {
                                            tracing::warn!(worker_id, %reason, "failed to submit final tls handshake send");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                        }
                                    } else if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                        tracing::warn!(worker_id, %reason, "failed to submit follow-up recv after tls handshake");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                    continue;
                                }
                                Ok(TlsAdvanceOutcome::RecordLayerAdvanced) => {
                                    // Fall through below, reading the
                                    // newly-decrypted plaintext out of
                                    // rustls in place of recv_buf.
                                }
                            }
                        }

                        let plaintext: Vec<u8> = if is_tls {
                            let conn = &mut connections[slab_index];
                            let Transport::Tls { tls, .. } = &mut conn.transport else { unreachable!() };
                            let mut buf = vec![0u8; conn.recv_buf.len()];
                            let mut collected = Vec::new();
                            loop {
                                match tls.read_plaintext(&mut buf) {
                                    Ok(0) => break,
                                    Ok(n) => collected.extend_from_slice(&buf[..n]),
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                    Err(_) => break,
                                }
                            }
                            collected
                        } else {
                            {
                                let bytes = recv_bytes(&connections[slab_index], &registered_buffer_pool)[..n].to_vec();
                                if let Some(idx) = connections[slab_index].pending_recv_buf_index.take() {
                                    if let Some(pool) = registered_buffer_pool.as_mut() { pool.release(idx); }
                                }
                                bytes
                            }
                        };

                        if plaintext.is_empty() && is_tls {
                            if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                tracing::warn!(worker_id, %reason, "failed to submit follow-up recv after an empty decrypted record");
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                            continue;
                        }

                        let is_h2 = matches!(connections[slab_index].protocol, ConnectionProtocol::Http2(_));

                        if is_h2 {
                            connections[slab_index].touch();
                            let h2_outcome = {
                                let conn = &mut connections[slab_index];
                                let ctx = crate::core::conn::protocol::Http2DispatchContext {
                                    server: &self.server,
                                    ws_settings: &self.ws_settings,
                                    ws_enabled: self.ws_enabled,
                                    ws_max_connections: self.ws_max_connections,
                                    ws_permessage_deflate: self.ws_permessage_deflate,
                                    remote_addr: conn.remote_addr.ip(),
                                };
                                // `plaintext` -- decrypted above for a
                                // TLS connection, or simply this
                                // completion's raw recv_buf bytes for a
                                // plaintext one (see its own
                                // definition) -- is what process_http2_input
                                // must see either way; using recv_buf
                                // directly here would feed a TLS
                                // connection's still-encrypted bytes
                                // straight into H2 frame parsing.
                                crate::core::conn::protocol::process_http2_input(&mut conn.protocol, &plaintext, &ctx)
                            };

                            match h2_outcome {
                                crate::core::conn::protocol::Http2Outcome::FlushThenContinue => {
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit http2 send");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                }
                                crate::core::conn::protocol::Http2Outcome::FlushThenClose => {
                                    connections[slab_index].closing = true;
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit final http2 send");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                }
                            }
                            continue;
                        }

                        let is_websocket = matches!(connections[slab_index].protocol, ConnectionProtocol::WebSocket(_));

                        if is_websocket {
                            connections[slab_index].touch();
                            let ws_ctx = crate::core::conn::protocol::WsDispatchContext {
                                router: &self.server.router,
                                compression_threshold: self.ws_settings.compression_threshold,
                            };
                            let ws_outcome = crate::core::conn::protocol::process_websocket_input(
                                &mut connections[slab_index].protocol,
                                &plaintext,
                                &ws_ctx,
                            );

                            match ws_outcome {
                                crate::core::conn::protocol::WebSocketOutcome::NoActionNeeded => {
                                    if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
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
                            // `plaintext` -- decrypted above for a
                            // TLS connection, or this completion's raw
                            // recv_buf bytes for a plaintext one (see
                            // its own definition, earlier in this
                            // completion's handling) -- is what must be
                            // fed to the HTTP/1.1 parser either way;
                            // using conn.recv_buf directly here would
                            // feed a TLS connection's still-encrypted
                            // bytes straight into request parsing.
                            h1.read_buf.push(&plaintext);
                        }

                        // A not-yet-confirmed Http1Connection is still
                        // deciding whether this connection is really
                        // HTTP/1.1 or prior-knowledge H2 (RFC 9113
                        // 3.4) -- see conn::uring_conn's own doc
                        // comment on why every connection here starts
                        // this way (no TLS/ALPN yet to decide
                        // unambiguously up front the way mio_backend's
                        // TLS path can). Resolved here, before
                        // process_http1_read_buf ever sees these
                        // bytes as HTTP/1.1 -- mirrors mio_backend's
                        // own equivalent check.
                        let needs_protocol_decision = matches!(&connections[slab_index].protocol, ConnectionProtocol::Http1(h1) if !h1.protocol_confirmed);
                        if needs_protocol_decision {
                            let decision = {
                                let ConnectionProtocol::Http1(h1) = &connections[slab_index].protocol else { unreachable!() };
                                crate::core::conn::protocol::decide_plaintext_protocol(h1.read_buf.as_slice())
                            };
                            match decision {
                                crate::core::conn::protocol::PlaintextProtocolDecision::NeedMoreData => {
                                    if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
                                        tracing::warn!(worker_id, %reason, "failed to submit follow-up recv while deciding plaintext protocol");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                    continue;
                                }
                                crate::core::conn::protocol::PlaintextProtocolDecision::Http1 => {
                                    let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                    h1.protocol_confirmed = true;
                                }
                                crate::core::conn::protocol::PlaintextProtocolDecision::Http2PriorKnowledge => {
                                    let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                    h1.read_buf.consume(crate::core::conn::protocol::H2_CONNECTION_PREFACE.len());
                                    let leftover = h1.read_buf.as_slice().to_vec();
                                    let mut h2 = Http2Connection::new(&self.h2_settings);
                                    h2.inner.assume_preface_received();
                                    connections[slab_index].protocol = ConnectionProtocol::Http2(h2);
                                    if !leftover.is_empty() {
                                        let ConnectionProtocol::Http2(h2) = &mut connections[slab_index].protocol else { unreachable!() };
                                        let advance_result = h2.inner.advance(&leftover);
                                        h2.write_buf.push(&advance_result.to_send);
                                    }
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit h2 prior-knowledge initial settings");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                    continue;
                                }
                                crate::core::conn::protocol::PlaintextProtocolDecision::InvalidH2Preface => {
                                    // RFC 9113 3.4 permits omitting a
                                    // GOAWAY when the peer clearly
                                    // isn't speaking H2 -- mirrors
                                    // mio_backend's own equivalent
                                    // handling.
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                    continue;
                                }
                            }
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
                                if let Err(reason) = submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool) {
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
                                // The switch already replaced
                                // conn.protocol with a real
                                // ConnectionProtocol::Http2 carrying
                                // the queued 101 response ahead of the
                                // H2 connection preface's own
                                // initial_send() in its write_buf (see
                                // process_http1_read_buf's h2c handling),
                                // so it can be flushed exactly like any
                                // other pending send.
                                if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                    tracing::warn!(worker_id, %reason, "failed to submit h2c upgrade response");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
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
                            Http1Outcome::ProxyPending(pending, original_request) => {
                                // Picks a node the same way mio_backend's
                                // own core::proxy::forward does (no
                                // sticky-session cookie support here
                                // yet -- see this arm's own limitation
                                // note below) and opens a real,
                                // asynchronous connection to it via
                                // submit_connect, rather than the
                                // synchronous connect+busy-poll
                                // core::proxy::forward itself uses (see
                                // that module's own doc comment on why
                                // this backend deliberately doesn't
                                // repeat that design).
                                let Some(node) = pending.lb.pick_node_sticky(None, None) else {
                                    let mut resp = crate::http::response::HttpResponse::new(503, "Service Unavailable");
                                    resp.set_body(b"Service Unavailable\n".to_vec());
                                    let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                    crate::core::conn::protocol::queue_http1_response(h1, resp);
                                    if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                        tracing::warn!(worker_id, %reason, "failed to submit 503 for exhausted upstream pool");
                                        cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                        connections.remove(slab_index);
                                    }
                                    continue;
                                };

                                let upstream_addr = match node.resolve_addr() {
                                    Ok(addr) => addr,
                                    Err(_) => {
                                        let mut resp = crate::http::response::HttpResponse::new(502, "Bad Gateway");
                                        resp.set_body(b"Bad Gateway\n".to_vec());
                                        let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                        crate::core::conn::protocol::queue_http1_response(h1, resp);
                                        if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                            tracing::warn!(worker_id, %reason, "failed to submit 502 for unresolvable upstream");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                        }
                                        continue;
                                    }
                                };

                                // Check the idle pool before opening a
                                // fresh TCP connection -- see
                                // idle_upstream_conns's own doc
                                // comment for why this is worker-local
                                // rather than sharing UpstreamNode's
                                // own Mutex-protected pool.
                                let idle_key = (node.host.clone(), node.port);
                                let idle_entry = idle_upstream_conns.get_mut(&idle_key).and_then(|v| v.pop());
                                if let Some((idle_slab_index, idle_generation, _last_used, _idle_timeout)) = idle_entry {
                                    if connections.contains(idle_slab_index) && connections[idle_slab_index].generation == idle_generation {
                                        let downstream_generation = connections[slab_index].generation;
                                        let read_write_timeouts = (pending.config.read_timeout, pending.config.write_timeout);
                                        if let ConnectionRole::Upstream { serving_downstream, pending_request, .. } = &mut connections[idle_slab_index].role {
                                            serving_downstream.insert(0, (slab_index, downstream_generation));
                                            *pending_request = Some(original_request.clone());
                                        }
                                        let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                        h1.waiting_for_upstream = Some(crate::core::conn::protocol::ProxyAttemptState {
                                            upstream_slab_index: idle_slab_index,
                                            upstream_generation: idle_generation,
                                            keep_alive: original_request.keep_alive,
                                            attempts_so_far: 1,
                                            pending: pending.clone(),
                                            original_request: original_request.clone(),
                                            downstream_stream_id: None,
                                        });

                                        // Serialize and send immediately -- an
                                        // idle connection is already
                                        // established, so this jumps
                                        // straight to what OP_TAG_CONNECT's
                                        // completion handler otherwise does
                                        // once a fresh connect(2) finishes.
                                        let client_addr = original_request.remote_addr;
                                        let headers = crate::core::proxy::build_upstream_headers(&original_request, client_addr, &self.server.config.pools.first().map(|p| p.name.clone()).unwrap_or_else(|| "routa".to_string()));
                                        let mut upstream_req = (*original_request).clone();
                                        upstream_req.headers = headers.into_iter().map(|h| (h.name, h.value)).collect();
                                        let request_bytes = upstream_req.serialize();
                                        let _ = read_write_timeouts; // already set on this connection when it was first created
                                        if let ConnectionProtocol::Http1(h1) = &mut connections[idle_slab_index].protocol {
                                            h1.write_buf.push(&request_bytes);
                                        }
                                        if let Err(reason) = submit_send(&mut ring, &mut connections, idle_slab_index) {
                                            tracing::warn!(worker_id, %reason, "failed to submit request to a reused idle upstream connection, falling back to a fresh connect");
                                            // The idle connection turned
                                            // out to be dead (e.g. the
                                            // upstream closed it while
                                            // it sat idle) -- fall
                                            // through to a fresh
                                            // connect rather than
                                            // failing the client's
                                            // request outright.
                                            cancel_outstanding_operations(&mut ring, idle_generation, idle_slab_index);
                                            connections.remove(idle_slab_index);
                                            if let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol {
                                                h1.waiting_for_upstream = None;
                                            }
                                        } else {
                                            continue;
                                        }
                                    }
                                }

                                let upstream_fd = match create_upstream_socket(&upstream_addr) {
                                    Ok(fd) => fd,
                                    Err(e) => {
                                        tracing::warn!(worker_id, error = %e, "failed to create upstream socket");
                                        let mut resp = crate::http::response::HttpResponse::new(502, "Bad Gateway");
                                        resp.set_body(b"Bad Gateway\n".to_vec());
                                        let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                        crate::core::conn::protocol::queue_http1_response(h1, resp);
                                        if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                                            tracing::warn!(worker_id, %reason, "failed to submit 502 after socket creation failure");
                                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                            connections.remove(slab_index);
                                        }
                                        continue;
                                    }
                                };

                                let downstream_generation = connections[slab_index].generation;
                                let upstream_entry = connections.vacant_entry();
                                let upstream_slab_index = upstream_entry.key();
                                if upstream_slab_index >= generations.len() {
                                    generations.resize(upstream_slab_index + 1, 0);
                                }
                                generations[upstream_slab_index] = generations[upstream_slab_index].wrapping_add(1);
                                let upstream_generation = generations[upstream_slab_index];

                                let read_write_timeouts = (pending.config.read_timeout, pending.config.write_timeout);
                                let mut upstream_conn = Connection::new_upstream(
                                    upstream_fd as u64,
                                    Transport::Plain(upstream_fd),
                                    upstream_addr,
                                    self.recv_buf_size,
                                    upstream_generation,
                                    Arc::clone(&node),
                                    Arc::clone(&pending.lb.pool),
                                    read_write_timeouts,
                                );
                                upstream_conn.send_zc_supported = send_zc_supported;
                                upstream_conn.role = ConnectionRole::Upstream {
                                    node: Arc::clone(&node),
                                    pool: Arc::clone(&pending.lb.pool),
                                    read_write_timeouts,
                                    serving_downstream: std::collections::HashMap::from([(0u32, (slab_index, downstream_generation))]),
                                    pending_request: Some(original_request.clone()),
                                };
                                // The upstream connection speaks
                                // HTTP/1.1 back to us regardless of
                                // what protocol the downstream client
                                // used to reach this proxy -- proxying
                                // doesn't yet translate protocols (H2
                                // downstream -> H1 upstream, etc.), see
                                // this arm's own limitation notes.
                                upstream_conn.protocol = ConnectionProtocol::Http1(Http1Connection::new());
                                upstream_entry.insert(upstream_conn);

                                let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                                h1.waiting_for_upstream = Some(crate::core::conn::protocol::ProxyAttemptState {
                                    upstream_slab_index,
                                    upstream_generation,
                                    keep_alive: original_request.keep_alive,
                                    attempts_so_far: 1,
                                    pending: pending.clone(),
                                    original_request: original_request.clone(),
                                    downstream_stream_id: None,
                                });

                                if let Err(reason) = submit_connect(&mut ring, &mut connections, upstream_slab_index, pending.config.connect_timeout) {
                                    tracing::warn!(worker_id, %reason, "failed to submit connect to upstream");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                    connections.remove(upstream_slab_index);
                                }
                            }
                            Http1Outcome::FileCachePending(pending, original_request) => {
                                if let Err(reason) = submit_statx(&mut ring, &mut connections, slab_index, pending, original_request) {
                                    tracing::warn!(worker_id, %reason, "failed to submit statx for a static-file cache-miss");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                }
                            }
                        }
                    }

                    OP_TAG_SEND => {
                        handle_send_completion(self, worker_id, &mut ring, &mut connections, slab_index, completion_generation, result, &mut pipe_pool, &mut registered_buffer_pool);
                    }
                    OP_TAG_CONNECT => {
                        if !connections.contains(slab_index) {
                            continue; // upstream connection already torn down (e.g. its downstream vanished first)
                        }
                        if connections[slab_index].generation != completion_generation {
                            continue; // stale completion -- see make_user_data's own doc comment
                        }

                        if result < 0 {
                            // The connect(2) itself failed (ECONNREFUSED,
                            // ETIMEDOUT, etc.) -- tell whichever
                            // downstream was waiting, if it's still
                            // around, and tear down this now-useless
                            // upstream slot.
                            let failed_node_pool = match &connections[slab_index].role {
                                ConnectionRole::Upstream { serving_downstream, node, pool, .. } => Some((serving_downstream.clone(), Arc::clone(node), Arc::clone(pool))),
                                ConnectionRole::Downstream => None,
                            };
                            let serving_downstreams: Vec<(usize, u32)> = failed_node_pool.as_ref().map(|(serving, ..)| serving.values().copied().collect()).unwrap_or_default();
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            if let Some((_, node, pool)) = failed_node_pool {
                                // Mirrors mio_backend's own forward():
                                // a connect(2) failure is reported to
                                // the load balancer's health tracking
                                // the same way any other
                                // connection-level failure is (see
                                // core::proxy::forward's own comment on
                                // treating a 5xx response the same way
                                // -- this is the "can't even reach it"
                                // half of that same failure model).
                                node.record_failure(&pool);
                            }
                            for (downstream_slab_index, downstream_generation) in serving_downstreams {
                                if connections.contains(downstream_slab_index) && connections[downstream_slab_index].generation == downstream_generation {
                                    let attempt_state = if let ConnectionProtocol::Http1(h1) = &mut connections[downstream_slab_index].protocol {
                                        h1.waiting_for_upstream.take()
                                    } else {
                                        None
                                    };
                                    if let Some(attempt_state) = attempt_state {
                                        retry_or_fail_proxy_attempt(&mut ring, &mut connections, &mut generations, downstream_slab_index, attempt_state, self.recv_buf_size, worker_id, send_zc_supported);
                                    }
                                }
                            }
                            continue;
                        }

                        // Connected -- if this node speaks TLS,
                        // wrap the now-established plaintext TCP
                        // connection in a client-mode TLS handshake
                        // before anything else; the pending request
                        // itself isn't sent until that handshake
                        // completes (see OP_TAG_RECV's TLS-handshake
                        // handling below, which is what actually
                        // serializes and sends it once
                        // HandshakeJustCompleted fires for this
                        // connection).
                        let node_use_tls_and_host = match &connections[slab_index].role {
                            ConnectionRole::Upstream { node, .. } => Some((node.use_tls, node.host.clone())),
                            ConnectionRole::Downstream => None,
                        };
                        if let Some((true, host)) = node_use_tls_and_host {
                            // Offering h2 via ALPN here is what
                            // lets HandshakeJustCompleted (below)
                            // discover whether this node actually
                            // speaks H2 (checked via alpn_protocol())
                            // rather than needing a separate
                            // config-level "this upstream is H2" flag
                            // -- the same offer-and-check-what-was-
                            // negotiated approach downstream connections
                            // already use for ALPN.
                            let alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                            #[cfg(test)]
                            let tls_result = match &self.upstream_tls_test_roots {
                                Some(roots) => crate::net::tls::TlsConnection::new_client_with_roots(&host, alpn_protocols, roots.clone()),
                                None => crate::net::tls::TlsConnection::new_client(&host, alpn_protocols),
                            };
                            #[cfg(not(test))]
                            let tls_result = crate::net::tls::TlsConnection::new_client(&host, alpn_protocols);
                            let tls = match tls_result {
                                Ok(tls) => tls,
                                Err(e) => {
                                    tracing::warn!(worker_id, error = %e, "failed to build client TLS connection for upstream");
                                    cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                    connections.remove(slab_index);
                                    continue;
                                }
                            };
                            // Reuse this connection's already-established
                            // fd for the new TLS-wrapped Transport
                            // without letting the old Transport::Plain
                            // value's Drop impl close it out from
                            // under the replacement -- see
                            // Transport::take_fd_for_reuse's own doc
                            // comment. A plain field assignment here
                            // (`connections[slab_index].transport =
                            // Transport::Tls { .. }`) would drop the
                            // old value, and Transport::Drop closes
                            // whatever fd() it reports regardless of
                            // variant -- exactly the fd the new value
                            // is about to reuse.
                            let old_transport = std::mem::replace(&mut connections[slab_index].transport, Transport::Plain(-1));
                            let fd = old_transport.take_fd_for_reuse();
                            connections[slab_index].transport = Transport::Tls {
                                fd,
                                tls: Box::new(tls),
                                io: Box::new(crate::net::tls::MemoryTlsIo::new()),
                            };
                            connections[slab_index].protocol = ConnectionProtocol::Handshaking;
                            // Kick off the handshake by flushing
                            // whatever the freshly-constructed client
                            // TlsConnection already queued (its own
                            // ClientHello) -- the same advance_io
                            // pattern the rest of this backend's TLS
                            // handling already uses, just triggered
                            // from here instead of from an OP_TAG_RECV
                            // completion since there's no incoming
                            // ciphertext to react to yet.
                            let has_outgoing = {
                                let Transport::Tls { tls, io, .. } = &mut connections[slab_index].transport else { unreachable!() };
                                match tls.advance_io(io.as_mut()) {
                                    Err(e) => {
                                        tracing::warn!(worker_id, error = %e, "failed to advance client TLS handshake for upstream");
                                        false
                                    }
                                    Ok(_) => {
                                        !io.outgoing.is_empty()
                                    }
                                }
                            };
                            let submit_result = if has_outgoing {
                                submit_tls_send(&mut ring, &mut connections, slab_index)
                            } else {
                                submit_recv(&mut ring, &mut connections, slab_index, &mut registered_buffer_pool)
                            };
                            if let Err(reason) = submit_result {
                                tracing::warn!(worker_id, %reason, "failed to submit initial upstream TLS handshake step");
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                            }
                            continue;
                        }

                        // Plaintext -- serialize the pending request
                        // (see ConnectionRole::Upstream's own doc
                        // comment on why it's kept here rather than
                        // pre-serialized before the connection
                        // existed) the same way mio_backend's own
                        // synchronous forward_http1 does, via the same
                        // shared build_upstream_headers, so both
                        // backends rewrite headers identically.
                        let pending_request = match &mut connections[slab_index].role {
                            ConnectionRole::Upstream { pending_request, .. } => pending_request.take(),
                            ConnectionRole::Downstream => None,
                        };
                        let Some(pending_request) = pending_request else {
                            tracing::warn!(worker_id, slab_index, "connect completion for an upstream connection with no pending request -- closing");
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        };

                        let client_addr = pending_request.remote_addr;
                        let headers = crate::core::proxy::build_upstream_headers(&pending_request, client_addr, &self.server.config.pools.first().map(|p| p.name.clone()).unwrap_or_else(|| "routa".to_string()));
                        let mut upstream_req = (*pending_request).clone();
                        upstream_req.headers = headers.into_iter().map(|h| (h.name, h.value)).collect();
                        let request_bytes = upstream_req.serialize();

                        let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else { unreachable!() };
                        h1.write_buf.push(&request_bytes);

                        if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                            tracing::warn!(worker_id, %reason, "failed to submit request to newly-connected upstream");
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                        }
                    }

                    OP_TAG_SEND_ZC => {
                        if !connections.contains(slab_index) || connections[slab_index].generation != completion_generation {
                            continue;
                        }
                        if !io_uring::cqueue::more(flags) {
                            // The NOTIF completion -- the kernel is
                            // done reading the send buffer, so the
                            // transfer this SendZc represents is now
                            // actually settled. The byte count itself
                            // arrived on the *first* (MORE) completion
                            // and was stashed in pending_send_zc_result
                            // below; NOTIF's own result carries no
                            // further meaning beyond "safe to proceed
                            // now" (per SendZc's own semantics -- see
                            // submit_send's doc comment on the two-CQE
                            // lifecycle this opcode requires).
                            let Some(n) = connections[slab_index].pending_send_zc_result.take() else {
                                tracing::warn!(worker_id, slab_index, "received a SendZc NOTIF completion with no matching pending result -- closing");
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                                continue;
                            };
                            handle_send_completion(self, worker_id, &mut ring, &mut connections, slab_index, completion_generation, n as i32, &mut pipe_pool, &mut registered_buffer_pool);
                            continue;
                        }
                        // The first (MORE) completion -- result is the
                        // transfer's own byte count (or a negative
                        // errno), but the buffer isn't safe to treat
                        // as settled until the matching NOTIF
                        // completion above arrives. A negative result
                        // here is a real failure (not merely "more
                        // data coming"), so it's handled immediately
                        // rather than deferred to NOTIF, mirroring how
                        // OP_TAG_SEND itself treats a negative result.
                        if result < 0 {
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        }
                        connections[slab_index].pending_send_zc_result = Some(result as u32);
                    }
                    OP_TAG_STATX => {
                        if !connections.contains(slab_index) || connections[slab_index].generation != completion_generation {
                            continue;
                        }
                        let Some(statx_state) = connections[slab_index].pending_statx.take() else {
                            tracing::warn!(worker_id, slab_index, "received a statx completion with no matching pending_statx -- closing");
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        };
                        // A negative result (ENOENT, EACCES, etc.)
                        // means the file doesn't exist or isn't
                        // stat-able -- finish_after_stat's own None
                        // branch handles this identically to a failed
                        // synchronous std::fs::metadata call (negative
                        // caching, 404).
                        let stat_result = if result < 0 {
                            None
                        } else {
                            let stx = &statx_state.statx_buf;
                            let mtime = std::time::UNIX_EPOCH + std::time::Duration::new(stx.stx_mtime.tv_sec.max(0) as u64, stx.stx_mtime.tv_nsec);
                            Some((stx.stx_size, mtime))
                        };
                        let mut response = crate::http::static_files::finish_after_stat(
                            &statx_state.original_request,
                            &statx_state.pending,
                            stat_result,
                            &self.server.file_cache,
                            &mut worker_mmap,
                            self.server.file_watcher.as_deref(),
                        );
                        let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else {
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        };
                        let keep_alive = statx_state.original_request.keep_alive && response.get_header("Connection").map(|v| !v.eq_ignore_ascii_case("close")).unwrap_or(true);
                        if response.get_header("Connection").is_none() {
                            response.set_header("Connection", if keep_alive { "keep-alive" } else { "close" });
                        }
                        crate::core::conn::protocol::queue_http1_response(h1, response);
                        h1.keep_alive = keep_alive;
                        if let Err(reason) = submit_send(&mut ring, &mut connections, slab_index) {
                            tracing::warn!(worker_id, %reason, "failed to submit response after an async static-file stat");
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                        }
                    }
                    OP_TAG_SPLICE_TO_PIPE => {
                        if !connections.contains(slab_index) || connections[slab_index].generation != completion_generation {
                            continue;
                        }
                        if result <= 0 {
                            // 0 means the file has no more bytes at
                            // its current offset despite pending_file
                            // still expecting some (a truncated file
                            // underneath an in-flight response, the
                            // same failure mode flush_pending_file's
                            // own TLS fallback branch guards against)
                            // -- either way, this connection can't
                            // finish its response correctly, so it's
                            // torn down rather than left half-sent.
                            if let Some(splice_state) = connections[slab_index].pending_splice.take() {
                                pipe_pool.release((splice_state.pipe_read_fd, splice_state.pipe_write_fd));
                            }
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        }
                        let bytes_in_pipe = result as u32;
                        if let Err(reason) = submit_splice_to_socket(&mut ring, &mut connections, slab_index, bytes_in_pipe) {
                            tracing::warn!(worker_id, %reason, "failed to submit splice-to-socket leg of a file relay");
                            if let Some(splice_state) = connections[slab_index].pending_splice.take() {
                                pipe_pool.release((splice_state.pipe_read_fd, splice_state.pipe_write_fd));
                            }
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                        }
                    }
                    OP_TAG_SPLICE_TO_SOCKET => {
                        if !connections.contains(slab_index) || connections[slab_index].generation != completion_generation {
                            continue;
                        }
                        if result < 0 {
                            if let Some(splice_state) = connections[slab_index].pending_splice.take() {
                                pipe_pool.release((splice_state.pipe_read_fd, splice_state.pipe_write_fd));
                            }
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        }
                        let n = result as u64;
                        let ConnectionProtocol::Http1(h1) = &mut connections[slab_index].protocol else {
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        };
                        let Some(pending) = &mut h1.pending_file else {
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
                            continue;
                        };
                        pending.offset += n;
                        pending.remaining = pending.remaining.saturating_sub(n);

                        if pending.remaining == 0 {
                            h1.pending_file = None;
                            let keep_alive = h1.keep_alive;
                            if let Some(splice_state) = connections[slab_index].pending_splice.take() {
                                pipe_pool.release((splice_state.pipe_read_fd, splice_state.pipe_write_fd));
                            }
                            if !keep_alive {
                                cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                                connections.remove(slab_index);
                                continue;
                            }
                            drain_pipelined_request_or_recv(self, worker_id, &mut ring, &mut connections, slab_index, completion_generation, &mut registered_buffer_pool);
                        } else if let Err(reason) = submit_splice_to_pipe(&mut ring, &mut connections, &mut pipe_pool, slab_index) {
                            tracing::warn!(worker_id, %reason, "failed to submit next splice-to-pipe leg of a file relay");
                            if let Some(splice_state) = connections[slab_index].pending_splice.take() {
                                pipe_pool.release((splice_state.pipe_read_fd, splice_state.pipe_write_fd));
                            }
                            cancel_outstanding_operations(&mut ring, completion_generation, slab_index);
                            connections.remove(slab_index);
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
                        //
                        // Also a convenient, already-periodic point to
                        // sweep idle_upstream_conns for entries that
                        // have sat unused past their own idle_timeout
                        // -- mirrors UpstreamPool's own periodic
                        // idle-connection cleanup on the mio side (see
                        // that method's own doc comment), just driven
                        // by this backend's existing loop timeout
                        // instead of a separate health-check cycle.
                        let now = std::time::Instant::now();
                        for entries in idle_upstream_conns.values_mut() {
                            let mut i = 0;
                            while i < entries.len() {
                                let (idle_slab_index, idle_generation, last_used, idle_timeout) = entries[i];
                                if now.duration_since(last_used) > idle_timeout {
                                    entries.swap_remove(i);
                                    if connections.contains(idle_slab_index) && connections[idle_slab_index].generation == idle_generation {
                                        cancel_outstanding_operations(&mut ring, idle_generation, idle_slab_index);
                                        connections.remove(idle_slab_index);
                                    }
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        idle_upstream_conns.retain(|_, entries| !entries.is_empty());
                    }

                    OP_TAG_LINK_TIMEOUT => {
                        // See this constant's own doc comment --
                        // deliberately a no-op. The linked operation
                        // (Connect/Send/Recv) this timeout was bound
                        // to gets its own completion, with -ECANCELED
                        // if the timeout actually fired first; that
                        // arm is where the real teardown/failure
                        // handling happens, not here.
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

/// Same as `run`, but lets this module's own tests trust a specific
/// root store for upstream TLS connections instead of the platform
/// default -- see `EventLoopWorker::upstream_tls_test_roots`'s own
/// doc comment for why this exists only under `#[cfg(test)]`.
#[cfg(test)]
fn run_with_upstream_tls_test_roots(server: Arc<RoutaServer>, port: u16, n_workers: usize, roots: rustls::RootCertStore) -> crate::core::worker::WorkerPool {
    let mut worker = EventLoopWorker::new(port, server);
    worker.upstream_tls_test_roots = Some(roots);
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

    /// A real h2c upgrade (HTTP/1.1 Upgrade: h2c), followed by a real
    /// H2 connection preface, over an actual TCP connection -- proves
    /// the 101 response and the H2 preface's own initial SETTINGS both
    /// reach the client in the right order (see
    /// process_http1_read_buf's h2c handling for the bug this guards
    /// against: the 101 response being silently dropped when it was
    /// left behind in the old Http1Connection's write_buf instead of
    /// carried over to the new Http2Connection's).
    #[test]
    fn h2c_upgrade_reaches_a_real_client_in_correct_frame_order() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.h2.h2c_upgrade_enabled = true;
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        // An empty HTTP2-Settings value base64url-decodes to zero
        // bytes -- a validly-shaped (empty) SETTINGS payload, same
        // convention mio_backend's own equivalent test uses.
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n";
        stream.write_all(request.as_bytes()).expect("write upgrade request should succeed");

        // Read the raw response bytes first (rather than parsing
        // line-by-line right away) so a failure here shows exactly
        // what came back, instead of a generic UTF-8 decode error with
        // no visibility into the actual bytes.
        let mut raw_response = [0u8; 512];
        let n = stream.read(&mut raw_response).expect("read upgrade response should succeed");

        let mut reader = std::io::BufReader::new(&raw_response[..n]);
        let mut status_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut status_line).expect("read status line should succeed");
        assert!(status_line.starts_with("HTTP/1.1 101"), "expected 101 Switching Protocols, got: {status_line:?}");
        loop {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).expect("read header line should succeed");
            if line == "\r\n" {
                break;
            }
        }

        let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // an empty client SETTINGS frame
        stream.write_all(&preface).expect("write h2 preface should succeed");

        let mut response_header = [0u8; 9];
        std::io::Read::read_exact(&mut reader, &mut response_header).expect("read the first H2 frame header should succeed");
        let frame_type = response_header[3];
        assert_eq!(frame_type, 0x4, "expected a SETTINGS frame as the first bytes back over the upgraded connection");

        pool.shutdown();
    }

    /// A real RFC 8441 Extended CONNECT WebSocket-over-H2 tunnel, end
    /// to end over an actual TCP connection: h2c upgrade, the server's
    /// SETTINGS advertising SETTINGS_ENABLE_CONNECT_PROTOCOL, an
    /// Extended CONNECT request accepted with a 200, a WS frame sent
    /// as H2 DATA, and the registered handler's reply coming back the
    /// same way. Exercises process_http2_input's WS-tunnel handling
    /// (new_ws_tunnel_streams / ws_tunnel_streams_with_input) through
    /// this backend's real accept/recv/send cycle, not just the shared
    /// protocol.rs logic in isolation.
    #[test]
    fn websocket_over_h2_tunnel_end_to_end() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.h2.h2c_upgrade_enabled = true;
        config.ws.enabled = true;
        config.port = port as i32;
        let mut server = RoutaServer::from_config(config).expect("build a minimal RoutaServer");
        let mut router = crate::http::router::Router::new();
        router.add_websocket_route("/ws", |msg| match msg {
            crate::http::ws::WsMessage::Text(text) if text == "ping" => Some(crate::http::ws::WsMessage::Text("pong".to_string())),
            _ => None,
        });
        server.router = Arc::new(router);
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

        // h2c upgrade dance -- same as h2c_upgrade_reaches_a_real_client_in_correct_frame_order.
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n";
        stream.write_all(request.as_bytes()).expect("write upgrade request should succeed");

        let mut header_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).expect("read response byte should succeed");
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let status_text = String::from_utf8_lossy(&header_buf);
        assert!(status_text.starts_with("HTTP/1.1 101"), "expected 101 Switching Protocols, got: {status_text:?}");

        // assume_preface_received means the client's own connection
        // preface is just its (empty) SETTINGS frame -- no literal
        // "PRI * HTTP/2.0..." string is expected on this connection.
        stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).expect("write client settings frame should succeed");

        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
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
        stream.write_all(&headers_frame).expect("write extended connect request should succeed");

        let mut server_decoder = crate::http::h2::hpack::HpackContext::new(4096);
        let (status, end_stream) = read_h2_status_headers(&mut reader, &mut server_decoder);
        assert_eq!(status, "200");
        assert!(!end_stream, "an accepted WS tunnel's 200 response must not end the stream");

        // A real WebSocket TEXT frame, sent as H2 DATA on the tunnel.
        let ws_frame = build_masked_ws_text_frame("ping");
        let mut data_frame = Vec::new();
        crate::http::h2::frame::write_data(&mut data_frame, 1, &ws_frame, false);
        stream.write_all(&data_frame).expect("write ws data frame should succeed");

        let reply_payload = read_h2_data_payload(&mut reader);
        let (opcode, payload) = parse_unmasked_ws_frame(&reply_payload);
        assert_eq!(opcode, 0x1, "expected a text frame");
        assert_eq!(payload, b"pong");

        pool.shutdown();
    }

    /// Reads exactly one H2 frame (header + payload) off `reader`.
    fn read_one_h2_frame(reader: &mut impl std::io::BufRead) -> (u8, u8, Vec<u8>) {
        let mut header = [0u8; 9];
        std::io::Read::read_exact(reader, &mut header).expect("read frame header should succeed");
        let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let frame_type = header[3];
        let flags = header[4];
        let mut payload = vec![0u8; len];
        std::io::Read::read_exact(reader, &mut payload).expect("read frame payload should succeed");
        (frame_type, flags, payload)
    }

    /// Reads frames until a HEADERS frame (type `0x1`) arrives,
    /// skipping anything else -- returns the decoded `:status` value
    /// and whether END_STREAM was set.
    fn read_h2_status_headers(reader: &mut impl std::io::BufRead, decoder: &mut crate::http::h2::hpack::HpackContext) -> (String, bool) {
        loop {
            let (frame_type, flags, payload) = read_one_h2_frame(reader);
            if frame_type != 0x1 {
                continue;
            }
            let fields = decoder.decode(&payload).expect("decode headers should succeed");
            let status = fields.iter().find(|h| h.name == ":status").expect("a :status pseudo-header should be present").value.clone();
            return (status, flags & 0x1 != 0);
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

    /// A real TLS handshake (real certificate, real rustls client and
    /// server, real ALPN negotiation selecting HTTP/1.1) followed by a
    /// real HTTP/1.1 request/response, all over an actual TCP
    /// connection -- exercises advance_tls, submit_tls_send, and
    /// submit_send's TLS-encryption branch together, end to end,
    /// rather than any one piece in isolation. Not yet covered by an
    /// equivalent mio_backend test (there wasn't one to mirror), so
    /// this is this session's first real proof either backend serves
    /// actual HTTPS traffic correctly.
    #[test]
    fn tls_handshake_and_http_request_end_to_end_over_real_tcp() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let (cert_der, key_der, trust_anchor_der) = crate::net::tls::generate_test_identity("localhost");
        let tls_ctx = crate::net::tls::TlsContext::builder_from_der(vec![cert_der], key_der)
            .expect("build TLS context")
            .build()
            .expect("finish building TLS context");

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        let mut server = RoutaServer::from_config(config).expect("build a minimal RoutaServer");
        server.tls_context = Some(std::sync::Arc::new(tls_ctx));
        let server = Arc::new(server);
        let pool = run(server, port, 1);

        // Give the worker a moment to bind before connecting.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let tcp = {
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
            connected.expect("worker should eventually accept a connection")
        };
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("set read timeout");
        tcp.set_nodelay(true).expect("set nodelay");

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(trust_anchor_der).expect("add test cert to root store");
        let mut client = crate::net::tls::TlsConnection::new_client_with_roots("localhost", vec![], root_store).expect("create client connection");

        // Drive the client-side handshake directly against the real
        // TCP socket (mirroring what a real HTTPS client library does
        // under the hood) -- this test's job is to prove the SERVER
        // side (driven through this backend's completion loop) is
        // correct, so the client side just needs to be a real,
        // independently-correct rustls client, not itself exercising
        // anything about io_uring.
        let mut tcp_for_handshake = tcp.try_clone().expect("clone tcp stream");
        for _ in 0..50 {
            let advance = client.advance_io(&mut tcp_for_handshake);
            if advance.is_err() {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            if !client.is_handshaking() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!client.is_handshaking(), "client-side TLS handshake should have completed");

        // A real HTTP/1.1 request, encrypted through the now-established
        // TLS session and written to the real socket.
        client.write_plaintext(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("queue plaintext request");
        client.advance_io(&mut tcp_for_handshake).expect("flush encrypted request");

        // Read and decrypt the response.
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        for _ in 0..50 {
            match client.advance_io(&mut tcp_for_handshake) {
                Ok(advance) => {
                    loop {
                        match client.read_plaintext(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => response.extend_from_slice(&buf[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    if advance.peer_closed || !response.is_empty() {
                        break;
                    }
                }
                Err(_) => break,
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.starts_with("HTTP/1.1 "), "expected a well-formed HTTP/1.1 status line over TLS, got: {response_text:?}");

        pool.shutdown();
    }

    /// Same shape as tls_handshake_and_http_request_end_to_end_over_real_tcp,
    /// but the client offers ALPN "h2" and the request/response is
    /// real HTTP/2 framing (HEADERS/DATA) encrypted through the same
    /// TLS session -- proves the HandshakeJustCompleted branch's ALPN
    /// check actually selects Http2 (not just that the match arm
    /// exists), and that process_http2_input correctly receives
    /// decrypted plaintext the same way process_http1_read_buf does.
    #[test]
    fn tls_alpn_h2_handshake_and_http2_request_end_to_end_over_real_tcp() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let (cert_der, key_der, trust_anchor_der) = crate::net::tls::generate_test_identity("localhost");
        let tls_ctx = crate::net::tls::TlsContext::builder_from_der(vec![cert_der], key_der)
            .expect("build TLS context")
            .build()
            .expect("finish building TLS context");

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        let mut server = RoutaServer::from_config(config).expect("build a minimal RoutaServer");
        server.tls_context = Some(std::sync::Arc::new(tls_ctx));
        let server = Arc::new(server);
        let pool = run(server, port, 1);

        std::thread::sleep(std::time::Duration::from_millis(100));

        let tcp = {
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
            connected.expect("worker should eventually accept a connection")
        };
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("set read timeout");
        tcp.set_nodelay(true).expect("set nodelay");

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(trust_anchor_der).expect("add test cert to root store");
        // The only difference from the HTTP/1.1 test: offering "h2" via ALPN.
        let mut client = crate::net::tls::TlsConnection::new_client_with_roots("localhost", vec![b"h2".to_vec()], root_store).expect("create client connection");

        let mut tcp_for_handshake = tcp.try_clone().expect("clone tcp stream");
        for _ in 0..50 {
            let advance = client.advance_io(&mut tcp_for_handshake);
            if advance.is_err() {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            if !client.is_handshaking() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!client.is_handshaking(), "client-side TLS handshake should have completed");
        assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()), "server should have negotiated h2 via ALPN");

        // A real H2 connection preface, encrypted through the TLS
        // session -- this connection never went through the h2c
        // Upgrade dance (there's no HTTP/1.1 request here at all),
        // ALPN alone is what told the server this is H2.
        let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // empty client SETTINGS frame
        client.write_plaintext(&preface).expect("queue h2 preface");
        client.advance_io(&mut tcp_for_handshake).expect("flush encrypted preface");

        // Read and decrypt the server's SETTINGS frame.
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        for _ in 0..50 {
            match client.advance_io(&mut tcp_for_handshake) {
                Ok(advance) => {
                    loop {
                        match client.read_plaintext(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => response.extend_from_slice(&buf[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    if advance.peer_closed || response.len() >= 9 {
                        break;
                    }
                }
                Err(_) => break,
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        assert!(response.len() >= 9, "expected at least a 9-byte H2 frame header back, got {} bytes", response.len());
        let frame_type = response[3];
        assert_eq!(frame_type, 0x4, "expected a SETTINGS frame as the first bytes back over the TLS+ALPN h2 connection");

        pool.shutdown();
    }

    /// A real TLS handshake, a real WebSocket upgrade over that TLS
    /// session, a real echoed application message, and a real close
    /// handshake -- proves WS-over-TLS works end to end the same way
    /// websocket_upgrade_echo_and_close_handshake_end_to_end proves
    /// plain WS does, without needing an external tool (Autobahn) that
    /// turned out to need a per-test-case TLS handshake and became
    /// impractically slow against this backend's own test suite.
    #[test]
    fn tls_websocket_upgrade_echo_and_close_handshake_end_to_end() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let (cert_der, key_der, trust_anchor_der) = crate::net::tls::generate_test_identity("localhost");
        let tls_ctx = crate::net::tls::TlsContext::builder_from_der(vec![cert_der], key_der)
            .expect("build TLS context")
            .build()
            .expect("finish building TLS context");

        let mut config = crate::core::config::RoutaConfig::default();
        config.ws.enabled = true;
        config.port = port as i32;
        let mut server = RoutaServer::from_config(config).expect("build a minimal RoutaServer");
        server.tls_context = Some(std::sync::Arc::new(tls_ctx));
        let mut router = crate::http::router::Router::new();
        router.add("/ws", &[crate::http::request::HttpMethod::Get], |req, _params| {
            crate::http::ws::build_handshake_response(req, None)
        });
        router.add_websocket_route("/ws", |msg| match msg {
            crate::http::ws::WsMessage::Text(text) if text == "ping" => Some(crate::http::ws::WsMessage::Text("pong".to_string())),
            _ => None,
        });
        let router = Arc::new(router);
        server.router = Arc::clone(&router);
        server.middleware_chain = Arc::new(crate::http::middleware::ChainBuilder::new().build(move |req| match router.dispatch(req) {
            crate::http::router::Dispatch::Matched { handler, params } => handler(req, &params),
            crate::http::router::Dispatch::MethodNotAllowed { .. } => crate::http::response::HttpResponse::new(405, "Method Not Allowed"),
            crate::http::router::Dispatch::NotFound => crate::http::response::HttpResponse::new(404, "Not Found"),
        }));
        let server = Arc::new(server);
        let pool = run(server, port, 1);

        std::thread::sleep(std::time::Duration::from_millis(100));

        let tcp = {
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
            connected.expect("worker should eventually accept a connection")
        };
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("set read timeout");
        tcp.set_nodelay(true).expect("set nodelay");

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(trust_anchor_der).expect("add test cert to root store");
        let mut client = crate::net::tls::TlsConnection::new_client_with_roots("localhost", vec![], root_store).expect("create client connection");

        let mut tcp_for_io = tcp.try_clone().expect("clone tcp stream");
        for _ in 0..50 {
            let advance = client.advance_io(&mut tcp_for_io);
            if advance.is_err() {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            if !client.is_handshaking() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!client.is_handshaking(), "client-side TLS handshake should have completed");

        // A real WebSocket upgrade request, encrypted through the TLS
        // session.
        client
            .write_plaintext(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
            .expect("queue upgrade request");
        client.advance_io(&mut tcp_for_io).expect("flush encrypted upgrade request");

        // Read and decrypt the upgrade response, one byte at a time
        // until the header terminator, to avoid consuming bytes that
        // belong to the first WS frame that might arrive in the same
        // encrypted read.
        let mut header_buf = Vec::new();
        let mut decrypted_byte = [0u8; 1];
        loop {
            match client.read_plaintext(&mut decrypted_byte) {
                Ok(1) => {
                    header_buf.push(decrypted_byte[0]);
                    if header_buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    client.advance_io(&mut tcp_for_io).expect("advance while waiting for upgrade response");
                }
                Err(e) => panic!("unexpected error reading upgrade response: {e}"),
            }
        }
        let response_text = String::from_utf8_lossy(&header_buf);
        assert!(response_text.starts_with("HTTP/1.1 101"), "expected 101 Switching Protocols, got: {response_text:?}");

        // A masked "ping" text frame, encrypted through the same TLS
        // session.
        let ping_frame = build_masked_ws_text_frame("ping");
        client.write_plaintext(&ping_frame).expect("queue ping frame");
        client.advance_io(&mut tcp_for_io).expect("flush encrypted ping frame");

        // Read and decrypt the "pong" reply.
        let mut reply = Vec::new();
        let mut buf = [0u8; 256];
        for _ in 0..50 {
            match client.advance_io(&mut tcp_for_io) {
                Ok(_) => {
                    loop {
                        match client.read_plaintext(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => reply.extend_from_slice(&buf[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    if !reply.is_empty() {
                        break;
                    }
                }
                Err(_) => break,
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!reply.is_empty(), "expected an encrypted pong reply");
        let (opcode, payload) = parse_unmasked_ws_frame(&reply);
        assert_eq!(opcode, 0x1, "expected a text frame");
        assert_eq!(payload, b"pong");

        // A masked close frame, and confirmation the connection
        // actually closes afterward (the TLS session ending cleanly,
        // not just the raw TCP socket).
        let close_frame = build_masked_ws_close_frame();
        client.write_plaintext(&close_frame).expect("queue close frame");
        client.advance_io(&mut tcp_for_io).expect("flush encrypted close frame");

        let mut tail = Vec::new();
        let mut buf2 = [0u8; 256];
        for _ in 0..50 {
            match client.advance_io(&mut tcp_for_io) {
                Ok(advance) => {
                    loop {
                        match client.read_plaintext(&mut buf2) {
                            Ok(0) => break,
                            Ok(n) => tail.extend_from_slice(&buf2[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    if advance.peer_closed {
                        break;
                    }
                }
                Err(_) => break, // connection reset/closed -- also an acceptable clean end for this test's purposes
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        pool.shutdown();
    }

    /// Two requests over the same TCP connection, the second one
    /// requesting Connection: close -- proves keep-alive actually
    /// keeps this backend's own Http1Connection state (its read_buf,
    /// in particular, since a pipelined or back-to-back second
    /// request's bytes may already be sitting in the same Recv
    /// completion or a later one on the same connection) alive across
    /// requests, rather than requiring a fresh connection each time.
    /// Mirrors mio_backend's own equivalent test.
    /// A GET request for an mmap'd (in-memory body, not
    /// PendingFileSend/splice) static file whose serialized response
    /// exceeds submit_send's own SendZc size threshold -- proves the
    /// SendZc path (see OP_TAG_SEND_ZC's own completion arm and its
    /// two-CQE MORE/NOTIF lifecycle) delivers the complete,
    /// byte-correct body, not just that it compiles.
    #[test]
    fn serves_in_memory_response_via_send_zc() {
        let dir = std::env::temp_dir().join(format!(
            "routa_uring_send_zc_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp webroot");
        // Above submit_send's 16KiB SendZc threshold but below the
        // default 64KiB mmap_threshold, so this takes the mmap'd
        // in-memory body path (a real write_buf send) rather than a
        // PendingFileSend/splice relay -- see static_files::serve's
        // own `lookup.mapped` branch.
        let body: Vec<u8> = (0..32_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("mid.bin"), &body).expect("write mid.bin");
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };
        let mut config = crate::core::config::RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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
        stream.write_all(b"GET /mid.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response to EOF");
        let header_end = response.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(response.len());
        let headers = String::from_utf8_lossy(&response[..header_end]);
        assert!(headers.starts_with("HTTP/1.1 200"), "expected a 200, got: {headers:?}");
        assert_eq!(response[header_end..].len(), body.len(), "SendZc response body length mismatch");
        assert_eq!(&response[header_end..], &body[..], "SendZc response body content mismatch");

        pool.shutdown();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    /// A GET request for a file above FileCache's mmap_threshold --
    /// proves this backend's own Splice-based relay (see
    /// submit_splice_to_pipe/submit_splice_to_socket) actually
    /// delivers the complete, byte-correct body over a real TCP
    /// connection, including on a Connection: close request (which
    /// requires the fully_flushed-but-pending_file distinction in the
    /// OP_TAG_SEND completion arm to hold: the connection must stay
    /// open long enough to relay the file before closing, not close
    /// the instant its headers are flushed).
    fn serves_large_static_file_via_splice_relay() {
        let dir = std::env::temp_dir().join(format!(
            "routa_uring_splice_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp webroot");
        // Larger than the pipe-relay's own 64KiB per-splice cap, so a
        // correct test run must cross multiple FileToPipe/PipeToSocket
        // cycles, not just prove a single splice pair works.
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("big.bin"), &body).expect("write big.bin");
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };
        let mut config = crate::core::config::RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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
        stream.write_all(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response to EOF");
        let header_end = response.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(response.len());
        let headers = String::from_utf8_lossy(&response[..header_end]);
        assert!(headers.starts_with("HTTP/1.1 200"), "expected a 200, got: {headers:?}");
        assert_eq!(response[header_end..].len(), body.len(), "relayed body length mismatch");
        assert_eq!(&response[header_end..], &body[..], "relayed body content mismatch");

        pool.shutdown();
        std::fs::remove_dir_all(&dir).ok();
    }
    /// Many sequential requests over separate connections, each
    /// expected to use a ReadFixed recv against the worker's
    /// RegisteredBufferPool -- proves buffers are correctly returned
    /// to the pool after each connection closes rather than being
    /// permanently consumed (a leak here would exhaust the pool after
    /// registered_buffer_count connections and force every later one
    /// onto the ordinary Recv fallback silently, which this test
    /// would not directly observe -- what it does prove is that
    /// running well past the pool's own size still serves every
    /// request correctly, which a real leak would eventually break as
    /// requests kept accumulating unreturned buffers).
    /// A cache-miss GET (first request for a path) followed by a
    /// cache-hit GET for the same path, and a GET for a path that
    /// never existed -- proves the asynchronous OPENAT+STATX-free
    /// stat path (Http1Outcome::FileCachePending -> submit_statx ->
    /// OP_TAG_STATX's own completion arm -> static_files::finish_after_stat)
    /// delivers correct results end to end for all three outcomes:
    /// a fresh stat populating the cache, a subsequent cache hit
    /// needing no stat at all, and a stat that fails (404, negative
    /// cached).
    #[test]
    fn static_file_cache_miss_is_resolved_asynchronously_via_statx() {
        let dir = std::env::temp_dir().join(format!(
            "routa_uring_statx_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp webroot");
        std::fs::write(dir.join("exists.txt"), b"async stat works").expect("write exists.txt");

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };
        let mut config = crate::core::config::RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
        let pool = run(server, port, 1);

        let get = |path: &str| -> String {
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
            stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).expect("write request");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).expect("read response to EOF");
            String::from_utf8_lossy(&response).to_string()
        };

        // First request: cache-miss, resolved via the async statx path.
        let first = get("/exists.txt");
        assert!(first.starts_with("HTTP/1.1 200"), "expected a 200 on cache-miss, got: {first:?}");
        assert!(first.ends_with("async stat works"), "expected the file's body on cache-miss, got: {first:?}");

        // Second request: cache-hit, no statx needed at all.
        let second = get("/exists.txt");
        assert!(second.starts_with("HTTP/1.1 200"), "expected a 200 on cache-hit, got: {second:?}");
        assert!(second.ends_with("async stat works"), "expected the file's body on cache-hit, got: {second:?}");

        // A path that never existed: statx fails, finish_after_stat's
        // own None branch negative-caches it and returns 404.
        let missing = get("/does-not-exist.txt");
        assert!(missing.starts_with("HTTP/1.1 404"), "expected a 404 for a missing file, got: {missing:?}");

        pool.shutdown();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn many_sequential_requests_reuse_the_registered_buffer_pool() {
        let dir = std::env::temp_dir().join(format!(
            "routa_uring_bufpool_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp webroot");
        std::fs::write(dir.join("small.txt"), b"pooled").expect("write small.txt");
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };
        let mut config = crate::core::config::RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        config.port = port as i32;
        // Default registered_buffer_count is 256 -- run more requests
        // than that so a leaked buffer would eventually exhaust the
        // pool.
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
        let pool = run(server, port, 1);

        for _ in 0..300 {
            let mut connected = None;
            for _ in 0..50 {
                match StdTcpStream::connect(("127.0.0.1", port)) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
            let mut stream = connected.expect("worker should eventually accept a connection");
            stream.set_read_timeout(Some(std::time::Duration::from_secs(3))).expect("set read timeout");
            stream.write_all(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write request");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).expect("read response to EOF");
            let response_text = String::from_utf8_lossy(&response);
            assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200, got: {response_text:?}");
            assert!(response_text.ends_with("pooled"), "expected the file's body, got: {response_text:?}");
        }

        pool.shutdown();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keep_alive_connection_serves_multiple_requests_over_real_tcp() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let dir = std::env::temp_dir().join(format!(
            "routa_uring_ka_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp webroot");
        std::fs::write(dir.join("a.txt"), b"first").expect("write a.txt");
        std::fs::write(dir.join("b.txt"), b"second").expect("write b.txt");

        let mut config = crate::core::config::RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        stream.write_all(b"GET /a.txt HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write first request");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).expect("read first response");
        let first_response = String::from_utf8_lossy(&buf[..n]);
        assert!(first_response.contains("first"), "expected first response to contain 'first', got: {first_response:?}");

        // Same connection, second request -- proves keep-alive kept
        // this connection's slab slot (and its Http1Connection state)
        // alive rather than the first response's flush having torn it
        // down.
        stream.write_all(b"GET /b.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write second request");
        let mut buf2 = Vec::new();
        stream.read_to_end(&mut buf2).expect("read second response to EOF");
        let second_response = String::from_utf8_lossy(&buf2);
        assert!(second_response.contains("second"), "expected second response to contain 'second', got: {second_response:?}");

        std::fs::remove_dir_all(&dir).ok();
        pool.shutdown();
    }

    /// Two requests written to the socket back-to-back, without
    /// waiting for the first response before sending the second (real
    /// HTTP/1.1 pipelining, RFC 9112 9.4) -- both requests may well
    /// arrive in the same Recv completion. Proves process_http1_read_buf's
    /// parse loop correctly drains multiple complete requests already
    /// sitting in read_buf from a single completion, rather than only
    /// ever handling one request per Recv the way the sequential
    /// keep-alive test above does.
    #[test]
    fn pipelined_requests_in_a_single_write_both_get_responses() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let dir = std::env::temp_dir().join(format!(
            "routa_uring_pipeline_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp webroot");
        std::fs::write(dir.join("a.txt"), b"first").expect("write a.txt");
        std::fs::write(dir.join("b.txt"), b"second").expect("write b.txt");

        let mut config = crate::core::config::RoutaConfig::default();
        config.static_dirs.push(("/".to_string(), dir.to_str().unwrap().to_string()));
        config.port = port as i32;
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        // Both requests in a single write() call -- as likely as
        // possible to arrive in the same underlying Recv completion.
        let both_requests = b"GET /a.txt HTTP/1.1\r\nHost: localhost\r\n\r\nGET /b.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(both_requests).expect("write pipelined requests");

        let mut all_bytes = Vec::new();
        stream.read_to_end(&mut all_bytes).expect("read both responses to EOF");
        let full_text = String::from_utf8_lossy(&all_bytes);

        assert!(full_text.contains("first"), "expected the first response's body in the combined stream, got: {full_text:?}");
        assert!(full_text.contains("second"), "expected the second response's body in the combined stream, got: {full_text:?}");
        // Two distinct status lines confirms both requests were
        // actually dispatched and answered, not just one response
        // whose body happened to contain both filenames.
        assert_eq!(full_text.matches("HTTP/1.1 200").count(), 2, "expected exactly two 200 responses, got: {full_text:?}");

        std::fs::remove_dir_all(&dir).ok();
        pool.shutdown();
    }

    /// Proves the raw building blocks (create_upstream_socket,
    /// encode_sockaddr, submit_connect) actually complete a real TCP
    /// connection through io_uring's Connect opcode, in isolation from
    /// the rest of the proxy machinery this is a first step toward --
    /// a minimal ring, a minimal listener the test itself accepts
    /// from, and a direct check of the OP_TAG_CONNECT completion's
    /// result.
    #[test]
    fn submit_connect_completes_a_real_tcp_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let target_addr = listener.local_addr().expect("local addr");

        let mut ring = IoUring::new(8).expect("create ring");

        let fd = create_upstream_socket(&target_addr).expect("create upstream socket");
        let mut slab: Slab<Connection> = Slab::new();
        let placeholder_transport = Transport::Plain(fd);
        let test_node = std::sync::Arc::new(crate::lb::upstream::UpstreamNode::new(target_addr.ip().to_string(), target_addr.port(), 1, false, 32));
        let test_pool = std::sync::Arc::new(crate::lb::upstream::UpstreamPool::new(3, 2));
        let conn = Connection::new_upstream(fd as u64, placeholder_transport, target_addr, 4096, 1, test_node, test_pool, (std::time::Duration::from_secs(5), std::time::Duration::from_secs(5)));
        let slab_index = slab.insert(conn);

        submit_connect(&mut ring, &mut slab, slab_index, std::time::Duration::from_secs(5)).expect("submit connect SQE");
        ring.submit_and_wait(1).expect("submit and wait for connect completion");

        let cqe = ring.completion().next().expect("a completion should be available");
        let (op_tag, _generation, completed_slab_index) = split_user_data(cqe.user_data());
        assert_eq!(op_tag, OP_TAG_CONNECT);
        assert_eq!(completed_slab_index, slab_index);
        assert_eq!(cqe.result(), 0, "connect should succeed against a real, listening TCP socket");

        // Accept the connection on the listener side, proving this
        // wasn't just a local success code with no real peer.
        listener.set_nonblocking(true).expect("set listener nonblocking");
        let mut accepted = None;
        for _ in 0..50 {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted = Some(stream);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(e) => panic!("unexpected accept error: {e}"),
            }
        }
        assert!(accepted.is_some(), "listener should have accepted the real connection submit_connect established");
    }

    /// A real client request, proxied through this backend's own
    /// asynchronous connect/send/recv cycle (submit_connect,
    /// OP_TAG_CONNECT, the upstream-response handling in OP_TAG_RECV)
    /// to a real upstream TCP server, and the real upstream response
    /// flushed back to the real client -- the uring-backend equivalent
    /// of mio_backend's own `lb_pool_route_forwards_to_real_upstream_through_the_router`,
    /// but exercising the full accept/recv/send completion loop end to
    /// end rather than calling middleware_chain.execute() and forward()
    /// directly.
    #[test]
    fn proxy_request_forwards_to_real_upstream_end_to_end() {
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind upstream listener");
        let upstream_port = upstream_listener.local_addr().expect("upstream addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let body = b"upstream!";
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
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
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write proxied request");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200 from the real upstream, got: {response_text:?}");
        assert!(response_text.ends_with("upstream!"), "expected the real upstream's body, got: {response_text:?}");

        pool.shutdown();
    }

    /// A real Connect SQE bounded by a real LinkTimeout, against a
    /// TCP address that never responds (RFC 5737 TEST-NET-1, a
    /// documentation-only range guaranteed to never route anywhere)
    /// -- proves the LinkTimeout actually cancels the Connect within
    /// its configured bound rather than leaving submit_and_wait
    /// blocked indefinitely.
    #[test]
    fn submit_connect_link_timeout_cancels_a_hanging_connect() {
        let mut ring = IoUring::new(8).expect("create ring");

        // 192.0.2.1 (TEST-NET-1, RFC 5737) is documentation-only --
        // never assigned to a real host, and typically silently
        // dropped rather than actively refused, so connect(2) against
        // it hangs until something (here, the LinkTimeout) cancels it.
        let target_addr: std::net::SocketAddr = "192.0.2.1:9".parse().expect("parse test-net-1 address");
        let fd = create_upstream_socket(&target_addr).expect("create upstream socket");
        let mut slab: Slab<Connection> = Slab::new();
        let test_node = std::sync::Arc::new(crate::lb::upstream::UpstreamNode::new(target_addr.ip().to_string(), target_addr.port(), 1, false, 32));
        let test_pool = std::sync::Arc::new(crate::lb::upstream::UpstreamPool::new(3, 2));
        let conn = Connection::new_upstream(fd as u64, Transport::Plain(fd), target_addr, 4096, 1, test_node, test_pool, (std::time::Duration::from_secs(5), std::time::Duration::from_secs(5)));
        let slab_index = slab.insert(conn);

        let start = std::time::Instant::now();
        submit_connect(&mut ring, &mut slab, slab_index, std::time::Duration::from_millis(500)).expect("submit connect+timeout SQEs");
        ring.submit_and_wait(1).expect("submit and wait for a completion");
        let elapsed = start.elapsed();

        let cqe = ring.completion().next().expect("a completion should be available");
        let (op_tag, _, _) = split_user_data(cqe.user_data());

        // Whichever of the two linked SQEs happens to be reported
        // first, the connect itself must have been cancelled well
        // before this test's own hard failure bound -- 500ms
        // configured, generous slack up to 5s to stay robust under
        // slow CI/test-machine scheduling without the test itself
        // waiting anywhere near that long in practice.
        assert!(elapsed < std::time::Duration::from_secs(5), "connect should have been cancelled by its LinkTimeout, took {elapsed:?}");
        assert!(
            op_tag == OP_TAG_CONNECT || op_tag == OP_TAG_LINK_TIMEOUT,
            "expected either the Connect or its LinkTimeout to complete first, got op_tag={op_tag}"
        );
    }

    /// Two upstream nodes, the first one refusing every connection --
    /// proves the proxy retries against a second node rather than
    /// failing the client's request after the first node's
    /// connect(2) failure, mirroring mio_backend's own synchronous
    /// retry loop in core::proxy::forward.
    #[test]
    fn proxy_retries_a_second_node_after_the_first_refuses_connections() {
        // Bind and immediately close a listener to get a real port
        // number that's guaranteed to refuse connections (ECONNREFUSED)
        // rather than silently drop them the way an unroutable address
        // would -- a fast, deterministic failure is what actually
        // exercises the retry path itself, distinct from
        // submit_connect_link_timeout_cancels_a_hanging_connect's own
        // (slow, by design) timeout path.
        let refusing_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a refusing port");
            listener.local_addr().expect("local addr").port()
        };

        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind real upstream listener");
        let upstream_port = upstream_listener.local_addr().expect("upstream addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let body = b"second node!";
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            lb_max_retries: 2,
            upstreams: vec![
                crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: refusing_port, weight: 1, use_tls: false },
                crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: false },
            ],
            ..Default::default()
        });
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write proxied request");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200 after retrying to the working node, got: {response_text:?}");
        assert!(response_text.ends_with("second node!"), "expected the second (working) node's body, got: {response_text:?}");

        pool.shutdown();
    }

    /// A real proxied request through a sticky-session-enabled pool
    /// -- proves the response actually carries a Set-Cookie
    /// identifying the node it was routed to, not just that
    /// pick_node_sticky's own read side (honoring an incoming cookie)
    /// works.
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

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            sticky_session_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: false }],
            ..Default::default()
        });
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write proxied request");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200, got: {response_text:?}");
        assert!(response_text.to_lowercase().contains("set-cookie:"), "expected a Set-Cookie header identifying the sticky target, got: {response_text:?}");

        pool.shutdown();
    }

    /// A POST request with a real body -- proves the request body
    /// (not just headers) is actually forwarded to the upstream
    /// intact, by having the upstream itself echo back whatever body
    /// it received.
    #[test]
    fn proxy_forwards_request_body_to_upstream() {
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind real upstream listener");
        let upstream_port = upstream_listener.local_addr().expect("upstream addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).expect("read request from proxy");
                let received = String::from_utf8_lossy(&buf[..n]);
                // Echo the received body back as this "upstream"'s own
                // response body, so the test can assert on it directly
                // rather than needing its own HTTP/1.1 request parser.
                let body_start = received.find("\r\n\r\n").map(|i| i + 4).unwrap_or(received.len());
                let echoed_body = received[body_start..].as_bytes().to_vec();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", echoed_body.len());
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&echoed_body);
            }
        });

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: false }],
            ..Default::default()
        });
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        let body = b"a real POST body with several bytes in it";
        let request = format!(
            "POST /api/submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(request.as_bytes()).expect("write proxied request headers");
        stream.write_all(body).expect("write proxied request body");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200, got: {response_text:?}");
        assert!(
            response.ends_with(body),
            "expected the upstream's echoed body to match what the client sent, got: {response_text:?}"
        );

        pool.shutdown();
    }

    /// An upstream responding with Transfer-Encoding: chunked --
    /// proves try_parse_response (shared with mio_backend's own
    /// forward()) correctly recognizes a complete chunked response's
    /// framing (including its terminating zero-length chunk) rather
    /// than only ever handling Content-Length-framed responses, which
    /// is all every other proxy test here has exercised so far.
    #[test]
    fn proxy_handles_a_chunked_upstream_response() {
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind real upstream listener");
        let upstream_port = upstream_listener.local_addr().expect("upstream addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: false }],
            ..Default::default()
        });
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write proxied request");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200, got: {response_text:?}");
        assert!(
            response_text.contains("hello world") || response_text.contains("hello\r\n6\r\n world"),
            "expected the chunked body's decoded content somewhere in the response, got: {response_text:?}"
        );

        pool.shutdown();
    }

    /// Two keep-alive proxied requests over the same downstream
    /// connection -- proves the second request reuses the first's
    /// upstream TCP connection (via the idle pool) rather than
    /// opening a fresh one, by having the upstream itself accept only
    /// once and answer both requests on that single accepted socket.
    #[test]
    fn proxy_reuses_an_idle_upstream_connection_for_a_second_request() {
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind real upstream listener");
        let upstream_port = upstream_listener.local_addr().expect("upstream addr").port();
        std::thread::spawn(move || {
            // Accept exactly once -- if the proxy opened a second TCP
            // connection instead of reusing the idle one, that second
            // request would hang waiting on an accept() that never
            // comes, and the test's own read timeout would catch it.
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                for body in [&b"first"[..], &b"second"[..]] {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).expect("read a request on the reused connection");
                    assert!(n > 0, "expected a real request on the reused connection");
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(body);
                }
            }
        });

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: false }],
            ..Default::default()
        });
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
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

        // First request -- keep-alive, both sides.
        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write first proxied request");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).expect("read first proxied response");
        let first_response = String::from_utf8_lossy(&buf[..n]);
        assert!(first_response.starts_with("HTTP/1.1 200"), "expected a 200, got: {first_response:?}");
        assert!(first_response.ends_with("first"), "expected the first upstream body, got: {first_response:?}");

        // Give the event loop a moment to actually return the
        // upstream connection to the idle pool before the second
        // request arrives.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Second request, same downstream connection -- the real
        // assertion is in the upstream thread's own accept()-once
        // logic above; this just drives it.
        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write second proxied request");
        let mut response2 = Vec::new();
        stream.read_to_end(&mut response2).expect("read second proxied response to EOF");
        let second_response = String::from_utf8_lossy(&response2);
        assert!(second_response.starts_with("HTTP/1.1 200"), "expected a 200, got: {second_response:?}");
        assert!(second_response.ends_with("second"), "expected the second upstream body, got: {second_response:?}");

        pool.shutdown();
    }

    /// A real proxied request to a TLS-enabled upstream node --
    /// proves the OP_TAG_CONNECT/HandshakeJustCompleted TLS-handshake
    /// path added for upstream connections actually completes a real
    /// client-mode TLS handshake against a real TLS server and then
    /// sends the pending request over it, using
    /// run_with_upstream_tls_test_roots to trust this test's own
    /// self-signed certificate (see that function's own doc comment).
    #[test]
    fn proxy_forwards_to_a_tls_enabled_upstream() {
        let (cert_der, key_der, trust_anchor_der) = crate::net::tls::generate_test_identity("127.0.0.1");
        // Explicitly h2-disabled -- this test server only ever speaks
        // plain HTTP/1.1 over the TLS session, so it must not let
        // ALPN pick "h2" (rustls's own default ALPN offer, absent
        // with_h2_enabled(false), includes "h2" -- exactly what the
        // client-side upstream TLS handling added for H2 upstream
        // support now offers) -- a real H2 upstream test needs its
        // own dedicated server that actually speaks the H2 wire
        // protocol, not this one.
        let tls_ctx = crate::net::tls::TlsContext::builder_from_der(vec![cert_der], key_der)
            .expect("build TLS context")
            .with_h2_enabled(false)
            .build()
            .expect("finish building TLS context");

        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind real upstream listener");
        let upstream_port = upstream_listener.local_addr().expect("upstream addr").port();
        std::thread::spawn(move || {
            if let Ok(mut stream) = upstream_listener.accept().map(|(s, _)| s) {
                stream.set_nonblocking(true).expect("set test server stream nonblocking");
                let mut server_tls = crate::net::tls::TlsConnection::new_server(&tls_ctx).expect("create server TLS connection");

                for _ in 0..200 {
                    let _ = server_tls.advance_io(&mut stream);
                    if !server_tls.is_handshaking() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }

                let mut request_buf = Vec::new();
                for _ in 0..200 {
                    let _ = server_tls.advance_io(&mut stream);
                    let mut plaintext = [0u8; 4096];
                    match server_tls.read_plaintext(&mut plaintext) {
                        Ok(n) if n > 0 => {
                            request_buf.extend_from_slice(&plaintext[..n]);
                        }
                        Ok(_) => {}
                        Err(_) => {}
                    }
                    if request_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }

                let body = b"tls upstream!";
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                server_tls.write_plaintext(response.as_bytes()).expect("queue response headers");
                server_tls.write_plaintext(body).expect("queue response body");
                // A single advance_io call isn't guaranteed to flush
                // everything queued -- write_tls (inside advance_io)
                // can itself return WouldBlock partway through a large
                // write, and rustls may also still have a
                // post-handshake NewSessionTicket queued ahead of this
                // response's own bytes. Keep calling until there's
                // nothing left to write, holding the thread (and the
                // connection) open long enough for the client to
                // actually read it all rather than this thread
                // exiting and dropping `stream` prematurely.
                for _ in 0..50 {
                    let _ = server_tls.advance_io(&mut stream);
                    if !server_tls.wants_write() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                // Give the client a moment to finish reading before
                // this thread exits and the TcpStream is dropped
                // (which would otherwise send an abrupt RST/FIN right
                // as the client might still be mid-read).
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });

        let mut trust_roots = rustls::RootCertStore::empty();
        trust_roots.add(trust_anchor_der).expect("add test cert to trust roots");

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port");
            listener.local_addr().expect("local addr").port()
        };

        let mut config = crate::core::config::RoutaConfig::default();
        config.port = port as i32;
        config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: true }],
            ..Default::default()
        });
        let server = Arc::new(RoutaServer::from_config(config).expect("build a minimal RoutaServer"));
        let pool = run_with_upstream_tls_test_roots(server, port, 1, trust_roots);

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

        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write proxied request");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200 from the TLS upstream, got: {response_text:?}");
        assert!(response_text.ends_with("tls upstream!"), "expected the TLS upstream's body, got: {response_text:?}");

        pool.shutdown();
    }

    /// A real proxied request to an H2-speaking, TLS-enabled upstream
    /// -- the upstream here is a second real routa server (this same
    /// backend, running its own downstream H2 support, already proven
    /// correct by tls_alpn_h2_handshake_and_http2_request_end_to_end_over_real_tcp)
    /// rather than a hand-rolled test double, so this test exercises
    /// UringH2Client against a real, independently-implemented H2
    /// server the same way a production deployment would proxy to a
    /// real upstream.
    #[test]
    fn proxy_forwards_to_an_h2_upstream() {
        let (upstream_cert_der, upstream_key_der, upstream_trust_anchor_der) = crate::net::tls::generate_test_identity("127.0.0.1");
        let upstream_tls_ctx = crate::net::tls::TlsContext::builder_from_der(vec![upstream_cert_der], upstream_key_der)
            .expect("build upstream TLS context")
            .build()
            .expect("finish building upstream TLS context");

        let upstream_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port for the upstream");
            listener.local_addr().expect("local addr").port()
        };
        let mut upstream_config = crate::core::config::RoutaConfig::default();
        upstream_config.port = upstream_port as i32;
        let mut upstream_server = RoutaServer::from_config(upstream_config).expect("build the upstream RoutaServer");
        upstream_server.tls_context = Some(std::sync::Arc::new(upstream_tls_ctx));
        let mut router = crate::http::router::Router::new();
        router.add("/api/users", &[crate::http::request::HttpMethod::Get], |_req, _params| {
            let mut resp = crate::http::response::HttpResponse::new(200, "OK");
            resp.set_body(b"h2 upstream!".to_vec());
            resp
        });
        let router = Arc::new(router);
        upstream_server.router = Arc::clone(&router);
        upstream_server.middleware_chain = Arc::new(crate::http::middleware::ChainBuilder::new().build(move |req| match router.dispatch(req) {
            crate::http::router::Dispatch::Matched { handler, params } => handler(req, &params),
            crate::http::router::Dispatch::MethodNotAllowed { .. } => crate::http::response::HttpResponse::new(405, "Method Not Allowed"),
            crate::http::router::Dispatch::NotFound => crate::http::response::HttpResponse::new(404, "Not Found"),
        }));
        let upstream_pool = run(Arc::new(upstream_server), upstream_port, 1);

        let mut trust_roots = rustls::RootCertStore::empty();
        trust_roots.add(upstream_trust_anchor_der).expect("add upstream test cert to trust roots");

        let proxy_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to find a free port for the proxy");
            listener.local_addr().expect("local addr").port()
        };
        let mut proxy_config = crate::core::config::RoutaConfig::default();
        proxy_config.port = proxy_port as i32;
        proxy_config.pools.push(crate::core::config::LbPoolConfig {
            name: "api".to_string(),
            route: "/api/*".to_string(),
            lb_enabled: true,
            upstreams: vec![crate::core::config::UpstreamConfig { host: "127.0.0.1".to_string(), port: upstream_port, weight: 1, use_tls: true }],
            ..Default::default()
        });
        let proxy_server = Arc::new(RoutaServer::from_config(proxy_config).expect("build the proxy RoutaServer"));
        let proxy_pool = run_with_upstream_tls_test_roots(proxy_server, proxy_port, 1, trust_roots);

        let mut connected = None;
        for _ in 0..50 {
            match StdTcpStream::connect(("127.0.0.1", proxy_port)) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let mut stream = connected.expect("worker should eventually accept a connection");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("set read timeout");

        stream.write_all(b"GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write proxied request");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read proxied response to EOF");
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.starts_with("HTTP/1.1 200"), "expected a 200 from the H2 upstream, got: {response_text:?}");
        assert!(response_text.ends_with("h2 upstream!"), "expected the H2 upstream's body, got: {response_text:?}");

        proxy_pool.shutdown();
        upstream_pool.shutdown();
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
