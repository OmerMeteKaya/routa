//! The io_uring backend's connection shape: a completion-based
//! counterpart to `mio_conn`'s readiness-based one. `ConnectionProtocol`
//! and everything it contains (`Http1Connection`, `Http2Connection`,
//! `WsConnection`, their settings types) are backend-agnostic and live
//! in `core::conn::protocol` instead, shared with `mio_conn` unchanged
//! -- only the transport and the `Connection` struct that carries it
//! are specific to this backend.
//!
//! Plain TCP only today. TLS is a separate, later phase: rustls's
//! `read_plaintext`/`write_plaintext`/`advance_io` API is built
//! directly on synchronous `Read`/`Write`, the same way `mio_conn`'s
//! `Transport` uses it -- there's no "stream" to hand it here the way
//! there is on a readiness-based backend, since submitting a read and
//! receiving its result are two separate steps under io_uring rather
//! than one blocking-or-`WouldBlock` call. Bridging that gap (either
//! adapting rustls's own buffers into the SQE/CQE cycle, or a
//! different TLS integration built for a completion-based model
//! specifically) is its own design problem, deliberately not solved
//! here.

use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::Instant;

use crate::core::conn::protocol::ConnectionProtocol;

/// Monotonically increasing identifier, unique within a single worker
/// -- same meaning as `mio_conn::ConnId`, duplicated rather than
/// shared from there since the two backends otherwise have no
/// dependency on each other (see this module's own doc comment).
pub type ConnId = u64;

/// The transport a connection is speaking over: plain TCP, or TCP with
/// TLS driven through `net::tls::MemoryTlsIo` (see its own doc comment
/// for why rustls -- built on synchronous `Read`/`Write` -- can still
/// be driven correctly under io_uring's completion-based model: the
/// `Read`/`Write` it needs are satisfied by in-memory buffers rather
/// than the real fd, and this backend's own submit/completion loop is
/// what shuttles bytes between those buffers and real `Recv`/`Send`
/// SQEs). Carries the raw fd directly (not a higher-level socket type)
/// either way: every actual read/write/accept goes through this
/// backend's own submission-queue plumbing, never a direct syscall
/// against this fd the way `mio_conn::Transport`'s `Read`/`Write`
/// impls call straight through to `mio::net::TcpStream`.
pub enum Transport {
    Plain(RawFd),
    Tls {
        fd: RawFd,
        tls: Box<crate::net::tls::TlsConnection>,
        /// The in-memory buffers `tls`'s `advance_io` reads from and
        /// writes to -- see `net::tls::MemoryTlsIo`'s own doc comment.
        /// `io.incoming` is filled from real `Recv` completions before
        /// each `advance_io` call; `io.outgoing` is drained into a
        /// real `Send` SQE after.
        io: Box<crate::net::tls::MemoryTlsIo>,
    },
}

impl Transport {
    pub fn fd(&self) -> RawFd {
        match self {
            Transport::Plain(fd) => *fd,
            Transport::Tls { fd, .. } => *fd,
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, Transport::Tls { .. })
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Transport::Plain(_) => None,
            Transport::Tls { tls, .. } => tls.alpn_protocol(),
        }
    }
}

impl Transport {
    /// Extracts this transport's fd for reuse in a *replacement*
    /// `Transport` value, without running `Drop::drop`'s own
    /// `libc::close` -- needed whenever an existing `Transport::Plain`
    /// is upgraded in place to `Transport::Tls` (see
    /// `OP_TAG_CONNECT`'s own upstream-TLS handling): a plain
    /// assignment (`connections[i].transport = Transport::Tls { .. }`)
    /// drops the old `Transport::Plain` value first, which closes its
    /// fd -- exactly the fd the new `Transport::Tls` value is about to
    /// reuse. `std::mem::forget` on the old value (after copying its
    /// fd out via this method) is what actually suppresses that close.
    pub(crate) fn take_fd_for_reuse(self) -> RawFd {
        let fd = self.fd();
        std::mem::forget(self);
        fd
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        // Plain fd ownership, mirroring what a std/mio socket type's
        // own Drop impl would do -- this type deliberately doesn't
        // wrap one (see its own doc comment), so closing the fd is
        // this struct's responsibility rather than an inner value's.
        // Both variants own exactly one real fd regardless of whether
        // TLS is layered on top -- MemoryTlsIo owns no fd of its own
        // to also close.
        unsafe {
            libc::close(self.fd());
        }
    }
}

/// A single client connection: transport plus whichever protocol is
/// currently active on it. Same shape and role as `mio_conn::Connection`
/// -- see its doc comment -- with a completion-based `Transport` in
/// place of a readiness-based one.
/// Which side of a connection a `Connection` value represents --
/// see `Connection::role`'s own doc comment for why this needs to
/// exist at all (a proxied request's upstream connection is driven
/// through this same event loop, the same Slab, and the same
/// generation/cancel discipline as any client connection, rather than
/// through a separate synchronous module the way mio_backend's own
/// core::proxy currently is -- see that module's own doc comment on
/// why it drives sockets synchronously, a design choice this backend
/// deliberately doesn't repeat).
pub enum ConnectionRole {
    /// An ordinary client connection -- everything this backend has
    /// done up to this point.
    Downstream,
    /// A connection to an upstream server, opened to satisfy a
    /// downstream connection's proxied request.
    Upstream {
        /// The `LoadBalancer` node this connection was opened to --
        /// kept here so a connect failure or an early close (both
        /// handled well after `pick_node_sticky` returned this same
        /// `Arc`, in a different completion entirely) can still report
        /// `record_failure`/`record_success` against the right node,
        /// the same way mio_backend's own synchronous `forward()`
        /// does immediately after each attempt.
        node: std::sync::Arc<crate::lb::upstream::UpstreamNode>,
        /// The pool `node` belongs to -- `record_success`/`record_failure`
        /// need this (see their own signatures in `lb::upstream`) to
        /// update the pool-wide outlier-detection/circuit-breaker
        /// bookkeeping alongside the node's own state, the same way
        /// mio_backend's own `forward()` always has both `node` and
        /// `lb.pool` on hand together when it calls them.
        pool: std::sync::Arc<crate::lb::upstream::UpstreamPool>,
        /// The read/write timeouts to bound this upstream connection's
        /// own `Send`/`Recv` SQEs with, via a `LinkTimeout` on each --
        /// `submit_send`/`submit_recv` check this field themselves
        /// (rather than every one of their many call sites needing to
        /// pass a timeout through explicitly) so a plaintext
        /// downstream connection's own calls to the very same two
        /// functions stay completely unchanged. Taken from
        /// `core::proxy::ProxyConfig`'s own `read_timeout`/`write_timeout`,
        /// the same fields mio_backend's own synchronous
        /// `write_all_with_timeout`/`read_http1_response` are bounded
        /// by.
        read_write_timeouts: (std::time::Duration, std::time::Duration),
        /// The downstream connection(s) currently waiting on this
        /// upstream connection's response(s), keyed by H2 stream id
        /// (each value identified by slab index and generation -- the
        /// same ABA-safety pairing every other cross-referenced slot
        /// in this backend uses). An HTTP/1.1 upstream connection only
        /// ever has at most one entry, always under the sentinel key
        /// `0` (H1 has no real stream ids of its own to key by, and
        /// only ever serves one request at a time regardless -- see
        /// this module's own doc comment on why a single shared map
        /// shape is used for both protocols rather than an enum
        /// switching between "one downstream" and "many"). An H2
        /// upstream connection can have as many entries as concurrent
        /// streams it's actually serving, each key being that
        /// stream's real id. Empty while this upstream connection is
        /// idle (in a pool, not currently serving any request).
        serving_downstream: std::collections::HashMap<u32, (usize, u32)>,
        /// The original client request to serialize and send once
        /// this upstream connection's `Connect` completes -- kept
        /// here (rather than, say, already serialized into
        /// `Http1Connection::write_buf` before the connection even
        /// exists) so this backend's own request-forwarding code
        /// (mirroring `core::proxy::build_upstream_headers`, the same
        /// header rewriting mio_backend's synchronous forward() does)
        /// runs exactly once, right before the real send, with the
        /// real upstream connection's own remote address available
        /// for the `X-Forwarded-For`-style headers that need it.
        /// `None` once actually taken and sent -- an upstream
        /// connection reused from an idle pool for a second request
        /// has this set again for that request, the same way the
        /// first one set it.
        pending_request: Option<Box<crate::http::request::HttpRequest>>,
    },
}

pub struct Connection {
    pub id: ConnId,
    pub transport: Transport,
    pub protocol: ConnectionProtocol,
    pub remote_addr: SocketAddr,
    pub created_at: Instant,
    pub last_active_at: Instant,
    /// Which side of a proxied request this connection represents --
    /// see `ConnectionRole`'s own doc comment. `Downstream` for every
    /// connection this backend has driven before proxy support was
    /// added; existing code paths that don't care about proxying
    /// never need to check this field.
    pub role: ConnectionRole,
    /// Set once this connection has been told to close (peer EOF, a
    /// fatal I/O error, or the server initiating a graceful drain) --
    /// checked before scheduling any further I/O on it.
    pub closing: bool,
    /// Fixed-size recv buffer a `Recv` SQE reads into -- a backend-specific
    /// detail `mio_conn::Connection` has no equivalent of, since mio's
    /// synchronous `read()` only ever needs a transient stack buffer,
    /// never one that has to stay at a stable address across an
    /// outstanding operation the way a submitted-but-not-yet-completed
    /// io_uring SQE's buffer does (see `core::event_loop::uring_backend`'s
    /// own doc comment on buffer ownership).
    pub recv_buf: Vec<u8>,
    /// The encoded `sockaddr` bytes for an in-flight `Connect` SQE on
    /// this connection -- must stay alive at a stable address for as
    /// long as the kernel might still read from it (i.e. until the
    /// Connect completion arrives), the same buffer-ownership
    /// constraint `recv_buf` documents for `Recv`/`Send`. `None`
    /// outside of an in-flight connect (which is the common case:
    /// once the completion arrives, whether success or failure, this
    /// is set back to `None` -- there's no further use for the
    /// encoded address after that point).
    pub pending_connect_addr: Option<Box<libc::sockaddr_storage>>,
    /// The `Timespec` backing an in-flight `LinkTimeout` SQE bounding
    /// this connection's current `Connect`/`Send`/`Recv` -- same
    /// buffer-ownership constraint as `pending_connect_addr` and
    /// `recv_buf` (must stay alive at a stable address until the
    /// timeout's own completion arrives). Only ever set on an
    /// *upstream* connection (see `ConnectionRole::Upstream`'s own doc
    /// comment) -- downstream connections have no per-operation
    /// timeout of their own yet (client-facing timeouts are a
    /// separate, not-yet-implemented concern from ProxyConfig's
    /// upstream-facing ones).
    pub pending_timeout: Option<Box<io_uring::types::Timespec>>,
    /// This slot's current generation, embedded in every SQE's
    /// `user_data` for as long as this connection occupies it -- see
    /// `core::event_loop::uring_backend`'s `make_user_data` for the
    /// ABA-style race this guards against. Set by the caller managing
    /// this connection's `Slab` slot (see `EventLoopWorker`'s own
    /// per-slot generation counters), not derived from anything this
    /// type tracks on its own -- `Connection` has no notion of "which
    /// slot" it occupies, only the backend driving it does.
    pub generation: u32,
    /// Tracks an in-progress `Http1Connection::pending_file` transfer
    /// being driven over a pipe via two chained `Splice` SQEs
    /// (file -> pipe write end, then pipe read end -> socket) -- direct
    /// file-to-socket splicing isn't a kernel-supported shape (splice(2)
    /// requires one side of the transfer to be a pipe), so this two-hop
    /// relay is the io_uring-native equivalent of `sendfile(2)`, which
    /// mio_backend's own `flush_pending_file` calls directly. `None`
    /// whenever no splice is currently in flight on this connection --
    /// only ever `Some` on a plaintext HTTP/1.1 connection actively
    /// relaying a `PendingFileSend` body (a TLS connection's own
    /// pending-file body still goes through the ordinary read+encrypt+
    /// send path, since splice can't see through TLS's userspace
    /// encryption step).
    pub pending_splice: Option<PendingSplice>,
    /// Whether this worker's kernel supports `SendZc` -- copied in at
    /// construction time from the worker-level probe result (see
    /// `uring_backend::probe_send_zc_support`) rather than re-probed
    /// per connection, since the answer is identical for every
    /// connection a given worker ever drives and re-probing per
    /// connection would be pure overhead for a value that never
    /// changes during the worker's lifetime. Read by `submit_send` to
    /// decide between `Send` and `SendZc` for a given write (see that
    /// function's own doc comment for the size threshold).
    pub send_zc_supported: bool,
    /// The byte count reported by a `SendZc` SQE's first completion
    /// (the one carrying `IORING_CQE_F_MORE`) -- held here until the
    /// matching second completion (carrying `IORING_CQE_F_NOTIF`,
    /// which reports the kernel is done reading the send buffer)
    /// arrives, since only that second completion makes it safe to
    /// treat the transfer as settled (consume write_buf, decide
    /// fully_flushed, etc. -- see OP_TAG_SEND_ZC's own completion
    /// arm). `None` whenever no SendZc is currently between its two
    /// completions on this connection.
    pub pending_send_zc_result: Option<u32>,
    /// Set when a SendZc's own MORE completion reported a negative
    /// result (observed in practice: -ENOMEM under memory pressure --
    /// MSG_ZEROCOPY requires pinning the send buffer's pages, which
    /// can fail where an ordinary copying send never would) --
    /// checked once the matching NOTIF completion arrives (mirroring
    /// pending_send_zc_result's own two-completion bookkeeping) to
    /// retry via an ordinary Send rather than silently tearing the
    /// connection down. send_zc_supported is also cleared at the same
    /// time so this connection doesn't keep hitting the same failure
    /// on every subsequent large send.
    pub send_zc_failed_needs_retry: bool,
    /// The registered buffer index backing this connection's current
    /// in-flight `ReadFixed` recv, if it's using one (see
    /// `submit_recv`'s own doc comment on the ReadFixed/Recv choice).
    /// Returned to the worker's `RegisteredBufferPool` once the recv
    /// completes (or the connection is torn down) -- see
    /// `OP_TAG_RECV`'s own completion arm. `None` whenever the most
    /// recent (or current) recv used an ordinary (non-fixed) `Recv`
    /// instead, which reads directly into `recv_buf` and has no
    /// pool-owned buffer to return.
    pub pending_recv_buf_index: Option<u16>,
    /// How much plaintext was handed to rustls for encryption by the
    /// most recent submit_send call on a TLS connection, not yet
    /// consumed from the active protocol's own write_buf -- `None`
    /// once that consumption has happened (or there's no TLS send in
    /// flight). Deferred rather than consumed immediately inside
    /// submit_send because rustls's own TLS record framing means the
    /// ciphertext byte count OP_TAG_SEND's completion reports has no
    /// direct correspondence to this plaintext length, AND a single
    /// Send SQE covering a large ciphertext payload (a multi-hundred-
    /// KB response body, encrypted, easily exceeds what one Send call
    /// actually transmits) can complete with only part of it sent --
    /// consuming the full plaintext length against write_buf at that
    /// point would silently drop the unsent remainder, since
    /// write_buf would report empty (fully flushed) while
    /// MemoryTlsIo::outgoing still held bytes that were never put on
    /// the wire. Only consumed once outgoing is fully drained (see
    /// OP_TAG_SEND's own TLS completion arm).
    pub pending_tls_plaintext_len: Option<usize>,
    /// How much plaintext was handed to rustls for encryption by the
    /// most recent submit_send call on a TLS connection, not yet
    /// consumed from the active protocol's own write_buf -- `None`
    /// once that consumption has happened (or there's no TLS send in
    /// flight). Deferred rather than consumed immediately inside
    /// submit_send because rustls's own TLS record framing means the
    /// ciphertext byte count OP_TAG_SEND's completion reports has no
    /// direct correspondence to this plaintext length, AND a single
    /// Send SQE covering a large ciphertext payload (a multi-hundred-
    /// KB response body, encrypted, easily exceeds what one Send call
    /// actually transmits) can complete with only part of it sent --
    /// consuming the full plaintext length against write_buf at that
    /// point would silently drop the unsent remainder, since
    /// write_buf would report empty (fully flushed) while
    /// MemoryTlsIo::outgoing still held bytes that were never put on
    /// the wire. Only consumed once outgoing is fully drained (see
    /// OP_TAG_SEND's own TLS completion arm).
    /// State for an in-flight `Statx` SQE stat'ing a static file's
    /// path asynchronously (see `Http1Outcome::FileCachePending`'s own
    /// doc comment) -- `Some` from the moment the Statx SQE is
    /// submitted until its completion is processed. The `Box<statx>`
    /// is the raw kernel-written buffer the SQE's own pointer targets
    /// -- boxed (not stack-local) so its address stays stable across
    /// this struct being moved around (a Slab entry can be relocated
    /// on Vec growth elsewhere, though not typically mid-flight here;
    /// boxing removes the need to reason about whether that could
    /// ever happen), the same buffer-stability requirement
    /// `pending_connect_addr`/`pending_timeout` already document for
    /// their own boxed buffers.
    pub pending_statx: Option<PendingStatx>,
}

/// What's needed to finish a static-file cache-miss once its `Statx`
/// completes -- see `Connection::pending_statx`'s own doc comment.
pub struct PendingStatx {
    pub pending: crate::http::static_files::FileCachePending,
    pub original_request: Box<crate::http::request::HttpRequest>,
    pub statx_buf: Box<libc::statx>,
    /// Which H2 stream this stat belongs to -- `None` for an
    /// HTTP/1.1 downstream (one request per connection), `Some` for
    /// one of possibly several concurrently in-flight streams on an
    /// H2 downstream connection. Read by OP_TAG_STATX's own
    /// completion arm to decide whether to queue the resolved
    /// response into Http1Connection::write_buf or hand it to the H2
    /// connection's own per-stream response machinery.
    pub downstream_stream_id: Option<u32>,
}

/// The pipe fd pair (and current relay phase) backing one in-flight
/// `Splice`-based file transfer -- see `Connection::pending_splice`'s
/// own doc comment for why a pipe hop is required at all. The pipe fds
/// themselves are borrowed from a worker-lokal `PipePool` (see
/// `core::event_loop::uring_backend`) for the transfer's duration and
/// returned there once it completes, rather than being opened and
/// closed on every single file response.
pub struct PendingSplice {
    pub pipe_read_fd: i32,
    pub pipe_write_fd: i32,
    pub phase: SplicePhase,
}

/// Which leg of the file -> pipe -> socket relay is currently
/// in-flight. A single `PendingFileSend::remaining` byte range may be
/// relayed across many `FileToPipe`/`PipeToSocket` cycles -- one cycle
/// moves at most one pipe's worth of buffered bytes (bounded by the
/// pipe's own kernel buffer size), not the whole remaining length in
/// one shot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplicePhase {
    /// A `Splice(file_fd -> pipe_write_fd)` SQE is in flight; its
    /// completion reports how many bytes now sit in the pipe, which is
    /// exactly how many the follow-up `PipeToSocket` splice must move.
    FileToPipe,
    /// A `Splice(pipe_read_fd -> socket_fd)` SQE is in flight, moving
    /// the `n` bytes the prior `FileToPipe` completion reported.
    PipeToSocket { bytes_in_pipe: u32 },
}

impl Connection {
    pub fn new(id: ConnId, transport: Transport, remote_addr: SocketAddr, recv_buf_size: usize, generation: u32) -> Self {
        let now = Instant::now();
        Connection {
            id,
            transport,
            protocol: ConnectionProtocol::Handshaking,
            remote_addr,
            created_at: now,
            last_active_at: now,
            role: ConnectionRole::Downstream,
            closing: false,
            recv_buf: vec![0u8; recv_buf_size],
            pending_connect_addr: None,
            pending_timeout: None,
            generation,
            pending_splice: None,
            send_zc_supported: false,
            pending_send_zc_result: None,
            send_zc_failed_needs_retry: false,
            pending_recv_buf_index: None,
            pending_tls_plaintext_len: None,
            pending_statx: None,
        }
    }

    /// Same as `new`, but for a connection opened to an upstream
    /// server rather than accepted from a client -- see
    /// `ConnectionRole::Upstream`'s own doc comment.
    pub fn new_upstream(
        id: ConnId,
        transport: Transport,
        remote_addr: SocketAddr,
        recv_buf_size: usize,
        generation: u32,
        node: std::sync::Arc<crate::lb::upstream::UpstreamNode>,
        pool: std::sync::Arc<crate::lb::upstream::UpstreamPool>,
        read_write_timeouts: (std::time::Duration, std::time::Duration),
    ) -> Self {
        let mut conn = Self::new(id, transport, remote_addr, recv_buf_size, generation);
        conn.role = ConnectionRole::Upstream { node, pool, read_write_timeouts, serving_downstream: std::collections::HashMap::new(), pending_request: None };
        conn
    }

    pub fn touch(&mut self) {
        self.last_active_at = Instant::now();
    }

    pub fn is_tls(&self) -> bool {
        self.transport.is_tls()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
    use std::os::unix::io::IntoRawFd;

    fn accept_one_connection() -> (RawFd, SocketAddr) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _client = StdTcpStream::connect(addr).expect("connect");
        let (stream, peer) = listener.accept().expect("accept");
        (stream.into_raw_fd(), peer)
    }

    #[test]
    fn plain_connection_reports_not_tls() {
        let (fd, addr) = accept_one_connection();
        let transport = Transport::Plain(fd);
        let conn = Connection::new(1, transport, addr, 4096, 0);
        assert!(!conn.is_tls());
        assert!(conn.transport.alpn_protocol().is_none());
        assert!(matches!(conn.protocol, ConnectionProtocol::Handshaking));
        assert_eq!(conn.recv_buf.len(), 4096);
    }

    #[test]
    fn touch_updates_last_active_at() {
        let (fd, addr) = accept_one_connection();
        let transport = Transport::Plain(fd);
        let mut conn = Connection::new(1, transport, addr, 4096, 0);
        let before = conn.last_active_at;
        std::thread::sleep(std::time::Duration::from_millis(5));
        conn.touch();
        assert!(conn.last_active_at > before);
    }
}
