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
        /// The downstream connection currently waiting on this
        /// upstream connection's response, identified by slab index
        /// and generation (the same ABA-safety pairing every other
        /// cross-referenced slot in this backend uses -- see
        /// `core::event_loop::uring_backend`'s own `make_user_data`
        /// doc comment). `None` while this upstream connection is
        /// idle (in a pool, not currently serving any request).
        serving_downstream: Option<(usize, u32)>,
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
    /// This slot's current generation, embedded in every SQE's
    /// `user_data` for as long as this connection occupies it -- see
    /// `core::event_loop::uring_backend`'s `make_user_data` for the
    /// ABA-style race this guards against. Set by the caller managing
    /// this connection's `Slab` slot (see `EventLoopWorker`'s own
    /// per-slot generation counters), not derived from anything this
    /// type tracks on its own -- `Connection` has no notion of "which
    /// slot" it occupies, only the backend driving it does.
    pub generation: u32,
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
            generation,
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
    ) -> Self {
        let mut conn = Self::new(id, transport, remote_addr, recv_buf_size, generation);
        conn.role = ConnectionRole::Upstream { node, pool, serving_downstream: None, pending_request: None };
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
