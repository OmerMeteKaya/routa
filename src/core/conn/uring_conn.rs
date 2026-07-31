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

/// The transport a connection is speaking over. Plain TCP only -- see
/// this module's own doc comment for why TLS isn't a variant here yet.
/// Carries the raw fd directly rather than any higher-level socket
/// type: every actual read/write/accept goes through this backend's
/// own submission-queue plumbing (not yet implemented -- see
/// `core::event_loop::uring_backend`), never a direct syscall against
/// this fd the way `mio_conn::Transport`'s `Read`/`Write` impls call
/// straight through to `mio::net::TcpStream`.
pub struct Transport {
    pub fd: RawFd,
}

impl Transport {
    pub fn is_tls(&self) -> bool {
        false // no TLS variant exists yet -- see this module's own doc comment
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        None // meaningless without TLS
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        // Plain fd ownership, mirroring what a std/mio socket type's
        // own Drop impl would do -- this type deliberately doesn't
        // wrap one (see its own doc comment), so closing the fd is
        // this struct's responsibility rather than an inner value's.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// A single client connection: transport plus whichever protocol is
/// currently active on it. Same shape and role as `mio_conn::Connection`
/// -- see its doc comment -- with a completion-based `Transport` in
/// place of a readiness-based one.
pub struct Connection {
    pub id: ConnId,
    pub transport: Transport,
    pub protocol: ConnectionProtocol,
    pub remote_addr: SocketAddr,
    pub created_at: Instant,
    pub last_active_at: Instant,
    /// Set once this connection has been told to close (peer EOF, a
    /// fatal I/O error, or the server initiating a graceful drain) --
    /// checked before scheduling any further I/O on it.
    pub closing: bool,
}

impl Connection {
    pub fn new(id: ConnId, transport: Transport, remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Connection {
            id,
            transport,
            protocol: ConnectionProtocol::Handshaking,
            remote_addr,
            created_at: now,
            last_active_at: now,
            closing: false,
        }
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
        let transport = Transport { fd };
        let conn = Connection::new(1, transport, addr);
        assert!(!conn.is_tls());
        assert!(conn.transport.alpn_protocol().is_none());
        assert!(matches!(conn.protocol, ConnectionProtocol::Handshaking));
    }

    #[test]
    fn touch_updates_last_active_at() {
        let (fd, addr) = accept_one_connection();
        let transport = Transport { fd };
        let mut conn = Connection::new(1, transport, addr);
        let before = conn.last_active_at;
        std::thread::sleep(std::time::Duration::from_millis(5));
        conn.touch();
        assert!(conn.last_active_at > before);
    }
}
