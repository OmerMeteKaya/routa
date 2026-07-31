//! The mio backend's connection shape: transport (plain TCP or TLS,
//! read/written directly via mio's readiness-based `TcpStream`) plus
//! whichever protocol is currently speaking over it. `ConnectionProtocol`
//! and everything it contains (`Http1Connection`, `Http2Connection`,
//! `WsConnection`, their settings types) are backend-agnostic and live
//! in `core::conn::protocol` instead -- only the transport and the
//! `Connection` struct that carries it are specific to this backend.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::Instant;

use mio::net::TcpStream;

use crate::core::conn::protocol::ConnectionProtocol;
use crate::net::poller::PollKey;
use crate::net::tls::TlsConnection;

/// Monotonically increasing identifier, unique within a single worker
/// (not globally -- two different workers may reuse the same id after
/// their respective connections close, which is fine since nothing
/// ever compares ids across workers). Used for logging/observability.
pub type ConnId = u64;

/// The transport a connection is speaking over: plain TCP, or TCP
/// wrapped in an in-progress-or-established TLS session. Deliberately
/// separate from `ConnectionProtocol` -- transport (how bytes are
/// encrypted) and protocol (how bytes are structured) are independent
/// axes, e.g. H2 can run over either plain TCP (h2c) or TLS.
pub enum Transport {
    Plain(TcpStream),
    Tls {
        stream: TcpStream,
        tls: Box<TlsConnection>,
    },
}

impl Transport {
    pub fn is_tls(&self) -> bool {
        matches!(self, Transport::Tls { .. })
    }

    /// The negotiated ALPN protocol, if this is a TLS transport whose
    /// handshake has completed far enough to know it. Always `None` for
    /// plain transports (h2c negotiation happens via the HTTP/1.1
    /// Upgrade mechanism instead, handled at the protocol layer, not
    /// here).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Transport::Plain(_) => None,
            Transport::Tls { tls, .. } => tls.alpn_protocol(),
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls { tls, .. } => tls.read_plaintext(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls { tls, .. } => tls.write_plaintext(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls { .. } => Ok(()), // rustls buffers internally; see advance_io
        }
    }
}

/// Drives one pass of TLS record-layer I/O if this transport is TLS
/// (a no-op returning `None` for plain transports, which have no
/// separate record layer to advance). See `TlsConnection::advance_io`
/// for what this actually does.
pub fn advance_tls_io(transport: &mut Transport) -> Option<io::Result<crate::net::tls::IoAdvance>> {
    match transport {
        Transport::Plain(_) => None,
        Transport::Tls { stream, tls } => Some(tls.advance_io(stream)),
    }
}

/// A single client connection: transport plus whichever protocol is
/// currently active on it, plus metadata that outlives any one
/// protocol switch (e.g. an h2c upgrade from Http1 to Http2 on the
/// same underlying transport keeps the same `id`/`remote_addr`/
/// timestamps).
pub struct Connection {
    pub id: ConnId,
    pub poll_key: PollKey,
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
    pub fn new(
        id: ConnId,
        poll_key: PollKey,
        transport: Transport,
        remote_addr: SocketAddr,
    ) -> Self {
        let now = Instant::now();
        Connection {
            id,
            poll_key,
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
    use crate::net::poller::{EventPoller, Interests, MioPoller};
    use mio::net::{TcpListener, TcpStream as MioTcpStream};
    use std::net::TcpStream as StdTcpStream;

    fn accept_one_connection() -> (MioTcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _client = StdTcpStream::connect(addr).expect("connect");
        // A real accept() needs the listener to be polled readable
        // first in production, but for this unit test a short retry
        // loop is simpler than pulling in a full poller just to prove
        // Connection wraps a TcpStream correctly.
        for _ in 0..50 {
            match listener.accept() {
                Ok((stream, peer)) => return (stream, peer),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        }
        panic!("never accepted a connection");
    }

    #[test]
    fn plain_connection_reports_not_tls() {
        let (stream, addr) = accept_one_connection();
        let mut poller = MioPoller::new(4).expect("create poller");
        let mut transport = Transport::Plain(stream);
        let key = poller
            .register(
                match &mut transport {
                    Transport::Plain(s) => s,
                    _ => unreachable!(),
                },
                Interests::READABLE,
            )
            .expect("register");

        let conn = Connection::new(1, key, transport, addr);
        assert!(!conn.is_tls());
        assert!(conn.transport.alpn_protocol().is_none());
        assert!(matches!(conn.protocol, ConnectionProtocol::Handshaking));
    }

    #[test]
    fn touch_updates_last_active_at() {
        let (stream, addr) = accept_one_connection();
        let mut poller = MioPoller::new(4).expect("create poller");
        let mut transport = Transport::Plain(stream);
        let key = poller
            .register(
                match &mut transport {
                    Transport::Plain(s) => s,
                    _ => unreachable!(),
                },
                Interests::READABLE,
            )
            .expect("register");

        let mut conn = Connection::new(1, key, transport, addr);
        let before = conn.last_active_at;
        std::thread::sleep(std::time::Duration::from_millis(5));
        conn.touch();
        assert!(conn.last_active_at > before);
    }
}
