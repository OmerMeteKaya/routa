//! Thin socket-setup helpers shared by anything that needs a listening
//! or outbound socket with specific options applied (`SO_REUSEPORT`,
//! non-blocking mode, receive/send buffer sizes). Deliberately small:
//! everything past "here is a configured, non-blocking socket" --
//! TLS, HTTP parsing, connection lifecycle -- belongs to other modules
//! (`net::tls`, `core::conn`, `core::event_loop`), not here. Rust's
//! `Drop` also means there's no equivalent needed for an explicit
//! "close this fd" helper: a socket is closed automatically once it
//! goes out of scope, so forgetting to close one isn't a category of
//! bug that can happen here the way it can in C.

use std::io;
use std::net::SocketAddr;

use mio::net::TcpListener;
use socket2::{Domain, Socket, Type};

/// Binds a `SO_REUSEPORT` listener on `port`, backed by the given
/// backlog. Each caller (typically one per worker -- see
/// `core::event_loop`) gets its own independent listening socket for
/// the same port; the kernel distributes incoming connections across
/// every such listener itself; see `core::event_loop`'s module doc for
/// why this is preferable to a single shared listener at routa's
/// target connection rates.
///
/// `SO_REUSEPORT` support itself is treated as best-effort: if the
/// platform doesn't support it, binding still succeeds (falling back
/// to ordinary single-listener behavior) rather than failing outright.
pub fn bind_reuseport(port: u16, backlog: i32) -> io::Result<TcpListener> {
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid address");
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_reuse_port(true); // best-effort, see doc comment above
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    Ok(TcpListener::from_std(socket.into()))
}

/// Applies the receive/send buffer size overrides from config (0 means
/// "leave the OS default alone", matching `socket_recv_buf_size` /
/// `socket_send_buf_size`'s meaning in `core::config`) to an already-open
/// socket. Takes a `socket2::SockRef` so it works uniformly on whatever
/// concrete socket type the caller has (a `mio::net::TcpStream`, a
/// `std::net::TcpStream`, etc.) without needing a conversion at every
/// call site.
pub fn apply_buffer_sizes(
    socket: socket2::SockRef<'_>,
    recv_buf_size: i32,
    send_buf_size: i32,
) -> io::Result<()> {
    if recv_buf_size > 0 {
        socket.set_recv_buffer_size(recv_buf_size as usize)?;
    }
    if send_buf_size > 0 {
        socket.set_send_buffer_size(send_buf_size as usize)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream as StdTcpStream;

    #[test]
    fn bind_reuseport_accepts_connections() {
        let port = 18081;
        let listener = bind_reuseport(port, 128).expect("bind");

        // A second listener on the same port should also succeed,
        // proving SO_REUSEPORT actually took effect (without it, the
        // second bind would fail with "address already in use").
        let _second = bind_reuseport(port, 128).expect("second bind with SO_REUSEPORT");

        let client = StdTcpStream::connect(("127.0.0.1", port));
        assert!(client.is_ok(), "should be able to connect to a bound, listening socket");

        drop(listener);
    }

    #[test]
    fn buffer_sizes_zero_is_left_alone() {
        // 0 for both means "don't touch anything" -- this should never
        // error, even on a freshly-created socket with only OS defaults.
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("create socket");
        let result = apply_buffer_sizes(socket2::SockRef::from(&socket), 0, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn buffer_sizes_applies_nonzero_values() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("create socket");
        apply_buffer_sizes(socket2::SockRef::from(&socket), 65536, 65536)
            .expect("apply buffer sizes");
        // The kernel is free to round the requested size up (Linux
        // commonly doubles it for bookkeeping overhead), so just check
        // it's at least what was requested, not an exact match.
        let recv = socket.recv_buffer_size().expect("read recv buffer size");
        assert!(recv >= 65536, "expected recv buffer >= 65536, got {recv}");
    }
}
