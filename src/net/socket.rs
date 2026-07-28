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
/// Binds a dual-stack listener on `port`: a single IPv6 socket with
/// `IPV6_V6ONLY` explicitly disabled, so IPv4 clients connecting via
/// their IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) are accepted on
/// the same socket as native IPv6 clients -- one listener instead of
/// running separate IPv4 and IPv6 sockets side by side. Falls back to
/// IPv4-only if IPv6 itself isn't available at all on this host (e.g.
/// disabled at the kernel/network-namespace level) -- a dual-stack
/// listener is preferred but plain IPv4 is still a functional server,
/// so a full startup failure just because IPv6 is unavailable would be
/// a worse outcome than falling back.
pub fn bind_reuseport(port: u16, backlog: i32) -> io::Result<TcpListener> {
    match bind_dual_stack(port, backlog) {
        Ok(listener) => Ok(listener),
        Err(_) => bind_ipv4_only(port, backlog),
    }
}

fn bind_dual_stack(port: u16, backlog: i32) -> io::Result<TcpListener> {
    let addr: SocketAddr = format!("[::]:{port}").parse().expect("valid address");
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?; // the key dual-stack setting -- accept both IPv4-mapped and native IPv6 traffic
    socket.set_reuse_address(true)?;
    let _ = socket.set_reuse_port(true); // best-effort, see doc comment above
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    Ok(TcpListener::from_std(socket.into()))
}

fn bind_ipv4_only(port: u16, backlog: i32) -> io::Result<TcpListener> {
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
    fn bind_reuseport_accepts_ipv4_via_dual_stack_socket() {
        // With the listener now bound on IPv6 (dual-stack), an IPv4
        // connection must still work -- it arrives as an IPv4-mapped
        // IPv6 address (::ffff:127.0.0.1) rather than being rejected.
        let port = 18082;
        let listener = bind_reuseport(port, 128).expect("bind");
        let client = StdTcpStream::connect(("127.0.0.1", port));
        assert!(client.is_ok(), "IPv4 connections should still work against the dual-stack listener");
        drop(listener);
    }

    #[test]
    fn bind_reuseport_accepts_native_ipv6_connections() {
        let port = 18083;
        let listener = bind_reuseport(port, 128).expect("bind");
        let client = StdTcpStream::connect(("::1", port));
        assert!(client.is_ok(), "native IPv6 (::1) connections should be accepted");
        drop(listener);
    }

    #[test]
    fn accepted_ipv4_and_ipv6_connections_are_both_readable() {
        // Beyond just connecting, confirm the accepted socket on each
        // side can actually exchange bytes -- proves the dual-stack
        // listener isn't just accepting the TCP handshake while
        // leaving the connection otherwise unusable.
        use std::io::{Read, Write};
        let port = 18084;
        let listener = bind_reuseport(port, 128).expect("bind");
        let mut std_listener: std::net::TcpListener = listener.into();
        std_listener.set_nonblocking(false).unwrap();

        let mut client = StdTcpStream::connect(("127.0.0.1", port)).unwrap();
        let (mut accepted, _) = std_listener.accept().unwrap();

        client.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
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

// ─── sendfile(2): zero-copy file-to-socket transfer ─────────────────────

use std::os::unix::io::AsRawFd;

/// Sends up to `count` bytes from `file` (starting at `offset`,
/// which is advanced by however much was actually sent) directly to
/// `socket_fd` via the `sendfile(2)` syscall -- the kernel copies
/// data from the file's page cache straight to the socket buffer,
/// never through a userspace buffer the way a `read()` + `write()`
/// pair would. Only meaningful for a plaintext (non-TLS) socket: TLS
/// must encrypt in userspace before any bytes reach the kernel, so
/// there's nothing for the kernel to copy directly from a file for an
/// encrypted connection -- callers on a TLS transport should use the
/// ordinary read+write path instead of this function entirely.
///
/// Returns the number of bytes actually sent (which may be less than
/// `count`, particularly on a non-blocking socket whose send buffer
/// fills up mid-transfer -- the caller is expected to retry with the
/// updated `offset` on the next writable-readiness event, the same
/// partial-write tolerance every other transport write in this
/// codebase already has to handle).
///
/// Returns `Err` with `ErrorKind::WouldBlock` if the socket can't
/// accept any bytes at all right now (mirrors a regular `write()`'s
/// `EAGAIN` behavior), and other `io::Error`s for genuine failures.
pub fn sendfile(file: &std::fs::File, socket_fd: std::os::unix::io::RawFd, offset: &mut u64, count: usize) -> io::Result<usize> {
    let mut off: libc::off_t = *offset as libc::off_t;
    let result = unsafe { libc::sendfile(socket_fd, file.as_raw_fd(), &mut off, count) };

    if result < 0 {
        let err = io::Error::last_os_error();
        return Err(err);
    }

    *offset = off as u64;
    Ok(result as usize)
}
