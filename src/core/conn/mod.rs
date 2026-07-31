//! A single client connection: transport plus whichever protocol is
//! currently active on it. Two backends exist side by side, selected
//! at compile time: `mio_conn` (default -- readiness-based, mio/epoll)
//! and, once added, `uring_conn` (behind the `io_uring` feature --
//! completion-based). Each backend defines its own `Connection` and
//! `Transport` shape, since the two I/O models don't share a
//! meaningful common representation for either -- `Read`/`Write` on a
//! `mio::net::TcpStream` has no equivalent in a completion-based model,
//! where submitting a read and receiving its result are two separate
//! steps rather than one blocking-or-`WouldBlock` call.
//!
//! `protocol` holds everything that *is* backend-agnostic: the
//! `ConnectionProtocol` enum and the HTTP/1.1, HTTP/2, and WebSocket
//! state machines nested inside it. None of those touch a socket or a
//! poller -- they only parse/frame bytes into and out of plain
//! buffers -- so both backends depend on the same `protocol` module
//! rather than one backend depending on the other's connection type.

pub mod protocol;
pub use protocol::{
    ConnectionProtocol, Http1Connection, Http2Connection, Http2Settings, PendingFileSend,
    WsConnection, WsSettings,
};

#[cfg(not(feature = "io_uring"))]
mod mio_conn;
#[cfg(not(feature = "io_uring"))]
pub use mio_conn::*;

#[cfg(feature = "io_uring")]
pub(crate) mod uring_conn;
#[cfg(feature = "io_uring")]
pub use uring_conn::*;
