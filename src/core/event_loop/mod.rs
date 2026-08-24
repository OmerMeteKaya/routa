//! The per-worker event loop: accepts connections, drives each one's
//! TLS handshake and application-protocol state machine, and
//! dispatches complete requests through a `RoutaServer`'s middleware
//! chain and router. Two backends exist side by side, selected at
//! compile time: `mio_backend` (default -- readiness-based, mio/epoll)
//! and, once added, `uring_backend` (behind the `io_uring` feature --
//! completion-based, Linux-only). They are independent implementations
//! of the same job, not a shared abstraction forced over both I/O
//! models -- see `core::conn`'s module doc for why.

#[cfg(not(feature = "io_uring"))]
mod mio_backend;
#[cfg(not(feature = "io_uring"))]
pub use mio_backend::*;
#[cfg(not(feature = "io_uring"))]
mod mio_upstream;

#[cfg(feature = "io_uring")]
mod uring_kernel_check;
#[cfg(feature = "io_uring")]
mod uring_backend;
#[cfg(feature = "io_uring")]
pub use uring_backend::*;
