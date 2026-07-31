#[cfg(all(feature = "io_uring", not(target_os = "linux")))]
compile_error!(
    "the `io_uring` feature is Linux-only (it selects a completion-based \
    I/O backend built directly on the io_uring kernel interface, which \
    has no equivalent on this target). Build without `--features \
    io_uring` to use the default mio/epoll backend instead, which is \
    portable across platforms."
);

pub mod core;
pub mod http;
pub mod lb;
pub mod net;
pub mod util;
