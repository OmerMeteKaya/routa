//! The io_uring backend's per-worker event loop: a completion-based
//! counterpart to `mio_backend`, selected in its place at compile time
//! by the `io_uring` feature (see this crate's top-level
//! `compile_error!` guard for why this is Linux-only, and
//! `uring_kernel_check` for the runtime version floor this backend
//! additionally requires beyond what building it at all needs).
//!
//! Scope today: worker startup and the kernel-version gate that must
//! run before anything else does. The actual submission/completion
//! loop -- accept, read, write, and every protocol state machine this
//! backend will eventually drive over it -- doesn't exist yet.
//! `EventLoopWorker::run` reflects that honestly (a panic, not a
//! silently-idle worker) rather than presenting a worker that appears
//! to start successfully but can never actually serve a connection.

use std::sync::Arc;

use crate::core::server::RoutaServer;
use crate::core::worker::{ShutdownSignal, WorkerBody};

pub struct EventLoopWorker {
    port: u16,
    server: Arc<RoutaServer>,
}

impl EventLoopWorker {
    pub fn new(port: u16, server: Arc<RoutaServer>) -> Self {
        EventLoopWorker { port, server }
    }
}

impl WorkerBody for EventLoopWorker {
    fn run(&self, worker_id: usize, _shutdown: &ShutdownSignal) {
        if let Err(reason) = super::uring_kernel_check::check_kernel_version() {
            tracing::error!(worker_id, port = self.port, %reason, "io_uring backend refusing to start");
            // Matches mio_backend's own convention for a worker that
            // can't start at all (see its bind/poller-creation failure
            // paths): return rather than panic, so the worker pool's
            // reconciler logs a clean "worker exited" rather than an
            // unwind -- but since every worker will fail this same
            // check on this host, the pool will simply keep respawning
            // and failing forever rather than the process exiting.
            // That's `WorkerPool`'s existing behavior for a
            // structurally-unfixable startup failure (a bad bind is
            // the same story) and not something this backend needs to
            // special-case -- but it does mean an operator watching
            // only "is the process still running" rather than logs
            // could miss that every worker is failing. Revisit once
            // this backend is otherwise complete: a from_config-time
            // check (before any worker thread is even spawned) would
            // surface this as an immediate, unmistakable startup
            // failure instead.
            return;
        }

        unimplemented!(
            "the io_uring backend's submission/completion loop is not yet implemented -- \
            only its startup-time kernel version gate exists so far. Build without \
            `--features io_uring` to use the working mio/epoll backend."
        );
    }
}

/// Starts `n_workers` worker threads bound to `port`, using the
/// io_uring backend -- signature-compatible with `mio_backend::run`,
/// which this fully replaces (never both at once) when the `io_uring`
/// feature is enabled. Not yet meaningfully usable -- see
/// `EventLoopWorker::run`'s own doc comment.
pub fn run(server: Arc<RoutaServer>, port: u16, n_workers: usize) -> crate::core::worker::WorkerPool {
    let worker = EventLoopWorker::new(port, server);
    crate::core::worker::WorkerPool::spawn(n_workers, worker)
}
