//! Worker lifecycle: each worker runs on its own OS thread and is
//! panic-isolated from the others. If a worker's thread panics, only
//! that worker is affected -- `WorkerPool` catches the unwind, logs it,
//! and respawns a fresh worker with the same identity in its place,
//! rather than the whole process going down. Shared, read-only state
//! (config, router, load-balancer pools -- see `core::event_loop`) is
//! handed to every worker via `Arc`, so a respawned worker picks up
//! exactly the same shared state its predecessor had.
//!
//! This module knows nothing about connections, HTTP, or sockets -- it
//! only knows how to keep N numbered workers alive, each running some
//! caller-supplied function. `core::event_loop` supplies that function
//! (the actual accept/poll loop) and owns everything protocol-related.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Shared shutdown flag every worker's run function should poll
/// periodically and return promptly once it's set -- see `poll()`'s
/// timeout in `net::poller`, which bounds how long a worker can go
/// between checks.
#[derive(Clone)]
pub struct ShutdownSignal(Arc<AtomicBool>);

impl ShutdownSignal {
    pub fn new() -> Self {
        ShutdownSignal(Arc::new(AtomicBool::new(false)))
    }

    pub fn signal(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// What a worker actually does, supplied by the caller (`core::event_loop`
/// in practice). Receives its own worker id and the shared shutdown
/// signal; expected to return once `shutdown.is_set()` becomes true.
/// Implementors must be safe to simply run again from scratch after a
/// panic -- a respawned worker calls `run()` fresh, with no memory of
/// the panicked attempt, so `run()` shouldn't depend on partial state
/// left behind by a previous call.
pub trait WorkerBody: Send + Sync + 'static {
    fn run(&self, worker_id: usize, shutdown: &ShutdownSignal);
}

/// Lets a plain closure act as a `WorkerBody`, for callers that don't
/// need a full trait impl (tests, simple cases).
impl<F> WorkerBody for F
where
    F: Fn(usize, &ShutdownSignal) + Send + Sync + 'static,
{
    fn run(&self, worker_id: usize, shutdown: &ShutdownSignal) {
        self(worker_id, shutdown)
    }
}

/// Backoff applied before respawning a panicked worker, so a bug that
/// reliably panics on its first action (e.g. a bad request) can't spin
/// the CPU restarting in a tight loop -- it still comes back quickly,
/// just not instantly.
const RESTART_BACKOFF: Duration = Duration::from_millis(100);

/// How often the background reconciler thread checks whether any
/// worker thread has exited and needs restarting.
const RECONCILE_INTERVAL: Duration = Duration::from_millis(20);

/// Owns a fixed set of numbered workers (ids `0..n`), each running the
/// same `WorkerBody`, and keeps every one of them alive for the pool's
/// lifetime -- panics respawn, they don't propagate. A background
/// thread (the "reconciler") watches for panicked workers and restarts
/// them; `shutdown()` stops everything, including the reconciler
/// itself.
pub struct WorkerPool {
    shutdown: ShutdownSignal,
    reconciler: Option<JoinHandle<()>>,
    restarts: Arc<AtomicUsize>,
}

impl WorkerPool {
    /// Spawns `n_workers` threads, each running `body.run(id, &shutdown)`,
    /// plus one background reconciler thread that respawns any worker
    /// whose thread exits because of a panic.
    pub fn spawn<B: WorkerBody>(n_workers: usize, body: B) -> Self {
        let shutdown = ShutdownSignal::new();
        let body = Arc::new(body);
        let restarts = Arc::new(AtomicUsize::new(0));

        let handles: Vec<JoinHandle<()>> = (0..n_workers)
            .map(|id| Self::spawn_one(id, Arc::clone(&body), shutdown.clone()))
            .collect();

        let reconciler = {
            let shutdown = shutdown.clone();
            let restarts = Arc::clone(&restarts);
            std::thread::spawn(move || Self::reconcile(handles, body, shutdown, restarts))
        };

        WorkerPool {
            shutdown,
            reconciler: Some(reconciler),
            restarts,
        }
    }

    fn spawn_one<B: WorkerBody>(
        id: usize,
        body: Arc<B>,
        shutdown: ShutdownSignal,
    ) -> JoinHandle<()> {
        // No catch_unwind here: letting the panic actually unwind the
        // thread is what makes JoinHandle::join() return Err(..) for
        // the reconciler to detect below. Rust's panic runtime already
        // confines an unwind to the panicking thread alone (with
        // panic = "unwind", set in Cargo.toml) -- no other thread is
        // affected, so there's nothing to additionally isolate here.
        std::thread::Builder::new()
            .name(format!("routa-worker-{id}"))
            .spawn(move || {
                body.run(id, &shutdown);
            })
            .expect("failed to spawn worker thread")
    }

    /// Runs on its own thread for the pool's whole lifetime: polls each
    /// worker's `JoinHandle`, and whenever one has finished because of
    /// a panic (rather than a clean post-shutdown return), waits out
    /// `RESTART_BACKOFF` and spawns a fresh replacement with the same
    /// worker id. Exits once `shutdown` is set and every worker has
    /// exited cleanly.
    fn reconcile<B: WorkerBody>(
        mut handles: Vec<JoinHandle<()>>,
        body: Arc<B>,
        shutdown: ShutdownSignal,
        restarts: Arc<AtomicUsize>,
    ) {
        let mut live: Vec<Option<JoinHandle<()>>> = handles.drain(..).map(Some).collect();
        loop {
            let mut any_alive = false;
            for (id, slot) in live.iter_mut().enumerate() {
                let Some(handle) = slot.take() else {
                    continue;
                };
                if !handle.is_finished() {
                    *slot = Some(handle);
                    any_alive = true;
                    continue;
                }
                match handle.join() {
                    Ok(()) => {
                        // Clean exit after shutdown was signaled: leave
                        // this slot empty, that worker id is done for good.
                    }
                    Err(payload) => {
                        tracing::error!(worker_id = id, message = %panic_message(&payload), "worker panicked, restarting");
                        if !shutdown.is_set() {
                            std::thread::sleep(RESTART_BACKOFF);
                            restarts.fetch_add(1, Ordering::SeqCst);
                            *slot = Some(Self::spawn_one(id, Arc::clone(&body), shutdown.clone()));
                            any_alive = true;
                        }
                    }
                }
            }
            if !any_alive {
                return;
            }
            std::thread::sleep(RECONCILE_INTERVAL);
        }
    }

    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown.clone()
    }

    /// Total number of times any worker has been respawned after a
    /// panic, summed across all worker ids. Zero in steady-state
    /// operation; a nonzero, growing value is a signal worth alerting
    /// on even though the process as a whole kept running.
    pub fn total_restarts(&self) -> usize {
        self.restarts.load(Ordering::SeqCst)
    }

    /// Signals every worker to stop and blocks until the reconciler
    /// (and, through it, every worker) has exited cleanly.
    pub fn shutdown(mut self) {
        self.shutdown.signal();
        if let Some(handle) = self.reconciler.take() {
            let _ = handle.join();
        }
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingBody {
        calls: Arc<AtomicUsize>,
    }

    impl WorkerBody for CountingBody {
        fn run(&self, _worker_id: usize, shutdown: &ShutdownSignal) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            while !shutdown.is_set() {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    #[test]
    fn spawns_requested_worker_count() {
        let calls = Arc::new(AtomicUsize::new(0));
        let pool = WorkerPool::spawn(
            4,
            CountingBody {
                calls: calls.clone(),
            },
        );
        // Give threads a moment to actually start running.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        pool.shutdown();
    }

    struct PanicOnceBody {
        panicked_already: Arc<AtomicBool>,
        run_count: Arc<AtomicUsize>,
    }

    impl WorkerBody for PanicOnceBody {
        fn run(&self, _worker_id: usize, shutdown: &ShutdownSignal) {
            self.run_count.fetch_add(1, Ordering::SeqCst);
            if !self.panicked_already.swap(true, Ordering::SeqCst) {
                panic!("intentional test panic");
            }
            while !shutdown.is_set() {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    #[test]
    fn respawns_after_panic() {
        let run_count = Arc::new(AtomicUsize::new(0));
        let body = PanicOnceBody {
            panicked_already: Arc::new(AtomicBool::new(false)),
            run_count: run_count.clone(),
        };
        let pool = WorkerPool::spawn(1, body);

        // Give the first attempt time to panic and the reconciler time
        // to detect and respawn it. Poll rather than a single fixed
        // sleep, since thread scheduling latency under test-suite load
        // can otherwise make this flaky.
        for _ in 0..100 {
            if run_count.load(Ordering::SeqCst) >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(
            run_count.load(Ordering::SeqCst) >= 2,
            "expected at least one restart after the panic, got {} runs",
            run_count.load(Ordering::SeqCst)
        );
        assert!(pool.total_restarts() >= 1);
        pool.shutdown();
    }
}
