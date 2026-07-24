//! Per-worker accept/poll loop. Each worker opens its own listening
//! socket with `SO_REUSEPORT` -- the kernel distributes incoming
//! connections across every worker's listener itself, so there's no
//! userspace synchronization point (a mutex, a shared accept queue)
//! that a single-listener design would need, and no thundering-herd
//! wakeup either. At routa's target connection rates, avoiding any
//! cross-worker synchronization on the accept path matters more than
//! perfectly even distribution.
//!
//! This module is deliberately protocol-agnostic today: it accepts
//! connections and echoes back whatever it reads, as a minimal
//! end-to-end proof that worker + poller + real sockets compose
//! correctly. Real HTTP/1.1, TLS, and H2 handling replace the echo body
//! in later layers without changing the accept/poll structure here.

use std::io::{self, Read, Write};

use mio::net::{TcpListener, TcpStream};
use slab::Slab;

use crate::core::worker::{ShutdownSignal, WorkerBody, WorkerPool};
use crate::net::poller::{EventPoller, Interests, MioPoller, PollKey};
use crate::net::socket::bind_reuseport;

/// Reserved key for each worker's own listening socket. Real
/// connections are keyed by their slot in the worker's `Slab<Connection>`
/// (see `accept_all`), which starts at 0 and grows from there --
/// `usize::MAX` is used here specifically because it can never be a
/// valid slab index, so it can never collide with a real connection's
/// key. (Registering the listener through the poller's own
/// auto-allocating `register()` would also start counting from 0,
/// colliding with the very first accepted connection's slab-index key.)
const LISTENER_KEY: PollKey = PollKey::from_slab_index(usize::MAX);

/// Per-connection state tracked by a worker. `buf` accumulates bytes
/// read but not yet written back out -- needed because a socket can
/// become readable and fill this faster than the peer drains what we
/// write, so writes must tolerate partial completion (`WouldBlock`)
/// without losing data.
struct Connection {
    stream: TcpStream,
    poll_key: PollKey,
    buf: Vec<u8>,
    peer_closed: bool,
}

/// A worker's entire runtime state: its listener, its poller, and the
/// connections it currently owns. Nothing here is shared with other
/// workers -- each worker's `Slab<Connection>` and `MioPoller` are
/// exclusively its own, which is what makes per-worker panics safe to
/// isolate (see `core::worker`): a respawned worker starts this all
/// fresh, with no state inherited from its predecessor.
struct EventLoopWorker {
    port: u16,
}

impl WorkerBody for EventLoopWorker {
    fn run(&self, worker_id: usize, shutdown: &ShutdownSignal) {
        let mut listener = match bind_reuseport(self.port, 1024) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("worker {worker_id}: failed to bind port {}: {e}", self.port);
                return;
            }
        };

        let mut poller = match MioPoller::new(1024) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("worker {worker_id}: failed to create poller: {e}");
                return;
            }
        };

        if let Err(e) = poller.register_with_key(&mut listener, LISTENER_KEY, Interests::READABLE) {
            eprintln!("worker {worker_id}: failed to register listener: {e}");
            return;
        }

        let mut connections: Slab<Connection> = Slab::new();

        while !shutdown.is_set() {
            let events = match poller.poll(Some(std::time::Duration::from_millis(200))) {
                Ok(evs) => evs,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("worker {worker_id}: poll error: {e}");
                    break;
                }
            };

            for (key, readiness) in events {
                if key == LISTENER_KEY {
                    accept_all(&mut listener, &mut poller, &mut connections);
                    continue;
                }
                handle_connection_event(&mut poller, &mut connections, key, readiness);
            }
        }
    }
}

/// Accepts every pending connection on `listener` (there may be more
/// than one queued per readiness notification) and registers each for
/// read interest.
///
/// Uses the connection's own slab index as its `PollKey` (via
/// `register_with_key`) rather than letting the poller allocate an
/// independent one: this makes `handle_connection_event`'s lookup a
/// direct `O(1)` slab index instead of a linear search over every live
/// connection, which matters once a worker is holding thousands of
/// them.
fn accept_all(listener: &mut TcpListener, poller: &mut MioPoller, connections: &mut Slab<Connection>) {
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _addr)) => stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) => {
                eprintln!("accept error: {e}");
                return;
            }
        };

        let entry = connections.vacant_entry();
        let poll_key = PollKey::from_slab_index(entry.key());

        if let Err(e) = poller.register_with_key(&mut stream, poll_key, Interests::READABLE) {
            eprintln!("failed to register accepted connection: {e}");
            continue;
        }

        entry.insert(Connection {
            stream,
            poll_key,
            buf: Vec::new(),
            peer_closed: false,
        });
    }
}

/// Drives the connection at `key`'s slab index one step: reads
/// whatever is available (on readable), writes whatever is buffered
/// (on writable), and removes the connection once the peer has closed
/// and every buffered byte has been flushed back out. `key`'s index is
/// the connection's own slab slot (see `accept_all`), so this is a
/// direct O(1) lookup rather than a search.
fn handle_connection_event(
    poller: &mut MioPoller,
    connections: &mut Slab<Connection>,
    key: PollKey,
    readiness: crate::net::poller::Readiness,
) {
    let slot = key.slab_index();
    let Some(conn) = connections.get_mut(slot) else {
        return; // stale event for an already-removed connection
    };
    debug_assert_eq!(conn.poll_key, key);

    if readiness.readable {
        read_into_buffer(conn);
    }
    if readiness.writable || !conn.buf.is_empty() {
        flush_buffer(conn);
    }

    let done = conn.peer_closed && conn.buf.is_empty();
    if done || readiness.error || readiness.hup {
        let _ = poller.deregister(&mut conn.stream, key);
        connections.remove(slot);
    }
}

fn read_into_buffer(conn: &mut Connection) {
    let mut chunk = [0u8; 4096];
    loop {
        match conn.stream.read(&mut chunk) {
            Ok(0) => {
                conn.peer_closed = true;
                return;
            }
            Ok(n) => conn.buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                conn.peer_closed = true;
                return;
            }
        }
    }
}

fn flush_buffer(conn: &mut Connection) {
    while !conn.buf.is_empty() {
        match conn.stream.write(&conn.buf) {
            Ok(0) => return,
            Ok(n) => {
                conn.buf.drain(..n);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                conn.buf.clear();
                return;
            }
        }
    }
}

/// Spawns a panic-isolated `WorkerPool` of `n_workers` workers, each
/// running its own accept/poll loop bound (via `SO_REUSEPORT`) to the
/// same `port`.
pub fn run(port: u16, n_workers: usize) -> WorkerPool {
    WorkerPool::spawn(n_workers, EventLoopWorker { port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;
    use std::time::Duration;

    #[test]
    fn echoes_data_back_to_client() {
        // Port 0 would let the OS pick a free port, but SO_REUSEPORT
        // across multiple worker-owned sockets needs a fixed port they
        // all bind to -- pick one unlikely to collide with anything
        // else running during tests.
        let port = 18080;
        let pool = run(port, 2);

        // Give the workers a moment to bind and start polling.
        std::thread::sleep(Duration::from_millis(100));

        let mut client =
            StdTcpStream::connect(("127.0.0.1", port)).expect("connect to worker listener");
        client
            .write_all(b"hello routa")
            .expect("write to worker");

        let mut response = [0u8; 32];
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let n = client.read(&mut response).expect("read echo response");

        assert_eq!(&response[..n], b"hello routa");

        pool.shutdown();
    }
}
