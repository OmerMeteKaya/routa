//! Event-readiness polling: a small trait (`EventPoller`) so the rest of
//! routa depends on a stable, minimal interface rather than directly on
//! whichever backend implements it. `MioPoller` is the only
//! implementation today (mio transparently uses epoll on Linux, kqueue
//! on BSD/macOS, and IOCP on Windows -- no per-OS code needed here). A
//! future io_uring-backed implementation can be added later as a second
//! type implementing the same trait, selected at compile time via a
//! Cargo feature, without any caller changing.

use std::io;
use std::time::Duration;

use mio::{Events, Interest, Token};
use slab::Slab;

/// Readiness flags for a registered source. `readable`/`writable` mirror
/// what the caller asked to be notified about; `error`/`hup` are
/// set by the kernel regardless of what was requested and always worth
/// checking (e.g. a non-blocking connect() failure surfaces as an error
/// readiness event, not as a normal writable one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub hup: bool,
}

/// What a registered source should be notified about. Always
/// edge-triggered: routa's connection state machines are written
/// against edge-triggered semantics throughout, so this isn't a
/// per-registration choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interests {
    pub readable: bool,
    pub writable: bool,
}

impl Interests {
    pub const READABLE: Interests = Interests {
        readable: true,
        writable: false,
    };
    pub const WRITABLE: Interests = Interests {
        readable: false,
        writable: true,
    };
    pub const READABLE_WRITABLE: Interests = Interests {
        readable: true,
        writable: true,
    };

    fn to_mio(self) -> Interest {
        match (self.readable, self.writable) {
            (true, true) => Interest::READABLE | Interest::WRITABLE,
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            (false, false) => Interest::READABLE, // mio requires at least one
        }
    }
}

/// A trait object-safe identifier for a registered source, opaque to
/// callers. Backed by a slab slot today; a future io_uring
/// implementation is free to give this a different meaning internally
/// as long as it keeps handing back values through this same type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PollKey(usize);

impl PollKey {
    /// Constructs a `PollKey` from a slot index a caller already
    /// allocated itself (e.g. a `Slab`'s `vacant_entry().key()`) --
    /// see `register_with_key` for why a caller would want to control
    /// this rather than receiving an independently-allocated key.
    pub const fn from_slab_index(index: usize) -> Self {
        PollKey(index)
    }

    /// The reverse of `from_slab_index`: recovers the slot index for a
    /// key that was constructed that way. Meaningless for keys that
    /// came from plain `register()` unless the caller happens to know
    /// they're numerically compatible with their own slab.
    pub const fn slab_index(self) -> usize {
        self.0
    }
}

/// The minimal readiness-polling surface routa's event loop needs:
/// register/reregister/deregister a source, and block waiting for
/// readiness events. Implementations own the mapping from their
/// internal token representation back to `PollKey`.
pub trait EventPoller {
    /// Registers `source` for the given interests, returning a key the
    /// caller uses for all future operations on it (reregister,
    /// deregister, and identifying it in `poll()`'s results).
    fn register<S: mio::event::Source>(
        &mut self,
        source: &mut S,
        interests: Interests,
    ) -> io::Result<PollKey>;

    /// Same as `register`, but the caller supplies the `PollKey` rather
    /// than receiving a freshly-allocated one. Lets a caller that
    /// already has its own O(1) slot allocator (e.g. a `Slab` of
    /// connections, keyed by the same index it wants back from
    /// `poll()`) avoid a second, independent id space -- the caller's
    /// slot index and this poller's key are then always the same
    /// number, so matching a readiness event back to connection state
    /// is a direct index, not a search.
    fn register_with_key<S: mio::event::Source>(
        &mut self,
        source: &mut S,
        key: PollKey,
        interests: Interests,
    ) -> io::Result<()>;

    /// Changes the interests for an already-registered source.
    fn reregister<S: mio::event::Source>(
        &mut self,
        source: &mut S,
        key: PollKey,
        interests: Interests,
    ) -> io::Result<()>;

    /// Deregisters a source. The key becomes invalid and may be reused
    /// for a future registration.
    fn deregister<S: mio::event::Source>(&mut self, source: &mut S, key: PollKey) -> io::Result<()>;

    /// Blocks until at least one readiness event is available (or
    /// `timeout` elapses, or `None` to block indefinitely), then
    /// returns the keys that became ready along with their readiness.
    /// Reuses an internal events buffer across calls -- callers should
    /// call this in a loop rather than constructing a new poller per
    /// iteration.
    fn poll(&mut self, timeout: Option<Duration>) -> io::Result<Vec<(PollKey, Readiness)>>;
}

/// mio-backed `EventPoller`. `Slab<()>` tracks which `PollKey`s are
/// currently live purely so keys can be validated/reused; the
/// association between a key and the caller's own connection state
/// lives in the caller (see `core::event_loop`), not here -- this type
/// only knows about readiness, never about what a source represents.
pub struct MioPoller {
    poll: mio::Poll,
    events: Events,
    slots: Slab<()>,
}

impl MioPoller {
    pub fn new(events_capacity: usize) -> io::Result<Self> {
        Ok(MioPoller {
            poll: mio::Poll::new()?,
            events: Events::with_capacity(events_capacity),
            slots: Slab::new(),
        })
    }

    fn key_to_token(key: PollKey) -> Token {
        Token(key.0)
    }

    fn token_to_key(token: Token) -> PollKey {
        PollKey(token.0)
    }

    /// Exposes the underlying `mio::Registry` so callers can build a
    /// `mio::Waker` bound to this poller (see `http::ws::WsRegistry`,
    /// which uses one to let a broadcast sent from another thread wake
    /// this poller's `poll()` call promptly instead of waiting for its
    /// next timeout).
    pub fn registry(&self) -> &mio::Registry {
        self.poll.registry()
    }
}

impl EventPoller for MioPoller {
    fn register<S: mio::event::Source>(
        &mut self,
        source: &mut S,
        interests: Interests,
    ) -> io::Result<PollKey> {
        let slot = self.slots.insert(());
        let key = PollKey(slot);
        if let Err(e) = self
            .poll
            .registry()
            .register(source, Self::key_to_token(key), interests.to_mio())
        {
            self.slots.remove(slot);
            return Err(e);
        }
        Ok(key)
    }

    fn register_with_key<S: mio::event::Source>(
        &mut self,
        source: &mut S,
        key: PollKey,
        interests: Interests,
    ) -> io::Result<()> {
        // No slab slot to reserve here -- the caller owns key allocation
        // in this path, we just need mio's registry to know about it.
        self.poll
            .registry()
            .register(source, Self::key_to_token(key), interests.to_mio())
    }

    fn reregister<S: mio::event::Source>(
        &mut self,
        source: &mut S,
        key: PollKey,
        interests: Interests,
    ) -> io::Result<()> {
        self.poll
            .registry()
            .reregister(source, Self::key_to_token(key), interests.to_mio())
    }

    fn deregister<S: mio::event::Source>(&mut self, source: &mut S, key: PollKey) -> io::Result<()> {
        self.poll.registry().deregister(source)?;
        if self.slots.contains(key.0) {
            self.slots.remove(key.0);
        }
        Ok(())
    }

    fn poll(&mut self, timeout: Option<Duration>) -> io::Result<Vec<(PollKey, Readiness)>> {
        self.poll.poll(&mut self.events, timeout)?;
        let mut out = Vec::with_capacity(self.events.iter().count());
        for ev in self.events.iter() {
            let key = Self::token_to_key(ev.token());
            out.push((
                key,
                Readiness {
                    readable: ev.is_readable(),
                    writable: ev.is_writable(),
                    error: ev.is_error(),
                    hup: ev.is_read_closed() || ev.is_write_closed(),
                },
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mio::net::{TcpListener, TcpStream};
    use std::net::SocketAddr;

    #[test]
    fn register_and_poll_readable() {
        let mut poller = MioPoller::new(16).expect("create poller");

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut listener = TcpListener::bind(addr).expect("bind listener");
        let actual_addr = listener.local_addr().expect("local addr");

        let listener_key = poller
            .register(&mut listener, Interests::READABLE)
            .expect("register listener");

        let mut client = TcpStream::connect(actual_addr).expect("connect");
        let client_key = poller
            .register(&mut client, Interests::WRITABLE)
            .expect("register client");

        // Poll until we see both the listener become readable (an
        // incoming connection queued) and the client become writable
        // (connection established) -- on loopback this should happen
        // within a handful of iterations, well under the timeout.
        let mut saw_listener_readable = false;
        let mut saw_client_writable = false;
        for _ in 0..50 {
            let events = poller
                .poll(Some(Duration::from_millis(100)))
                .expect("poll");
            for (key, readiness) in events {
                if key == listener_key && readiness.readable {
                    saw_listener_readable = true;
                }
                if key == client_key && readiness.writable {
                    saw_client_writable = true;
                }
            }
            if saw_listener_readable && saw_client_writable {
                break;
            }
        }

        assert!(saw_listener_readable, "listener never became readable");
        assert!(saw_client_writable, "client never became writable");

        poller
            .deregister(&mut client, client_key)
            .expect("deregister client");
        poller
            .deregister(&mut listener, listener_key)
            .expect("deregister listener");
    }

    #[test]
    fn deregistered_key_does_not_reappear() {
        let mut poller = MioPoller::new(16).expect("create poller");
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut listener = TcpListener::bind(addr).expect("bind listener");
        let key = poller
            .register(&mut listener, Interests::READABLE)
            .expect("register");
        poller.deregister(&mut listener, key).expect("deregister");

        let events = poller
            .poll(Some(Duration::from_millis(50)))
            .expect("poll");
        assert!(
            events.iter().all(|(k, _)| *k != key),
            "deregistered key should not produce further events"
        );
    }
}
